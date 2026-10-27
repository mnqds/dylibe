// ============================================================
//  NetSniffer.dylib —— 网络抓包 dylib（独立于 WatermarkGuard）
//  用途：hook NSURLSession / NSURLConnection，打印请求 URL + 响应
//  目标：扒出「晒一晒」隐藏的 API 域名、登录请求/响应结构
//  日志：NSLog（可用 idevicesyslog 实时看）+ 写文件 Documents/net_sniffer.log
// ============================================================

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <stdarg.h>

// ---------- 日志 helper ----------
static NSString *g_logPath = nil;
static NSRecursiveLock *g_lock = nil;

static void sn_log(NSString *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:args];
    va_end(args);

    // 1) 控制台日志（idevicesyslog / Xcode 可见）
    NSLog(@"[NetSniffer] %@", msg);

    // 2) 写文件（保证不丢）
    if (g_lock && g_logPath) {
        [g_lock lock];
        NSString *line = [msg stringByAppendingString:@"\n"];
        NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:g_logPath];
        if (!fh) {
            [line writeToFile:g_logPath atomically:YES encoding:NSUTF8StringEncoding error:nil];
        } else {
            [fh seekToEndOfFile];
            [fh writeData:[line dataUsingEncoding:NSUTF8StringEncoding]];
            [fh closeFile];
        }
        [g_lock unlock];
    }
}

static void sn_init_log(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        g_lock = [[NSRecursiveLock alloc] init];
        NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
        NSString *doc = paths.count ? paths[0] : NSTemporaryDirectory();
        g_logPath = [doc stringByAppendingPathComponent:@"net_sniffer.log"];
        sn_log(@"=== NetSniffer loaded, log file: %@ ===", g_logPath);
    });
}

// ---------- 请求/响应 格式化 ----------
static NSString *sn_body(NSData *data) {
    if (!data || data.length == 0) return @"<empty>";
    if (data.length > 8192) return [NSString stringWithFormat:@"<%lu bytes>", (unsigned long)data.length];
    NSString *s = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    if (s) return s;
    return [[NSString alloc] initWithData:data encoding:NSASCIIStringEncoding] ?: @"<binary>";
}

static void sn_log_request(NSURLRequest *req) {
    sn_log(@"▶ REQUEST  %@ %@", req.HTTPMethod ?: @"GET", req.URL.absoluteString ?: @"(nil)");
    NSDictionary *h = req.allHTTPHeaderFields;
    if (h.count) sn_log(@"    HEADERS %@", h);
    if (req.HTTPBody) sn_log(@"    BODY    %@", sn_body(req.HTTPBody));
    if (req.HTTPBodyStream) sn_log(@"    BODY    <stream>");
}

static void sn_log_response(NSURL *url, NSData *data, NSURLResponse *resp, NSError *err) {
    if (err) {
        sn_log(@"◀ ERROR    %@  error=%@", url.absoluteString, err);
        return;
    }
    NSHTTPURLResponse *h = [resp isKindOfClass:[NSHTTPURLResponse class]] ? (NSHTTPURLResponse *)resp : nil;
    sn_log(@"◀ RESPONSE %@  status=%ld", url.absoluteString, (long)(h ? h.statusCode : -1));
    if (data) sn_log(@"    DATA    %@", sn_body(data));
}

// ---------- Method swizzling ----------
static void sn_swizzle(Class cls, SEL origSel, SEL newSel) {
    Method orig = class_getInstanceMethod(cls, origSel);
    Method new  = class_getInstanceMethod(cls, newSel);
    if (!orig || !new) return;
    method_exchangeImplementations(orig, new);
}

// ============================================================
//  NSURLSession  hook
// ============================================================
@interface NSURLSession (NetSniffer)
- (NSURLSessionDataTask *)sniff_dataTaskWithRequest:(NSURLRequest *)request
                                 completionHandler:(void (^)(NSData *, NSURLResponse *, NSError *))handler;
- (NSURLSessionDataTask *)sniff_dataTaskWithURL:(NSURL *)url
                             completionHandler:(void (^)(NSData *, NSURLResponse *, NSError *))handler;
- (NSURLSessionDataTask *)sniff_dataTaskWithRequest:(NSURLRequest *)request;
@end

@implementation NSURLSession (NetSniffer)

- (NSURLSessionDataTask *)sniff_dataTaskWithRequest:(NSURLRequest *)request
                                 completionHandler:(void (^)(NSData *, NSURLResponse *, NSError *))handler {
    sn_log_request(request);
    void (^wrapped)(NSData *, NSURLResponse *, NSError *) = ^(NSData *data, NSURLResponse *resp, NSError *err) {
        sn_log_response(request.URL, data, resp, err);
        if (handler) handler(data, resp, err);
    };
    // 注意：swizzle 后这里调用的是原始实现
    return [self sniff_dataTaskWithRequest:request completionHandler:wrapped];
}

- (NSURLSessionDataTask *)sniff_dataTaskWithURL:(NSURL *)url
                             completionHandler:(void (^)(NSData *, NSURLResponse *, NSError *))handler {
    sn_log(@"▶ REQUEST  GET %@", url.absoluteString);
    void (^wrapped)(NSData *, NSURLResponse *, NSError *) = ^(NSData *data, NSURLResponse *resp, NSError *err) {
        sn_log_response(url, data, resp, err);
        if (handler) handler(data, resp, err);
    };
    return [self sniff_dataTaskWithURL:url completionHandler:wrapped];
}

- (NSURLSessionDataTask *)sniff_dataTaskWithRequest:(NSURLRequest *)request {
    sn_log_request(request);
    return [self sniff_dataTaskWithRequest:request];
}

@end

// ============================================================
//  NSURLConnection  hook（旧 API，有些库还在用）
// ============================================================
@interface NSURLConnection (NetSniffer)
+ (void)sniff_sendAsynchronousRequest:(NSURLRequest *)request
                                queue:(NSOperationQueue *)queue
                    completionHandler:(void (^)(NSURLResponse *, NSData *, NSError *))handler;
@end

@implementation NSURLConnection (NetSniffer)
+ (void)sniff_sendAsynchronousRequest:(NSURLRequest *)request
                                queue:(NSOperationQueue *)queue
                    completionHandler:(void (^)(NSURLResponse *, NSData *, NSError *))handler {
    sn_log_request(request);
    void (^wrapped)(NSURLResponse *, NSData *, NSError *) = ^(NSURLResponse *resp, NSData *data, NSError *err) {
        sn_log_response(request.URL, data, resp, err);
        if (handler) handler(resp, data, err);
    };
    [self sniff_sendAsynchronousRequest:request queue:queue completionHandler:wrapped];
}
@end

// ============================================================
//  constructor：启动时自动 hook
// ============================================================
__attribute__((constructor))
static void NetSniffer_init(void) {
    @autoreleasepool {
        sn_init_log();

        // NSURLSession 实例方法
        sn_swizzle(objc_getClass("NSURLSession"),
                   @selector(dataTaskWithRequest:completionHandler:),
                   @selector(sniff_dataTaskWithRequest:completionHandler:));
        sn_swizzle(objc_getClass("NSURLSession"),
                   @selector(dataTaskWithURL:completionHandler:),
                   @selector(sniff_dataTaskWithURL:completionHandler:));
        sn_swizzle(objc_getClass("NSURLSession"),
                   @selector(dataTaskWithRequest:),
                   @selector(sniff_dataTaskWithRequest:));

        // NSURLConnection 类方法
        sn_swizzle(objc_getMetaClass("NSURLConnection"),
                   @selector(sendAsynchronousRequest:queue:completionHandler:),
                   @selector(sniff_sendAsynchronousRequest:queue:completionHandler:));

        sn_log(@"=== NetSniffer hooks installed (NSURLSession + NSURLConnection) ===");
    }
}
