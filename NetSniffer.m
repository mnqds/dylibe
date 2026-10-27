// ============================================================
//  NetSniffer.dylib —— 网络抓包 dylib（独立于 WatermarkGuard）
//  hook NSURLSession / NSURLConnection，抓请求 URL + 响应
//  日志输出：NSLog + 文件 + 系统剪贴板（每 2 秒刷新一次）
//  用户操作：打开「备忘录」→ 长按 → 粘贴，即可看到日志全文
// ============================================================

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <stdarg.h>

// ---------- 日志缓冲区 ----------
static NSMutableString *g_buffer = nil;
static NSRecursiveLock *g_lock = nil;
static NSString *g_logPath = nil;

static void sn_log(NSString *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:args];
    va_end(args);

    NSLog(@"[NetSniffer] %@", msg);

    if (g_lock) {
        [g_lock lock];
        if (!g_buffer) g_buffer = [[NSMutableString alloc] init];
        [g_buffer appendFormat:@"%@\n", msg];
        if (g_buffer.length > 20000) {
            [g_buffer deleteCharactersInRange:NSMakeRange(0, g_buffer.length - 20000)];
        }
        if (g_logPath) {
            NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:g_logPath];
            if (!fh) {
                [[msg stringByAppendingString:@"\n"] writeToFile:g_logPath atomically:YES encoding:NSUTF8StringEncoding error:nil];
            } else {
                [fh seekToEndOfFile];
                [fh writeData:[[msg stringByAppendingString:@"\n"] dataUsingEncoding:NSUTF8StringEncoding]];
                [fh closeFile];
            }
        }
        [g_lock unlock];
    }
}

static void sn_init_log(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        g_lock = [[NSRecursiveLock alloc] init];
        g_buffer = [[NSMutableString alloc] init];
        NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
        NSString *doc = paths.count ? paths[0] : NSTemporaryDirectory();
        g_logPath = [doc stringByAppendingPathComponent:@"net_sniffer.log"];
        sn_log(@"=== NetSniffer loaded ===");
    });
}

// ---------- 剪贴板输出（每 2 秒刷新）----------
static NSString *g_last_pb = nil;
static void sn_update_pasteboard(void) {
    NSString *log = nil;
    [g_lock lock];
    log = [g_buffer copy];
    [g_lock unlock];
    if (!log || log.length == 0) return;
    if (g_last_pb && [g_last_pb isEqualToString:log]) return;  // 没变化跳过
    g_last_pb = log;
    dispatch_async(dispatch_get_main_queue(), ^{
        [UIPasteboard generalPasteboard].string = log;
        NSLog(@"[NetSniffer] 日志已写入剪贴板（%lu 字符）", (unsigned long)log.length);
    });
}

static dispatch_source_t g_pb_timer = nil;
static void sn_start_pb_timer(void) {
    if (g_pb_timer) return;
    g_pb_timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, dispatch_get_main_queue());
    dispatch_source_set_timer(g_pb_timer,
                              dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC),
                              2 * NSEC_PER_SEC, 1 * NSEC_PER_SEC);
    dispatch_source_set_event_handler(g_pb_timer, ^{ sn_update_pasteboard(); });
    dispatch_resume(g_pb_timer);
}

// ---------- 请求/响应 格式化 ----------
static NSString *sn_body(NSData *data) {
    if (!data || data.length == 0) return @"<empty>";
    if (data.length > 6000) return [NSString stringWithFormat:@"<%lu bytes>", (unsigned long)data.length];
    NSString *s = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    return s ?: @"<binary>";
}

static void sn_log_request(NSURLRequest *req) {
    sn_log(@"REQ %@ %@", req.HTTPMethod ?: @"GET", req.URL.absoluteString ?: @"(nil)");
    NSDictionary *h = req.allHTTPHeaderFields;
    if (h.count) sn_log(@"  HDR %@", h);
    if (req.HTTPBody) sn_log(@"  BODY %@", sn_body(req.HTTPBody));
}

static void sn_log_response(NSURL *url, NSData *data, NSURLResponse *resp, NSError *err) {
    if (err) {
        sn_log(@"RSP %@ ERROR %@", url.absoluteString, err);
    } else {
        NSHTTPURLResponse *h = [resp isKindOfClass:[NSHTTPURLResponse class]] ? (NSHTTPURLResponse *)resp : nil;
        sn_log(@"RSP %@ status=%ld", url.absoluteString, (long)(h ? h.statusCode : -1));
        if (data) sn_log(@"  DATA %@", sn_body(data));
    }
}

// ---------- Method swizzling ----------
static void sn_swizzle(Class cls, SEL origSel, SEL newSel) {
    Method orig = class_getInstanceMethod(cls, origSel);
    Method new  = class_getInstanceMethod(cls, newSel);
    if (!orig || !new) return;
    method_exchangeImplementations(orig, new);
}

@interface NSURLSession (NetSniffer)
- (NSURLSessionDataTask *)sniff_dataTaskWithRequest:(NSURLRequest *)request
                                 completionHandler:(void (^)(NSData *, NSURLResponse *, NSError *))handler;
- (NSURLSessionDataTask *)sniff_dataTaskWithURL:(NSURL *)url
                             completionHandler:(void (^)(NSData *, NSURLResponse *, NSError *))handler;
@end

@implementation NSURLSession (NetSniffer)
- (NSURLSessionDataTask *)sniff_dataTaskWithRequest:(NSURLRequest *)request
                                 completionHandler:(void (^)(NSData *, NSURLResponse *, NSError *))handler {
    sn_log_request(request);
    void (^wrapped)(NSData *, NSURLResponse *, NSError *) = ^(NSData *data, NSURLResponse *resp, NSError *err) {
        sn_log_response(request.URL, data, resp, err);
        if (handler) handler(data, resp, err);
    };
    return [self sniff_dataTaskWithRequest:request completionHandler:wrapped];
}
- (NSURLSessionDataTask *)sniff_dataTaskWithURL:(NSURL *)url
                             completionHandler:(void (^)(NSData *, NSURLResponse *, NSError *))handler {
    sn_log(@"REQ GET %@", url.absoluteString);
    void (^wrapped)(NSData *, NSURLResponse *, NSError *) = ^(NSData *data, NSURLResponse *resp, NSError *err) {
        sn_log_response(url, data, resp, err);
        if (handler) handler(data, resp, err);
    };
    return [self sniff_dataTaskWithURL:url completionHandler:wrapped];
}
@end

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

__attribute__((constructor))
static void NetSniffer_init(void) {
    @autoreleasepool {
        sn_init_log();
        sn_swizzle(objc_getClass("NSURLSession"),
                   @selector(dataTaskWithRequest:completionHandler:),
                   @selector(sniff_dataTaskWithRequest:completionHandler:));
        sn_swizzle(objc_getClass("NSURLSession"),
                   @selector(dataTaskWithURL:completionHandler:),
                   @selector(sniff_dataTaskWithURL:completionHandler:));
        sn_swizzle(objc_getMetaClass("NSURLConnection"),
                   @selector(sendAsynchronousRequest:queue:completionHandler:),
                   @selector(sniff_sendAsynchronousRequest:queue:completionHandler:));
        sn_log(@"=== hooks installed ===");
        sn_start_pb_timer();
    }
}
