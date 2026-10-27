// ============================================================
//  NetSniffer.dylib —— 网络抓包 dylib（独立于 WatermarkGuard）
//  用途：hook NSURLSession / NSURLConnection，打印请求 URL + 响应
//  日志三重输出：NSLog + 文件 Documents/net_sniffer.log + 相册图片
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
    // 有响应了，触发保存相册（防抖）
    sn_schedule_album();
}

// ---------- 相册保存 ----------
static void sn_save_album_now(void);

static dispatch_block_t g_pending = nil;
static void sn_schedule_album(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        if (g_pending) dispatch_block_cancel(g_pending);
        g_pending = dispatch_block_create(0, ^{ sn_save_album_now(); });
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), g_pending);
    });
}

static UIImage *sn_render(NSString *text) {
    CGFloat w = 1080;
    UIFont *font = [UIFont systemFontOfSize:24];
    NSDictionary *attrs = @{NSFontAttributeName: font, NSForegroundColorAttributeName: [UIColor blackColor]};
    CGRect r = [text boundingRectWithSize:CGSizeMake(w - 60, CGFLOAT_MAX)
                                  options:NSStringDrawingUsesLineFragmentOrigin
                               attributes:attrs context:nil];
    CGFloat h = ceil(r.size.height) + 60;
    if (h < 200) h = 200;
    UIGraphicsBeginImageContextWithOptions(CGSizeMake(w, h), NO, 2.0);
    [[UIColor whiteColor] setFill];
    UIRectFill(CGRectMake(0, 0, w, h));
    [text drawInRect:CGRectMake(30, 30, w - 60, h - 60) withAttributes:attrs];
    UIImage *img = UIGraphicsGetImageFromCurrentImageContext();
    UIGraphicsEndImageContext();
    return img;
}

static void sn_save_album_now(void) {
    NSString *log = nil;
    [g_lock lock];
    log = [g_buffer copy];
    [g_lock unlock];
    if (!log || log.length == 0) return;
    UIImage *img = sn_render(log);
    if (img) {
        UIImageWriteToSavedPhotosAlbum(img, nil, nil, nil);
        sn_log(@"=== 日志已保存到相册（%lu 字符）===", (unsigned long)log.length);
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
    }
}
