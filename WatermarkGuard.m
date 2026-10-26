//
//  WatermarkGuard.m
//  通用 iOS「卡密验证 + 全局水印」dylib
//
//  兼容：iOS 14 ~ 18 / arm64 / UIKit · SwiftUI · SceneDelegate · AppDelegate 全架构
//  原则：核心自洽、增强可关、失败静默、绝不主动让宿主崩溃
//

#import "WatermarkGuard.h"

#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <sys/sysctl.h>
/* iOS SDK 不提供 <sys/ptrace.h> / <sys/proc.h>：ptrace 原型与 P_TRACED 自行声明 */
extern int ptrace(int _request, int _pid, void *_addr, int _data);
#ifndef P_TRACED
#define P_TRACED 0x00000800
#endif
#ifndef PT_DENY_ATTACH
#define PT_DENY_ATTACH 31
#endif
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <stdlib.h>
#import <string.h>
#import <CFNetwork/CFNetwork.h>
#import <Security/Security.h>
#import <CommonCrypto/CommonDigest.h>

/* 兜底：个别精简 SDK 可能缺这两个宏 */
#ifndef P_TRACED
#define P_TRACED 0x00000800
#endif
#ifndef PT_DENY_ATTACH
#define PT_DENY_ATTACH 31
#endif

/* 仅用于 @synchronized 的锚点类 */
@interface WatermarkGuardAnchor : NSObject
@end

/* ============================================================================
 * 一、功能开关（改这里即可，无需动下方逻辑）
 * ==========================================================================*/
#define WG_ENABLE_CORE                 1  // 总开关：0 = 整个 dylib 什么都不做
#define WG_ENABLE_WATERMARK            1  // 核心：全局水印 UI
#define WG_ENABLE_VERIFY               1  // 核心：独立卡密验证
#define WG_ENABLE_DEBUGGER_CHECK       1  // 增强：反调试（默认开，误杀极低）
#define WG_ENABLE_FRIDA_CHECK          1  // 增强：Frida / Cycript 检测（默认开）
#define WG_ENABLE_SELF_INTEGRITY       1  // 增强：自身完整性校验（默认开）
#define WG_ENABLE_JAILBREAK_CHECK      0  // 增强：越狱检测（误杀中等，默认关）
#define WG_ENABLE_MULTIOPEN_CHECK      0  // 增强：多开/分身检测（误杀中等，默认关）
#define WG_ENABLE_PROXY_CHECK          0  // 增强：系统代理检测（误杀高，默认关）
#define WG_ENABLE_SIMULATOR_CHECK      0  // 增强：模拟器检测（误判高，默认关）
#define WG_ENABLE_SSL_PINNING          0  // 增强：验证接口证书绑定（默认关）
#define WG_ENABLE_HTTP_HEADER_HOOK     0  // 增强：给原生请求追加 Header（默认关）
#define WG_ENABLE_FORCE_EXIT_L3        1  // 三级异常是否 exit(0)：1 开启（按需求）

/* ============================================================================
 * 二、常量配置（部署前必改）
 * ==========================================================================*/
static NSString *const kWGVerifyURL        = @"https://lib.ggboog.xin/verify.php"; // 卡密验证接口
static NSString *const kWGCardDefaultsKey  = @"licenseCode";                    // ← 卡密在 NSUserDefaults 的字段名
static NSString *const kWGAppID            = @"app_001";                        // ← 多软件隔离用
static NSString *const kWGPlatform         = @"ios";
static NSString *const kWGNoticeSeenKey    = @"wg_notice_seen";                  // 已展示过的公告 ID
static NSString *const kWGServiceCacheKey  = @"wg_service_cache";               // 缓存的客服信息
static NSString *const kWGModeCacheKey     = @"wg_verify_mode";                 // 服务端下发的验证模式 watermark / strict
static NSString *const kWGPassCacheKey     = @"wg_pass_cache";                  // 上次验证通过的卡密 + 时间（用于启动瞬间的免水印判定）
static NSString *const kWGDefaultWaterText = @"未授权 · 请激活";                 // 接口返回空 water_text 时的兜底文案
static NSString *const kWGRiskLevel1Text   = @"⚠ 运行环境异常";                  // 一级异常追加到水印的文字
static NSString *const kWGPinnedCertSHA256 = @"";                               // 开启 Pinning 时填证书 SHA256(hex)
static NSString *const kWGHTTPHookKeyword  = @"/api/";                          // 仅拦截 URL 含此关键字的 POST 请求

static const NSTimeInterval kWGFirstDelay       = 2.0;    // 首次校验延迟（秒）：启动后立即校验，公告/客服/卡密状态不用等
static const NSTimeInterval kWGVerifyInterval   = 120.0;  // 前台校验间隔（秒）
static const NSTimeInterval kWGSecurityInterval = 60.0;   // 安全复检间隔（秒）
static const NSTimeInterval kWGRequestTimeout   = 10.0;   // 验证请求超时（秒）
static const NSInteger      kWGAnomalyAlertLevel = 2;     // 连续 N 次弹提示框
static const NSInteger      kWGAnomalyExitLevel  = 3;     // 连续 N 次强制退出

/* ============================================================================
 * 三、内部状态
 * ==========================================================================*/
static UIWindow *gOverlayWindow = nil;
static UIView   *gWaterView     = nil;   // 全屏平铺水印层（斜 30° 重复文字）
static UIButton *gActivateBtn   = nil;   // 右下角/右上角「卡密激活」入口
static NSString *gWaterText     = nil;   // 接口下发的文案
static NSString *gRiskText      = nil;   // 安全模块追加的风险文案
static BOOL      gWaterHidden   = YES;   // YES = 无水印
static BOOL      gStarted       = NO;
static int       gSceneRetry    = 0;    // 等待 UIWindowScene 的重试计数

static NSMutableDictionary<NSString *, NSNumber *> *gAnomalyCounts = nil;
static NSMutableSet<NSString *> *gAlertedItems = nil;
static uint32_t  gSelfFingerprint = 0;
static volatile NSTimeInterval gLastActivationTry = 0;   // 用户手动点「激活」的时间（用于失败提示，跨线程读写）
static volatile BOOL gStrictMode = NO;   // 严格模式：激活弹窗只有「激活/退出」，不激活就退出；NO = 水印模式（可关闭弹窗继续用，水印保留）

static dispatch_queue_t gVerifyQueue = NULL;
static dispatch_queue_t gSecurityQueue = NULL;
static dispatch_source_t gVerifyTimer = NULL;
static dispatch_source_t gSecurityTimer = NULL;

/* 前向声明 */
static void WGEnsureOverlay(void);
static void WGApplyWatermark(void);
static void WGSetWatermark(BOOL hidden, NSString *text);
static void WGSetRiskText(NSString *text);
static void WGShowAnomalyAlert(NSString *message);
static void WGPerformVerify(void);
static BOOL WGIsAppActive(void);
static BOOL WGCachedPassValid(NSString *code);
static void WGShowActivationPanel(void);
static void WGApplyRemoteInfo(NSDictionary *d);
static void WGShowInfoAlert(NSString *title, NSString *message);
static NSString *WGServiceSummary(void);

/* ============================================================================
 * 四、通用小工具
 * ==========================================================================*/
static void WGLog(NSString *fmt, ...) {
#ifdef WG_DEBUG_LOG
    va_list ap;
    va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSLog(@"[WatermarkGuard] %@", s);
#endif
}

static NSString *WGURLEncode(NSString *s) {
    if (s.length == 0) return @"";
    NSCharacterSet *allowed = [NSCharacterSet alphanumericCharacterSet];
    NSString *r = [s stringByAddingPercentEncodingWithAllowedCharacters:allowed];
    return r ?: @"";
}

/// 宽松布尔解析：兼容 true/false、"true"/"1"/"yes"、1/0
static BOOL WGBoolValue(id v) {
    if (!v || v == [NSNull null]) return NO;
    if ([v isKindOfClass:[NSNumber class]]) return [v boolValue];
    if ([v isKindOfClass:[NSString class]]) {
        NSString *s = [(NSString *)v lowercaseString];
        return ([s isEqualToString:@"true"] || [s isEqualToString:@"1"] || [s isEqualToString:@"yes"]);
    }
    return NO;
}

static volatile int32_t gAppStateCache = 1;   // 1 = 前台，0 = 其它（后台/失活）

static BOOL WGIsAppActive(void) {
    if ([NSThread isMainThread]) {
        @try {
            return [UIApplication sharedApplication].applicationState == UIApplicationStateActive;
        } @catch (...) {
            return YES;
        }
    }
    // 子线程：异步回主线程取值并等 0.5 秒。
    // 不用 dispatch_sync —— 宿主主线程若被长时间阻塞会连带卡死检测队列；超时则退回上次缓存值。
    __block BOOL active = YES;
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    dispatch_async(dispatch_get_main_queue(), ^{
        @try {
            active = [UIApplication sharedApplication].applicationState == UIApplicationStateActive;
        } @catch (...) {}
        gAppStateCache = active ? 1 : 0;
        dispatch_semaphore_signal(sem);
    });
    if (dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC))) != 0) {
        return gAppStateCache != 0;
    }
    return active;
}

/// 启动瞬间判断：上次验证通过且未超过 6 小时 → 先不给水印，等后台校验结果再决定
static BOOL WGCachedPassValid(NSString *code) {
    @try {
        if (code.length == 0) return NO;
        NSDictionary *c = [[NSUserDefaults standardUserDefaults] dictionaryForKey:kWGPassCacheKey];
        if (![c isKindOfClass:[NSDictionary class]]) return NO;
        NSString *cc = c[@"code"];
        if (![cc isKindOfClass:[NSString class]] || ![cc isEqualToString:code]) return NO;
        double ts = [c[@"ts"] doubleValue];
        return ([[NSDate date] timeIntervalSince1970] - ts) < 6 * 3600.0;
    } @catch (...) {
        return NO;
    }
}

/// 判断宿主是否采用 UIScene 生命周期。
/// 场景型 App 用 initWithFrame: 建的 UIWindow 根本不会显示，所以不能回落 legacy 窗口。
static BOOL WGAppUsesScenes(void) {
    @try {
        if ([UIApplication sharedApplication].connectedScenes.count > 0) return YES;
        id m = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"UIApplicationSceneManifest"];
        if ([m isKindOfClass:[NSDictionary class]]) return YES;
    } @catch (...) {}
    return NO;
}

static UIWindowScene *WGActiveWindowScene(void) {
    @try {
        UIWindowScene *fallback = nil;
        for (UIScene *s in [UIApplication sharedApplication].connectedScenes) {
            if (![s isKindOfClass:[UIWindowScene class]]) continue;
            UIWindowScene *ws = (UIWindowScene *)s;
            if (ws.activationState == UISceneActivationStateForegroundActive) return ws;
            if (!fallback) fallback = ws;
        }
        return fallback;
    } @catch (...) {
        return nil;
    }
}

/* ============================================================================
 * 五、水印 UI（独立 Window，不侵入宿主视图）
 * ==========================================================================*/
/* 全屏平铺水印层：斜 30° 重复文字铺满整屏，只负责「画」，不参与触摸。
 * 未授权时 App 依然可以正常操作，只有底部「输入卡密」按钮和验证弹窗接收触摸。 */
@interface WGWatermarkView : UIView
@property (nonatomic, copy) NSString *text;
@end

@implementation WGWatermarkView
- (instancetype)initWithFrame:(CGRect)frame {
    if ((self = [super initWithFrame:frame])) {
        self.backgroundColor = [UIColor clearColor];
        self.opaque = NO;
        // 水印只是画上去，不吞触摸：没卡也能正常操作 App
        self.userInteractionEnabled = NO;
        // 旋转/尺寸变化时把画布拉伸会糊，必须重绘
        self.contentMode = UIViewContentModeRedraw;
        self.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    }
    return self;
}
- (void)setText:(NSString *)text {
    _text = [text copy];
    [self setNeedsDisplay];
}
- (void)drawRect:(CGRect)rect {
    NSString *t = self.text.length ? self.text : kWGDefaultWaterText;
    NSDictionary *attrs = @{
        NSFontAttributeName: [UIFont systemFontOfSize:13.0],
        NSForegroundColorAttributeName: [UIColor colorWithWhite:0.35 alpha:0.22],
    };
    CGSize ts = [t sizeWithAttributes:attrs];
    if (ts.width <= 0) return;
    CGContextRef ctx = UIGraphicsGetCurrentContext();
    if (!ctx) return;

    CGFloat W = self.bounds.size.width, H = self.bounds.size.height;
    CGFloat diag = sqrt(W * W + H * H);
    CGFloat stepX = ts.width + 72.0;
    CGFloat stepY = ts.height + 86.0;

    CGContextSaveGState(ctx);
    CGContextTranslateCTM(ctx, W / 2.0, H / 2.0);
    CGContextRotateCTM(ctx, -0.5236);           // -30°
    CGFloat half = diag / 2.0 + stepX;
    for (CGFloat y = -half; y <= half; y += stepY) {
        for (CGFloat x = -half; x <= half; x += stepX) {
            [t drawAtPoint:CGPointMake(x - ts.width / 2.0, y - ts.height / 2.0) withAttributes:attrs];
        }
    }
    CGContextRestoreGState(ctx);
}
@end

/* 水印窗口：只让「输入卡密」按钮和弹窗接收触摸，其余区域的触摸全部透传给宿主 App。
 * 这样没卡也能正常用 App，只是画面带水印。 */
@interface WGOverlayWindow : UIWindow
@end

@implementation WGOverlayWindow
- (UIView *)hitTest:(CGPoint)point withEvent:(UIEvent *)event {
    UIView *v = [super hitTest:point withEvent:event];
    if (!v) return nil;
    // 弹窗（激活/公告/提示）展示期间正常接收，否则按钮点不动
    if (self.rootViewController.presentedViewController) return v;
    // 空白区 / 水印层 / 根视图 → 返回 nil，事件交给下面的宿主窗口
    if (v == self || v == self.rootViewController.view || (gWaterView && v == gWaterView)) return nil;
    return v;
}
@end

@interface WGOverlayController : UIViewController
- (void)onActivateTap:(id)sender;
- (void)onCopyServiceTap:(id)sender;
@end

@implementation WGOverlayController
- (void)loadView {
    UIView *v = [[UIView alloc] initWithFrame:[UIScreen mainScreen].bounds];
    v.backgroundColor = [UIColor clearColor];
    v.userInteractionEnabled = YES;
    self.view = v;
}
- (void)onActivateTap:(id)sender {
    WGShowActivationPanel();
}
- (void)onCopyServiceTap:(id)sender {
    @try {
        NSString *svc = WGServiceSummary();
        if (svc.length) [UIPasteboard generalPasteboard].string = svc;
    } @catch (...) {}
}
- (BOOL)shouldAutorotate { return YES; }
- (UIInterfaceOrientationMask)supportedInterfaceOrientations { return UIInterfaceOrientationMaskAll; }
@end

static void WGEnsureOverlay(void) {
    @try {
        if (![NSThread isMainThread]) {
            dispatch_async(dispatch_get_main_queue(), ^{ WGEnsureOverlay(); });
            return;
        }
        // 注意：即使水印功能关闭也要允许创建窗口——二级异常的全局提示框需要它做容器。
        // 水印文案的显隐由 WGApplyWatermark 里的 WG_ENABLE_WATERMARK 单独控制，窗口平时保持 hidden。

        if (gOverlayWindow) {
            // 多窗口/多场景切换时重新挂载：窗口挂在「非前台激活」的 scene 上是不可见的，
            // 只要当前 scene 不是 ForegroundActive 就换到活跃 scene 上
            UIWindowScene *cur = gOverlayWindow.windowScene;
            if (!cur || cur.activationState != UISceneActivationStateForegroundActive) {
                UIWindowScene *s2 = WGActiveWindowScene();
                if (s2) {
                    gOverlayWindow.windowScene = s2;
                    cur = s2;
                }
            }
            // 注意：无 scene（传统 AppDelegate 架构）时不能取 coordinateSpace.bounds，否则 frame 归零
            gOverlayWindow.frame = cur ? cur.coordinateSpace.bounds : [UIScreen mainScreen].bounds;
            return;
        }

        UIWindowScene *ws = WGActiveWindowScene();
        if (!ws) {
            if (WGAppUsesScenes()) {
                // 场景型 App（SwiftUI / SceneDelegate）启动瞬间 scene 可能还没就绪。
                // 这种 App 用 initWithFrame: 建的窗口不会显示，绝不能回落成 legacy 窗口，
                // 否则未授权状态下直接裸奔。有限重试，之后交给 4 秒看门狗继续补。
                if (gSceneRetry < 20) {
                    gSceneRetry++;
                    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)),
                                   dispatch_get_main_queue(), ^{ WGEnsureOverlay(); });
                }
                return;
            }
            // 传统 AppDelegate 架构（Info.plist 无 UIApplicationSceneManifest）：直接建 legacy 窗口
            WGLog(@"legacy app, use plain UIWindow");
        }

        WGOverlayWindow *w = ws ? [[WGOverlayWindow alloc] initWithWindowScene:ws]
                                : [[WGOverlayWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
        w.frame = ws ? ws.coordinateSpace.bounds : [UIScreen mainScreen].bounds;
        w.windowLevel = UIWindowLevelAlert + 1;     // 高于宿主所有页面
        w.backgroundColor = [UIColor clearColor];
        // 窗口本身必须可交互，否则按钮也点不到；空白区的穿透交给 WGOverlayWindow 的 hitTest 处理
        w.userInteractionEnabled = YES;
        w.hidden = YES;

        WGOverlayController *vc = [[WGOverlayController alloc] init];
        w.rootViewController = vc;

        // 水印层与按钮都挂在 rootViewController.view 上：
        // 直接挂 UIWindow 会被 UIKit 的 window 视图重排盖到 root view 下面，导致按钮点不动。
        UIView *rootView = vc.view;

        WGWatermarkView *wm = [[WGWatermarkView alloc] initWithFrame:rootView.bounds];
        wm.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
        [rootView addSubview:wm];

        // 屏幕下方「输入卡密」按钮：未授权时唯一可点的东西
        UIButton *b = [UIButton buttonWithType:UIButtonTypeSystem];
        [b setTitle:@"输入卡密" forState:UIControlStateNormal];
        [b setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
        b.titleLabel.font = [UIFont boldSystemFontOfSize:14.0];
        b.backgroundColor = [UIColor colorWithWhite:0.12 alpha:0.86];
        b.layer.cornerRadius = 19.0;
        b.translatesAutoresizingMaskIntoConstraints = NO;
        b.hidden = YES;
        [b addTarget:vc action:@selector(onActivateTap:) forControlEvents:UIControlEventTouchUpInside];
        [rootView addSubview:b];
        [NSLayoutConstraint activateConstraints:@[
            [b.centerXAnchor constraintEqualToAnchor:rootView.centerXAnchor],
            [b.bottomAnchor constraintEqualToAnchor:rootView.safeAreaLayoutGuide.bottomAnchor constant:-36.0],
            [b.widthAnchor constraintEqualToConstant:136.0],
            [b.heightAnchor constraintEqualToConstant:38.0],
        ]];

        gOverlayWindow = w;
        gWaterView = wm;
        gActivateBtn = b;
        WGLog(@"overlay window created");
    } @catch (...) {
        WGLog(@"ensure overlay failed");
    }
}

/* 激活面板里要输入卡密：必须让覆盖窗口成为 key window，键盘才会挂到这个窗口上。
 * 面板关闭后把 key window 还给宿主，避免影响宿主自己的输入框。 */
static UIWindow *gPrevKeyWindow = nil;

static void WGMakeOverlayKeyWindow(BOOL on) {
    @try {
        if (![NSThread isMainThread] || !gOverlayWindow) return;
        if (on) {
            UIWindow *prev = nil;
            @try {
                for (UIWindow *x in gOverlayWindow.windowScene.windows) {
                    if (x != gOverlayWindow && x.isKeyWindow) { prev = x; break; }
                }
            } @catch (...) {}
            if (prev) gPrevKeyWindow = prev;
            [gOverlayWindow makeKeyWindow];
        } else {
            UIWindow *prev = gPrevKeyWindow;
            gPrevKeyWindow = nil;
            if (prev && prev != gOverlayWindow) [prev makeKeyWindow];
        }
    } @catch (...) {}
}

static void WGApplyWatermark(void) {
    @try {
        if (![NSThread isMainThread]) {
            dispatch_async(dispatch_get_main_queue(), ^{ WGApplyWatermark(); });
            return;
        }
        if (!WG_ENABLE_WATERMARK) return;
        WGEnsureOverlay();
        if (!gOverlayWindow || !gWaterView) return;

        NSMutableString *text = [NSMutableString string];
        // 有风险提示时即使当前「无水印」也要显示（一级异常的处置就是追加文字）
        if (!gWaterHidden || gRiskText.length) {
            [text appendString:(gWaterText.length ? gWaterText : kWGDefaultWaterText)];
            if (gRiskText.length) {
                [text appendString:@" "];
                [text appendString:gRiskText];
            }
        }
        [(WGWatermarkView *)gWaterView setText:text];
        BOOL show = (text.length != 0);
        gOverlayWindow.hidden = !show;
        // 注意：这里不能再动 userInteractionEnabled。
        // 未授权时窗口要一直可交互，「输入卡密」按钮才点得动；
        // 而窗口上除按钮/弹窗以外的区域由 WGOverlayWindow.hitTest 返回 nil 直接穿透给宿主，
        // 所以没输入卡密也能正常操作 App（水印只是画在上面）。
        if (gActivateBtn) gActivateBtn.hidden = !show;   // 已授权（无水印）就收起激活入口
    } @catch (...) {
        WGLog(@"apply watermark failed");
    }
}

static void WGSetWatermark(BOOL hidden, NSString *text) {
    @try {
        NSString *copy = [text isKindOfClass:[NSString class]] ? [text copy] : nil;
        dispatch_async(dispatch_get_main_queue(), ^{
            @try {
                gWaterHidden = hidden;
                if (copy.length) gWaterText = copy;
                WGApplyWatermark();
            } @catch (...) {}
        });
    } @catch (...) {}
}

static void WGSetRiskText(NSString *text) {
    @try {
        NSString *copy = [text copy];
        dispatch_async(dispatch_get_main_queue(), ^{
            @try {
                gRiskText = copy;
                WGApplyWatermark();
            } @catch (...) {}
        });
    } @catch (...) {}
}

/* ============================================================================
 * 五之二、卡密激活入口 / 远程公告 / 客服信息
 * ==========================================================================*/

/// 拼接缓存的客服信息，用于激活窗口里的说明文字
static NSString *WGServiceSummary(void) {
    @try {
        NSDictionary *s = [[NSUserDefaults standardUserDefaults] dictionaryForKey:kWGServiceCacheKey];
        if (![s isKindOfClass:[NSDictionary class]]) return nil;
        NSMutableArray *parts = [NSMutableArray array];
        id note = s[@"note"];
        if ([note isKindOfClass:[NSString class]] && [(NSString *)note length]) [parts addObject:note];
        id wx = s[@"wechat"];
        if ([wx isKindOfClass:[NSString class]] && [(NSString *)wx length]) [parts addObject:[@"微信：" stringByAppendingString:wx]];
        id qq = s[@"qq"];
        if ([qq isKindOfClass:[NSString class]] && [(NSString *)qq length]) [parts addObject:[@"QQ：" stringByAppendingString:qq]];
        id url = s[@"url"];
        if ([url isKindOfClass:[NSString class]] && [(NSString *)url length]) [parts addObject:url];
        return parts.count ? [parts componentsJoinedByString:@"\n"] : nil;
    } @catch (...) {
        return nil;
    }
}

static void WGShowInfoAlertRetry(NSString *title, NSString *message, NSString *markKey, int attempt) {
    dispatch_async(dispatch_get_main_queue(), ^{
        @try {
            WGEnsureOverlay();
            UIViewController *host = gOverlayWindow.rootViewController;
            if (!host) return;
            if (host.presentedViewController) {
                if (attempt < 3) {
                    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)),
                                   dispatch_get_main_queue(), ^{ WGShowInfoAlertRetry(title, message, markKey, attempt + 1); });
                }
                return;
            }
            gOverlayWindow.hidden = NO;
            gOverlayWindow.userInteractionEnabled = YES;

            UIAlertController *ac = [UIAlertController alertControllerWithTitle:title
                                                                       message:message
                                                                preferredStyle:UIAlertControllerStyleAlert];
            [ac addAction:[UIAlertAction actionWithTitle:@"知道了" style:UIAlertActionStyleDefault
                                                 handler:^(UIAlertAction *a) { WGApplyWatermark(); }]];
            [host presentViewController:ac animated:YES completion:^{
                @try {
                    if (markKey.length) {   // 真正弹出后才记为「已读」，避免被挡住导致公告丢失
                        NSArray *seen = [[NSUserDefaults standardUserDefaults] arrayForKey:kWGNoticeSeenKey];
                        NSMutableArray *arr = [NSMutableArray arrayWithArray:seen ?: @[]];
                        if (![arr containsObject:markKey]) [arr addObject:markKey];
                        while (arr.count > 20) [arr removeObjectAtIndex:0];
                        [[NSUserDefaults standardUserDefaults] setObject:arr forKey:kWGNoticeSeenKey];
                    }
                } @catch (...) {}
            }];
        } @catch (...) {}
    });
}

static void WGShowInfoAlert(NSString *title, NSString *message) {
    WGShowInfoAlertRetry(title, message, nil, 0);
}

static void WGShowActivationPanelRetry(int attempt) {
    dispatch_async(dispatch_get_main_queue(), ^{
        @try {
            WGEnsureOverlay();
            UIViewController *host = gOverlayWindow.rootViewController;
            if (!host) {
                if (attempt < 3) {
                    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)),
                                   dispatch_get_main_queue(), ^{ WGShowActivationPanelRetry(attempt + 1); });
                }
                return;
            }
            if (host.presentedViewController) {
                if (attempt < 4) {
                    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)),
                                   dispatch_get_main_queue(), ^{ WGShowActivationPanelRetry(attempt + 1); });
                }
                return;
            }

            gOverlayWindow.hidden = NO;
            gOverlayWindow.userInteractionEnabled = YES;

            NSString *tips = @"输入卡密后点「激活」，激活成功后水印自动消失；不输入卡密也能继续使用 App，只是会一直保留水印。";
            NSString *svc = WGServiceSummary();
            NSString *msg = svc.length ? [tips stringByAppendingFormat:@"\n\n%@", svc] : tips;
            UIAlertController *ac = [UIAlertController alertControllerWithTitle:@"卡密激活"
                                                                       message:msg
                                                                preferredStyle:UIAlertControllerStyleAlert];
            [ac addTextFieldWithConfigurationHandler:^(UITextField *tf) {
                tf.placeholder = @"XXXX-XXXX-XXXX-XXXX";
                id old = [[NSUserDefaults standardUserDefaults] objectForKey:kWGCardDefaultsKey];
                if ([old isKindOfClass:[NSString class]]) tf.text = (NSString *)old;
                tf.autocapitalizationType = UITextAutocapitalizationTypeAllCharacters;
                tf.autocorrectionType = UITextAutocorrectionTypeNo;
                tf.clearButtonMode = UITextFieldViewModeWhileEditing;
            }];
            [ac addAction:[UIAlertAction actionWithTitle:@"激活" style:UIAlertActionStyleDefault handler:^(UIAlertAction *a) {
                @try {
                    WGMakeOverlayKeyWindow(NO);     // 面板即将关闭，先把焦点还给宿主
                    NSString *code = ac.textFields.firstObject.text;
                    code = [code stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
                    if (code.length == 0) {
                        // 没输卡密就点「激活」：明确提示，并把激活窗口重新弹出来
                        WGShowInfoAlert(@"提示", @"请先输入卡密再点「激活」。");
                        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.6 * NSEC_PER_SEC)),
                                       dispatch_get_main_queue(), ^{ WGShowActivationPanel(); });
                        return;
                    }
                    [[NSUserDefaults standardUserDefaults] setObject:code forKey:kWGCardDefaultsKey];
                    [[NSUserDefaults standardUserDefaults] synchronize];
                    gLastActivationTry = [NSDate timeIntervalSinceReferenceDate];
                    WGPerformVerify();
                } @catch (...) {}
            }]];
            if (svc.length) {
                [ac addAction:[UIAlertAction actionWithTitle:@"复制客服信息" style:UIAlertActionStyleDefault
                                                     handler:^(UIAlertAction *a) {
                    @try {
                        [UIPasteboard generalPasteboard].string = svc;
                        WGMakeOverlayKeyWindow(NO);
                    } @catch (...) {}
                }]];
            }
            if (gStrictMode) {
                // 严格模式：不激活就强制退出 App
                [ac addAction:[UIAlertAction actionWithTitle:@"退出" style:UIAlertActionStyleDestructive
                                                     handler:^(UIAlertAction *a) { exit(0); }]];
            } else {
                // 水印模式：关掉弹窗继续用 App，水印保留
                [ac addAction:[UIAlertAction actionWithTitle:@"关闭" style:UIAlertActionStyleCancel
                                                     handler:^(UIAlertAction *a) {
                    WGMakeOverlayKeyWindow(NO);
                    WGApplyWatermark();
                }]];
            }
            WGMakeOverlayKeyWindow(YES);    // 让键盘挂到覆盖窗口上，卡密输入框才能输入
            [host presentViewController:ac animated:YES completion:nil];
        } @catch (...) {}
    });
}

static void WGShowActivationPanel(void) {
    WGShowActivationPanelRetry(0);
}

/// 解析服务端下发的公告与客服信息：客服缓存到本地；新公告只弹一次
static void WGApplyRemoteInfo(NSDictionary *d) {
    @try {
        id svc = d[@"service"];
        if ([svc isKindOfClass:[NSDictionary class]]) {
            [[NSUserDefaults standardUserDefaults] setObject:svc forKey:kWGServiceCacheKey];
        }

        // 验证模式：watermark（水印）/ strict（严格拦截）
        id md = d[@"mode"];
        if ([md isKindOfClass:[NSString class]]) {
            NSString *m = (NSString *)md;
            if ([m isEqualToString:@"strict"] || [m isEqualToString:@"watermark"]) {
                [[NSUserDefaults standardUserDefaults] setObject:m forKey:kWGModeCacheKey];
                gStrictMode = [m isEqualToString:@"strict"];
            }
        }

        id nt = d[@"notice"];
        if (![nt isKindOfClass:[NSDictionary class]]) return;
        NSDictionary *n = (NSDictionary *)nt;
        id c = n[@"content"];
        if (![c isKindOfClass:[NSString class]] || [(NSString *)c length] == 0) return;

        id rawId = n[@"id"];
        NSString *nid = [rawId isKindOfClass:[NSString class]] ? (NSString *)rawId
                       : ([rawId respondsToSelector:@selector(stringValue)] ? [rawId stringValue] : @"");
        if (nid.length == 0) nid = (NSString *)c;

        NSArray *seen = [[NSUserDefaults standardUserDefaults] arrayForKey:kWGNoticeSeenKey];
        if ([seen containsObject:nid]) return;

        id t = n[@"title"];
        NSString *title = ([t isKindOfClass:[NSString class]] && [(NSString *)t length]) ? (NSString *)t : @"公告";
        // 弹出成功后才标记已读（markKey），避免被激活窗口挡住导致公告永久丢失
        WGShowInfoAlertRetry(title, (NSString *)c, nid, 0);
    } @catch (...) {}
}

/* ============================================================================
 * 六、卡密验证（独立于宿主业务）
 * ==========================================================================*/
#if WG_ENABLE_SSL_PINNING
@interface WGPinningDelegate : NSObject <NSURLSessionDelegate>
@end

@implementation WGPinningDelegate
- (void)URLSession:(NSURLSession *)session
        didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge
          completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition, NSURLCredential *))completionHandler {
    @try {
        if (![challenge.protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust]
            || kWGPinnedCertSHA256.length == 0) {
            completionHandler(NSURLSessionAuthChallengePerformDefaultHandling, nil);
            return;
        }
        SecTrustRef trust = challenge.protectionSpace.serverTrust;
        if (trust == NULL) {
            completionHandler(NSURLSessionAuthChallengePerformDefaultHandling, nil);
            return;
        }
        SecCertificateRef cert = SecTrustGetCertificateAtIndex(trust, 0);
        if (cert == NULL) {
            completionHandler(NSURLSessionAuthChallengePerformDefaultHandling, nil);
            return;
        }
        NSData *data = (__bridge NSData *)SecCertificateCopyData(cert);
        unsigned char digest[CC_SHA256_DIGEST_LENGTH];
        CC_SHA256(data.bytes, (CC_LONG)data.length, digest);
        NSMutableString *hex = [NSMutableString string];
        for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) [hex appendFormat:@"%02x", digest[i]];
        if ([[hex lowercaseString] isEqualToString:[kWGPinnedCertSHA256 lowercaseString]]) {
            completionHandler(NSURLSessionAuthChallengeUseCredential, [NSURLCredential credentialForTrust:trust]);
        } else {
            completionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge, nil);
        }
    } @catch (...) {
        completionHandler(NSURLSessionAuthChallengePerformDefaultHandling, nil);
    }
}
@end
#endif

static NSURLSession *WGMakeVerifySession(void) {
    @try {
#if WG_ENABLE_SSL_PINNING
        static NSURLSession *session = nil;
        if (!session) {
            NSURLSessionConfiguration *cfg = [NSURLSessionConfiguration ephemeralSessionConfiguration];
            cfg.timeoutIntervalForRequest = kWGRequestTimeout;
            session = [NSURLSession sessionWithConfiguration:cfg delegate:[WGPinningDelegate new] delegateQueue:nil];
        }
        return session;
#else
        return [NSURLSession sharedSession];
#endif
    } @catch (...) {
        return [NSURLSession sharedSession];
    }
}

/// 稳定设备号：优先用 Keychain 里持久化的一份（卸载重装也不变），避免卡密被误判为「换设备」
static NSString *WGDeviceIdentifier(void) {
    static NSString *cached = nil;
    if (cached) return cached;
    NSString *vid = nil;
    @try { vid = [[[UIDevice currentDevice] identifierForVendor] UUIDString]; } @catch (...) {}
    if (vid.length == 0) vid = [[NSUUID UUID] UUIDString];
    @try {
        NSDictionary *base = @{
            (__bridge id)kSecClass:       (__bridge id)kSecClassGenericPassword,
            (__bridge id)kSecAttrService: @"WatermarkGuard.device_id",
            (__bridge id)kSecAttrAccount: @"device",
        };
        NSMutableDictionary *q = [base mutableCopy];
        q[(__bridge id)kSecReturnData] = @YES;
        q[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitOne;
        CFTypeRef out = NULL;
        if (SecItemCopyMatching((__bridge CFDictionaryRef)q, &out) == errSecSuccess && out) {
            NSString *s = [[NSString alloc] initWithData:(__bridge_transfer NSData *)out encoding:NSUTF8StringEncoding];
            if (s.length) { cached = s; return cached; }
        }
        NSMutableDictionary *add = [base mutableCopy];
        add[(__bridge id)kSecValueData] = [vid dataUsingEncoding:NSUTF8StringEncoding];
        add[(__bridge id)kSecAttrAccessible] = (__bridge id)kSecAttrAccessibleAfterFirstUnlock;
        OSStatus st = SecItemAdd((__bridge CFDictionaryRef)add, NULL);
        if (st == errSecSuccess || st == errSecDuplicateItem) { cached = vid; return cached; }
    } @catch (...) {}
    cached = vid;
    return cached;
}

static void WGPerformVerify(void) {
    @autoreleasepool {
        @try {
            if (!WG_ENABLE_VERIFY) return;

            // 1) 读取卡密：即使为空也要发请求——服务端会在 pass=false 的响应里带上公告/客服/模式
            NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
            id raw = [ud objectForKey:kWGCardDefaultsKey];
            NSString *code = nil;
            if ([raw isKindOfClass:[NSString class]]) code = (NSString *)raw;
            else if ([raw isKindOfClass:[NSNumber class]]) code = [(NSNumber *)raw stringValue];
            code = [code stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
            if (!code) code = @"";

            // 2) 设备号
            NSString *deviceId = WGDeviceIdentifier();

            // 3) 组装表单（x-www-form-urlencoded，服务端更好兼容）
            NSString *body = [NSString stringWithFormat:@"code=%@&device_id=%@&app_id=%@&platform=%@",
                              WGURLEncode(code), WGURLEncode(deviceId),
                              WGURLEncode(kWGAppID), WGURLEncode(kWGPlatform)];

            NSURL *url = [NSURL URLWithString:kWGVerifyURL];
            if (!url) return;   // 地址配错：保持当前水印状态（未授权继续显示水印）

            NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:url];
            req.HTTPMethod = @"POST";
            req.timeoutInterval = kWGRequestTimeout;
            [req setValue:@"application/x-www-form-urlencoded; charset=utf-8" forHTTPHeaderField:@"Content-Type"];
            req.HTTPBody = [body dataUsingEncoding:NSUTF8StringEncoding];

            // 4) 请求 + 解析（网络/解析异常时保持当前状态，不放行也不误锁）
            NSURLSessionDataTask *task =
            [WGMakeVerifySession() dataTaskWithRequest:req
                                    completionHandler:^(NSData *data, NSURLResponse *resp, NSError *err) {
                @try {
                    // 网络失败 / 返回异常：不改变当前状态（未授权继续显示水印，已授权保持无水印），避免断网即绕过
                    if (err || data.length == 0) { WGLog(@"verify net error"); return; }
                    id obj = [NSJSONSerialization JSONObjectWithData:data options:0 error:NULL];
                    if (![obj isKindOfClass:[NSDictionary class]]) return;
                    NSDictionary *d = (NSDictionary *)obj;
                    BOOL pass = WGBoolValue(d[@"pass"]);
                    id t = d[@"water_text"];
                    NSString *text = [t isKindOfClass:[NSString class]] ? t : nil;
                    WGApplyRemoteInfo(d);       // 公告 + 客服 + 验证模式
                    if (pass) {
                        [[NSUserDefaults standardUserDefaults] setObject:
                            @{ @"code": code, @"ts": @([[NSDate date] timeIntervalSince1970]) }
                                                              forKey:kWGPassCacheKey];
                    }
                    // 水印模式：pass=false 时铺满水印但 App 仍可操作（触摸穿透）；strict 模式同样铺水印，只是激活弹窗不给「关闭」
                    WGSetWatermark(pass ? YES : NO, text);
                    // 用户刚手动激活却失败 → 明确提示原因（定时校验的失败不打扰用户）
                    if (!pass && text.length &&
                        ([NSDate timeIntervalSinceReferenceDate] - gLastActivationTry) < 60.0) {
                        gLastActivationTry = 0;
                        WGShowInfoAlert(@"激活失败", text);
                    }
                    WGLog(@"verify pass=%d", (int)pass);
                } @catch (...) {
                    WGLog(@"verify parse failed");
                }
            }];
            [task resume];
        } @catch (...) {
            WGLog(@"verify build failed");   // 保持当前状态，不因异常放行
        }
    }
}

static void WGStartVerifyTimer(void) {
    @try {
        if (!WG_ENABLE_VERIFY || gVerifyTimer) return;
        gVerifyQueue = dispatch_queue_create("cn.watermarkguard.verify", DISPATCH_QUEUE_SERIAL);
        gVerifyTimer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, gVerifyQueue);
        // 首次 1 分钟后；之后每 120 秒；leeway 2 秒（省电且不影响判断）
        dispatch_source_set_timer(gVerifyTimer,
                                  dispatch_time(DISPATCH_TIME_NOW, (int64_t)(kWGFirstDelay * NSEC_PER_SEC)),
                                  (uint64_t)(kWGVerifyInterval * NSEC_PER_SEC),
                                  (uint64_t)(2 * NSEC_PER_SEC));
        dispatch_source_set_event_handler(gVerifyTimer, ^{
            @try {
                // 后台自动暂停：不触发校验；回前台后的下一次 tick 自动恢复
                if (!WGIsAppActive()) return;
                WGPerformVerify();
                dispatch_async(dispatch_get_main_queue(), ^{ WGEnsureOverlay(); });
            } @catch (...) {}
        });
        dispatch_resume(gVerifyTimer);
    } @catch (...) {}
}

/* ============================================================================
 * 七、分级安全防护（全部子线程、全部可关）
 * ==========================================================================*/
static void WGShowAnomalyAlert(NSString *message) {
    dispatch_async(dispatch_get_main_queue(), ^{
        @try {
            WGEnsureOverlay();
            UIViewController *host = gOverlayWindow.rootViewController;
            if (!host || host.presentedViewController) return;

            // 弹框前确保窗口可见（交互不受影响：空白区始终穿透给宿主）
            gOverlayWindow.hidden = NO;
            gOverlayWindow.userInteractionEnabled = YES;

            UIAlertController *ac = [UIAlertController alertControllerWithTitle:@"环境异常"
                                                                      message:message
                                                               preferredStyle:UIAlertControllerStyleAlert];
            [ac addAction:[UIAlertAction actionWithTitle:@"知道了"
                                                   style:UIAlertActionStyleDefault
                                                 handler:^(UIAlertAction *a) {
                @try {
                    if (!WG_ENABLE_WATERMARK) {
                        // 水印关闭时 WGApplyWatermark 不会重算显隐，这里手动藏回窗口
                        gOverlayWindow.hidden = YES;
                    }
                    WGApplyWatermark();     // 重算水印显隐，避免窗口一直停留在可见状态
                } @catch (...) {}
            }]];
            [host presentViewController:ac animated:YES completion:nil];
        } @catch (...) {}
    });
}

static void WGReportAnomaly(NSString *name, NSString *desc) {
    @try {
        NSInteger count = 0;
        @synchronized (gAnomalyCounts) {
            if (!gAnomalyCounts) gAnomalyCounts = [NSMutableDictionary dictionary];
            count = [gAnomalyCounts[name] integerValue] + 1;
            gAnomalyCounts[name] = @(count);
        }
        WGLog(@"anomaly %@ x%ld", name, (long)count);

        if (count == 1) {
            // 一级：水印追加风险提示，不弹窗、不闪退
            WGSetRiskText(kWGRiskLevel1Text);
        } else if (count == kWGAnomalyAlertLevel) {
            // 二级：弹一次全局提示
            @synchronized (gAlertedItems) {
                if (!gAlertedItems) gAlertedItems = [NSMutableSet set];
                if (![gAlertedItems containsObject:name]) {
                    [gAlertedItems addObject:name];
                    WGShowAnomalyAlert([NSString stringWithFormat:@"检测到%@，请使用正版环境。", desc]);
                }
            }
        } else if (count >= kWGAnomalyExitLevel && WG_ENABLE_FORCE_EXIT_L3) {
            // 三级：强制退出（可按需把 WG_ENABLE_FORCE_EXIT_L3 置 0 关闭）
            exit(0);
        }
    } @catch (...) {}
}

/// 按「连续」语义更新异常：检出异常 → 计数+1（走分级处置）；恢复正常 → 清零。
/// 当所有检测项都不再异常时，撤掉一级风险水印文字。
static void WGUpdateAnomaly(NSString *name, NSString *desc, BOOL detected) {
    @try {
        if (detected) {
            WGReportAnomaly(name, desc);
            return;
        }
        BOOL hadPositive = NO;
        BOOL anyLeft = NO;
        @synchronized (gAnomalyCounts) {
            if (!gAnomalyCounts) gAnomalyCounts = [NSMutableDictionary dictionary];
            hadPositive = [gAnomalyCounts[name] integerValue] > 0;
            if (hadPositive) gAnomalyCounts[name] = @0;
            for (NSNumber *v in gAnomalyCounts.allValues) {
                if ([v integerValue] > 0) { anyLeft = YES; break; }
            }
        }
        if (hadPositive && !anyLeft) WGSetRiskText(nil);
    } @catch (...) {}
}

#pragma mark - 7.1 反调试

static BOOL WGIsBeingDebugged(void) {
    @try {
        int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()};
        struct kinfo_proc info;
        memset(&info, 0, sizeof(info));
        size_t size = sizeof(info);
        if (sysctl(mib, 4, &info, &size, NULL, 0) == 0) {
            return (info.kp_proc.p_flag & P_TRACED) != 0;
        }
    } @catch (...) {}
    return NO;
}

#pragma mark - 7.2 注入框架检测

static BOOL WGHasInjectedFramework(void) {
    @try {
        uint32_t count = _dyld_image_count();
        for (uint32_t i = 0; i < count; i++) {
            const char *name = _dyld_get_image_name(i);
            if (!name) continue;
            NSString *s = [NSString stringWithUTF8String:name].lowercaseString;
            if (!s) continue;
            if ([s containsString:@"frida"] ||
                [s containsString:@"cycript"] ||
                [s containsString:@"cynject"] ||
                [s containsString:@"libsubstrate"] ||
                [s containsString:@"substitute"]) {
                return YES;
            }
        }
    } @catch (...) {}
    return NO;
}

#pragma mark - 7.3 自身完整性（运行期函数指纹）

static uint32_t WGFingerprint(void) {
    @try {
        const uint8_t *p = (const uint8_t *)(void *)&WGPerformVerify;
        if (!p) return 0;
        uint32_t h = 2166136261u;
        for (int i = 0; i < 64; i++) { h ^= p[i]; h *= 16777619u; }
        return h;
    } @catch (...) {
        return 0;
    }
}

static BOOL WGIsSelfModified(void) {
    @try {
        if (gSelfFingerprint == 0) return NO;
        return WGFingerprint() != gSelfFingerprint;
    } @catch (...) {
        return NO;
    }
}

#pragma mark - 7.4 越狱 / 多开 / 代理 / 模拟器

static BOOL WGIsJailbroken(void) {
    @try {
        NSArray *paths = @[@"/Applications/Cydia.app",
                           @"/Library/MobileSubstrate/MobileSubstrate.dylib",
                           @"/bin/bash",
                           @"/usr/sbin/sshd",
                           @"/etc/apt",
                           @"/private/var/lib/apt",
                           @"/var/jb"];
        NSFileManager *fm = [NSFileManager defaultManager];
        for (NSString *p in paths) {
            if ([fm fileExistsAtPath:p]) return YES;
        }
    } @catch (...) {}
    return NO;
}

static BOOL WGIsMultiOpen(void) {
    @try {
        NSString *path = [[NSBundle mainBundle] bundlePath];
        if ([path containsString:@"/Documents/"]) return YES;
        if ([path containsString:@"/var/mobile/"] && ![path containsString:@"/var/containers/Bundle/Application/"]) return YES;
        const char *env = getenv("DYLD_INSERT_LIBRARIES");
        if (env && strlen(env) > 0 && strstr(env, "WatermarkGuard") == NULL) return YES;
    } @catch (...) {}
    return NO;
}

static BOOL WGHasSystemProxy(void) {
    @try {
        CFDictionaryRef dict = CFNetworkCopySystemProxySettings();
        if (!dict) return NO;
        BOOL on = NO;
        int v = 0;
        // 取到的值不一定是 CFNumber，必须先验类型，否则 CFNumberGetValue 直接崩
        CFTypeRef n = CFDictionaryGetValue(dict, kCFNetworkProxiesHTTPEnable);
        if (n && CFGetTypeID(n) == CFNumberGetTypeID() &&
            CFNumberGetValue((CFNumberRef)n, kCFNumberIntType, &v) && v) on = YES;
        v = 0;
        // kCFNetworkProxiesHTTPSEnable 是 macOS 常量，iOS SDK 标记为不可用；
        // iOS 下字典里同样存在 "HTTPSEnable" 键，用字符串键取即可。
        n = CFDictionaryGetValue(dict, (__bridge CFStringRef)@"HTTPSEnable");
        if (n && CFGetTypeID(n) == CFNumberGetTypeID() &&
            CFNumberGetValue((CFNumberRef)n, kCFNumberIntType, &v) && v) on = YES;
        CFRelease(dict);
        return on;
    } @catch (...) {
        return NO;
    }
}

static BOOL WGIsSimulator(void) {
#if TARGET_OS_SIMULATOR
    return YES;
#else
    return getenv("SIMULATOR_DEVICE_NAME") != NULL;
#endif
}

static void WGRunSecurityChecks(void) {
    @autoreleasepool {
        @try {
#if WG_ENABLE_DEBUGGER_CHECK
            WGUpdateAnomaly(@"debugger", @"调试器", WGIsBeingDebugged());
#endif
#if WG_ENABLE_FRIDA_CHECK
            WGUpdateAnomaly(@"inject", @"注入框架", WGHasInjectedFramework());
#endif
#if WG_ENABLE_SELF_INTEGRITY
            WGUpdateAnomaly(@"selfcheck", @"自身被篡改", WGIsSelfModified());
#endif
#if WG_ENABLE_JAILBREAK_CHECK
            WGUpdateAnomaly(@"jailbreak", @"越狱环境", WGIsJailbroken());
#endif
#if WG_ENABLE_MULTIOPEN_CHECK
            WGUpdateAnomaly(@"multiopen", @"多开环境", WGIsMultiOpen());
#endif
#if WG_ENABLE_PROXY_CHECK
            WGUpdateAnomaly(@"proxy", @"网络代理", WGHasSystemProxy());
#endif
#if WG_ENABLE_SIMULATOR_CHECK
            WGUpdateAnomaly(@"simulator", @"模拟器", WGIsSimulator());
#endif
        } @catch (...) {}
    }
}

static void WGStartSecurityTimer(void) {
    @try {
        if ((!WG_ENABLE_DEBUGGER_CHECK && !WG_ENABLE_FRIDA_CHECK && !WG_ENABLE_SELF_INTEGRITY &&
             !WG_ENABLE_JAILBREAK_CHECK && !WG_ENABLE_MULTIOPEN_CHECK && !WG_ENABLE_PROXY_CHECK &&
             !WG_ENABLE_SIMULATOR_CHECK) || gSecurityTimer) {
            return;
        }
        gSecurityQueue = dispatch_queue_create("cn.watermarkguard.security", DISPATCH_QUEUE_SERIAL);
        gSecurityTimer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, gSecurityQueue);
        dispatch_source_set_timer(gSecurityTimer,
                                  dispatch_time(DISPATCH_TIME_NOW, (int64_t)(kWGSecurityInterval * NSEC_PER_SEC)),
                                  (uint64_t)(kWGSecurityInterval * NSEC_PER_SEC),
                                  (uint64_t)(2 * NSEC_PER_SEC));
        dispatch_source_set_event_handler(gSecurityTimer, ^{
            @try {
                if (!WGIsAppActive()) return;   // 后台不检测，省电
                WGRunSecurityChecks();
            } @catch (...) {}
        });
        dispatch_resume(gSecurityTimer);
    } @catch (...) {}
}

/// 看门狗：每 4 秒确认「未授权时水印窗口一定可见」，防止宿主改 keyWindow / 系统回收导致裸奔
static void WGStartGuardTimer(void) {
    @try {
        static dispatch_source_t t = NULL;
        if (t) return;
        t = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, dispatch_get_main_queue());
        dispatch_source_set_timer(t, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(4 * NSEC_PER_SEC)),
                                  (uint64_t)(4 * NSEC_PER_SEC), (uint64_t)(1 * NSEC_PER_SEC));
        dispatch_source_set_event_handler(t, ^{
            @try {
                if (!WG_ENABLE_WATERMARK) return;       // 水印功能关闭时别造出看不见的全屏水印层
                if (gWaterHidden) return;              // 已授权：窗口保持隐藏
                WGEnsureOverlay();
                if (!gOverlayWindow) return;
                if (gOverlayWindow.hidden) WGApplyWatermark();
                if (gOverlayWindow.hidden) gOverlayWindow.hidden = NO;   // 兜底强显
                gOverlayWindow.userInteractionEnabled = YES;
            } @catch (...) {}
        });
        dispatch_resume(t);
    } @catch (...) {}
}

/* ============================================================================
 * 八、可选：原生请求追加 Header（默认关闭）
 *   只加 Header，绝不改 Body；任何异常都退回原始请求
 * ==========================================================================*/
#if WG_ENABLE_HTTP_HEADER_HOOK

typedef NSURLSessionDataTask *(*WGDTHandlerIMP)(id, SEL, NSURLRequest *, void (^)(NSData *, NSURLResponse *, NSError *));
typedef NSURLSessionDataTask *(*WGDTDelegateIMP)(id, SEL, NSURLRequest *, id);

static WGDTHandlerIMP  gOrigDTHandler  = NULL;
static WGDTDelegateIMP gOrigDTDelegate = NULL;

static NSURLRequest *WGAppendHeaders(NSURLRequest *req) {
    @try {
        if (![req isKindOfClass:[NSURLRequest class]]) return req;
        if (![[req.HTTPMethod uppercaseString] isEqualToString:@"POST"]) return req;
        NSString *url = req.URL.absoluteString;
        if (kWGHTTPHookKeyword.length && ![url containsString:kWGHTTPHookKeyword]) return req;

        NSMutableURLRequest *m = [req mutableCopy];
        NSString *deviceId = [[[UIDevice currentDevice] identifierForVendor] UUIDString] ?: @"";
        if (![m valueForHTTPHeaderField:@"device_id"]) [m setValue:deviceId forHTTPHeaderField:@"device_id"];
        if (![m valueForHTTPHeaderField:@"app_id"])    [m setValue:kWGAppID forHTTPHeaderField:@"app_id"];
        return m;
    } @catch (...) {
        return req;
    }
}

static NSURLSessionDataTask *WGDTWithHandler(id self, SEL _cmd, NSURLRequest *req,
                                             void (^handler)(NSData *, NSURLResponse *, NSError *)) {
    @try {
        req = WGAppendHeaders(req);
    } @catch (...) {}
    return gOrigDTHandler ? gOrigDTHandler(self, _cmd, req, handler) : nil;
}

static NSURLSessionDataTask *WGDTWithDelegate(id self, SEL _cmd, NSURLRequest *req, id delegate) {
    @try {
        req = WGAppendHeaders(req);
    } @catch (...) {}
    return gOrigDTDelegate ? gOrigDTDelegate(self, _cmd, req, delegate) : nil;
}

static void WGInstallURLSessionHook(void) {
    @try {
        Class cls = NSClassFromString(@"NSURLSession");
        if (!cls) return;

        SEL sel1 = @selector(dataTaskWithRequest:completionHandler:);
        Method m1 = class_getInstanceMethod(cls, sel1);
        if (m1 && !gOrigDTHandler) {
            gOrigDTHandler = (WGDTHandlerIMP)method_getImplementation(m1);
            method_setImplementation(m1, (IMP)WGDTWithHandler);
        }

        SEL sel2 = @selector(dataTaskWithRequest:delegate:);
        Method m2 = class_getInstanceMethod(cls, sel2);
        if (m2 && !gOrigDTDelegate) {
            gOrigDTDelegate = (WGDTDelegateIMP)method_getImplementation(m2);
            method_setImplementation(m2, (IMP)WGDTWithDelegate);
        }
        WGLog(@"urlsession hook installed");
    } @catch (...) {
        WGLog(@"urlsession hook failed, skipped");
    }
}
#endif /* WG_ENABLE_HTTP_HEADER_HOOK */

/* ============================================================================
 * 九、启动入口
 * ==========================================================================*/
void WGStart(void) {
    @try {
        if (!WG_ENABLE_CORE) return;
        @synchronized ([WatermarkGuardAnchor class]) {
            if (gStarted) return;
            gStarted = YES;
        }

#if WG_ENABLE_DEBUGGER_CHECK
        // 主动拒绝调试器附加（失败也无副作用）
        @try { ptrace(PT_DENY_ATTACH, 0, NULL, 0); } @catch (...) {}
#endif

        gSelfFingerprint = WGFingerprint();
        if (!gAnomalyCounts) gAnomalyCounts = [NSMutableDictionary dictionary];
        if (!gAlertedItems) gAlertedItems = [NSMutableSet set];

#if WG_ENABLE_HTTP_HEADER_HOOK
        WGInstallURLSessionHook();
#endif

        // 启动瞬间先定调：本地没卡密（或缓存过期）→ 立刻铺满水印，不能白等首次校验的 60 秒
        {
            id old = [[NSUserDefaults standardUserDefaults] objectForKey:kWGCardDefaultsKey];
            NSString *code = [old isKindOfClass:[NSString class]] ? (NSString *)old : nil;
            BOOL trusted = WGCachedPassValid(code);
            if (WG_ENABLE_WATERMARK) WGSetWatermark(trusted ? YES : NO, nil);
        }

        // 核心：验证定时器（首次 1 分钟后）
#if WG_ENABLE_VERIFY
        WGStartVerifyTimer();
#else
        // 只开水印、关掉验证时，没有接口判定就直接常显兜底文案（否则水印永远不出来）
        if (WG_ENABLE_WATERMARK) WGSetWatermark(NO, nil);
#endif
        // 增强：安全复检（每 60 秒）
        WGStartSecurityTimer();
        // 看门狗：未授权时保证水印窗口始终在最上层
        WGStartGuardTimer();

        // UI：推迟到 App 启动完成、场景就绪后再创建
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{ WGEnsureOverlay(); });

        // 只有严格模式才在启动后自动弹激活窗口（不激活就用不了）；
        // 水印模式不打扰用户，底部「输入卡密」按钮随时可点，激活前照常使用 App。
        gStrictMode = [[[NSUserDefaults standardUserDefaults] stringForKey:kWGModeCacheKey] isEqualToString:@"strict"];
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(7.0 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            @try {
                if (!gStrictMode) return;
                id old = [[NSUserDefaults standardUserDefaults] objectForKey:kWGCardDefaultsKey];
                NSString *code = [old isKindOfClass:[NSString class]] ? (NSString *)old : nil;
                if (code.length == 0) WGShowActivationPanel();
            } @catch (...) {}
        });
    } @catch (...) {
        WGLog(@"start failed");
    }
}

/// 仅用于 @synchronized 的锚点类
@implementation WatermarkGuardAnchor
@end

__attribute__((constructor))
static void WatermarkGuardConstructor(void) {
    @autoreleasepool {
        @try { WGStart(); } @catch (...) {}
    }
}
