#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <sqlite3.h>

// ===== 读数据库 =====
static NSDictionary *LoadAccountRow(NSString *tableName, NSString *pkid) {
    if (pkid.length == 0) return nil;
    NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *dbPath = [[paths firstObject] stringByAppendingPathComponent:@"zdd.sqlite"];
    sqlite3 *db = NULL;
    if (sqlite3_open([dbPath UTF8String], &db) != SQLITE_OK) return nil;
    NSString *sql = [NSString stringWithFormat:@"SELECT * FROM %@ WHERE pkid = ? LIMIT 1", tableName];
    sqlite3_stmt *stmt = NULL;
    NSMutableDictionary *row = [NSMutableDictionary dictionary];
    if (sqlite3_prepare_v2(db, [sql UTF8String], -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, [pkid UTF8String], -1, SQLITE_TRANSIENT);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            int n = sqlite3_column_count(stmt);
            for (int i = 0; i < n; i++) {
                const char *cn = sqlite3_column_name(stmt, i);
                if (!cn) continue;
                NSString *key = [NSString stringWithUTF8String:cn];
                id val = [NSNull null];
                int t = sqlite3_column_type(stmt, i);
                if (t == SQLITE_TEXT) {
                    const unsigned char *s = sqlite3_column_text(stmt, i);
                    if (s) val = [NSString stringWithUTF8String:(const char *)s];
                } else if (t == SQLITE_INTEGER) {
                    val = @(sqlite3_column_int64(stmt, i));
                } else if (t == SQLITE_FLOAT) {
                    val = @(sqlite3_column_double(stmt, i));
                } else if (t == SQLITE_BLOB) {
                    const void *blob = sqlite3_column_blob(stmt, i);
                    int len = sqlite3_column_bytes(stmt, i);
                    if (blob && len > 0) val = [NSData dataWithBytes:blob length:len];
                }
                row[key] = val;
            }
        }
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return row.count > 0 ? row : nil;
}

static void ApplyRowToModel(id model, NSDictionary *row) {
    if (!model || !row) return;
    for (NSString *key in row) {
        id val = row[key];
        if ([val isKindOfClass:[NSNull class]]) continue;
        if ([key isEqualToString:@"pkid"] || [key isEqualToString:@"ownerId"] || [key isEqualToString:@"chatId"]) continue;
        @try { [model setValue:val forKey:key]; } @catch (NSException *e) {}
    }
}

// ===== hook setUser: =====
typedef void (*SetUserImp)(id, SEL, id);
static SetUserImp orig_Wx_setUser = NULL;

static void swizzled_Wx_setUser(id self, SEL _cmd, id user) {
    orig_Wx_setUser(self, _cmd, user);
    NSString *currentId = [[NSUserDefaults standardUserDefaults] stringForKey:@"WeChatCurrentId"];
    NSDictionary *row = LoadAccountRow(@"wechat_user", currentId);
    if (row) {
        ApplyRowToModel(user, row);
        NSLog(@"[AccountCache] 微信 setUser 回填完成");
    }
}

// ===== hook viewDidLoad（兜底：支付宝"我的"页 + 其他）=====
typedef void (*VoidImp)(id, SEL);
static VoidImp orig_Zfb_viewDidLoad = NULL;
static VoidImp orig_Wx_viewDidLoad = NULL;

static void zfb_backfill(id self) {
    NSString *currentId = [[NSUserDefaults standardUserDefaults] stringForKey:@"ZFBCurrentId"];
    NSDictionary *row = LoadAccountRow(@"zfb_user", currentId);
    if (!row) return;
    id account = nil;
    @try { account = [self valueForKey:@"currentAccount"]; } @catch (NSException *e) {}
    if (!account) {
        @try { account = [self valueForKey:@"person"]; } @catch (NSException *e) {}
    }
    if (account) { ApplyRowToModel(account, row); NSLog(@"[AccountCache] 支付宝回填完成"); }
}

static void swizzled_Zfb_viewDidLoad(id self, SEL _cmd) {
    orig_Zfb_viewDidLoad(self, _cmd);
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 0.3 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
        zfb_backfill(self);
    });
}

static void swizzled_Wx_viewDidLoad(id self, SEL _cmd) {
    orig_Wx_viewDidLoad(self, _cmd);
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 0.3 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
        NSString *currentId = [[NSUserDefaults standardUserDefaults] stringForKey:@"WeChatCurrentId"];
        NSDictionary *row = LoadAccountRow(@"wechat_user", currentId);
        if (!row) return;
        id account = nil;
        @try { account = [self valueForKey:@"user"]; } @catch (NSException *e) {}
        if (!account) { @try { account = [self valueForKey:@"currentAccount"]; } @catch (NSException *e) {} }
        if (account) { ApplyRowToModel(account, row); NSLog(@"[AccountCache] 微信 viewDidLoad 回填完成"); }
    });
}

static void Swizzle(Class cls, SEL sel, IMP newImp, IMP *origImp) {
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) return;
    *origImp = method_getImplementation(m);
    method_setImplementation(m, newImp);
}

__attribute__((constructor))
static void AccountCacheInit(void) {
    NSLog(@"[AccountCache] 已加载");
    Class wxMine = NSClassFromString(@"WeChatMineViewController");
    if (wxMine) {
        Swizzle(wxMine, @selector(setUser:), (IMP)swizzled_Wx_setUser, (IMP *)&orig_Wx_setUser);
        Swizzle(wxMine, @selector(viewDidLoad), (IMP)swizzled_Wx_viewDidLoad, (IMP *)&orig_Wx_viewDidLoad);
        NSLog(@"[AccountCache] 已 hook WeChatMineViewController");
    }
    Class zfbMine = NSClassFromString(@"ZFBMineViewController");
    if (zfbMine) {
        Swizzle(zfbMine, @selector(viewDidLoad), (IMP)swizzled_Zfb_viewDidLoad, (IMP *)&orig_Zfb_viewDidLoad);
        NSLog(@"[AccountCache] 已 hook ZFBMineViewController");
    }
}
