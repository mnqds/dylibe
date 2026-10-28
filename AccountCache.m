#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <sqlite3.h>

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

// ===== hook getCurrentUser =====
typedef id (*GetUserImp)(id, SEL);
static GetUserImp orig_Wx_getCurrentUser = NULL;
static GetUserImp orig_Zfb_getCurrentUser = NULL;

static id swizzled_Wx_getCurrentUser(id self, SEL _cmd) {
    id user = orig_Wx_getCurrentUser(self, _cmd);
    NSString *currentId = [[NSUserDefaults standardUserDefaults] stringForKey:@"WeChatCurrentId"];
    NSDictionary *row = LoadAccountRow(@"wechat_user", currentId);
    if (row) { ApplyRowToModel(user, row); NSLog(@"[AccountCache] 微信 getCurrentUser 回填完成"); }
    return user;
}

static id swizzled_Zfb_getCurrentUser(id self, SEL _cmd) {
    id user = orig_Zfb_getCurrentUser(self, _cmd);
    NSString *currentId = [[NSUserDefaults standardUserDefaults] stringForKey:@"ZFBCurrentId"];
    NSDictionary *row = LoadAccountRow(@"zfb_user", currentId);
    if (row) { ApplyRowToModel(user, row); NSLog(@"[AccountCache] 支付宝 getCurrentUser 回填完成"); }
    return user;
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
    Class wxTool = NSClassFromString(@"WeChatHandelTool");
    if (wxTool) {
        Swizzle(wxTool, @selector(getCurrentUser), (IMP)swizzled_Wx_getCurrentUser, (IMP *)&orig_Wx_getCurrentUser);
        NSLog(@"[AccountCache] 已 hook WeChatHandelTool getCurrentUser");
    } else {
        NSLog(@"[AccountCache] 未找到 WeChatHandelTool");
    }

    // 支付宝侧也尝试同名方法
    Class zfbTool = NSClassFromString(@"ZFBHandelTool");
    if (!zfbTool) zfbTool = NSClassFromString(@"ZFBHandleTool");
    if (zfbTool) {
        Swizzle(zfbTool, @selector(getCurrentUser), (IMP)swizzled_Zfb_getCurrentUser, (IMP *)&orig_Zfb_getCurrentUser);
        NSLog(@"[AccountCache] 已 hook 支付宝 getCurrentUser");
    }
}
