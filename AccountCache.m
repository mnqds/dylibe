#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <sqlite3.h>

// ===== 读数据库，把账号数据读回来 =====
static NSDictionary *LoadAccountRow(NSString *tableName, NSString *pkid) {
    if (pkid.length == 0) return nil;

    NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *docPath = [paths firstObject];
    NSString *dbPath = [docPath stringByAppendingPathComponent:@"zdd.sqlite"];

    sqlite3 *db = NULL;
    if (sqlite3_open([dbPath UTF8String], &db) != SQLITE_OK) {
        return nil;
    }

    NSString *sql = [NSString stringWithFormat:@"SELECT * FROM %@ WHERE pkid = ? LIMIT 1", tableName];
    sqlite3_stmt *stmt = NULL;
    NSMutableDictionary *row = [NSMutableDictionary dictionary];

    if (sqlite3_prepare_v2(db, [sql UTF8String], -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, [pkid UTF8String], -1, SQLITE_TRANSIENT);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            int colCount = sqlite3_column_count(stmt);
            for (int i = 0; i < colCount; i++) {
                const char *colName = sqlite3_column_name(stmt, i);
                if (!colName) continue;
                NSString *key = [NSString stringWithUTF8String:colName];
                id val = [NSNull null];

                int type = sqlite3_column_type(stmt, i);
                if (type == SQLITE_TEXT) {
                    const unsigned char *t = sqlite3_column_text(stmt, i);
                    if (t) val = [NSString stringWithUTF8String:(const char *)t];
                } else if (type == SQLITE_INTEGER) {
                    val = @(sqlite3_column_int64(stmt, i));
                } else if (type == SQLITE_FLOAT) {
                    val = @(sqlite3_column_double(stmt, i));
                } else if (type == SQLITE_BLOB) {
                    const void *blob = sqlite3_column_blob(stmt, i);
                    int len = sqlite3_column_bytes(stmt, i);
                    if (blob && len > 0) {
                        val = [NSData dataWithBytes:blob length:len];
                    }
                }
                row[key] = val;
            }
        }
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return row.count > 0 ? row : nil;
}

// 把数据库行回填到 Model 对象（用 KVC）
static void ApplyRowToModel(id model, NSDictionary *row) {
    if (!model || !row) return;
    for (NSString *key in row) {
        id val = row[key];
        if ([val isKindOfClass:[NSNull class]]) continue;
        // 跳过主键和关联 id，避免破坏对象内部引用
        if ([key isEqualToString:@"pkid"] ||
            [key isEqualToString:@"ownerId"] ||
            [key isEqualToString:@"chatId"]) continue;
        @try {
            [model setValue:val forKey:key];
        } @catch (NSException *e) {
            // 字段名不匹配就跳过
        }
    }
}

// ===== hook viewDidLoad =====
static IMP orig_WeChat_viewDidLoad = NULL;
static IMP orig_ZFB_viewDidLoad = NULL;

static void swizzled_WeChat_viewDidLoad(id self, SEL _cmd) {
    ((void (*)(id, SEL))orig_WeChat_viewDidLoad)(self, _cmd);
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 0.5 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
        NSString *currentId = [[NSUserDefaults standardUserDefaults] stringForKey:@"WeChatCurrentId"];
        NSDictionary *row = LoadAccountRow(@"wechat_user", currentId);
        id account = [self valueForKey:@"currentAccount"];
        ApplyRowToModel(account, row);
    });
}

static void swizzled_ZFB_viewDidLoad(id self, SEL _cmd) {
    ((void (*)(id, SEL))orig_ZFB_viewDidLoad)(self, _cmd);
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 0.5 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
        NSString *currentId = [[NSUserDefaults standardUserDefaults] stringForKey:@"ZFBCurrentId"];
        NSDictionary *row = LoadAccountRow(@"zfb_user", currentId);
        id account = [self valueForKey:@"currentAccount"];
        ApplyRowToModel(account, row);
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
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 1.0 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
        Class wxCls = NSClassFromString(@"WeChatAccountViewController");
        if (wxCls) Swizzle(wxCls, @selector(viewDidLoad), (IMP)swizzled_WeChat_viewDidLoad, &orig_WeChat_viewDidLoad);

        Class zfbCls = NSClassFromString(@"ZFBCreateAccountViewController");
        if (zfbCls) Swizzle(zfbCls, @selector(viewDidLoad), (IMP)swizzled_ZFB_viewDidLoad, &orig_ZFB_viewDidLoad);
    });
}
