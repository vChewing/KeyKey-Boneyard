// Objective-C swizzles to capture file paths passed via Cocoa APIs
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#include <limits.h>

// We rely on C helpers in cerod_interpose.c
extern void log_match(const char *fn, const char *path, const void *retaddr);
extern int path_matches(const char *p);

static IMP orig_NSURL_fileURLWithPath = NULL;
static IMP orig_NSURL_initFileURLWithPath = NULL;
static IMP orig_NSFileManager_fileExistsAtPath = NULL;
static IMP orig_NSFileManager_createFile = NULL;
static IMP orig_NSData_initWithContentsOfFile = NULL;
static IMP orig_NSFileHandle_fileHandleForReadingAtPath = NULL;

// helpers
static void logNSStringIfMatch(const char *label, NSString *s) {
    if (!s) return;
    const char *c = [s UTF8String];
    if (c && path_matches(c)) log_match(label, c, __builtin_return_address(0));
}

// NSURL +fileURLWithPath:
static id my_NSURL_fileURLWithPath(id self, SEL _cmd, NSString *path) {
    logNSStringIfMatch("NSURL+fileURLWithPath", path);
    id (*orig)(id, SEL, NSString*) = (id(*)(id,SEL,NSString*))orig_NSURL_fileURLWithPath;
    return orig(self, _cmd, path);
}

// NSURL -initFileURLWithPath:
static id my_NSURL_initFileURLWithPath(id self, SEL _cmd, NSString *path) {
    logNSStringIfMatch("NSURL-initFileURLWithPath", path);
    id (*orig)(id, SEL, NSString*) = (id(*)(id,SEL,NSString*))orig_NSURL_initFileURLWithPath;
    return orig(self, _cmd, path);
}

// NSFileManager fileExistsAtPath:
static BOOL my_NSFileManager_fileExistsAtPath(id self, SEL _cmd, NSString *path) {
    logNSStringIfMatch("NSFileManager-fileExistsAtPath", path);
    BOOL (*orig)(id, SEL, NSString*) = (BOOL(*)(id,SEL,NSString*))orig_NSFileManager_fileExistsAtPath;
    return orig(self, _cmd, path);
}

// NSFileManager createFileAtPath:contents:attributes:
static BOOL my_NSFileManager_createFile(id self, SEL _cmd, NSString *path, NSData *data, NSDictionary *attribs) {
    logNSStringIfMatch("NSFileManager-createFile", path);
    BOOL (*orig)(id, SEL, NSString*, NSData*, NSDictionary*) = (BOOL(*)(id,SEL,NSString*,NSData*,NSDictionary*))orig_NSFileManager_createFile;
    return orig(self, _cmd, path, data, attribs);
}

// NSData initWithContentsOfFile:
static id my_NSData_initWithContentsOfFile(id self, SEL _cmd, NSString *path) {
    logNSStringIfMatch("NSData-initWithContentsOfFile", path);
    id (*orig)(id, SEL, NSString*) = (id(*)(id,SEL,NSString*))orig_NSData_initWithContentsOfFile;
    return orig(self, _cmd, path);
}

// NSFileHandle fileHandleForReadingAtPath:
static id my_NSFileHandle_fileHandleForReadingAtPath(id self, SEL _cmd, NSString *path) {
    logNSStringIfMatch("NSFileHandle-fileHandleForReadingAtPath", path);
    id (*orig)(id, SEL, NSString*) = (id(*)(id,SEL,NSString*))orig_NSFileHandle_fileHandleForReadingAtPath;
    return orig(self, _cmd, path);
}

__attribute__((constructor)) static void objc_swizzle_init(void) {
    @autoreleasepool {
        Class NSURLClass = objc_getClass("NSURL");
        if (NSURLClass) {
            // class method +fileURLWithPath:
            Method classMethod = class_getClassMethod(NSURLClass, @selector(fileURLWithPath:));
            if (classMethod) {
                orig_NSURL_fileURLWithPath = method_getImplementation(classMethod);
                method_setImplementation(classMethod, (IMP)my_NSURL_fileURLWithPath);
            }
            // -initFileURLWithPath:
            Method initMethod = class_getInstanceMethod(NSURLClass, @selector(initFileURLWithPath:));
            if (initMethod) {
                orig_NSURL_initFileURLWithPath = method_getImplementation(initMethod);
                method_setImplementation(initMethod, (IMP)my_NSURL_initFileURLWithPath);
            }
        }

        Class NSFileManagerClass = objc_getClass("NSFileManager");
        if (NSFileManagerClass) {
            Method m1 = class_getInstanceMethod(NSFileManagerClass, @selector(fileExistsAtPath:));
            if (m1) {
                orig_NSFileManager_fileExistsAtPath = method_getImplementation(m1);
                method_setImplementation(m1, (IMP)my_NSFileManager_fileExistsAtPath);
            }
            Method m2 = class_getInstanceMethod(NSFileManagerClass, @selector(createFileAtPath:contents:attributes:));
            if (m2) {
                orig_NSFileManager_createFile = method_getImplementation(m2);
                method_setImplementation(m2, (IMP)my_NSFileManager_createFile);
            }
        }

        Class NSDataClass = objc_getClass("NSData");
        if (NSDataClass) {
            Method d1 = class_getInstanceMethod(NSDataClass, @selector(initWithContentsOfFile:));
            if (d1) {
                orig_NSData_initWithContentsOfFile = method_getImplementation(d1);
                method_setImplementation(d1, (IMP)my_NSData_initWithContentsOfFile);
            }
        }

        Class NSFileHandleClass = objc_getClass("NSFileHandle");
        if (NSFileHandleClass) {
            Method f1 = class_getInstanceMethod(NSFileHandleClass, @selector(fileHandleForReadingAtPath:));
            if (f1) {
                orig_NSFileHandle_fileHandleForReadingAtPath = method_getImplementation(f1);
                method_setImplementation(f1, (IMP)my_NSFileHandle_fileHandleForReadingAtPath);
            }
        }
    }
}
