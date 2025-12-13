#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <dlfcn.h>
#include <unistd.h>
#include <time.h>
#include <CoreFoundation/CoreFoundation.h>
#include <syslog.h>
#include <limits.h>
#include <sys/types.h>

static const char *ACT_KEY = "7bb07b8d471d642e";
static const char *CEROD_MARK = ":cerod:";
static const char *LOG_PATH = "/tmp/cerod_trace.log";

void log_match(const char *fn, const char *path, const void *retaddr) {
    time_t t = time(NULL);
    pid_t pid = getpid();
    char buf[1024];
    int len = snprintf(buf, sizeof(buf), "%ld PID=%d %s: %s ret=%p\n", (long)t, (int)pid, fn, path ? path : "(null)", retaddr);
    if (len <= 0) return;
    FILE *f = fopen(LOG_PATH, "a");
    if (f) {
        fwrite(buf, 1, (size_t)len, f);
        fclose(f);
        return;
    }
    /* fallback to syslog if fopen fails */
    openlog("cerod_interpose", LOG_PID|LOG_CONS, LOG_USER);
    syslog(LOG_INFO, "%s", buf);
    closelog();
}

int path_matches(const char *p) {
    if (!p) return 0;
    if (strstr(p, CEROD_MARK)) return 1;
    if (strstr(p, ACT_KEY)) return 1;
    if (strstr(p, "KeyKey.db")) return 1;
    return 0;
}

// Our implementations (named to avoid symbol conflict)
int my_open(const char *path, int oflag, ...) {
    static int (*real_open)(const char*, int, ...) = NULL;
    if (!real_open) {
        real_open = dlsym(RTLD_NEXT, "open");
    }
    mode_t mode = 0;
    if (oflag & 0200) { // O_CREAT
        va_list ap; va_start(ap, oflag); mode = va_arg(ap, int); va_end(ap);
        if (path_matches(path)) log_match("open", path, __builtin_return_address(0));
        return real_open(path, oflag, mode);
    } else {
        if (path_matches(path)) log_match("open", path, __builtin_return_address(0));
        return real_open(path, oflag);
    }
}

int my_openat(int fd, const char *path, int oflag, ...) {
    static int (*real_openat)(int, const char*, int, ...) = NULL;
    if (!real_openat) {
        real_openat = dlsym(RTLD_NEXT, "openat");
    }
    mode_t mode = 0;
    if (oflag & 0200) {
        va_list ap; va_start(ap, oflag); mode = va_arg(ap, int); va_end(ap);
        if (path_matches(path)) log_match("openat", path, __builtin_return_address(0));
        return real_openat(fd, path, oflag, mode);
    } else {
        if (path_matches(path)) log_match("openat", path, __builtin_return_address(0));
        return real_openat(fd, path, oflag);
    }
}

FILE *my_fopen(const char *path, const char *mode) {
    static FILE *(*real_fopen)(const char*, const char*) = NULL;
    if (!real_fopen) {
        real_fopen = dlsym(RTLD_NEXT, "fopen");
    }
    if (path_matches(path)) log_match("fopen", path, __builtin_return_address(0));
    return real_fopen(path, mode);
}

// fopen64 alias (some programs use it)
FILE *fopen64(const char *path, const char *mode) {
    static FILE *(*real_fopen64)(const char*, const char*) = NULL;
    if (!real_fopen64) {
        real_fopen64 = dlsym(RTLD_NEXT, "fopen64");
    }
    if (path_matches(path)) log_match("fopen64", path, __builtin_return_address(0));
    return real_fopen64 ? real_fopen64(path, mode) : my_fopen(path, mode);
}

// creat is sometimes used instead of open
int my_creat(const char *path, mode_t mode) {
    static int (*real_creat)(const char*, mode_t) = NULL;
    if (!real_creat) {
        real_creat = dlsym(RTLD_NEXT, "creat");
    }
    if (path_matches(path)) log_match("creat", path, __builtin_return_address(0));
    return real_creat(path, mode);
}

// weak declaration for sqlite3_open (we don't include sqlite3.h to avoid dependency)
int sqlite3_open(const char *filename, void **ppDb) {
    static int (*real_sqlite3_open)(const char*, void**) = NULL;
    if (!real_sqlite3_open) {
        real_sqlite3_open = dlsym(RTLD_NEXT, "sqlite3_open");
    }
    if (path_matches(filename)) log_match("sqlite3_open", filename, __builtin_return_address(0));
    if (real_sqlite3_open) return real_sqlite3_open(filename, ppDb);
    return -1;
}

int sqlite3_open_v2(const char *filename, void **ppDb, int flags, const char *zVFS) {
    static int (*real_sqlite3_open_v2)(const char*, void**, int, const char*) = NULL;
    if (!real_sqlite3_open_v2) {
        real_sqlite3_open_v2 = dlsym(RTLD_NEXT, "sqlite3_open_v2");
    }
    if (path_matches(filename)) log_match("sqlite3_open_v2", filename, __builtin_return_address(0));
    if (real_sqlite3_open_v2) return real_sqlite3_open_v2(filename, ppDb, flags, zVFS);
    return -1;
}

// CF wrappers (for CFString and CFURL-based file conversions)

Boolean my_CFStringGetCString(CFStringRef theString, char *buffer, CFIndex bufferSize, CFStringEncoding encoding) {
    static Boolean (*real_CFStringGetCString)(CFStringRef, char*, CFIndex, CFStringEncoding) = NULL;
    if (!real_CFStringGetCString) {
        real_CFStringGetCString = dlsym(RTLD_NEXT, "CFStringGetCString");
    }
    Boolean ret = real_CFStringGetCString(theString, buffer, bufferSize, encoding);
    if (ret && buffer && path_matches(buffer)) {
        log_match("CFStringGetCString", buffer, __builtin_return_address(0));
    }
    return ret;
}

Boolean my_CFURLGetFileSystemRepresentation(CFURLRef url, Boolean resolveToBase, char *buffer, CFIndex maxBufLen) {
    static Boolean (*real_CFURLGetFileSystemRepresentation)(CFURLRef, Boolean, char*, CFIndex) = NULL;
    if (!real_CFURLGetFileSystemRepresentation) {
        real_CFURLGetFileSystemRepresentation = dlsym(RTLD_NEXT, "CFURLGetFileSystemRepresentation");
    }
    Boolean ret = real_CFURLGetFileSystemRepresentation(url, resolveToBase, buffer, maxBufLen);
    if (ret && buffer && path_matches(buffer)) {
        log_match("CFURLGetFileSystemRepresentation", buffer, __builtin_return_address(0));
    }
    return ret;
}

CFURLRef my_CFURLCreateWithFileSystemPath(CFAllocatorRef allocator, CFStringRef filePath, CFURLPathStyle pathStyle, Boolean isDirectory) {
    static CFURLRef (*real_CFURLCreateWithFileSystemPath)(CFAllocatorRef, CFStringRef, CFURLPathStyle, Boolean) = NULL;
    if (!real_CFURLCreateWithFileSystemPath) {
        real_CFURLCreateWithFileSystemPath = dlsym(RTLD_NEXT, "CFURLCreateWithFileSystemPath");
    }
    char buf[PATH_MAX];
    if (filePath && CFStringGetCString(filePath, buf, sizeof(buf), kCFStringEncodingUTF8)) {
        if (path_matches(buf)) log_match("CFURLCreateWithFileSystemPath", buf, __builtin_return_address(0));
    }
    if (real_CFURLCreateWithFileSystemPath) return real_CFURLCreateWithFileSystemPath(allocator, filePath, pathStyle, isDirectory);
    return NULL;
}

// Declare originals so we can reference their symbol names in the interpose table
int open(const char *path, int oflag, ...);
int openat(int fd, const char *path, int oflag, ...);
int creat(const char *path, mode_t mode);
int sqlite3_open(const char *filename, void **ppDb);

// Interpose table to reliably replace libc symbols even when called internally
struct interpose_t { void *new_func; void *orig_func; };
__attribute__((used)) static struct interpose_t interposers[] __attribute__((section("__DATA,__interpose"))) = {
    { (void*)my_open, (void*)open },
    { (void*)my_openat, (void*)openat },
    { (void*)my_fopen, (void*)fopen },
    { (void*)my_creat, (void*)creat },
    { (void*)my_CFStringGetCString, (void*)CFStringGetCString },
    { (void*)my_CFURLGetFileSystemRepresentation, (void*)CFURLGetFileSystemRepresentation },
    { (void*)my_CFURLCreateWithFileSystemPath, (void*)CFURLCreateWithFileSystemPath },
};

// ensure library is loaded message
__attribute__((constructor)) static void init_msg(void) {
    char buf[128];
    int len = snprintf(buf, sizeof(buf), "cerod_interpose loaded pid=%d\n", (int)getpid());
    FILE *f = fopen(LOG_PATH, "a");
    if (f) {
        fwrite(buf, 1, (size_t)len, f);
        fclose(f);
        return;
    }
    /* fallback to syslog */
    openlog("cerod_interpose", LOG_PID|LOG_CONS, LOG_USER);
    syslog(LOG_INFO, "%s", buf);
    closelog();
}
