#import <Foundation/Foundation.h>

int main(int argc, char *argv[]) {
    @autoreleasepool {
        NSString *p1 = @"/tmp/test:cerod:example.db";
        NSURL *u = [NSURL fileURLWithPath:p1];
        BOOL exists = [[NSFileManager defaultManager] fileExistsAtPath:p1];
        (void)exists;
        NSData *d = [NSData dataWithContentsOfFile:p1];
        (void)d;
        NSFileHandle *h = [NSFileHandle fileHandleForReadingAtPath:p1];
        (void)h;
        [[NSFileManager defaultManager] createFileAtPath:p1 contents:[@"abc" dataUsingEncoding:NSUTF8StringEncoding] attributes:nil];
        printf("objc test done\n");
    }
    return 0;
}
