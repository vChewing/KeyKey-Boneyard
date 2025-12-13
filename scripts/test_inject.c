#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
int main(void) {
    printf("test_inject starting\n");
    FILE *f = fopen("/tmp/test:cerod:example.db", "w");
    if (f) { fprintf(f, "hello\n"); fclose(f); printf("wrote fopen\n"); }

    int fd = open("/tmp/7bb07b8d471d642e_key.db", O_CREAT|O_WRONLY, 0644);
    if (fd >= 0) { write(fd, "x", 1); close(fd); printf("wrote open (key)"); }

    int fd2 = open("/tmp/KeyKey.db", O_CREAT|O_WRONLY, 0644);
    if (fd2 >= 0) { write(fd2, "x", 1); close(fd2); printf("wrote open (KeyKey.db)\n"); }

    sleep(1);
    printf("test_inject done\n");
    return 0;
}
