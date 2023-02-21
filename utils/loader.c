#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <dlfcn.h>

typedef void *(*dlsym_f)(void *restrict handle, const char *restrict symbol);

typedef struct module_init_ctx
{
    dlsym_f dlsym;
} module_init_ctx_t;

typedef int (*call_f)(module_init_ctx_t *ctx);

int main(int argc, char *argv[])
{
    module_init_ctx_t ctx = {0};
    ctx.dlsym = dlsym;

    if (argc != 2)
    {
        printf("Usage: %s <file>\n", argv[0]);
        return 1;
    }

    int fd = open(argv[1], O_RDONLY);
    if (fd == -1)
    {
        perror("open");
        return 1;
    }

    struct stat st;
    if (fstat(fd, &st) == -1)
    {
        perror("fstat");
        return 1;
    }

    void *map = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE, fd, 0);
    if (map == MAP_FAILED)
    {
        perror("mmap");
        return 1;
    }

    // Read the contents of the file into the memory-mapped buffer
    ssize_t bytes_read = read(fd, map, st.st_size);
    if (bytes_read == -1)
    {
        perror("read");
        return 1;
    }

    call_f func = (call_f)((char *)map + 0x1000);
    puts("jumping to 0x1000");
    int check = func(&ctx);

    if (0 == check)
    {
        puts("success");
    }
    else
    {
        puts("failure");
    }

    return 0;
}