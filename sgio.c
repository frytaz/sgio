/*
 * Copyright 2016 Cyril Plisko. All rights reserved.
 * Use is subject to license terms.
 */

#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>

typedef struct {
    uint64_t flags;
    int fd;
} sgio_magic_t;

static sgio_magic_t _sgiom[1];

static int
add_sgio(int fd)
{
    return -1;
}

static int
rem_sgio(int fd)
{
    return -1;
}

static sgio_magic_t *
lookup_sgio(int fd)
{
    return NULL;
}

static bool
sgio_capable(const char *path)
{
    return false;
}

#define WRAPSYSCALL(ptr, name) \
    if (ptr == NULL) ptr = dlsym(RTLD_NEXT, name); \
    if (ptr == NULL) return -1;

int
open(const char *path, int flags, ...)
{
    static int (*open_)(const char *path, int flags, ...);

    WRAPSYSCALL(open_, "open");

    /* XXX Add ... handler for O_CREAT */
    int fd = open_(path, flags);

    if (sgio_capable(path)) {
        add_sgio(fd);
    }

    return fd;
}

int
close(int fd)
{
    static int (*close_)(int) = NULL;

    WRAPSYSCALL(close_, "close");

    return -1;
}

ssize_t
pread(int fd, void *buf, size_t nbyte, off_t offset)
{
    static int (*pread_)(int, void  *, size_t, off_t) = NULL;

    WRAPSYSCALL(pread_, "pread");

    return -1;
}

ssize_t
read(int fd, void *buf, size_t nbyte)
{
    static int (*read_)(int, void  *, size_t, off_t) = NULL;

    WRAPSYSCALL(read_, "read");

    return -1;
}

ssize_t
readv(int fd, const struct iovec *iov, int iovcnt)
{
    static int (*readv_)(int, const struct iovec *, int) = NULL;

    WRAPSYSCALL(readv_, "readv");

    return -1;
}

ssize_t
pwrite(int fd, const void *buf, size_t nbyte, off_t offset)
{
    static int (*pwrite_)(int, const void  *, size_t, off_t) = NULL;

    WRAPSYSCALL(pwrite_, "pwrite");

    return -1;
}

ssize_t
write(int fd, const void *buf, size_t nbyte)
{
    static int (*write_)(int, const void  *, size_t, off_t) = NULL;

    WRAPSYSCALL(write_, "write");

    return -1;
}

ssize_t
writev(int fd, const struct iovec *iov, int iovcnt)
{
    static int (*writev_)(int, const struct iovec *, int) = NULL;

    WRAPSYSCALL(writev_, "writev");

    return -1;
}
