/*
 * Copyright 2016 Cyril Plisko. All rights reserved.
 * Use is subject to license terms.
 */

#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/uio.h>
#include <dlfcn.h>
#include <fcntl.h>
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

#define WRAPSYSCALL(ptr, name) \
        if (ptr == NULL) ptr = dlsym(RTLD_NEXT, name); \
        if (ptr == NULL) return -1;

int
open(const char *path, int flags, ...)
{
        static int (*open_)(const char *path, int flags, ...);

        WRAPSYSCALL(open_, "open");

	return -1;
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
	return -1;
}

ssize_t
read(int fd, void *buf, size_t nbyte)
{
        return -1;
}

ssize_t
readv(int fd, const struct iovec *iov, int iovcnt)
{
        return -1;
}

ssize_t
pwrite(int fd, const void *buf, size_t nbyte, off_t offset)
{
        return -1;
}

ssize_t
write(int fd, const void *buf, size_t nbyte)
{
        return -1;
}

ssize_t
writev(int fd, const struct iovec *iov, int iovcnt)
{
        return -1;
}
