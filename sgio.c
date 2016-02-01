/*
 * Copyright 2016 Cyril Plisko. All rights reserved.
 * Use is subject to license terms.
 */

#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <assert.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <scsi/sg.h>

#if !defined(BLKGETSIZE64)
#include <linux/fs.h>
#endif

#define DEFAULT_SCSI_TIMEOUT 10000  /* 10 sec */
#define BUFLEN 128

typedef struct {
    int fd;
    uint64_t flags;
    uint32_t blocksize;
    uint64_t nblocks;
    off_t offset;
} sgiom_t;

#define SGIO_ACTIVE (1ULL << 63)

typedef enum {
    SGIO_READ = SG_DXFER_FROM_DEV,
    SGIO_WRITE = SG_DXFER_TO_DEV,
} sgio_rdwr_t;

static sgiom_t sgiom[1];

static void
sgdbg(int lvl, const char *file, const int line, const char *fmt, ...)
{
    char buf[BUFLEN];
    va_list ap;

#if defined(NDEBUG)
    /* when in non-debug mode only emit messages up to LOG_INFO */
    if (lvl > LOG_INFO) {
        return;
    }
#endif

    va_start(ap, fmt);
    //vsnprintf(buf, BUFLEN, fmt, ap);
    vfprintf(stderr, fmt, ap); fprintf(stderr, "\n");
    va_end(ap);

    return;

    syslog(LOG_LOCAL0 | lvl, "%s:%d\t%s", file, line, buf);
}

#define SGDBG(lvl, ...) sgdbg(lvl, __FILE__, __LINE__, __VA_ARGS__)

static int
sgio_readcap(sgiom_t *sgm)
{
    sg_io_hdr_t hdr;
    uint8_t cdb[16] = { 0 };
    uint8_t sense[128] = { 0 };
    uint8_t readcap16[32];
    struct iovec iov = { .iov_base = readcap16, .iov_len = sizeof(readcap16) };
    const char *cmd = "READ CAPACITY(16)";

    // Build READ CAPACITY(16) CDB
    cdb[0] = 0x9e;
    cdb[1] = 0x10;
    cdb[10] = (uint8_t)(sizeof(readcap16) >> 24 & 0xFF);
    cdb[11] = (uint8_t)(sizeof(readcap16) >> 16 & 0xFF);
    cdb[12] = (uint8_t)(sizeof(readcap16) >> 8 & 0xFF);
    cdb[13] = (uint8_t)(sizeof(readcap16) & 0xFF);

    hdr.interface_id = 'S';
    hdr.dxfer_direction = SG_DXFER_FROM_DEV;
    hdr.cmd_len = sizeof(cdb);
    hdr.mx_sb_len = sizeof(sense);
    hdr.iovec_count = 1;
    hdr.dxfer_len = sizeof(readcap16);
    hdr.dxferp = &iov;
    hdr.cmdp = cdb;
    hdr.sbp = sense;
    hdr.flags = SG_FLAG_DIRECT_IO;
    hdr.timeout = DEFAULT_SCSI_TIMEOUT;

    int rc = ioctl(sgm->fd, SG_IO, &hdr);

    SGDBG(LOG_DEBUG, "ioctl(SG_IO)=%d", rc);

    if (rc < 0) {
        SGDBG(LOG_ERR, "ioctl(SG_IO) failed (%s)", strerror(errno));
        return rc;
    }

    if (hdr.status != 0) {
        SGDBG(LOG_ERR, "%s failed, SCSI STATUS 0x%hhx", cmd, hdr.status);
        return -1;
    }

    sgm->blocksize = ((uint32_t)readcap16[11]) +
                    ((uint32_t)readcap16[10] << 8) +
                    ((uint32_t)readcap16[9] << 16) +
                    ((uint32_t)readcap16[8] << 24);

    sgm->nblocks = ((uint64_t)readcap16[7]) +
                    ((uint64_t)readcap16[6] << 8) +
                    ((uint64_t)readcap16[5] << 16) +
                    ((uint64_t)readcap16[4] << 24) +
                    ((uint64_t)readcap16[3] << 32) +
                    ((uint64_t)readcap16[2] << 40) +
                    ((uint64_t)readcap16[1] << 48) +
                    ((uint64_t)readcap16[0] << 56) +
                    1;

    return 0;
}

static ssize_t
sgio_rdwr(sgiom_t *sgm, sgio_rdwr_t dir, const struct iovec *iov, int iovcnt)
{
    sg_io_hdr_t hdr;
    uint8_t cdb[16] = { 0 };
    uint8_t sense[128] = { 0 };
    size_t total = 0;
    const char *cmd = (dir == SGIO_READ) ? "READ(16)" : "WRITE(16)";

    for (int i = 0; i < iovcnt; i++) {
        total += iov->iov_len;
    }

    assert(total % sgm->blocksize == 0);

    uint64_t lba = sgm->offset / sgm->blocksize;
    uint32_t xfer_length = total / sgm->blocksize;

    SGDBG(LOG_DEBUG,
        "Issuing %s for %zd bytes (%d blocks) from fd=%d at LBA %lld",
        cmd, total, xfer_length, sgm->fd, lba);

    // Build CDB
    cdb[0] = (dir == SGIO_READ) ? 0x88 : 0x8a;
    cdb[2] = (uint8_t)(lba >> 56 & 0xFF);
    cdb[3] = (uint8_t)(lba >> 48 & 0xFF);
    cdb[4] = (uint8_t)(lba >> 40 & 0xFF);
    cdb[5] = (uint8_t)(lba >> 32 & 0xFF);
    cdb[6] = (uint8_t)(lba >> 24 & 0xFF);
    cdb[7] = (uint8_t)(lba >> 16 & 0xFF);
    cdb[8] = (uint8_t)(lba >> 8 & 0xFF);
    cdb[9] = (uint8_t)(lba & 0xFF);
    cdb[10] = (uint8_t)(xfer_length >> 24 & 0xFF);
    cdb[11] = (uint8_t)(xfer_length >> 16 & 0xFF);
    cdb[12] = (uint8_t)(xfer_length >> 8 & 0xFF);
    cdb[13] = (uint8_t)(xfer_length & 0xFF);

    hdr.interface_id = 'S';
    hdr.dxfer_direction = dir;
    hdr.cmd_len = sizeof(cdb);
    hdr.mx_sb_len = sizeof(sense);
    hdr.iovec_count = iovcnt;
    hdr.dxfer_len = total;
    hdr.dxferp = iov;
    hdr.cmdp = cdb;
    hdr.sbp = sense;
    hdr.flags = SG_FLAG_DIRECT_IO;
    hdr.timeout = DEFAULT_SCSI_TIMEOUT;

    int rc = ioctl(sgm->fd, SG_IO, &hdr);

    SGDBG(LOG_DEBUG, "ioctl(SG_IO)=%d", rc);

    if (rc < 0) {
        SGDBG(LOG_ERR, "ioctl(SG_IO) failed (%s)", strerror(errno));
        return rc;
    }

    if (hdr.status != 0) {
        SGDBG(LOG_ERR, "%s failed, SCSI STATUS 0x%hhx", cmd, hdr.status);
        return -1;
    }

    int xferred = total - hdr.resid;
    sgm->offset += xferred;

    return xferred;
}

static sgiom_t *
lookup_sgio(int fd)
{
    for (int i = 0; i < sizeof(sgiom) / sizeof(sgiom_t); i++) {
        if ((fd == sgiom[i].fd) && (sgiom[i].flags & SGIO_ACTIVE)) {
            return &sgiom[i];
        }
    }

    return NULL;
}

static int
add_sgio(int fd)
{
    sgiom_t *sgio = sgiom;

    if (sgio->flags & SGIO_ACTIVE) {
        SGDBG(LOG_WARNING, "Another SGIO already active, skipping");
        return -1;
    }

    SGDBG(LOG_DEBUG, "Adding SGIO for fd=%d", fd);

    sgio->flags |= SGIO_ACTIVE;
    sgio->fd = fd;
    sgio_readcap(sgio);
    sgio->offset = 0;

    return 0;
}

static int
rem_sgio(int fd)
{
    sgiom_t *sgio = lookup_sgio(fd);

    if (sgio == NULL) {
        return -1;
    }

    SGDBG(LOG_DEBUG, "Removing SGIO for fd=%d", fd);

    sgio->flags &= ~SGIO_ACTIVE;
    sgio->fd = -1;
    sgio->blocksize = 0;
    sgio->nblocks = 0;
    sgio->offset = 0;

    return 0;
}

static void
update_sgio(int oldfd, int newfd) {
    sgiom_t *sgio = lookup_sgio(oldfd);

    if (sgio != NULL) {
        SGDBG(LOG_DEBUG, "Replacing fd=%d with new fd=%d", oldfd, newfd);
        sgio->fd = newfd;
    }
}

static bool
sgio_capable(const char *path)
{
    const char *devsg = "/dev/sg";

    return strncmp(path, devsg, strlen(devsg)) == 0;
}

#define WRAPSYSCALL(ptr, name) \
    if (ptr == NULL) ptr = dlsym(RTLD_NEXT, name); \
    if (ptr == NULL) return -1;

int
open(const char *path, int flags, ...)
{
    static int (*open_)(const char *path, int flags, ...);

    WRAPSYSCALL(open_, "open");

    va_list ap;
    mode_t mode;
    int fd;

    if (flags & O_CREAT) {
        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
        fd = open_(path, flags, mode);
    } else {
        fd = open_(path, flags);
    }

    SGDBG(LOG_DEBUG, "Checking %s", path);
    if ((fd != -1) && sgio_capable(path)) {
        SGDBG(LOG_DEBUG, "Adding %s", path);
        add_sgio(fd);
    }

    return fd;
}

int
dup(int oldfd)
{
    static int (*dup_)(int) = NULL;

    WRAPSYSCALL(dup_, "dup");

    int newfd = dup_(oldfd);
    if (newfd != -1) {
        update_sgio(oldfd, newfd);
    }

    return newfd;
}

int
dup2(int oldfd, int newfd)
{
    static int (*dup2_)(int, int) = NULL;

    WRAPSYSCALL(dup2_, "dup2");

    int rc = dup2_(oldfd, newfd);
    if (rc != -1) {
        update_sgio(oldfd, newfd);
    }

    return rc;
}

int
dup3(int oldfd, int newfd, int flags)
{
    static int (*dup3_)(int, int, int) = NULL;

    WRAPSYSCALL(dup3_, "dup3");

    int rc = dup3_(oldfd, newfd, flags);
    if (rc != -1) {
        update_sgio(oldfd, newfd);
    }

    return rc;
}

int
ioctl(int fd, unsigned long request, ...)
{
    static int (*ioctl_)(int, unsigned long, ...);

    WRAPSYSCALL(ioctl_, "ioctl");

    va_list ap;
    uintptr_t arg;

    va_start(ap, request);
    arg = va_arg(ap, uintptr_t);
    va_end(ap);

    sgiom_t *sgio = lookup_sgio(fd);
    if ((sgio != NULL) && (request == BLKGETSIZE64)) {
        uint64_t *size = (uint64_t*)arg;
        *size = sgio->blocksize * sgio->nblocks;
        return 0;
    } else {
        return ioctl_(fd, request, arg);
    }
}

int
close(int fd)
{
    static int (*close_)(int) = NULL;

    WRAPSYSCALL(close_, "close");

    int rc = close_(fd);

    if (lookup_sgio(fd) != NULL) {
        rem_sgio(fd);
    }

    return rc;
}

ssize_t
pread(int fd, void *buf, size_t count, off_t offset)
{
    static ssize_t (*pread_)(int, void  *, size_t, off_t) = NULL;

    WRAPSYSCALL(pread_, "pread");

    return pread_(fd, buf, count, offset);
}

ssize_t
read(int fd, void *buf, size_t count)
{
    static ssize_t (*read_)(int, void  *, size_t) = NULL;

    WRAPSYSCALL(read_, "read");

    sgiom_t *sgio = lookup_sgio(fd);
    if (sgio == NULL) {
        return read_(fd, buf, count);
    } else {
        const struct iovec iov = {
            .iov_base = buf,
            .iov_len = count
        };
        SGDBG(LOG_DEBUG, "Replacing read(%d) with ioctl(%d, SG_IO)", fd, fd);
        return sgio_rdwr(sgio, SGIO_READ, &iov, 1);
    }
}

ssize_t
readv(int fd, const struct iovec *iov, int iovcnt)
{
    static ssize_t (*readv_)(int, const struct iovec *, int) = NULL;

    WRAPSYSCALL(readv_, "readv");

    sgiom_t *sgio = lookup_sgio(fd);
    if (sgio == NULL) {
        return readv_(fd, iov, iovcnt);
    } else {
        return sgio_rdwr(sgio, SGIO_READ, iov, iovcnt);
    }
}

ssize_t
pwrite(int fd, const void *buf, size_t count, off_t offset)
{
    static ssize_t (*pwrite_)(int, const void  *, size_t, off_t) = NULL;

    WRAPSYSCALL(pwrite_, "pwrite");

    return pwrite_(fd, buf, count, offset);
}

ssize_t
write(int fd, const void *buf, size_t count)
{
    static ssize_t (*write_)(int, const void  *, size_t) = NULL;

    WRAPSYSCALL(write_, "write");

    sgiom_t *sgio = lookup_sgio(fd);
    if (sgio == NULL) {
        return write_(fd, buf, count);
    } else {
        const struct iovec iov = {
            .iov_base = buf,
            .iov_len = count
        };
        SGDBG(LOG_DEBUG, "Replacing write(%d) with ioctl(%d, SG_IO)", fd, fd);
        return sgio_rdwr(sgio, SGIO_WRITE, &iov, 1);
    }
}

ssize_t
writev(int fd, const struct iovec *iov, int iovcnt)
{
    static ssize_t (*writev_)(int, const struct iovec *, int) = NULL;

    WRAPSYSCALL(writev_, "writev");

    sgiom_t *sgio = lookup_sgio(fd);
    if (sgio == NULL) {
        return writev_(fd, iov, iovcnt);
    } else {
        return sgio_rdwr(sgio, SGIO_WRITE, iov, iovcnt);
    }
}

int
fsync(int fd){
    static int (*fsync_)(int) = NULL;

    WRAPSYSCALL(fsync_, "fsync");

    if (lookup_sgio(fd) == NULL) {
        return fsync_(fd);
    } else {
        return 0;
    }
}

int
fdatasync(int fd) {
    static int (*fdatasync_)(int) = NULL;

    WRAPSYSCALL(fdatasync_, "fdatasync");

    if (lookup_sgio(fd) == NULL) {
        return fdatasync_(fd);
    } else {
        return 0;
    }
}
