# sgio

SGIO Magic that turns regular read/write into direct SCSI command
using library interposition

How to Use

```sh
make all
LD_PRELOAD=./sgio.so cmd --with arguments
```

Note that by default it builds native 32 or 64 bit binary according to the
compiler native configuration.
