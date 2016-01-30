# sgio

SGIO Magic that turns regular read/write into direct SCSI command
using library interposition

How to Use

```sh
make all
LD_PRELOAD=./sgio.so cmd --with arguments
```
