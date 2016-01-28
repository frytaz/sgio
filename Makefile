#
# Copyright 2016 Cyril Plisko
#
SRCS = sgio.c
OBJS = $(SRCS:.c=.o)
TARGET = sgio.so

CFLAGS = -fPIC
LDLIBS = -ldl

$(TARGET): $(OBJS)
	$(CC) -shared $< -o $@ $(LDLIBS)
	#$(CC) -shared $(OBJS) -o $(TARGET) $(LDLIBS)

clean:
	$(RM) $(TARGET) $(OBJS)
