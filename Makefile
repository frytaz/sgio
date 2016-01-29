#
# Copyright 2016 Cyril Plisko
#
SRCS = sgio.c
OBJS = $(SRCS:.c=.o)
TARGET = sgio.so

CFLAGS = -fPIC
CFLAGS += -Wall
CFLAGS += -std=c99

LDLIBS = -ldl

$(TARGET): $(OBJS)
	$(CC) -shared $< -o $@ $(LDLIBS)

all: $(TARGET)

clean:
	$(RM) $(TARGET) $(OBJS)
