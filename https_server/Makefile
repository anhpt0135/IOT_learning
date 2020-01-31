TARGET=embedtls_https
src=src/https_server.c
obj=$(src:.c=.o)

CC=arm-linux-gcc

CFLAGS=-Wall -Werror -g -I. -I./include
CFLAGS+=-I/usr/local/arm-linux-gm/arm-unknown-linux-uclibcgnueabi/include -I/usr/local/arm-linux-gm/arm-unknown-linux-uclibcgnueabi/sysroot/usr/include
CFLAGS+=-I/usr/local/arm-linux-gm/lib/gcc/arm-unknown-linux-uclibcgnueabi/4.4.0/include -I/usr/local/arm-linux-gm/lib/gcc/arm-unknown-linux-uclibcgnueabi/4.4.0/include-fixed
LDFLAGS=-L./library -lmbedtls -lmbedx509 -lmbedcrypto

.PHONY: clean $(TARGET) all

all:$(TARGET)
	
$(TARGET):$(obj)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) 
	
clean:
	rm src/*.o $(TARGET)