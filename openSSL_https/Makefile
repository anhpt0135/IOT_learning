target=https_client
src=$(wildcard ./src/*.c)
obj=$(src:*.c=*.o)

CFLAGS=-Wall -g -I. -I./src/include
LDFLAGS=-L./lib -lcrypto -lssl

.PHONY: all clean $(target)
$(target):$(obj)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
	
all:$(target)
	$(STRIP) $(target)
	
strip:
	$(STRIP) $(target)
	
clean:
	rm -rf ./src/*.o $(target)
