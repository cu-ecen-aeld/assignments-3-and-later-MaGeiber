CC?=$(CROSS_COMPILE)gcc
CFLAGS?=-I.
FILENAME?=aesdsocket
TARGET?=aesdsocket
LDFLAGS?=-lpthread -lrt

default all: $(FILENAME).o
	$(CC) $(CFLAGS) $^ -o $@ $(INCLUDES) $(LDFLAGS)
clean:
	rm -f *.o $(FILENAME)
