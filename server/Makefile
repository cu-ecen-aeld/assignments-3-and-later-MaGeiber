CC=$(CROSS_COMPILE)gcc
CFLAGS=-I.
FILENAME=aesdsocket

default all: $(FILENAME).o
	$(CC) $(CFLAGS) $(INCLUDES) $(OBJS) -o $(FILENAME) $(FILENAME).o -pthread
clean:
	rm -f *.o $(FILENAME)
