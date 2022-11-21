CC=$(CROSS_COMPILE)gcc
CFLAGS=-I.
FILENAME=writer

all: writer.o
	$(CC) $(CFLAGS) $(INCLUDES) $(OBJS) -o $(FILENAME) $(FILENAME).o
clean:
	rm -f *.o writer
