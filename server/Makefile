CC?=$(CROSS_COMPILE)gcc
CFLAGS?=-I.
TARGET?=aesdsocket
LDFLAGS?=-pthread -lrt
OBJS?=$(TARGET).o

default all: $(TARGET)
	$(CC) $(CFLAGS) $(OBJS) -o $(TARGET) $(INCLUDES) $(LDFLAGS)
clean:
	rm -f *.o $(TARGET)
