TARGET = hub

all: $(TARGET)

CC = gcc
LD = gcc

CFLAGS = -g -Wall -Iinclude
LDFLAGS = 

LIBS = 

SRCS = main.c

OBJS = $(patsubst %.c,%.o,$(SRCS))

$(OBJS) : %.o : %.c include/*.h
	$(CC) -c $(CFLAGS) $< -o $@

$(TARGET): $(OBJS)
	$(LD) $(LDFLAGS) $(OBJS) -o $(TARGET) $(LIBS) 

clean:
	rm -f $(OBJS) $(TARGET)
