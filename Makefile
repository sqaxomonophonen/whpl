.PHONY: all debug clean

TARGET=test
SRC=whpl.c sha1.c base64.c log.c test.c
OBJ=$(SRC:.c=.o)
DEP=$(SRC:.c=.dep)
CFLAGS=-Wall

all: CFLAGS+=-O3
all: $(TARGET)

debug: CFLAGS+=-O0 -g
debug: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $^ $(CFLAGS) -o $@

%.dep: %.c
	$(CC) -M $(CFLAGS) $< > $@

-include $(DEP)

clean:
	rm -rf $(TARGET) *.o *.dep

