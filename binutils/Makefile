CC=gcc
SOURCES=disasm.c debug.c
OBJS=$(SOURCES:.c=.o)
EXEC=disasm
LIBS=-lbfd -liberty -lopcodes -lz -ldl
CFLAGS=


all: $(SOURCES) $(EXEC) test

test: test.c
	$(CC) test.c -c -o test.o

$(EXEC): $(OBJS)
	$(CC) $(OBJS) $(LIBS) -o $@

.o:
	$(CC) $(CFLAGS) $< -o $@

clean:
	-rm *.o
	unlink $(EXEC)
