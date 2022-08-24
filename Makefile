PROJECT = ftpd
SOURCES = $(wildcard *.c)
HEADERS = $(filter-out main.h, $(SOURCES:.c=.h))
OBJECTS = $(SOURCES:.c=.o)
SPECIAL = Makefile README.md LICENSE
CSOURCE = -D _XOPEN_SOURCE=500 -D _POSIX_C_SOURCE=200809L -D FOR_LINUX
CC = gcc
CFLAGS = -Wall -g -ansi -pedantic $(CSOURCE)
CTAGS = ctags
ARGV = 127.0.0.1 2000

$(PROJECT): $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $(OBJECTS)

%.o: %.c %.h
	$(CC) $(CFLAGS) -c -o $@ $<

$(PROJECT).tar: $(SOURCES) $(HEADERS) $(SPECIAL)
	tar -cf $@ $(SOURCES) $(HEADERS) $(SPECIAL)

deps.mk: $(SOURCES) Makefile
	$(CC) -MM $(SOURCES) > $@

run: $(PROJECT)
	./$(PROJECT) $(ARGV)

stop:
	pkill -SIGTERM $(PROJECT)

memcheck: $(PROJECT)
	valgrind -s --leak-check=full ./$(PROJECT) $(ARGV)

systrace: $(PROJECT)
	strace -f ./$(PROJECT) $(ARGV)

tags: $(SOURCES) $(HEADERS)
	$(CTAGS) $(SOURCES) $(HEADERS)

tar: $(PROJECT).tar

clean:
	rm -f $(PROJECT) *.o *.a *.bin deps.mk tags

ifneq (clean, $(MAKECMDGOALS))
ifneq (stop, $(MAKECMDGOALS))
ifneq (tags, $(MAKECMDGOALS))
ifneq (tar, $(MAKECMDGOALS))
-include deps.mk
endif
endif
endif
endif

