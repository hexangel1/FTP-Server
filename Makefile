PROJECT = ftpserv
SOURCES = $(wildcard *.c)
HEADERS = $(filter-out main.h, $(SOURCES:.c=.h))
OBJECTS = $(SOURCES:.c=.o)
SPECIAL = Makefile README.md LICENSE
CSOURCE = -D _XOPEN_SOURCE=500 -D _POSIX_C_SOURCE=200809L
CDEFINE = -D BUILD_FOR_LINUX
CFLAGS = -Wall -g -ansi -pedantic $(CSOURCE) $(CDEFINE)
CC = gcc
CTAGS = ctags
INSTALL = install
PREFIX = /usr/local
ARGV = -i 127.0.0.1 -p 2000

$(PROJECT): $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $(OBJECTS)

$(PROJECT).tar: $(SOURCES) $(HEADERS) $(SPECIAL)
	tar -cf $@ $(SOURCES) $(HEADERS) $(SPECIAL)

%.o: %.c %.h
	$(CC) $(CFLAGS) -c -o $@ $<

deps.mk: $(SOURCES) Makefile
	$(CC) -MM $(SOURCES) > $@

run: $(PROJECT)
	./$(PROJECT) $(ARGV)

memcheck: $(PROJECT)
	valgrind -s --leak-check=full ./$(PROJECT) $(ARGV)

systrace: $(PROJECT)
	strace -Cwf ./$(PROJECT) $(ARGV)

stop:
	pkill -SIGTERM $(PROJECT)

tags: $(SOURCES) $(HEADERS)
	$(CTAGS) $(SOURCES) $(HEADERS)

tar: $(PROJECT).tar

clean:
	rm -f $(PROJECT) *.o *.a *.bin deps.mk tags

install: $(PROJECT)
	$(INSTALL) $(PROJECT) $(PREFIX)/bin

uninstall:
	rm -f $(PREFIX)/bin/$(PROJECT)

ifneq (unistall, $(MAKECMDGOALS))
ifneq (clean, $(MAKECMDGOALS))
ifneq (stop, $(MAKECMDGOALS))
ifneq (tags, $(MAKECMDGOALS))
ifneq (tar, $(MAKECMDGOALS))
-include deps.mk
endif
endif
endif
endif
endif

