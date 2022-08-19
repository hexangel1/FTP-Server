PROJECT = ftpd
SOURCES = $(wildcard *.c)
HEADERS = $(filter-out main.h, $(SOURCES:.c=.h))
OBJECTS = $(SOURCES:.c=.o)
SPECIAL = Makefile README.md LICENSE
CC = gcc
CFLAGS = -Wall -g -pedantic
LDLIBS = 
CTAGS = ctags
ARGV = 127.0.0.1 2000

$(PROJECT): $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $(OBJECTS) $(LDLIBS)

%.o: %.c %.h
	$(CC) $(CFLAGS) -c -o $@ $<

$(PROJECT).tar: $(SOURCES) $(HEADERS) $(SPECIAL)
	tar -cvf $@ $(SOURCES) $(HEADERS) $(SPECIAL)

deps.mk: $(SOURCES) Makefile
	$(CC) -MM $(SOURCES) > $@

run: $(PROJECT)
	./$(PROJECT) $(ARGV)

memcheck: $(PROJECT)
	valgrind -s --leak-check=full ./$(PROJECT) $(ARGV)

tags: $(SOURCES) $(HEADERS)
	$(CTAGS) $(SOURCES) $(HEADERS)

tar: $(PROJECT).tar

clean:
	rm -f $(PROJECT) *.o *.a *.bin deps.mk tags

ifneq (clean, $(MAKECMDGOALS))
ifneq (tags, $(MAKECMDGOALS))
ifneq (tar, $(MAKECMDGOALS))
-include deps.mk
endif
endif
endif

