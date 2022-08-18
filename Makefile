PROJECT = ftpd
SOURCES = $(wildcard *.c)
HEADERS = $(filter-out main.h, $(SOURCES:.cpp=.h))
OBJECTS = $(SOURCES:.c=.o)
CC = gcc
CFLAGS = -Wall -g -pedantic
LDLIBS = 
CTAGS = ctags

$(PROJECT): $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $(OBJECTS) $(LDLIBS)

%.o: %.c %.h
	$(CC) $(CFLAGS) -c -o $@ $<

deps.mk: $(SOURCES) Makefile
	$(CC) -MM $(SOURCES) > $@

run: $(PROJECT)
	./$(PROJECT) 127.0.0.1 2000

memcheck: $(PROJECT)
	valgrind -s --leak-check=full ./$(PROJECT) 127.0.0.1 2000

tags: $(SOURCES) $(HEADERS)
	$(CTAGS) $(SOURCES) $(HEADERS)

clean:
	rm -f $(PROJECT) *.o *.a *.bin deps.mk tags

ifneq (clean, $(MAKECMDGOALS))
ifneq (tags, $(MAKECMDGOALS))
-include deps.mk
endif
endif

