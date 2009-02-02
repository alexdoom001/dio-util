.SUFFIXES:
.SUFFIXES: .c .o

EXE = dio-key
OBJ = dio-key.o

CC ?= gcc
CFLAGS ?= -std=c99 -Wall -O2
DESTDIR ?= /

all: $(EXE)

$(EXE): $(OBJ)
	$(CC) -s -o $@ $^

$(OBJ): Makefile

dio-key.o: dio-key.c

%.o: %.c
	$(CC) -c $(CFLAGS) -o $@ $<

clean:
	rm -f $(EXE) $(OBJ)

install:
	install -d $(DESTDIR)/usr/bin
	install -m 0755 dio-key $(DESTDIR)/usr/bin/
	install -m 0755 dio-util $(DESTDIR)/usr/bin/
