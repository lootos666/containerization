C=gcc
CFLAGS=-Wall -Werror -lcap -lseccomp
SOURCES=src/contained.c

all: contained

contained: 
	$(C) $(CFLAGS) $(SOURCES) -o contained

clean:
	rm -rf *.o contained 