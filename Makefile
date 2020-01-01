C=gcc
CFLAGS=-Wall -Werror -lcap -lseccomp
SOURCES=src/contained.c
PROGRAM=contained
.PHONY:	build
.PHONY:	clean

build:	$(PROGRAM)

$(PROGRAM):	$(SOURCES)
	$(C) $(SOURCES) $(CFLAGS) -o $(PROGRAM)

clean: 
	rm -rf $(PROGRAM)