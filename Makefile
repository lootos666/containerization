C=gcc
CFLAGS=-Wall -Werror -lcap -lseccomp
SOURCES=src/contained.c
PROGRAM=contained
.PHONY:	build
.PHONY:	clean

build:	$(PROGRAM)

$(PROGRAM):	$(SOURCES)
	$(C) $(CFLAGS) $(SOURCES) -o $(PROGRAM)

clean: 
	rm -rf $(PROGRAM)