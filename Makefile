CC = gcc
CFLAGS = -g -Wall -Werror
OS = $(shell uname -s)
PROC = $(shell uname -p)
EXEC_SUFFIX=$(OS)-$(PROC)

ifeq ("$(OS)", "SunOS")
	OSLIB=-L/opt/csw/lib -R/opt/csw/lib -lsocket -lnsl
	OSINC=-I/opt/csw/include
	OSDEF=-DSOLARIS
else
ifeq ("$(OS)", "Darwin")
	OSLIB=
	OSINC=
	OSDEF=-DDARWIN
else
	OSLIB=
	OSINC=
	OSDEF=-DLINUX
endif
endif

all:  trace-$(EXEC_SUFFIX)

trace-$(EXEC_SUFFIX): trace.o smartalloc.o checksum.o
	$(CC) $(CFLAGS) $(OSINC) $(OSLIB) $(OSDEF) -o $@ trace.o checksum.o smartalloc.o -lpcap

trace.o: trace.c trace.h
	$(CC) $(CFLAGS) -c trace.c trace.h

smartalloc.o: smartalloc.c smartalloc.h
	$(CC) $(CFLAGS) -c smartalloc.c smartalloc.h

checksum.o: checksum.c checksum.h
	$(CC) $(CFLAGS) -c checksum.c checksum.h

clean:
	rm -rf trace-* trace-*.dSYM *.o *.gch
