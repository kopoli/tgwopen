CLEANFILES=*~

INCLUDES =

EXTRA_DIST =  common/defines.h

bin_PROGRAMS = tgwopen

tgwopen_SOURCES = main.c tgw.c tgw.h \
common/gen_cli.c  common/getopt_clone.h \
common/gen_cli.h  common/getopt_clone.c \
common/commonconf.h  common/iolet.h   common/useful.h \
common/iolet.c       common/useful.c \
common/llist.c  common/llist.h

tgwopen_LDFLAGS =
tgwopen_LDADD = 
tgwopen_CFLAGS = -Icommon -Wall

all: tgwopen

