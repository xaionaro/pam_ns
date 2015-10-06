
DESTDIR ?= /
PREFIX  ?= /usr
COMPRESS_MAN ?= yes
STRIP_BINARY ?= yes
EXAMPLES ?= yes

CSECFLAGS ?= -fstack-protector-all -Wall --param ssp-buffer-size=4 -D_FORTIFY_SOURCE=2 -fstack-check -DPARANOID -std=gnu99
CFLAGS ?= -pipe -O2
CFLAGS += $(CSECFLAGS)
DEBUGCFLAGS ?= -pipe -Wall -Werror -ggdb3 -export-dynamic -Wno-error=unused-variable -O0 -pipe $(CSECFLAGS)

CARCHFLAGS ?= -march=native

LIBS := -lpam
LDSECFLAGS ?= -Xlinker -zrelro
LDFLAGS += $(LDSECFLAGS) -pthread -flto -L.
INC := $(INC)

INSTDIR = $(DESTDIR)$(PREFIX)

objs=\
pam_unshare.o\

binary_pam_unshare=pam_unshare.so

binaries=$(binary_pam_unshare)

.PHONY: doc

all: binary_pam_unshare_so

binary_pam_unshare_so: $(objs) $(objs_pam_unshare)
	$(CC) $(CARCHFLAGS) $(CFLAGS) $(LDFLAGS) $(objs) $(LIBS) -shared -o $(binary_pam_unshare)

%.o: %.c
	$(CC) $(CARCHFLAGS) $(CFLAGS) $(INC) $< -fPIC -c -o $@

#debug:
#	$(CC) $(CARCHFLAGS) -D_DEBUG_SUPPORT $(DEBUGCFLAGS) $(INC) $(LDFLAGS) *.c $(LIBS) -o $(binary)

clean:
	rm -f $(binaries) $(objs)

distclean: clean

doc:
	doxygen .doxygen

install:
ifeq ($(STRIP_BINARY),yes)
	strip --strip-unneeded -R .comment -R .GCC.command.line -R .note.gnu.gold-version $(binaries)
endif
	install -m 644 $(binaries) "$(DESTDIR)"/lib/security/
	install -m 644 man/man8/pam_unshare.8 "$(INSTDIR)"/share/man/man8/
ifeq ($(COMPRESS_MAN),yes)
	rm -f "$(INSTDIR)"/share/man/man8/pam_unshare.8.gz
	gzip "$(INSTDIR)"/share/man/man8/pam_unshare.8
endif

deinstall:
	rm -f "$(DESTDIR)"/lib/security/$(binaries)

