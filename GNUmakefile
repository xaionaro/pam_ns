
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

LIBS := -lpam -lprocps
LDSECFLAGS ?= -Xlinker -zrelro
LDFLAGS += $(LDSECFLAGS) -pthread -flto -L.
INC := $(INC)

INSTDIR = $(DESTDIR)$(PREFIX)

objs=\
pam_ns.o\

binary_pam_ns=pam_ns.so

binaries=$(binary_pam_ns)

.PHONY: doc

all: binary_pam_ns_so

binary_pam_ns_so: $(objs) $(objs_pam_ns)
	$(CC) $(CARCHFLAGS) $(CFLAGS) $(LDFLAGS) $(objs) $(LIBS) -shared -o $(binary_pam_ns)

%.o: %.c
	$(CC) $(CARCHFLAGS) $(CFLAGS) $(INC) $< -fPIC -c -o $@

#debug:
#	$(CC) $(CARCHFLAGS) -D_DEBUG_SUPPORT $(DEBUGCFLAGS) $(INC) $(LDFLAGS) *.c $(LIBS) -o $(binary)

clean:
	rm -f $(binaries) $(objs)

distclean: clean

doc:
	doxygen .doxygen

# Don't forget to fix PATH_SO_PAM_NS in pam_ns.c after editing installation path
install:
ifeq ($(STRIP_BINARY),yes)
	strip --strip-unneeded -R .comment -R .GCC.command.line -R .note.gnu.gold-version $(binaries)
endif
	install -D -m 644 $(binaries) "$(DESTDIR)"/lib/security/$(binaries)
	install -D -m 644 man/man8/pam_ns.8 "$(INSTDIR)"/share/man/man8/pam_ns.8
ifeq ($(COMPRESS_MAN),yes)
	rm -f "$(INSTDIR)"/share/man/man8/pam_ns.8.gz
	gzip "$(INSTDIR)"/share/man/man8/pam_ns.8
endif

deinstall:
	rm -f "$(DESTDIR)"/lib/security/$(binaries)

