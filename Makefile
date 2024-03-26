# Derived from contrib/Makefile.in
# $Id: Makefile 65 2012-06-09 12:25:31Z stephen $
# Makefile.config should define source and prefix
include Makefile.config

CC		= gcc
RM		= /bin/rm
MV		= /bin/mv
CP		= /bin/cp
INSTALL		= /usr/bin/install -c
#source		= /home/jilles/src/svn/atheme
#prefix		= /home/jilles/ircd/atheme
exec_prefix	= ${prefix}
bindir		= ${exec_prefix}/bin
datadir		= ${prefix}/share
sysconfdir	= ${prefix}/etc
libdir		= ${exec_prefix}/lib
sbindir		= ${exec_prefix}/sbin
localstatedir	= ${prefix}/var
DOCDIR		= ${prefix}/doc
MODDIR		= ${exec_prefix}
SHAREDIR	= ${prefix}
MKDEP		= gcc -MM -DPREFIX=\"${prefix}\" -I${source}/include -I${source}/libmowgli-2/src/libmowgli
PICFLAGS	= -fPIC -DPIC -shared
CFLAGS		= -g -O2 -std=c99 -Wpointer-arith -Wimplicit -Wnested-externs -Wcast-align -Wcast-qual -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations -W -Wno-unused -Wshadow -Wmissing-noreturn -Wundef -Wpacked -Wnested-externs -Wbad-function-cast -Wredundant-decls -Wfloat-equal -Wformat=2 -Wdisabled-optimization -DPREFIX=\"${prefix}\" -DMODDIR=\"${MODDIR}\" -DSHAREDIR=\"${prefix}\" -DSYSCONFDIR=\"${prefix}/etc\" -DLOGDIR=\"var\" -DRUNDIR=\"var\" -DDATADIR=\"etc\" -I./include -I${source}/include -I${source}/libmowgli-2/src/libmowgli

LIBS		=  -lcrypt -lssl -lcrypto
LDFLAGS		+=  -Wl,-export-dynamic
#CPPFLAGS	= 

default: all

SRCS = \
	log_sasl_fail.c \
	cs_successor_freenodestaff.c \
	regnotice.c \
	noemailnotice.c \
	ns_defaultcloak.c \
	os_regts.c \
	os_klinechan.c \
	projectns/help.c \
	projectns/info.c \
	projectns/list.c \
	projectns/listchannel.c \
	projectns/listcloak.c \
	projectns/contact.c \
	projectns/channel.c \
	projectns/cloak.c \
	projectns/mark.c \
	projectns/hooks.c \
	projectns/set.c \
	projectns/manage.c \
	projectns/audit.c \
	projectns/cs_claim.c \
	projectns/cs_listgroupchans.c \
	projectns/ns_listgroupcloaks.c

# To compile your own modules, add them to SRCS or make blegh.so

PROJECTNS_MAIN_SRCS = \
	projectns/main/config.c \
	projectns/main/db.c \
	projectns/main/main.c \
	projectns/main/objects.c \
	projectns/main/persist.c \
	projectns/main/util.c

OBJS = ${SRCS:.c=.so} projectns/main.so
OTHER = fn-rotatelogs fn-sendemail

all: ${OBJS} ${OTHER}

install:
	${INSTALL} -m 755 -d $(DESTDIR)${MODDIR}/modules/freenode
	${INSTALL} -m 755 *.so $(DESTDIR)${MODDIR}/modules/freenode
	${INSTALL} -m 755 -d $(DESTDIR)${MODDIR}/modules/freenode/projectns
	${INSTALL} -m 755 projectns/*.so $(DESTDIR)${MODDIR}/modules/freenode/projectns
	${INSTALL} -m 755 -d $(DESTDIR)${bindir}
	${INSTALL} -m 755 ${OTHER} $(DESTDIR)${bindir}
	$(INSTALL) -m 755 -d $(DESTDIR)$(SHAREDIR)/help
	(cd help; for i in *; do \
		[ -f $$i ] && $(INSTALL) -m 644 $$i $(DESTDIR)$(SHAREDIR)/help; \
		if [ -d $$i ]; then \
			cd $$i; \
			$(INSTALL) -m 755 -d $(DESTDIR)$(SHAREDIR)/help/$$i; \
			for j in *; do \
				[ -f $$j ] && $(INSTALL) -m 644 $$j $(DESTDIR)$(SHAREDIR)/help/$$i; \
			done; \
			cd ..; \
		fi; \
	done)

.SUFFIXES: .so

.c.so:
	${CC} ${PICFLAGS} ${CPPFLAGS} ${CFLAGS} $< -o $@

projectns/main.so: ${PROJECTNS_MAIN_SRCS}
	${CC} ${PICFLAGS} ${CPPFLAGS} ${CFLAGS} $^ -o $@

fn-rotatelogs: fn-rotatelogs.in
	sed -e 's!@prefix@!${prefix}!g' fn-rotatelogs.in > fn-rotatelogs

.PHONY: depend clean distclean
# This sed command sucks but I don't know a better way -- jilles
depend:
	${MKDEP} ${PICFLAGS} ${CPPFLAGS} ${CFLAGS} ${SRCS} | sed -e 's/\.o:/.so:/' > .depend

clean:
	${RM} -f *.so
	${RM} -f projectns/*.so

distclean: clean
	${RM} -f Makefile version.c.last

# we don't really need this -- jilles
#include .depend
