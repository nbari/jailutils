sbin_PROGRAMS = killjail jails jstart
killjail_SOURCES = killjail.c getjail.c getjail.h
killjail_LDADD = -lkvm
jails_SOURCES = jails.c getjail.c getjail.h
jails_LDADD = -lkvm
jstart_SOURCES = jstart.c
jstart_LDADD = -lkvm
man_MANS = killjail.8 jails.8 jstart.8
EXTRA_DIST = $(man_MANS)

