
sbin_PROGRAMS = jstart jkill jails jid jps injail

jstart_SOURCES = jstart.c util.h util.c
jkill_SOURCES = jkill.c util.h util.c
jails_SOURCES = jails.c util.h util.c
jid_SOURCES = jid.c util.h util.c
jps_SOURCES = jps.c util.h util.c
injail_SOURCES = injail.c util.h util.c

install-exec-hook:
	ln -f $(DESTDIR)$(sbindir)/jkill$(EXEEXT) \
	   $(DESTDIR)$(sbindir)/killjail$(EXEEXT)

# Uninstall hook doesn't work :(
uninstall-local:
	rm -f $(DESTDIR)$(sbindir)/killjail$(EXEEXT)

man_MANS = jstart.8 jkill.8 jails.8 jid.8 jps.8 injail.8
EXTRA_DIST = $(man_MANS)

depend:
