# Makefile to install packet cloning and Spade into snort 1.9+

SNORTBASE=..

SNORTSRC=$(SNORTBASE)/src/
SNORTPREPROCSRC=$(SNORTSRC)/preprocessors/

target: spade-in-snort
justspade: spade

spade-in-snort: packet-cloning spade
	@echo "Don't forget to type 'make no-automake' if you don't have automake installed"

packet-cloning:
	cp patches/packets.[ch] $(SNORTSRC)/
	@# add packet cloning to Makefile.am
	perl -pi -e '$$_.="packets.c packets.h \\\n" if m/^snort_SOURCES\s*=/' $(SNORTSRC)/Makefile.am
	@#perl -pi -e '$$_.="packets.c packets.h \\\n" if m/^snort_SOURCES\s*=/' $(SNORTSRC)/Makefile.in
	@#perl -pi -e '$$_.="packets.o \\\n" if m/^snort_OBJECTS\s*=/' $(SNORTSRC)/Makefile.in
	@# disable caching done in PrintNetData(); makes a broken assumption
	perl -pi -e 's/^(\s*if\s*\()dump_ready/$$1 0/' $(SNORTSRC)/log.c
	@echo "Packet cloning installed!"

spade:
	(cd src; make plugin)
	cp spp_spade.[ch] $(SNORTPREPROCSRC)/
	perl -pi -e '$$_.="spp_spade.c spp_spade.h \\\n" if m/^libspp_a_SOURCES\s*=/' $(SNORTPREPROCSRC)/Makefile.am
	@#perl -pi -e '$$_.="spp_spade.c spp_spade.h \\\n" if m/^libspp_a_SOURCES\s*=/' $(SNORTPREPROCSRC)/Makefile.in
	@#perl -pi -e '$$_.="spp_spade.o \\\n" if m/^libspp_a_OBJECTS\s*=/' $(SNORTPREPROCSRC)/Makefile.in
	perl -pi -e '$$_.="#include \"preprocessors/spp_spade.h\"\n" if m/^\s*#include.*spp_conversation.h/' $(SNORTSRC)/plugbase.c
	perl -pi -e '$$_.="    SetupSpade();\n" if m/^\s*SetupConv\s*(\s*)/' $(SNORTSRC)/plugbase.c
	cp spade.*conf $(SNORTBASE)/etc
	chmod +w $(SNORTBASE)/etc/spade.*conf
	patch $(SNORTBASE)/etc/snort.conf < patches/snort.conf.patch
	cp README.Spade Usage.Spade $(SNORTBASE)/doc
	@echo "Spade installed!"

no-automake: packet-cloning-no-am spade-no-am

packet-cloning-no-am:
	perl -pi -e '$$_.="packets.c packets.h \\\n" if m/^snort_SOURCES\s*=/' $(SNORTSRC)/Makefile.in
	perl -pi -e '$$_.="packets.o \\\n" if m/^snort_OBJECTS\s*=/' $(SNORTSRC)/Makefile.in
	@echo "Packet cloning no automake provision added!"

spade-no-am:
	perl -pi -e '$$_.="spp_spade.c spp_spade.h \\\n" if m/^libspp_a_SOURCES\s*=/' $(SNORTPREPROCSRC)/Makefile.in
	perl -pi -e '$$_.="spp_spade.o \\\n" if m/^libspp_a_OBJECTS\s*=/' $(SNORTPREPROCSRC)/Makefile.in
	@echo "Spade no automake provision added!"
