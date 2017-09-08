# This Makefile produces the files spp_spade.c and spp_spade.h from the
# multiple Spade source files.  To make changes, edit the source files in
# this directory and run make.  This will install spp_spade.c and
# spp_spade.h in the directory set for INSTALL_DIR.  To skip the
# install, run "make snort-plugin".

INSTALL_DIR=..

SPADE_C_SRC= score_mgr.c score_calculator.c spade_prob_table.c \
  spade_prob_table_types.c spade_state.c thresh_adapter.c thresh_adviser.c \
  anomscore_surveyer.c strtok.c dll_double.c ll_double.c spade_event.c \
  event_recorder.c score_info.c spade_enviro.c spade_output.c
NETSPADE_C_SRC= netspade.c packet_resp_canceller.c spade_report.c \
  $(SPADE_C_SRC)

BASIS_SPADE_H_SRC= spade_features.h spade_prob_table_types.h
SPADE_H_SRC= $(BASIS_SPADE_H_SRC) anomscore_surveyer.h \
  dll_double.h ll_double.h spade_event.h \
  score_calculator.h spade_enviro.h spade_prob_table.h \
  spade_state.h score_mgr.h strtok.h event_recorder.h \
  thresh_adapter.h thresh_adviser.h score_info.h spade_output.h
NETSPADE_H_SRC= netspade.h netspade_features.h  packet_resp_canceller.h \
  spade_report.h $(SPADE_H_SRC)

spade: plugin install

plugin: snort-plugin
snort-plugin: spp_spade.c spp_spade.h install

spp_spade.c: snort_spade.c $(NETSPADE_C_SRC)
	cp snort_spade.c spp_spade.c
	grep -v -h '#include "' $(NETSPADE_C_SRC) >> spp_spade.c
	perl -pi -e 's/\044Id([:\044])/Id\1/' spp_spade.c
	perl -pi -e 's/ params\.h/ spp_spade.h/g' spp_spade.c

spp_spade.h: snort_spade.h $(NETSPADE_H_SRC)
	./merge_headers.pl snort_spade.h $(NETSPADE_H_SRC) > spp_spade.h
	perl -pi -e 's/ params\.h/ spp_spade.h/g' spp_spade.h
	perl -pi -e 's/\044Id([:\044])/Id\1/' spp_spade.h

install: spp_spade.c spp_spade.h
	cp spp_spade.c spp_spade.h $(INSTALL_DIR);
