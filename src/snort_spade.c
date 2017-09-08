/*********************************************************************
Spade, a Snort preprocessor plugin to report unusual packets
Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
copyright (c) 2002 by Silicon Defense (http://www.silicondefense.com/)

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.  

Spade description:

SPADE, the Statistical Packet Anomaly Detection Engine, is a Snort
preprocessor plugin to report packets that are unusual for your network. 
Port scans and probes tend to be unusual, so this will tend to report them
(as well as some benign packets that are simply uncommon).

Spade's home page: http://www.silicondefense.com/spice/

Please send complaints, kudos, and especially improvements and bugfixes to
hoagland@SiliconDefense.com. This is a research project and would love to
have your feedback.  It is still under active development and may change at
any time.

This file (snort_spade.c) is part of Spade v030125.1.  It makes netspade
available via a snort plugin.
*********************************************************************/

/* Internal version control: $Id: snort_spade.c,v 1.16 2003/01/23 17:41:21 jim Exp $ */
 
/*! \file snort_spade.c
 * \brief 
 *  snort_spade.c makes netspade available to snort
 * \ingroup snort_spade
 */

/*! \addtogroup snort_spade Netspade for Snort
 * \brief this group contains objects in the Snort binding to netspade
 * @{
*/

/*! \addtogroup libnetspade */

#define ENABLE_IDMEF 0


/* this should be in generators.h */
#ifndef SPADE_CLOSED_DESTPORT_USED
#define     SPADE_CLOSED_DESTPORT_USED   1
#define     SPADE_NONLIVE_DEST_USED   3
#define     SPADE_SRC_ODD_DESTPORT_USED   4
#define     SPADE_SRC_ODD_TYPECODE_USED   5
#define     SPADE_SRC_ODD_PORTDEST_USED   6
#endif
 
#include "snort.h"
#include "plugbase.h"
#include "generators.h"
#include "util.h"
#include "parser.h"
#include "log.h"
#include "detect.h"
#if ENABLE_IDMEF
#include "../output-plugins/spo_idmef.h"
#endif
#include "packets.h"
#include "spp_spade.h"
#include <string.h>
#include <stdarg.h>
#include <signal.h>

/** external globals from parser.c **/
extern char *file_name;
extern int file_line;

static void SpadeReportAnom(void *context,spade_report *rpt);
static void SpadeReportThreshChanged(void *context, char *id,char *mess, int using_corrscore);
static void SnortSpadeMsgFn(spade_message_type msg_type,const char *msg);

/// our instance of netspade
netspade *spade;

#define DEST_NOWHERE 0
#define DEST_ALERT_FACILITY 1
#define DEST_LOG_FACILITY 2
#define DEST_IDMEF_FACILITY 4

/// where to send spade alerts
int spade_alert_dest= DEST_ALERT_FACILITY;
/// where to send spade threshold adjusted messages
int spade_adj_dest= DEST_ALERT_FACILITY;

/// the bigger the number, the more debuging statements that are active
int as_debug= 0; 

/// is threshold adapting enabled?
int adapt_active= 0;
/// the number of detectors that have been enabled
int num_detectors= 0;
/// how many packets has Snort passed to us
int pkt_count= 0;

/*************/

/* A call to this function needs to be added to plugbase.c somehow */
void SetupSpade()
{
    /* link the preprocessor keyword list to the init functions in 
       the preproc list to arrange for modules to run when specified */
    RegisterPreprocessor("spade", SpadeInit);
    RegisterPreprocessor("spade-homenet", SpadeHomenetInit);
    RegisterPreprocessor("spade-detect", SpadeDetectInit);
    RegisterPreprocessor("spade-stats", SpadeStatInit);
    RegisterPreprocessor("spade-threshlearn", SpadeThreshadviseInit); /* for backwards compatability */
    RegisterPreprocessor("spade-threshadvise", SpadeThreshadviseInit);
    RegisterPreprocessor("spade-adapt", SpadeAdaptInit);
    RegisterPreprocessor("spade-adapt2", SpadeAdapt2Init);
    RegisterPreprocessor("spade-adapt3", SpadeAdapt3Init);
    RegisterPreprocessor("spade-survey", SpadeSurveyInit);

    if (as_debug) printf("Preprocessor: Spade is setup...\n");
}



/*========================================================================*/
/*========================= Spade core routines ==========================*/
/*========================================================================*/

/* Spade core init function:
     set up netspade, recover, register the signal handler,
     register the preprocessor function */
void SpadeInit(u_char *argsstr)
{
    int prob_mode=3,checkpoint_freq=50000,recover;
    double init_thresh= -1;
    char statefile[401]= "spade.rcv";
    char outfile[401]= "-";
    int use_corrscore= 0;
    char dest[11]= "alert";
    char adjdest[11]= "\0";
    char xsips[401]="",xdips[401]="",xsports[401]="",xdports[401]="";
    void *args[12];

    args[0]= &init_thresh;
    args[1]= &statefile;
    args[2]= &outfile;
    args[3]= &prob_mode;
    args[4]= &checkpoint_freq;
    args[5]= &use_corrscore;
    args[6]= &dest;
    args[7]= &adjdest;
    args[8]= &xsips;
    args[9]= &xdips;
    args[10]= &xsports;
    args[11]= &xdports;
    fill_args_space_sep(argsstr,"d:thresh;s400:statefile;s400:logfile;"
            "i:probmode;i:cpfreq;b:-corrscore,corrscore;s10:dest;s10:adjdest;"
            "s400:Xsips,Xsip,xsips;s400:Xdips,Xdip,xdips;"
            "s400:Xsports,Xsport,xsports;s400:Xdports,Xdport,xdports",args,SnortSpadeMsgFn);

    if (as_debug) printf("statefile=%s; logfile=%s; cpfreq=%d\n",statefile,outfile,checkpoint_freq);

    LogMessage("Spade is enabled\n");
    recover= strcmp(statefile,"0") && strcmp(statefile,"/dev/null");

    if (recover) {
        spade= new_netspade_from_statefile(statefile,SnortSpadeMsgFn,as_debug,&recover);
        if (recover)
            LogMessage("    Spade state initialized to what is in %s\n",statefile);
        else
            LogMessage("    Could not load Spade state from %s\n",statefile);
    }

    if (!recover) {
        spade= new_netspade(SnortSpadeMsgFn,as_debug);
        LogMessage("    Spade state initialized to a clean slate (no prior knowledge)\n");
    }
    if (spade == NULL) {
        FatalError("Spade initialization failed: out of memory!");
    }

    netspade_set_checkpointing(spade,statefile,checkpoint_freq);
    LogMessage("    Spade will record its state to %s after every %d updates\n",statefile,checkpoint_freq);
    netspade_set_output_file(spade,outfile);
    LogMessage("    Spade's log is %s\n",outfile);

    if (!strcmp(dest,"log")) {
        LogMessage("    Spade reports will go to the log facility\n");
        spade_alert_dest= DEST_LOG_FACILITY;
    } else if (!strcmp(dest,"both")) {
        LogMessage("    Spade reports will go to both the alert and log facility\n");
        spade_alert_dest= DEST_ALERT_FACILITY|DEST_LOG_FACILITY;
#if ENABLE_IDMEF
    } else if (!strcmp(dest,"spo_idmef")) {
        LogMessage("    Spade reports will go directly to the IDMEF facility\n");
        spade_alert_dest= DEST_IDMEF_FACILITY;
#endif
    } else {
        if (strcmp(dest,"alert"))
            ErrorMessage("Spade: dest=%s not recognized, using dest=alert\n",dest);
        LogMessage("    Spade reports will go to the alert facility\n");
        spade_alert_dest= DEST_ALERT_FACILITY;
    }
    if (adjdest[0] == '\0') {
        spade_adj_dest= spade_alert_dest;
    } else {
        if (!strcmp(adjdest,"log")) {
            LogMessage("    Spade threshold adjusted reports will go to the log facility\n");
            spade_adj_dest= DEST_LOG_FACILITY;
        } else if (!strcmp(adjdest,"both")) {
            LogMessage("    Spade threshold adjusted reports will go to both the alert and log facility\n");
            spade_adj_dest= DEST_ALERT_FACILITY|DEST_LOG_FACILITY;
        } else if (!strcmp(adjdest,"none")) {
            LogMessage("    Spade threshold adjusted reports will not be reported\n");
            spade_adj_dest= DEST_NOWHERE;
        } else {
            if (strcmp(adjdest,"alert"))
                ErrorMessage("Spade: adjdest=%s not recognized, using adjdest=alert\n",adjdest);
            LogMessage("    Spade threshold adjusted reports will go to the alert facility\n");
            spade_adj_dest= DEST_ALERT_FACILITY;
        }
    }
    netspade_set_callbacks(spade,NULL,SpadeReportAnom,((spade_adj_dest == DEST_NOWHERE) ? NULL : SpadeReportThreshChanged),(event_native_copier_t)ClonePacket,(event_native_freer_t)FreePacket);
    
    netspade_add_rpt_excludes(spade,xsips,xdips,xsports,xdports);
    
    /* at this point we don't know if there are any spade-detect lines, but
       if this looks like the old form of this line (corrscore, thresh, or
       probmode is specified).  Our approximation of specified is variance
       from defaults.  Because our defaults are the same as netspade's
       default detection mode, if the user did explicitly set things to the
       default and provides no spade-detect line, the default detector will
       be enabled in netspade automatically with the configuration we want. */
       
    if (prob_mode != 3 || init_thresh != -1 || use_corrscore) {
        char init_detect_str[100];
        /* backwards compatability mode */
        if (prob_mode > 4 || prob_mode < 0) {
            ErrorMessage("Warning: Spade probabity mode %d undefined, using #3 instead",prob_mode);
            prob_mode= 3;
        }
        if (as_debug) printf("thresh=%f; probmode=%d; corrscore=%d\n",init_thresh,prob_mode,use_corrscore);

        sprintf(init_detect_str,"id=default relscore=0  corrscore=0 thresh=%f probmode=%d corrscore=%d",
                                                init_thresh,prob_mode,use_corrscore);
        netspade_new_detector(spade,init_detect_str);
        
        LogMessage("    default detector enabled with: %s\n",init_detect_str);
        num_detectors++;

        if (as_debug) netspade_print_detector_config_details(spade,stdout,"default");
    }       
    

   /* Set the preprocessor function into the function list */
    AddFuncToPreprocList(PreprocSpade);
    AddFuncToCleanExitList(SpadeCatchSig,NULL);
    AddFuncToRestartList(SpadeCatchSig,NULL);
}


/*========================================================================*/
/*========================= SpadeHomenet module ==========================*/
/*========================================================================*/

/* Set the Spade homenet */

/* snort config file line:
    preprocessor spade-homenet: {<network>}
    where <network> is a network in CIDR notation (address/numbits)
                       or an IP address */
                                                        
/* Spade homenet init function:
     set up the homenet list */
void SpadeHomenetInit(u_char *args)
{
    if (spade == NULL) FatalError("Please initialize Spade with the "
        "'preprocessor spade:' line before listing spade-homenet: %s(%d)\n",
        file_name,file_line);

    netspade_set_homenet_from_str(spade,args);
    LogMessage("    Spade homenet set to: %s\n",args);
}



/*========================================================================*/
/*======================== SpadeDetect module ==========================*/
/*========================================================================*/

/* enable a Spade detector */                                                     
void SpadeDetectInit(u_char *args)
{
    char *id;
    if (spade == NULL) FatalError("Please initialize Spade with the "
        "'preprocessor spade:' line before listing spade-detect: %s(%d)\n",
        file_name,file_line);

    id= netspade_new_detector(spade,args);
    LogMessage("    detector %s enabled with: %s\n",id,args);
    num_detectors++;

    if (as_debug) netspade_print_detector_config_details(spade,stdout,id);
}


/*========================================================================*/
/*=========================== SpadeStat module ===========================*/
/*========================================================================*/

/* Whenever SpadeCatchSig is invoked, this module arranges for certain
   specified statistics to be written to the log file.  The available
   statistics depend on what is recorded in the tree, which depends on the
   probability measure used.  There is no good way to have more granularity
   at present. */

/* snort config file line:
    preprocessor spade-stats: {<stat-option>}
    where <stat-option> is one of:
      "entropy" (to display the known entropies and conditional entropies)
      "uncondprob" (to display the known non-0 simple (joint) probabilities)
      "condprob" (to display the known non-0 conditional (joint)
probabilities) */
                                                        
void SpadeStatInit(u_char *args)
{
    if (spade == NULL) FatalError("Please initialize Spade with the "
        "'preprocessor spade:' line before listing spade-stat: %s(%d)\n",
        file_name,file_line);

    /* parse the argument list from the rules file */
    netspade_set_output_stats_from_str(spade,args);
    LogMessage("    Spade will report certain observation statistics to its log file: %s\n",args);
}



/*========================================================================*/
/*======================== SpadeThreshadvise module =======================*/
/*========================================================================*/

/* Given a packet count and a length of time, this module reports a reporting
   threshold that would have been effective in producing that number of alerts
   in that time interval.  The idea is that one might use this as a threshold
   for future runs.  The module quietly watches the network for the length of
   time, adding events to the tree and calculating anomaly scores.  When the
   time period is up, the module calls exit() after reporting the top anomaly
   scores seen to the log file. */
   
   /* Spade threshold learning module init function:
     set up threshold learning module per args */
void SpadeThreshadviseInit(u_char *args)
{
    char *id;
    if (spade == NULL) FatalError("Please initialize Spade with the "
        "'preprocessor spade:' line before listing spade-threshadvise (a.k.a. "
        "spade-threshlearn): %s(%d)\n",
        file_name,file_line);
    
    id=netspade_setup_detector_advise_from_str(spade,args);

    LogMessage("    Spade threshold advising inited for %s: %s\n",id,args);
}

/*========================================================================*/
/*=========================== SpadeAdapt module ==========================*/
/*========================================================================*/

/* Given a report count target and a length of time, this module tries to keep
   the reporting threshold at a level that would produce that number of alerts
   in that time interval based on what was observed in the last interval.  To
   support this, a list of the most anomalous scores seen in the current
   interval is maintained.  At the end of the interval, an ideal threshold is
   calculated based on the interval's scores.  This is combined linearly with
   the current threshold to produce the threshold for the next interval.  As a
   default option, the interval can implemented in terms of a count of packets,
   where this count is the average number of packets seen during the specified
   time interval length; this tends to make the transitions more smooth and
   reliable since a more constant number of anomaly scores is used in finding
   the topmost anamolous ones. */

void SpadeAdaptInit(u_char *args)
{
    char *id;
    if (spade == NULL) FatalError("Please initialize Spade with the "
        "'preprocessor spade:' line before listing spade-adapt: %s(%d)\n",
        file_name,file_line);
    if (adapt_active && num_detectors < 2) {
        ErrorMessage("Spade threshold adapting repeatedly specified, "
            "ignoring later specification: %s(%d)\n",file_name,file_line);
        return;
    }
    adapt_active= 1;

    /* parse the argument list from the rules file */
    id= netspade_setup_detector_adapt_from_str(spade,1,args);
    
    LogMessage("    Spade adapt mode 1 inited for %s: %s\n",id,args);

    if (as_debug) netspade_print_detector_config_details(spade,stdout,id);
}


/*========================================================================*/
/*========================== SpadeAdapt2 module ==========================*/
/*========================================================================*/

/* Given an hourly alert target count (or target fraction) and a length of
   time, this module tries to keep the reporting threshold at a level that
   would produce that number of alerts (or fraction of total reports) in an
   hour based on what has been observed in the past.  When the report threshold
   is updated, it is based in equal parts on observations from the short term,
   middle term, and long term (at least for these that have been observed). 
   The user can specify the time period for observations, the number of those
   that make up the short term (NS), the number of short terms that make up the
   medium term (NM), and the number of medium terms that make up the long term
   (NL).  The short term component of the threshold is defined to be the
   average of the kth and (k+1)st highest anomaly scores in the last NS
   complete periods of observation, where k is number of anamoly reports that
   should occur in the observation period assuming a uniform rate.  The middle
   term component is the average of the last NM special short term components. 
   The special short term components are the ones that are multiples of NS if
   labeled with the number of observation periods that had completed when it
   was calculated (i.e., #NS, #2NS, #3NS, etc.); these have the property that
   they are based entirely on distinct measurements.  The long term component
   is based on the last NL medium term componenets, including the current one. 
   For each of the components, if there have been less than the specified
   number of constituant parts (but there has been at least one complete one),
   what is observed thus far is used.  To accomadate the varying rates of
   packets fairly, the observation period is based on a count of packets.  This
   count is the product of the specified observation period and the average
   packet rate.
*/

void SpadeAdapt2Init(u_char *args)
{
    char *id;
    
    if (spade == NULL) FatalError("Please initialize Spade with the "
        "'preprocessor spade:' line before listing spade-adapt2: %s(%d)\n",
        file_name,file_line);
    if (adapt_active && num_detectors < 2) {
        ErrorMessage("Spade threshold adapting repeatedly specified, "
            "ignoring later specification: %s(%d)\n",file_name,file_line);
        return;
    }
    adapt_active= 2;

    /* parse the argument list from the rules file */
    id= netspade_setup_detector_adapt_from_str(spade,2,args);
    
    LogMessage("    Spade adapt mode 2 inited for %s: %s\n",id,args);

    if (as_debug) netspade_print_detector_config_details(spade,stdout,id);
}

/*========================================================================*/
/*========================== SpadeAdapt3 module ==========================*/
/*========================================================================*/

/* Given an hourly alert target count (or target fraction) and a length of
   time, this module tries to keep the reporting threshold at a level that
   would produce that number of alerts (or fraction of total reports) in an
   hour based on what has been observed in the past.  ...
*/

void SpadeAdapt3Init(u_char *args)
{
    char *id;
    
    if (spade == NULL) FatalError("Please initialize Spade with the "
        "'preprocessor spade:' line before listing spade-adapt3: %s(%d)\n",
        file_name,file_line);
    if (adapt_active && num_detectors < 2) {
        ErrorMessage("Spade threshold adapting repeatedly specified, "
            "ignoring later specification: %s(%d)\n",file_name,file_line);
        return;
    }
    adapt_active= 3;

    /* parse the argument list from the rules file */
    id= netspade_setup_detector_adapt_from_str(spade,3,args);

    LogMessage("    Spade adapt mode 3 inited for %s: %s\n",id,args);
}


/*========================================================================*/
/*========================== SpadeSurvey module ==========================*/
/*========================================================================*/

/* This module surveys the anomoly scores observed across periods of time
and reports this to a specified survey file.  The period #, the packet
count, the median score, the 90th percentile score, and the 99th percentile
score are recorded to the file in tab-delinated format.  Interpolation is
used between scores if there is no score at exactly the position implied by
the percentile. */

/* efficiency note:  This use linked list to represent the observed anomoly
   scores.  While it is necessary to maintain all these scores (the current
   worst score might end up being the 99th percentile), a different
   representation (order stat tree?) should be used if the packet count gets
   high.  */

void SpadeSurveyInit(u_char *args)
{
    char *id;
    
    if (spade == NULL) FatalError("Please initialize Spade with the "
        "'preprocessor spade:' line before listing spade-survey: %s(%d)\n",
        file_name,file_line);

    /* parse the argument list from the rules file */
    id= netspade_setup_detector_survey_from_str(spade,args);

    LogMessage("    Spade survey mode inited for %s: %s\n",id,args);

    if (as_debug) netspade_print_detector_config_details(spade,stdout,id);
}


/*********************************************************************/

/* Spade core routine that is called with each packet; be efficient! */
void PreprocSpade(Packet *p)
{
    spade_event pkt;
    pkt_count++;
    
    if (p == NULL || p->iph == NULL) return; /* netspade only looks at IP packets for now */
    
    pkt.native= p;
    pkt.time= (time_t)p->pkth->ts.tv_sec;
    
    pkt.origin= PKTORIG_TOP;
    pkt.fldval[IPPROTO]= p->iph->ip_proto;
    
    switch (pkt.fldval[IPPROTO]) { /* protocol-specific processing */
    case IPPROTO_TCP:
        if (p->tcph == NULL) return;
        pkt.fldval[TCPFLAGS]= p->tcph->th_flags;
        break;
    case IPPROTO_UDP:
        if (p->udph == NULL) return;
        break;
    case IPPROTO_ICMP:
        if (p->icmph == NULL) return;
        pkt.fldval[ICMPTYPE]= p->icmph->type;
        pkt.fldval[ICMPTYPECODE]= (p->icmph->type << 8) | p->icmph->code;
        break;
    default:;
    }

    pkt.fldval[SIP]= ntohl(p->iph->ip_src.s_addr);
    pkt.fldval[DIP]= ntohl(p->iph->ip_dst.s_addr);
    pkt.fldval[SPORT]= p->sp;
    pkt.fldval[DPORT]= p->dp;
    //pkt.fldval[TTL]= p->iph->ip_ttl;
    //pkt.fldval[WIN] = p->tcph->th_win;

    netspade_new_pkt(spade,&pkt);
    
    if ((p->orig_iph != NULL) && (p->icmph != NULL) && (p->icmph->type == 3)) {
        pkt.origin= PKTORIG_UNRCH;

        pkt.fldval[IPPROTO]= p->orig_iph->ip_proto;
        
        switch (pkt.fldval[IPPROTO]) { /* protocol-specific processing */
        case IPPROTO_TCP:
            if (p->orig_tcph == NULL) return;
            pkt.fldval[TCPFLAGS]= p->orig_tcph->th_flags;
            break;
        case IPPROTO_UDP:
            if (p->orig_udph == NULL) return;
            break;
        case IPPROTO_ICMP:
            if (p->orig_icmph == NULL) return;
            //pkt.fldval[ICMPTYPE]= p->orig_icmph->type;
            //pkt.fldval[ICMPTYPECODE]= (p->orig_icmph->type << 8) | p->orig_icmph->code;
            break;
        default:;
        }
    
        pkt.fldval[SIP]= ntohl(p->orig_iph->ip_src.s_addr);
        pkt.fldval[DIP]= ntohl(p->orig_iph->ip_dst.s_addr);
        pkt.fldval[SPORT]= p->orig_sp;
        pkt.fldval[DPORT]= p->orig_dp;

        netspade_new_pkt(spade,&pkt);
    }
}


/*********************************************************************/
/*********************************************************************/

/* our netspade callback for when there is something anomalous to report */
static void SpadeReportAnom(void *context,spade_report *rpt) {
    char message[256];
    Event event;
    u_int32_t id;
    spade_event *pkt= rpt->pkt;
    Packet *p= pkt->native;
    double score= spade_report_mainscore(rpt);

    sprintf(message,"Spade: %s: %s: %.4f",rpt->detect_type_str,rpt->scope_str,score);
    
    switch (rpt->detect_type) {
    case SPADE_DR_TYPE_CLOSED_DPORT: id= SPADE_CLOSED_DESTPORT_USED; break;
    case SPADE_DR_TYPE_DEAD_DEST: id= SPADE_NONLIVE_DEST_USED; break;
    case SPADE_DR_TYPE_ODD_DPORT: id= SPADE_SRC_ODD_DESTPORT_USED; break;
    case SPADE_DR_TYPE_ODD_TYPECODE: id= SPADE_SRC_ODD_TYPECODE_USED; break;
    case SPADE_DR_TYPE_ODD_PORTDEST: id= SPADE_SRC_ODD_PORTDEST_USED; break;
    default : id= 0;
    }
    SetEvent(&event, GENERATOR_SPP_SPADE, id,
            1, 0, 0, 0);

#if ENABLE_IDMEF
    if (spade_alert_dest & DEST_IDMEF_FACILITY)
        SpadeIDMEFDirect(p, rpt->detect_type_str, NULL, &event, score, rpt->detectorid);
#endif
    if (spade_alert_dest & DEST_ALERT_FACILITY)
        CallAlertFuncs(p, message, NULL, &event);
    if (spade_alert_dest & DEST_LOG_FACILITY)
        CallLogFuncs(p, message, NULL, &event);
}   

/* our netspade callback for when there the threshold is adjusted */
static void SpadeReportThreshChanged(void *context,char *id,char *mess,int using_corrrscore) {
    char message[100];
    Event event;

    sprintf(message,"Spade: id=%s: %s",id,mess);

    SetEvent(&event, GENERATOR_SPP_SPADE,
            SPADE_ANOM_THRESHOLD_ADJUSTED, 1, 0, 0, 0);
    if (spade_adj_dest & DEST_ALERT_FACILITY)
        CallAlertFuncs(NULL, message, NULL, &event);
    if (spade_adj_dest & DEST_LOG_FACILITY)
        CallLogFuncs(NULL, message, NULL, &event);
}

static void SnortSpadeMsgFn(spade_message_type msg_type,const char *msg) {
    char buf[MAX_SPADE_MSG_LEN+1];
    const char *newmsg;
    
    if (!pkt_count)  { // must be a message originating from configuration activity; include conf file name and line #
        switch (msg_type) {
        case SPADE_MSG_TYPE_FATAL:
        case SPADE_MSG_TYPE_WARNING:
        case SPADE_MSG_TYPE_DEBUG:
        {
            int len= strlen(msg);
            strncpy(buf,msg,MAX_SPADE_MSG_LEN);
            snprintf(buf+len,MAX_SPADE_MSG_LEN-len,": %s(%d)\n",file_name,file_line);
            newmsg= (const char *)buf;
            break;
        }
        default:
            newmsg= msg;
            break;
        }
    } else {
        newmsg= msg;
    }
        
    switch (msg_type) {
    case SPADE_MSG_TYPE_FATAL:
        FatalError("%s", newmsg);
        break;
    case SPADE_MSG_TYPE_WARNING:
        ErrorMessage("%s", newmsg);
        break;
    default:
        LogMessage("%s", newmsg);
        break;
    }
}


/*****************************************************
 * Called on signals
 *****************************************************/
void SpadeCatchSig(int signal,void *arg) {
    if (signal == SIGUSR1) {
        LogMessage("Spade got SIGUSR1, refreshing its disk state");
        netspade_dump(spade);
    } else if (signal == SIGQUIT || signal == SIGHUP || signal == SIGINT) {
        LogMessage("Spade got shutdown signal, cleaning up");
        netspade_cleanup(spade);
    }
}

