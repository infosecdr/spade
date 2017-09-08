/*********************************************************************
netspade.c, distributed as part of Spade v030125.1
Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
copyright (c) 2002 by Silicon Defense (http://www.silicondefense.com/)
Released under GNU General Public License, see the COPYING file included
with the distribution or http://www.silicondefense.com/spice/ for details.

Please send complaints, kudos, and especially improvements and bugfixes to
hoagland@SiliconDefense.com.  As described in GNU General Public License, no
warranty is expressed for this program.
*********************************************************************/

/*! \file netspade.c
 * \ingroup netspade_layer
 * \brief 
 *  netspade.c contains a "class" netspade which applies Spade to a network
 */

/*! \addtogroup libnetspade Netspade Library
 * \brief This group contains objects the objects in libnetspade, which
 * applies Spade to the network packets.
  @{
*/
/*! \addtogroup libspade */
/*@}*/

/*! \addtogroup netspade_layer Netspade Layer
 * \brief This group contains objects the objects specific to Netspade, which
 * applies Spade to the network packets.
 * \ingroup libnetspade
  @{
*/

#include "netspade.h"
#include "spade_features.h"
#include "spade_event.h"
#include "spade_state.h"
#include "score_calculator.h"
#include "score_mgr.h"
#include "event_recorder.h"
#include "strtok.h"

#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>

/// an array mapping a netspade feature number to its name
const char *featurenames[NETSPADE_NUM_FEATURES+1]= {"sip","dip","sport","dport","proto","tcpflags","icmptype","icmptype+code",NULL};

#define IS_TCP          EVENT_CONDITION_NUM(1) ///< is the packet TCP?
#define IS_UDP          EVENT_CONDITION_NUM(2) ///< is the packet UDP?
#define IS_ICMP         EVENT_CONDITION_NUM(3) ///< is the packet ICMP?
#define IS_UNRCHTCP     EVENT_CONDITION_NUM(5) ///< is the packet from inside a unreachable packet and is TCP?
#define IS_UNRCHUDP     EVENT_CONDITION_NUM(6) ///< is the packet from inside a unreachable packet and is UDP?
#define IS_UNRCHICMP    EVENT_CONDITION_NUM(7) ///< is the packet from inside a unreachable packet and is ICMP?
#define SYNONLY         EVENT_CONDITION_NUM(9) ///< is the packet TCP and only have the SYN flag set (among the 6 flags)?
#define NORMAL_RST      EVENT_CONDITION_NUM(10) ///< is the packet TCP and a normal RST?
#define SYNACK          EVENT_CONDITION_NUM(11) ///< is the packet TCP and only have the SYN and ACK flags set?
#define WEIRDFLAGS      EVENT_CONDITION_NUM(12) ///< is the packet TCP and have an unusual combination of flags?
#define SETUPFLAGS      EVENT_CONDITION_NUM(13) ///< is the packet TCP and have flags associated with connection setup?
#define ESTFLAGS        EVENT_CONDITION_NUM(14) ///< is the packet TCP and have flags associated with the established phase of a connection?
#define TEARDOWNFLAGS   EVENT_CONDITION_NUM(15) ///< is the packet TCP and have flags associated with connection teardown?
#define SIP_IN_HOMENET      EVENT_CONDITION_NUM(17) ///< is the source IP of the packet in the homenet?
#define SIP_NOT_IN_HOMENET  EVENT_CONDITION_NUM(18) ///< is the source IP of the packet not in the homenet?
#define DIP_IN_HOMENET      EVENT_CONDITION_NUM(19) ///< is the dest IP of the packet in the homenet?
#define DIP_NOT_IN_HOMENET  EVENT_CONDITION_NUM(20) ///< is the dest IP of the packet not in the homenet?
#define ICMPNOTERR      EVENT_CONDITION_NUM(21) ///< is the packet an ICMP but not indicating an error?
#define ICMPERR         EVENT_CONDITION_NUM(22) ///< is the packet an ICMP and not indicating an error?
#define REPR_PKT        EVENT_CONDITION_NUM(23) ///< does this packet fit in the minority of packets that can be considered representative of the sources of packets?
#define UDPRESP         EVENT_CONDITION_NUM(25) ///< might the packet be a response to a UDP packet?
#define ICMPRESP        EVENT_CONDITION_NUM(26) ///< might the packet be a response to a ICMP packet?
#define SYNRESP         EVENT_CONDITION_NUM(27) ///< might the packet be a response to a SYN packet?
#define ESTRESP         EVENT_CONDITION_NUM(29) ///< might the packet be a response to a ESTFLAGS packet?
#define TEARDOWNRESP    EVENT_CONDITION_NUM(30) ///< might the packet be a response to a TEARDOWN packet?
#define SETUPRESP       EVENT_CONDITION_NUM(31) ///< might the packet be a response to a SETUP packet?

#define HOMENET_CONDS (CONDS_PLUS_3CONDS(SIP_IN_HOMENET,SIP_NOT_IN_HOMENET,DIP_IN_HOMENET,DIP_NOT_IN_HOMENET))
#define TCPFLAG_CONDS (CONDS_PLUS_6CONDS(SYNACK,SYNONLY,NORMAL_RST,WEIRDFLAGS,ESTFLAGS,TEARDOWNFLAGS,SETUPFLAGS))
#define REPR_PKT_CONDS (CONDS_PLUS_3CONDS(SETUPFLAGS,TEARDOWNFLAGS,IS_UDP,IS_ICMP))

#define SYNRESP_CONDS (CONDS_PLUS_2CONDS(SYNACK,NORMAL_RST,IS_UNRCHTCP))
#define ESTRESP_CONDS (CONDS_PLUS_2CONDS(ESTFLAGS,TEARDOWNFLAGS,IS_UNRCHTCP))
#define TEARDOWNRESP_CONDS (CONDS_PLUS_CONDS(TEARDOWNFLAGS,IS_UNRCHTCP))
#define SETUPRESP_CONDS (CONDS_PLUS_CONDS(SYNRESP_CONDS,ESTRESP_CONDS))
#define UDPRESP_CONDS (CONDS_PLUS_CONDS(IS_UDP,IS_UNRCHUDP))
#define ICMPRESP_CONDS (CONDS_PLUS_CONDS(ICMPNOTERR,IS_UNRCHICMP))


#define PKT_IP_IN_HOMENET_LIST(pkt,fldname,list,res) {\
    res= 0; \
    if (list != NULL) { \
        ll_net *home; \
        for (home= list; home != NULL; home= home->next) { \
            if ((pkt->fldval[fldname] & home->netmask) == home->netaddr) { \
                res= 1; \
                break; \
            } \
        } \
    } else { \
        res= 1; \
    } \
}

static void init_netspade_empty(netspade *self,spade_msg_fn msg_callback, int debug_level);
static netspade_detector *acquire_detector_for_id(netspade *self, char *id);
static netspade_detector *detector_for_id(netspade *self, char *id);
static void netspade_detector_dump(netspade_detector *detector);
static void netspade_detector_cleanup(netspade_detector *detector);
static void netspade_update_conds_to_calc(netspade *self);
static event_condition_set netspade_nonstore_conds(netspade *self);
static event_condition_set flipped_homenet_conds(event_condition_set orig);
static int do_checkpointing(netspade *self);
static int do_recovery(netspade *self, char *statefile);
static void threshold_was_exceeded(void *context, void *mgrref, spade_event *pkt, score_info *score);
static void canceller_status_report(void *context, spade_report *rpt, port_status_t status);
static void threshold_was_adjusted(void *context, void *mgrref);
static void netspade_add_net_to_homenet(netspade *self, char *net_str);
static char *scope_str_for_cond(event_condition_set cond);
static void process_netspade_xarg(netspade *self, char *str, features feat, xarg_type_t type);
static void process_detector_xargs(netspade_detector *d, char *xsips, char *xdips, char *xsports, char *xdports);
static void process_detector_xarg(netspade_detector *d, char *str, features feat, xarg_type_t type);
static void process_detector_xarg(netspade_detector *d,char *str,features feat,xarg_type_t type);
static xfeatval_link *process_xarg(char *str,features feat,xarg_type_t type,spade_msg_fn msg_callback,xfeatval_link **tail);
static xfeatval_link *new_xfeatval_link(features feat, xarg_type_t type, char *val);
static int pkt_is_excluded(xfeatval_link *list,spade_event *pkt);
static int cidr_to_netmask(char *str, u32 *netip, u32 *netmask);
static void file_print_conds(FILE *file,event_condition_set conds);

void init_netspade(netspade *self,spade_msg_fn msg_callback, int debug_level) {
    init_netspade_empty(self,msg_callback,debug_level);
}

static void init_netspade_empty(netspade *self,spade_msg_fn msg_callback, int debug_level) {
    self->msg_callback= (msg_callback == NULL) ? default_spade_msg_fn : msg_callback;
    self->debug_level= debug_level;

    self->detectors= NULL;
    self->detectors_tail= NULL;
    
    self->homelist_head= NULL;
    self->homelist_tail= NULL;
    
    self->checkpoint_file= NULL;
    self->checkpoint_freq= -1;

    self->records_since_checkpoint=0;
    self->last_time_forwarded= (time_t)0;
    
    self->callback_context= NULL;
    self->exc_callback= NULL;
    self->adj_callback= NULL;
    self->pkt_native_copier_callback= NULL;
    self->pkt_native_freer_callback= NULL;

    self->rpt_exclude_list= NULL;
    
    init_event_recorder(&self->recorder);
    self->recorder_needed_conds= 0;
    self->nonstore_conds= 0;
    self->conds_to_calc= 0;
    
    self->stats_to_print= 0;
    self->outfile= NULL;
    
    self->detector_id_nonce= 0;
    self->total_pkts= 0;
}

int init_netspade_from_statefile(netspade *self,char *statefile,spade_msg_fn msg_callback, int debug_level) {
    init_netspade_empty(self,msg_callback,debug_level);
    return do_recovery(self,statefile);
}

netspade *new_netspade(spade_msg_fn msg_callback, int debug_level) {
    netspade *new= (netspade *)malloc(sizeof(netspade));
    init_netspade(new,msg_callback,debug_level);
    return new;
}

netspade *new_netspade_from_statefile(char *statefile,spade_msg_fn msg_callback, int debug_level,int *succ) {
    netspade *new= (netspade *)malloc(sizeof(netspade));
    *succ= init_netspade_from_statefile(new,statefile,msg_callback,debug_level);
    return new;
}

void netspade_set_callbacks(netspade *self,void *context,netspade_exc_callback_t exc_callback,netspade_adj_callback_t adj_callback,event_native_copier_t pkt_native_copier_callback,event_native_freer_t pkt_native_freer_callback) {
    self->callback_context= context;
    self->exc_callback= exc_callback;
    self->adj_callback= adj_callback;
    self->pkt_native_copier_callback= pkt_native_copier_callback;
    self->pkt_native_freer_callback= pkt_native_freer_callback;
}

void netspade_set_checkpointing(netspade *self,char *checkpoint_file,int checkpoint_freq) {
    self->checkpoint_file= (checkpoint_file == NULL) ? NULL : strdup(checkpoint_file);
    self->checkpoint_freq= checkpoint_freq;
}

void netspade_set_homenet_from_str(netspade *self,char *homenet_str) {
    char *strcopy= (homenet_str == NULL) ? NULL : strdup(homenet_str);
    char *p= strcopy;
    int len;
    char oldchar,*term;
    if (strcopy == NULL) return;

    while (isspace((int)*p)) p++; /* kill leading whitepspace */
    if (*p == '[') {
        char *end;
        p++;
        end= strrchr(p, (int)']');
        if (end != NULL) *end = '\0'; /* null out the end-bracket */
    }
    while ((len= terminate_first_tok(p,", \t\n",&p,&oldchar)) > 0) {
        netspade_add_net_to_homenet(self,p);
        term= p+len;
        *term= oldchar;
        if (oldchar == '\0') { break; } /* Thanks Risto! */
        p= term+1;
    }

    free(strcopy);

    if (self->debug_level) {
        ll_net *n;
        struct in_addr net;
        (*self->msg_callback)(SPADE_MSG_TYPE_DEBUG,"Spade home nets are:\n");
        for (n=self->homelist_head; n != NULL; n=n->next) {
            net.s_addr= ntohl(n->netaddr);
            formatted_spade_msg_send(SPADE_MSG_TYPE_DEBUG,self->msg_callback,"\t%s with mask %lx\n",inet_ntoa(net),(u_long)ntohl(n->netmask));
        }
    }
}

void netspade_set_output_stats(netspade *self,int stats_to_print) {
    self->stats_to_print= stats_to_print;
}

void netspade_set_output_stats_from_str(netspade *self,char *str) {
    char *strcopy= strdup(str);
    char *head= strcopy;
    char oldchar;
    int len;
    char *term;
    
    self->stats_to_print= STATS_NONE;
    
    while ((len= terminate_first_tok(head,", \t\n",&head,&oldchar)) > 0) {
        if (!(strcmp(head,"entropy"))) {
            self->stats_to_print |= STATS_ENTROPY;
        } else if (!(strcmp(head,"condprob"))) {
            self->stats_to_print |= STATS_CONDPROB;
        } else if (!(strcmp(head,"uncondprob"))) {
            self->stats_to_print |= STATS_UNCONDPROB;
        } else {
            // warn
        }
        term= head+len;
        *term= oldchar;
        head= term+1;
    }
    free(strcopy);
}

int netspade_set_output(netspade *self,char *file,int stats_to_print) {
    self->outfile= strdup(file);
    self->stats_to_print= stats_to_print;
    return 1;
}

int netspade_set_output_file(netspade *self,char *file) {
    self->outfile= strdup(file);
    return 1;
}

void netspade_add_rpt_excludes(netspade *self,char *xsips,char *xdips,char *xsports,char *xdports) {
    process_netspade_xarg(self,xsports,SPORT,XARG_TYPE_UINT);
    process_netspade_xarg(self,xdips,DIP,XARG_TYPE_CIDR);
    process_netspade_xarg(self,xsips,SIP,XARG_TYPE_CIDR);
    process_netspade_xarg(self,xdports,DPORT,XARG_TYPE_UINT);
}

char *netspade_new_detector(netspade *self,char *str) {
    netspade_detector *new;
    char *strcopy= strdup(str);
    char *type;
    int calcboth;
    int minobs_prefix_len= -1,entropy_prefix_len=-1;
    int canceller_timeout_implication;
    event_condition_set cancel_homenet_conds;
    feature_list fla[4];
    char to[8]="home",from[8]="home",protocol[5]="tcp";
    char tcpflags[21]="synonly";
    char xsips[401]="",xdips[401]="",xsports[401]="",xdports[401]="";
    double thresh= 10000000;
    int wait=0;
    int relscore=1,minobs=0,probmode=3;
    int scalefreqmins=240;
    double scalefactor= 0.98363,scalecutoff= 0.18,scalehalflifehrs=-1;
    int reverse_reporting=0;
    double maxentropy= -1;
    void *args[30];
    char formatstr[500]="$i:wait;s50:id;i:minobs;"
                "i:scalefreq;d:scalefactor;d:scalecutoff;d:scalehalflife;"
                "s400:Xsips,Xsip,xsips;s400:Xdips,Xdip,xdips;"
                "s400:Xsports,Xsport,xsports;s400:Xdports,Xdport,xdports;"
                "b:revwaitrpt";
    char id[51]="\0";
    char defaultid[31];
    sprintf(defaultid,"%d",++self->detector_id_nonce);
    
    args[0]= &wait;
    args[1]= &id;
    args[2]= &minobs;
    args[3]= &scalefreqmins;
    args[4]= &scalefactor;
    args[5]= &scalecutoff;
    args[6]= &scalehalflifehrs;
    args[7]= &xsips;
    args[8]= &xdips;
    args[9]= &xsports;
    args[10]= &xdports;
    args[11]= &reverse_reporting;
    
    new= (netspade_detector *)malloc(sizeof(netspade_detector));
    new->parent= self;
    init_score_calculator_clear(&new->calculator,&self->recorder);
    new->store_conds= 0;
    new->scorecalc_conds= 0;
    new->thresh_exc_port_impl= PORT_UNKNOWN;
    PS_INIT_SET_WITH_STRONGER(new->port_report_criterea,PORT_UNKNOWN);
    new->cancel_closed_conds= EVENT_CONDITION_FALSE;
    new->cancel_open_conds= EVENT_CONDITION_FALSE;
    new->report_scope_str= NULL;
    new->exclude_broadcast_dip= 0;
    
    type= extract_str_arg_space_sep(strcopy,"type");

    if (type == NULL) type= "closed-dport";
    new->detect_type= SPADE_DR_TYPE_NUM4SHORT(type);
    new->report_detection_type= DEFAULT_DN_TYPE_FOR_DR_TYPE(new->detect_type); // may be overridden below
    
    switch (new->detect_type) {
    case SPADE_DR_TYPE_CLOSED_DPORT: {
        int corrscore=1;
        scalefactor= 0.96409; /* this detection type uses a different that normal scaling factor */
        minobs= -1;
        minobs_prefix_len= 0;
        
        new->thresh_exc_port_impl= PORT_PROBCLOSED;
        PS_INIT_SET_WITH_STRONGER(new->port_report_criterea,PORT_PROBCLOSED); /* override default default; this will be overriden if wait is set */
        
        args[12]= &protocol;
        args[13]= &to;
        args[14]= &tcpflags;
        args[15]= &thresh;
        args[16]= &relscore;
        args[17]= &probmode;
        args[18]= &corrscore;
        strcat(formatstr,";s4:protocol,proto;s7:to;s20:tcpflags;d:thresh;b:relscore;"
                          "i:probmode;b:-corrscore,corrscore");
        fill_args_space_sep(strcopy,formatstr,args,self->msg_callback);
            
        if (thresh == 10000000) thresh= relscore ? 0.85 : -1;
        if (minobs == -1) minobs= relscore ? 400 : 0;
        score_calculator_set_corrscore(&new->calculator,corrscore);

        fla[0].feat[0]= DIP; fla[0].feat[1]= DPORT;
        fla[0].feat[2]= SIP; fla[0].feat[3]= SPORT;
        switch (probmode) {
            case 0:
                fla[0].num= 1; fla[0].feat[0]= DIP;
                fla[1].num= 3; fla[1].feat[0]= SIP; fla[1].feat[1]= DPORT; fla[1].feat[2]= SPORT;
                fla[2].num= 2; fla[2].feat[0]= SPORT; fla[2].feat[1]= DPORT;
                fla[3].num= 3; fla[3].feat[0]= DIP; fla[3].feat[1]= SPORT; fla[3].feat[2]= SIP;
                /* P(dport) * P(sip|dport,sport) * P(sport|dport) * P(dip|sport,sip) */
                score_calculator_set_features(&new->calculator,4,fla,NULL,featurenames);
                minobs= 0; /* prob mode 0 disables minobs; what would it mean? */
                break;
            case 1: 
                fla[0].num= 4;
                score_calculator_set_features(&new->calculator,1,fla,NULL,featurenames);
                break;
            case 2:
                fla[0].num= 3;
                score_calculator_set_features(&new->calculator,1,fla,NULL,featurenames);
                break;
            default:
                if (probmode < 0 || probmode > 3) formatted_spade_msg_send(SPADE_MSG_TYPE_WARNING,self->msg_callback,"Probability mode %d not valid, using mode 3\n",probmode);
            case 3:
                fla[0].num= 2;
                score_calculator_set_features(&new->calculator,1,fla,NULL,featurenames);
                break;
        }

        score_calculator_set_condcutoff(&new->calculator,0);
        
        if (!strcmp(to,"any")) {
            /* no restriction => no conditions to set */
        } else if (!strcmp(to,"nothome")) {
            ADD_TO_CONDS(new->scorecalc_conds,DIP_NOT_IN_HOMENET);
            ADD_TO_CONDS(new->store_conds,DIP_NOT_IN_HOMENET);
        } else {
            if (strcmp(to,"home")) {
                formatted_spade_msg_send(SPADE_MSG_TYPE_WARNING,self->msg_callback,"\"to\" setting %s not valid, using home\n",to);
            }
            ADD_TO_CONDS(new->scorecalc_conds,DIP_IN_HOMENET);
            ADD_TO_CONDS(new->store_conds,DIP_IN_HOMENET);
        }

        if (!strcmp(protocol,"udp")) {
            ADD_TO_CONDS(new->store_conds,IS_UDP);
            ADD_TO_CONDS(new->scorecalc_conds,IS_UDP);
            //new->cancel_open_conds= IS_UDP; /* waiting to see if might be open is optional */
            new->cancel_closed_conds= IS_UNRCHUDP; /* waiting for a ICMP UNRCH to be sure it is a probe is optional */
            //if (!wait) wait= 5;
       } else {
            if (strcmp(protocol,"tcp")) {
                formatted_spade_msg_send(SPADE_MSG_TYPE_WARNING,self->msg_callback,"Protocol %s not valid, using tcp\n",protocol);
            }
            ADD_TO_CONDS(new->store_conds,SYNONLY);           /* only store tcp syns */
            if (!strcmp(tcpflags,"weird")) {
                ADD_TO_CONDS(new->scorecalc_conds,WEIRDFLAGS);
                new->cancel_open_conds= EVENT_CONDITION_FALSE; /* not available */
            } else if (!strcmp(tcpflags,"synack")) {
                ADD_TO_CONDS(new->scorecalc_conds,SYNACK);
                new->cancel_closed_conds= NORMAL_RST; /* we need to wait for a RST to be sure it is a probe */
                if (!wait) wait= 5;
            } else if (!strcmp(tcpflags,"established")) {
                ADD_TO_CONDS(new->scorecalc_conds,ESTFLAGS);
                new->cancel_closed_conds= NORMAL_RST; /* we need to wait for a RST to be sure it is a probe */
                if (!wait) wait= 5;
            } else if (!strcmp(tcpflags,"teardown")) {
                ADD_TO_CONDS(new->scorecalc_conds,TEARDOWNFLAGS);
                new->cancel_closed_conds= NORMAL_RST; /* we need to wait for a RST to be sure it is a probe */
                if (!wait) wait= 5;
            } else {
                if (strcmp(tcpflags,"synonly")) {
                    formatted_spade_msg_send(SPADE_MSG_TYPE_WARNING,self->msg_callback,"TCP flags %s not valid, using synonly\n",tcpflags);
                }
                ADD_TO_CONDS(new->scorecalc_conds,SYNONLY);
                new->cancel_open_conds= SYNACK; /* waiting to see if might be open is optional */
            }
        }
        
        if (!wait) {
            new->report_detection_type= SPADE_DN_TYPE_ODD_DPORT;
        } else if (reverse_reporting) {
            new->report_detection_type= SPADE_DN_TYPE_ODD_OPEN_DPORT;
        }
        break;
    }
    case SPADE_DR_TYPE_ODD_TYPECODE: {
        char icmptype[7]="any";
        thresh=0.9;
        scalefactor= 0.96409; /* this detection type uses a different that normal scaling factor */
        minobs=-1; /* this detection type uses a different that normal default minobs */
        
        minobs_prefix_len= 0;

        args[12]= &to;
        args[13]= &thresh;
        args[14]= &icmptype;        
        strcat(formatstr,";s7:to;d:thresh;s6:icmptype");
        fill_args_space_sep(strcopy,formatstr,args,self->msg_callback);
            
        fla[0].num= 1; fla[0].feat[0]= ICMPTYPECODE;
        score_calculator_set_features(&new->calculator,1,fla,NULL,featurenames);
        score_calculator_set_condcutoff(&new->calculator,0);

        if (!strcmp(to,"any")) {
            /* no restriction => no conditions to set */
        } else if (!strcmp(to,"nothome")) {
            ADD_TO_CONDS(new->scorecalc_conds,DIP_NOT_IN_HOMENET);
            ADD_TO_CONDS(new->store_conds,DIP_NOT_IN_HOMENET);
        } else {
            if (strcmp(to,"home")) {
                formatted_spade_msg_send(SPADE_MSG_TYPE_WARNING,self->msg_callback,"\"to\" setting %s not valid, using home\n",from);
            }
            ADD_TO_CONDS(new->scorecalc_conds,DIP_IN_HOMENET);
            ADD_TO_CONDS(new->store_conds,DIP_IN_HOMENET);
        }

        if (!strcmp(icmptype,"noterr")) {
            ADD_TO_CONDS(new->scorecalc_conds,ICMPNOTERR);
            ADD_TO_CONDS(new->store_conds,ICMPNOTERR);
            if (minobs == -1) minobs= 2000;
        } else if (!strcmp(icmptype,"err")) {
            ADD_TO_CONDS(new->scorecalc_conds,ICMPERR);
            ADD_TO_CONDS(new->store_conds,ICMPERR);
            if (minobs == -1) minobs= 2000;
        } else {
            if (strcmp(icmptype,"any")) {
                formatted_spade_msg_send(SPADE_MSG_TYPE_WARNING,self->msg_callback,"ICMP type %s not valid, using any\n",icmptype);
            }
            ADD_TO_CONDS(new->scorecalc_conds,IS_ICMP);
            ADD_TO_CONDS(new->store_conds,IS_ICMP);
            if (minobs == -1) minobs= 4000;
        }

        new->cancel_open_conds= ICMPNOTERR;
        
        break;
    }
    case SPADE_DR_TYPE_ODD_DPORT: {
        thresh=0.8;
        minobs=600; /* this detection type uses a different that normal default minobs */
        
        args[12]= &protocol;
        args[13]= &from;
        args[14]= &thresh;
        strcat(formatstr,";s4:protocol,proto;s7:from;d:thresh");
        fill_args_space_sep(strcopy,formatstr,args,self->msg_callback);
            
        fla[0].num= 2; fla[0].feat[0]= SIP; fla[0].feat[1]= DPORT;
        score_calculator_set_features(&new->calculator,1,fla,NULL,featurenames);
        score_calculator_set_condcutoff(&new->calculator,1);

        if (!strcmp(from,"any")) {
            /* no restriction => no conditions to set */
        } else if (!strcmp(from,"nothome")) {
            ADD_TO_CONDS(new->scorecalc_conds,SIP_NOT_IN_HOMENET);
            ADD_TO_CONDS(new->store_conds,SIP_NOT_IN_HOMENET);
        } else {
            if (strcmp(from,"home")) {
                formatted_spade_msg_send(SPADE_MSG_TYPE_WARNING,self->msg_callback,"\"from\" setting %s not valid, using home\n",from);
            }
            ADD_TO_CONDS(new->scorecalc_conds,SIP_IN_HOMENET);
            ADD_TO_CONDS(new->store_conds,SIP_IN_HOMENET);
        }

        /* this detection type only makes sense for connection-openers */    
        if (!strcmp(protocol,"udp")) {
            ADD_TO_CONDS(new->store_conds,IS_UDP);
            ADD_TO_CONDS(new->scorecalc_conds,IS_UDP);
            //new->cancel_open_conds= IS_UDP;
            new->cancel_closed_conds= IS_UNRCHUDP; /* waiting for a ICMP UNRCH is optional */
        } else {
            if (strcmp(protocol,"tcp")) {
                formatted_spade_msg_send(SPADE_MSG_TYPE_WARNING,self->msg_callback,"Protocol %s not valid, using tcp\n",protocol);
            }
            ADD_TO_CONDS(new->store_conds,SYNONLY);           /* only store tcp syns */
            ADD_TO_CONDS(new->scorecalc_conds,SYNONLY);
            new->cancel_open_conds= SYNACK;
        }
        
        break;
    }
    case SPADE_DR_TYPE_ODD_PORTDEST: {
        thresh=0.9;
        minobs=-1; /* this detection type uses a different that normal default minobs */
        maxentropy= 2.5;
        scalefreqmins= 90; /* override the default defaults */
        scalefactor= 0.97957;
        scalecutoff= 0.25;
        
        args[12]= &protocol;
        args[13]= &from;
        args[14]= &thresh;
        args[15]= &maxentropy;
        strcat(formatstr,";s4:protocol,proto;s7:from;d:thresh;d:maxentropy");
        fill_args_space_sep(strcopy,formatstr,args,self->msg_callback);

        fla[0].num= 3; fla[0].feat[0]= SIP; fla[0].feat[1]= DPORT; fla[0].feat[2]= DIP;
        score_calculator_set_features(&new->calculator,1,fla,NULL,featurenames);
        score_calculator_set_condcutoff(&new->calculator,1);

        if (!strcmp(from,"any")) {
            /* no restriction => no conditions to set */
        } else if (!strcmp(from,"nothome")) {
            ADD_TO_CONDS(new->scorecalc_conds,SIP_NOT_IN_HOMENET);
            ADD_TO_CONDS(new->store_conds,SIP_NOT_IN_HOMENET);
        } else {
            if (strcmp(from,"home")) {
                formatted_spade_msg_send(SPADE_MSG_TYPE_WARNING,self->msg_callback,"\"from\" setting %s not valid, using home\n",from);
            }
            ADD_TO_CONDS(new->scorecalc_conds,SIP_IN_HOMENET);
            ADD_TO_CONDS(new->store_conds,SIP_IN_HOMENET);
        }

        /* this detection type only makes sense for connection-openers */    
        if (!strcmp(protocol,"udp")) {
            ADD_TO_CONDS(new->store_conds,IS_UDP);
            ADD_TO_CONDS(new->scorecalc_conds,IS_UDP);
            //new->cancel_open_conds= IS_UDP;
            new->cancel_closed_conds= IS_UNRCHUDP; /* waiting for a ICMP UNRCH is optional */

            if (minobs == -1) minobs= pow(2,maxentropy) * 200; /* default is 200 times the minimum number of observations need to acheive maxentropy */
        } else {
            if (strcmp(protocol,"tcp")) {
                formatted_spade_msg_send(SPADE_MSG_TYPE_WARNING,self->msg_callback,"Protocol %s not valid, using tcp\n",protocol);
            }
            ADD_TO_CONDS(new->store_conds,SYNONLY);           /* only store tcp syns */
            ADD_TO_CONDS(new->scorecalc_conds,SYNONLY);
            new->cancel_open_conds= SYNACK;

            if (minobs == -1) minobs= pow(2,maxentropy) * 100; /* default is 100 times the minimum number of observations need to acheive maxentropy */
        }
        
        break;
    }
    case SPADE_DR_TYPE_DEAD_DEST: {
        feature_list cfl;
        char icmptype[7]="noterr";
        scalefreqmins= 60; /* override the default defaults */
        scalefactor= 0.94387;
        scalecutoff= 0.25;
        wait= 2;
        minobs= 2000;
        minobs_prefix_len= 0;
        thresh= 1;
        
        new->exclude_broadcast_dip= 1;
        new->thresh_exc_port_impl= PORT_PROBCLOSED;
        ADD_TO_CONDS(new->scorecalc_conds,DIP_IN_HOMENET);
        ADD_TO_CONDS(new->store_conds,SIP_IN_HOMENET);
        ADD_TO_CONDS(new->store_conds,REPR_PKT);

        fla[0].num= 1; fla[0].feat[0]= SIP;
        cfl.num= 1; cfl.feat[0]= DIP;
        score_calculator_set_features(&new->calculator,1,fla,&cfl,featurenames);
        score_calculator_set_corrscore(&new->calculator,1);
        
        args[12]= &protocol;
        args[13]= &tcpflags;        
        args[14]= &icmptype;        
        strcat(formatstr,";s4:protocol,proto;s20:tcpflags;s6:icmptype");
        fill_args_space_sep(strcopy,formatstr,args,self->msg_callback);

        score_calculator_set_condcutoff(&new->calculator,0);

        if (!strcmp(protocol,"udp")) {
            ADD_TO_CONDS(new->scorecalc_conds,IS_UDP);
            new->cancel_open_conds= UDPRESP; /* waiting to see if might be live is optional */
        } else if (!strcmp(protocol,"icmp")) {
            new->cancel_open_conds= ICMPRESP; /* waiting to see if might be live is optional */
            if (!strcmp(icmptype,"any")) {
                ADD_TO_CONDS(new->scorecalc_conds,IS_ICMP);
            } else if (!strcmp(icmptype,"err")) {
                ADD_TO_CONDS(new->scorecalc_conds,ICMPERR);
            } else {
                if (strcmp(icmptype,"noterr")) {
                    formatted_spade_msg_send(SPADE_MSG_TYPE_WARNING,self->msg_callback,"ICMP type %s not valid, using noterr\n",icmptype);
                }
                ADD_TO_CONDS(new->scorecalc_conds,ICMPNOTERR);
            }
        } else {
            if (strcmp(protocol,"tcp")) {
                formatted_spade_msg_send(SPADE_MSG_TYPE_WARNING,self->msg_callback,"Protocol %s not valid, using tcp\n",protocol);
            }
            if (!strcmp(tcpflags,"weird")) {
                ADD_TO_CONDS(new->scorecalc_conds,WEIRDFLAGS);
                new->cancel_open_conds= EVENT_CONDITION_FALSE; /* not available */
            } else if (!strcmp(tcpflags,"setup")) {
                ADD_TO_CONDS(new->scorecalc_conds,SETUPFLAGS);
                new->cancel_open_conds= SETUPRESP;
            } else if (!strcmp(tcpflags,"synack")) {
                ADD_TO_CONDS(new->scorecalc_conds,SYNACK);
                new->cancel_open_conds= ESTRESP;
            } else if (!strcmp(tcpflags,"established")) {
                ADD_TO_CONDS(new->scorecalc_conds,ESTFLAGS);
                new->cancel_open_conds= ESTRESP;
            } else if (!strcmp(tcpflags,"teardown")) {
                ADD_TO_CONDS(new->scorecalc_conds,TEARDOWNFLAGS);
                new->cancel_open_conds= TEARDOWNRESP;
            } else {
                if (strcmp(tcpflags,"synonly")) {
                    formatted_spade_msg_send(SPADE_MSG_TYPE_WARNING,self->msg_callback,"TCP flags %s not valid, using synonly\n",tcpflags);
                }
                ADD_TO_CONDS(new->scorecalc_conds,SYNONLY);
                new->cancel_open_conds= SYNRESP;
            }
        }

        break;
    }
    default:
        free(new);
        formatted_spade_msg_send(SPADE_MSG_TYPE_WARNING,self->msg_callback,"detector type \"%s\" not recognized, not enabling this detector: %s",type,str);
        return NULL;
    } 

    /* finish new->store_conds,scorecalc_conds and cancel_open_conds */
    
    if (wait > 0 && (CONDS_NOT_FALSE(new->cancel_open_conds) ||  CONDS_NOT_FALSE(new->cancel_closed_conds))) {
        int canceller_response_implication;
        int report_timeout;
        if (CONDS_NOT_FALSE(new->cancel_closed_conds)) { /* waiting is for closed */
            canceller_timeout_implication= PORT_UNKNOWN;
            canceller_response_implication= PORT_CLOSED;
            new->cancel_open_conds= EVENT_CONDITION_FALSE;
            report_timeout= 0 || reverse_reporting;
        } else { /* waiting is for open */
            canceller_timeout_implication= PORT_LIKELYCLOSED;
            canceller_response_implication= PORT_OPEN;
            new->cancel_closed_conds= EVENT_CONDITION_FALSE;
            report_timeout= 1 && !reverse_reporting;
        }
        if (report_timeout) {
            PS_INIT_SET(new->port_report_criterea,canceller_timeout_implication);
        } else {
            PS_INIT_SET_WITH_STRONGER(new->port_report_criterea,canceller_response_implication);
        }
        new->canceller= new_packet_resp_canceller(wait,&canceller_status_report,new,canceller_timeout_implication);
    } else {
        new->canceller= NULL;
        new->cancel_open_conds= EVENT_CONDITION_FALSE;
        new->cancel_closed_conds= EVENT_CONDITION_FALSE;
    }
    /* check if restrictions on report's homenet, need to flip for cancelling */
    cancel_homenet_conds= flipped_homenet_conds(new->scorecalc_conds);
    if (CONDS_NOT_FALSE(new->cancel_open_conds))
        ADD_TO_CONDS(new->cancel_open_conds,cancel_homenet_conds);
    if (CONDS_NOT_FALSE(new->cancel_closed_conds))
        ADD_TO_CONDS(new->cancel_closed_conds,cancel_homenet_conds);

    score_calculator_set_storage_conditions(&new->calculator,new->store_conds);
    
    calcboth= 0; /*relscore ? 0 : 1;*/
    score_calculator_set_relscore(&new->calculator,relscore || calcboth,relscore);
    score_calculator_set_rawscore(&new->calculator,!relscore || calcboth,!relscore);
    if (scalehalflifehrs >= 0) // set factor based on halflife and frequency
        scalefactor= exp((scalefreqmins/(scalehalflifehrs*60))*log(0.5));
    score_calculator_set_scaling(&new->calculator,scalefreqmins*60,scalefactor,scalecutoff);
    if (minobs > 0) {
        if (minobs_prefix_len < 0) minobs_prefix_len+= fla[0].num;
        score_calculator_set_min_obs(&new->calculator,minobs_prefix_len,minobs);
    }
    if (maxentropy >= 0) {
        if (entropy_prefix_len < 0) entropy_prefix_len+= fla[0].num;
        score_calculator_set_low_entropy_domain(&new->calculator,entropy_prefix_len,maxentropy);
    }
    init_spade_enviro(&new->enviro,thresh,&self->total_pkts);
    init_score_mgr(&new->mgr, new, &new->enviro, self,
                threshold_was_exceeded, threshold_was_adjusted,self->msg_callback);
    
    process_detector_xargs(new,xsips,xdips,xsports,xdports);
                
    if (id[0] == '\0' || detector_for_id(self,id)) {
        if (id[0] != '\0') formatted_spade_msg_send(SPADE_MSG_TYPE_WARNING,self->msg_callback,"Detector with id=%s already exists; using id=%s instead on: %s",id,defaultid,str);
        new->id= strdup(defaultid);
    } else {
        new->id= strdup(id);
    }
    new->last_adj_stats.scored= 0;
    new->last_adj_stats.reported= 0;
    
    /* append new detector to the list */
    new->next= NULL;
    if (self->detectors == NULL) { /* first entry */
        self->detectors= new;
    } else {
        self->detectors_tail->next= new;
    }
    self->detectors_tail= new;
    
    netspade_detector_scope_str(self,new->id);
                
    free(strcopy);
    return new->id;
}

int netspade_set_detector_scaling(netspade *self,char *detectorid,int scale_freq,double scale_factor,double prune_threshold) {
    netspade_detector *detector;
    detector= acquire_detector_for_id(self,detectorid);
    score_calculator_set_scaling(&detector->calculator,scale_freq,scale_factor,prune_threshold);
    return 1;
}

char *netspade_setup_detector_adapt_from_str(netspade *self,int adaptmode,char *str) {
    char *strcopy= strdup(str);
    char *detectorid= extract_str_arg_space_sep(strcopy,"id");
    netspade_detector *detector= acquire_detector_for_id(self,detectorid);
    score_mgr_setup_adapt_from_str(&detector->mgr,adaptmode,strcopy);
    free(strcopy);
    return detector->id;
}

int netspade_setup_detector_adapt1(netspade *self,char *detectorid,int adapttarget, time_t period, float new_obs_weight, int by_count) {
    netspade_detector *detector;
    detector= acquire_detector_for_id(self,detectorid);
    score_mgr_setup_adapt1(&detector->mgr,adapttarget,period,new_obs_weight,by_count);
    return 1;
}

int netspade_setup_detector_adapt2(netspade *self,char *detectorid,double targetspec, double obsper, int NS, int NM, int NL) {
    netspade_detector *detector;
    detector= acquire_detector_for_id(self,detectorid);
    score_mgr_setup_adapt2(&detector->mgr,targetspec,obsper,NS,NM,NL);
    return 1;
}

int netspade_setup_detector_adapt3(netspade *self,char *detectorid,double targetspec, double obsper, int NO) {
    netspade_detector *detector;
    detector= acquire_detector_for_id(self,detectorid);
    score_mgr_setup_adapt3(&detector->mgr,targetspec,obsper,NO);
    return 1;
}

int netspade_setup_detector_advise(netspade *self,char *detectorid,int obs_size, int obs_secs) {
    netspade_detector *detector;
    detector= acquire_detector_for_id(self,detectorid);
    score_mgr_setup_advise(&detector->mgr,obs_size,obs_secs);
    return 1;
}

char *netspade_setup_detector_advise_from_str(netspade *self,char *str) {
    char *strcopy= strdup(str);
    char *detectorid= extract_str_arg_space_sep(strcopy,"id");
    netspade_detector *detector= acquire_detector_for_id(self,detectorid);
    score_mgr_setup_advise_from_str(&detector->mgr,strcopy);
    free(strcopy);
    return detector->id;
}

int netspade_setup_detector_survey(netspade *self,char *detectorid,char *filename,float interval) {
    netspade_detector *detector;
    detector= acquire_detector_for_id(self,detectorid);
    score_mgr_setup_survey(&detector->mgr,filename,interval);
    return 1;
}

char *netspade_setup_detector_survey_from_str(netspade *self,char *str) {
    char *strcopy= strdup(str);
    char *detectorid= extract_str_arg_space_sep(strcopy,"id");
    netspade_detector *detector= acquire_detector_for_id(self,detectorid);
    score_mgr_setup_survey_from_str(&detector->mgr,strcopy);
    free(strcopy);
    return detector->id;
}

/* called frequently, should be efficient esp for packets we don't care about */
void netspade_new_pkt(netspade *self,spade_event *pkt) {
    event_condition_set pkt_conds=0;
    int write_log= 0;
    int ip_in_homenet;
    features orig_sip,orig_dip,orig_sport,orig_dport;
    netspade_detector *detector;
    int new_sec= (self->last_time_forwarded < (time_t)pkt->time);

    if (self->last_time_forwarded == 0) { /* first packet */
        if (self->detectors == NULL)
            netspade_new_detector(self,"relscore=0 corrscore=0");
        for (detector= self->detectors; detector != NULL; detector=detector->next) {
            score_calculator_init_complete(&detector->calculator); /* make sure calculator is all set up */
        }
    }

//printf("packet time is %.4f\n",pkt->time);

    /* update packet counts and tell detector of new time */
    self->total_pkts++;
    if (new_sec) {
        for (detector= self->detectors; detector != NULL; detector=detector->next) {
            if (score_mgr_new_time(&detector->mgr,pkt->time)) write_log=1; /* advising completed */
            if (detector->canceller != NULL)
                packet_resp_canceller_new_time(detector->canceller,pkt->time);
            detector->enviro.now= (time_t)pkt->time;
        }
        event_recorder_new_time(&self->recorder,(time_t)pkt->time);
        self->last_time_forwarded= (time_t)pkt->time;
    }
    
    /* calculate the conditions that this packet satisfies; no need to calculate any conditions we don't care about (i.e., not on recorder_needed_conds or nonstore_conds) */
    if (!self->nonstore_conds || !self->recorder_needed_conds)
        netspade_update_conds_to_calc(self);
    if (pkt->origin == PKTORIG_UNRCH) {
        orig_sip= DIP;
        orig_dip= SIP;
        orig_sport= DPORT;
        orig_dport= SPORT;
        if (pkt->fldval[IPPROTO] == IPPROTO_TCP) 
             ADD_TO_CONDS(pkt_conds,IS_UNRCHTCP);
        else if (pkt->fldval[IPPROTO] == IPPROTO_UDP) 
            ADD_TO_CONDS(pkt_conds,IS_UNRCHUDP);
        else if (pkt->fldval[IPPROTO] == IPPROTO_ICMP) 
            ADD_TO_CONDS(pkt_conds,IS_UNRCHICMP);
    } else {
        orig_sip= SIP;
        orig_dip= DIP;
        orig_sport= SPORT;
        orig_dport= DPORT;
        if (pkt->fldval[IPPROTO] == IPPROTO_TCP) {
            u8 tcpflags= pkt->fldval[TCPFLAGS] & 0x3F; /* strip off reserved bits */
            ADD_TO_CONDS(pkt_conds,IS_TCP);
            if (tcpflags == 0x02) {
                ADD_TO_CONDS(pkt_conds,SYNONLY);
            } else if (tcpflags == 0x12) {
                ADD_TO_CONDS(pkt_conds,SYNACK);
            } else {
                if (!(tcpflags & 0x16)) { /* no syn, no ack, and no rst */
                    ADD_TO_CONDS(pkt_conds,WEIRDFLAGS);
                } else if (tcpflags & 0x10) { /* has ack */
                    event_condition_set tmp= tcpflags & 0x07; /* now strip out A,P,U */
                    if (tmp != 0x00 && tmp != 0x01 && tmp != 0x04) /* not more than one of F or R */
                        ADD_TO_CONDS(pkt_conds,WEIRDFLAGS);
                } else if (!((tcpflags == 0x01) || (tcpflags == 0x02) || (tcpflags == 0x04))) { /* no ack, but no S,F,or R */
                    ADD_TO_CONDS(pkt_conds,WEIRDFLAGS);
                }
            }
            if (!SOME_CONDS_MET(pkt_conds,WEIRDFLAGS)) {
                event_condition_set tmp= (pkt->fldval[TCPFLAGS] & 0x07); /* strip off all but S,F,R */
                switch (tmp) {
                case 0x00: ADD_TO_CONDS(pkt_conds,ESTFLAGS); break;
                case 0x02: ADD_TO_CONDS(pkt_conds,SETUPFLAGS); break;
                case 0x01: ADD_TO_CONDS(pkt_conds,TEARDOWNFLAGS); break;
                case 0x04: ADD_TO_CONDS(pkt_conds,CONDS_PLUS_CONDS(NORMAL_RST,TEARDOWNFLAGS)); break;
                default:;
                }
            }
        } else if (pkt->fldval[IPPROTO] == IPPROTO_UDP) {
            ADD_TO_CONDS(pkt_conds,IS_UDP);
        } else if (pkt->fldval[IPPROTO] == IPPROTO_ICMP) {
            ADD_TO_CONDS(pkt_conds,IS_ICMP);
            if ((pkt->fldval[ICMPTYPE] < 3 || pkt->fldval[ICMPTYPE] > 5) &&
                pkt->fldval[ICMPTYPE] != 11 && pkt->fldval[ICMPTYPE] != 12) {
                ADD_TO_CONDS(pkt_conds,ICMPNOTERR);
            } else {
                ADD_TO_CONDS(pkt_conds,ICMPERR);
            }
        }
    }
    if (SOME_CONDS_MET(pkt_conds,REPR_PKT_CONDS))
        ADD_TO_CONDS(pkt_conds,REPR_PKT);
    if (SOME_CONDS_MET(pkt_conds,UDPRESP_CONDS))
        ADD_TO_CONDS(pkt_conds,UDPRESP);
    if (SOME_CONDS_MET(pkt_conds,ICMPRESP_CONDS))
        ADD_TO_CONDS(pkt_conds,ICMPRESP);
    if (SOME_CONDS_MET(pkt_conds,ONLY_CONDS(self->conds_to_calc,CONDS_PLUS_3CONDS(SYNRESP_CONDS,ESTRESP_CONDS,TEARDOWNRESP_CONDS,SETUPRESP_CONDS)))) {
        /* did that test so only TCP and ICMP unreachable will go in here */
        if (SOME_CONDS_MET(pkt_conds,SYNRESP_CONDS))
            ADD_TO_CONDS(pkt_conds,SYNRESP);
        if (SOME_CONDS_MET(pkt_conds,ESTRESP_CONDS))
            ADD_TO_CONDS(pkt_conds,ESTRESP);
        if (SOME_CONDS_MET(pkt_conds,TEARDOWNRESP_CONDS))
            ADD_TO_CONDS(pkt_conds,TEARDOWNRESP);
        if (SOME_CONDS_MET(pkt_conds,SETUPRESP_CONDS))
            ADD_TO_CONDS(pkt_conds,SETUPRESP);
    }

    
    if (SOME_CONDS_MET(self->conds_to_calc,CONDS_PLUS_CONDS(DIP_IN_HOMENET,DIP_NOT_IN_HOMENET))) {
        PKT_IP_IN_HOMENET_LIST(pkt,orig_dip,self->homelist_head,ip_in_homenet);
        ADD_TO_CONDS(pkt_conds,(ip_in_homenet ? DIP_IN_HOMENET : DIP_NOT_IN_HOMENET));
    }
    if (SOME_CONDS_MET(self->conds_to_calc,CONDS_PLUS_CONDS(SIP_IN_HOMENET,SIP_NOT_IN_HOMENET))) {
        PKT_IP_IN_HOMENET_LIST(pkt,orig_sip,self->homelist_head,ip_in_homenet);
        ADD_TO_CONDS(pkt_conds,(ip_in_homenet ? SIP_IN_HOMENET : SIP_NOT_IN_HOMENET));
    }
    
    if (SOME_CONDS_MET(pkt_conds,self->nonstore_conds)) { /* might match something to calculate or cancel */
        /* check for scoring and cancelling in each detector */
        int portless= (pkt->fldval[IPPROTO] != IPPROTO_TCP) && (pkt->fldval[IPPROTO] != IPPROTO_UDP);
        for (detector= self->detectors; detector != NULL; detector=detector->next) {
            if (ALL_CONDS_MET(pkt_conds,detector->scorecalc_conds) && (!detector->exclude_broadcast_dip || ((pkt->fldval[DIP] & 0xFF) != 0xFF))) {
                score_info score;
                int enoughobs;
                score_info *res= score_calculator_calc_event_score(&detector->calculator,pkt,&score,&enoughobs);
                if (!enoughobs || res != NULL) { // ignore events we decided not to apply this detector to */
                    detector->enviro.pkt_stats.scored++;
                    if (enoughobs) { // res != NULL
                        score_mgr_new_event(&detector->mgr,&score,pkt);
                    } else {  // !enoughobs
                        detector->enviro.pkt_stats.insuffobsed++;
                    }
                }
            }
            if (ALL_CONDS_MET(pkt_conds,detector->cancel_open_conds)) {
                detector->enviro.pkt_stats.respchecked++;
                packet_resp_canceller_note_response(detector->canceller,PORT_OPEN,
                    pkt->fldval[orig_dip],pkt->fldval[orig_dport],
                    pkt->fldval[orig_sip],pkt->fldval[orig_sport],portless);
            }
            if (ALL_CONDS_MET(pkt_conds,detector->cancel_closed_conds)) {
                detector->enviro.pkt_stats.respchecked++;
                packet_resp_canceller_note_response(detector->canceller,PORT_CLOSED,
                    pkt->fldval[orig_dip],pkt->fldval[orig_dport],
                    pkt->fldval[orig_sip],pkt->fldval[orig_sport],portless);
            }
        }
    }
    if (SOME_CONDS_MET(pkt_conds,self->recorder_needed_conds)) { /* might match something to record */
        self->records_since_checkpoint+=
            event_recorder_new_event(&self->recorder,pkt,pkt_conds);
    }
    
    if (write_log) { /* time to write the log */
        netspade_write_log(self);
    }
    if ((self->checkpoint_freq > 0) && (self->records_since_checkpoint >= self->checkpoint_freq)) { // see if its time to checkpoint
        do_checkpointing(self); // should report err if returns 0
        self->records_since_checkpoint= 0;
    }
}


void netspade_dump(netspade *self) 
{
    netspade_detector *detector;
    netspade_write_log(self);
    for (detector= self->detectors; detector != NULL; detector=detector->next) {
        netspade_detector_dump(detector);
    }
    if (self->checkpoint_file != NULL) do_checkpointing(self);
}

void netspade_cleanup(netspade *self) 
{
    netspade_detector *detector;
    netspade_write_log(self);
    for (detector= self->detectors; detector != NULL; detector=detector->next) {
        netspade_detector_cleanup(detector);
    }
    if (self->checkpoint_file != NULL) do_checkpointing(self);
}

char *netspade_detector_scope_str(netspade *self,char *id) {
    int i;
    char *str,*tail;
    int numconds= 0;
    netspade_detector *d= detector_for_id(self,id);
    if (d == NULL) return NULL;
    if (d->report_scope_str != NULL) return d->report_scope_str;
    
    for (i=0; i < 31; i++)
        if (SOME_CONDS_MET(d->scorecalc_conds,EVENT_CONDITION_NUM(i))) numconds++;
    
    str= (char *)malloc(sizeof(char)*(numconds*(15+2)+1));
    if (str == NULL) return NULL;
    
    tail= str;
    for (i=31; i >= 0; i--)
        if (SOME_CONDS_MET(d->scorecalc_conds,EVENT_CONDITION_NUM(i))) {
            char* new= scope_str_for_cond(EVENT_CONDITION_NUM(i));
            if (new == NULL) continue; /* nothing to add */
            if (tail != str) {
                *tail= ',';
                *(tail+1)= ' ';
                tail+= 2;
            }
            strcpy(tail,new);
            tail+= strlen(new);
        }

   d->report_scope_str= str;
   return str;         
}

static void condprinter(FILE *file,event_condition_set conds) {
    int i,first=1;
    for (i=31; i >= 0; i--)
        if (SOME_CONDS_MET(conds,EVENT_CONDITION_NUM(i))) {
            if (first) {
                first= 0;
            } else {
                fprintf(file,", ");
            }
            fprintf(file,"%s",scope_str_for_cond(EVENT_CONDITION_NUM(i)));
        }
}

static char *scope_str_for_cond(event_condition_set cond) {
    switch (cond) {
        case IS_TCP: return "tcp";
        case IS_UDP: return "udp";
        case IS_ICMP: return "icmp";
        case ICMPNOTERR: return "non-err icmp";
        case ICMPERR: return "error icmp";
        case IS_UNRCHTCP: return "returned tcp";
        case IS_UNRCHUDP: return "returned udp";
        case IS_UNRCHICMP: return "returned icmp";
        case SYNONLY: return "syn";
        case NORMAL_RST: return "rst";
        case SYNACK: return "synack";
        case WEIRDFLAGS: return "weird flags";
        case SETUPFLAGS: return "setup flags";
        case ESTFLAGS: return "est. flags";
        case TEARDOWNFLAGS: return "teardown flags";
        case SIP_IN_HOMENET: return "local source";
        case SIP_NOT_IN_HOMENET: return "nonlocal source";
        case DIP_IN_HOMENET: return "local dest";
        case DIP_NOT_IN_HOMENET: return "nonlocal dest";
        case UDPRESP: return "udp response";
        case ICMPRESP: return "icmp response";
        case SYNRESP: return "syn response";
        case ESTRESP: return "est. response";
        case TEARDOWNRESP: return "teardown response";
        case SETUPRESP: return "setup response";
        case REPR_PKT: return "representative";
        default: return NULL;
    }
}

static netspade_detector *acquire_detector_for_id(netspade *self,char *id) {
    netspade_detector *detector;
    if (id == NULL) {
        if (self->detectors == NULL) netspade_new_detector(self,"id=default");
        return self->detectors_tail; /* return most recent detector */
    }
    detector= detector_for_id(self,id);
    if (detector == NULL) {
        char detect_str[45];
        sprintf(detect_str,"id=%s",id);
        netspade_new_detector(self,detect_str);
        detector= detector_for_id(self,id);
    }
    return detector;
}

static netspade_detector *detector_for_id(netspade *self,char *id) {
    netspade_detector *detector;
    for (detector= self->detectors; detector != NULL; detector=detector->next) {
        if (!strcmp(detector->id,id)) {
            return detector;
        }
    }
    return NULL;
}

static void netspade_detector_dump(netspade_detector *detector) {
    score_mgr_dump(&detector->mgr);
}
static void netspade_detector_cleanup(netspade_detector *detector) {
    score_mgr_cleanup(&detector->mgr);
}

static void netspade_update_conds_to_calc(netspade *self) {
    if (!self->recorder_needed_conds)
        self->recorder_needed_conds= event_recorder_needed_conds(&self->recorder);
    if (!self->nonstore_conds)
        self->nonstore_conds= netspade_nonstore_conds(self);
        
    self->conds_to_calc= CONDS_PLUS_CONDS(self->recorder_needed_conds,self->nonstore_conds);
}

static event_condition_set netspade_nonstore_conds(netspade *self) {
    netspade_detector *detector;
    event_condition_set nonstore_conds= 0;
    for (detector= self->detectors; detector != NULL; detector=detector->next) {
        ADD_TO_CONDS(nonstore_conds,CONDS_PLUS_2CONDS(detector->scorecalc_conds,detector->cancel_open_conds,detector->cancel_closed_conds));
    }
    return nonstore_conds;
}

static event_condition_set flipped_homenet_conds(event_condition_set orig) {
    event_condition_set flipped=0;
    if (SOME_CONDS_MET(orig,SIP_IN_HOMENET)) {
        ADD_TO_CONDS(flipped,DIP_IN_HOMENET);
    }
    if (SOME_CONDS_MET(orig,SIP_NOT_IN_HOMENET)) {
        ADD_TO_CONDS(flipped,DIP_NOT_IN_HOMENET);
    }
    if (SOME_CONDS_MET(orig,DIP_IN_HOMENET)) {
        ADD_TO_CONDS(flipped,SIP_IN_HOMENET);
    }
    if (SOME_CONDS_MET(orig,DIP_NOT_IN_HOMENET)) {
        ADD_TO_CONDS(flipped,SIP_NOT_IN_HOMENET);
    }
    return flipped;
}


static int do_checkpointing(netspade *self) {
    statefile_ref *ref= spade_state_begin_checkpointing(self->checkpoint_file,"netspade",2);
    if (ref == NULL) return 0;
    
    return event_recorder_checkpoint(&self->recorder,ref)
        /* could checkpoint detectors in here */
        && spade_state_end_checkpointing(ref);
}

static int do_recovery(netspade *self,char *statefile) {
    char *appname;
    u8 file_app_fvers;
    
    statefile_ref *ref= spade_state_begin_recovery(statefile,2,&appname,&file_app_fvers);
    if (ref == NULL) return 0;
    if (strcmp(appname,"netspade")) return 0;
    
    return event_recorder_merge_recover(&self->recorder,ref)
        /* would checkpoint detectors in here; if we checkpointed that */
        && spade_state_end_recovery(ref);
}

static void threshold_was_exceeded(void *context,void *mgrref,spade_event *pkt,score_info *score) {
    netspade *self= (netspade *)context;
    netspade_detector *detector= (netspade_detector *)mgrref;
    char *id= detector->id;
    port_status_t port_status= detector->thresh_exc_port_impl;
    
    /* first check if this report should be excluded */
    if (pkt_is_excluded(self->rpt_exclude_list,pkt) ||
            pkt_is_excluded(detector->rpt_exclude_list,pkt)) {
        detector->enviro.pkt_stats.excluded++;
        return;
    } else {
        detector->enviro.pkt_stats.nonexcluded++;
    }
    
    if (PS_IN_SET(detector->port_report_criterea,port_status)) {
        spade_report *rpt= new_spade_report(pkt,score,detector->detect_type,id,SPADE_DN_TYPE_MEDDESCR4NUM(detector->report_detection_type),netspade_detector_scope_str(self,id),&detector->enviro.pkt_stats,port_status);
        (*(self->exc_callback))(self->callback_context,rpt);
        free_spade_report(rpt);
        detector->enviro.pkt_stats.reported++;
    } else if (detector->canceller != NULL) {
        /* we didn't meet criterea for reporting yet, and we have a canceller avail, so use it */
        spade_event *newpkt= spade_event_clone(pkt,self->pkt_native_copier_callback,self->pkt_native_freer_callback);
        score_info *newscore= score_info_clone(score);
        spade_report *rpt= new_spade_report(newpkt,newscore,detector->detect_type,id,SPADE_DN_TYPE_MEDDESCR4NUM(detector->report_detection_type),netspade_detector_scope_str(self,id),&detector->enviro.pkt_stats,port_status);
        packet_resp_canceller_add_report(detector->canceller,rpt);
        detector->enviro.pkt_stats.waited++;
    } else {
        /* drop the report since no canceller available to strengthen it; that was silly */
    }
}

static void canceller_status_report(void *context,spade_report *rpt,port_status_t status) {
    netspade_detector *d= (netspade_detector *)context;
    netspade *self= d->parent;
    if (self->debug_level > 1) formatted_spade_msg_send(SPADE_MSG_TYPE_DEBUG,self->msg_callback,"canceller_status_report(%p,%p %8x:%d %8x:%d,%s)\n",d,rpt,rpt->pkt->fldval[SIP],rpt->pkt->fldval[SPORT],rpt->pkt->fldval[DIP],rpt->pkt->fldval[DPORT],PORT_STATUS_AS_STR(status));
    if (PS_IN_SET(d->port_report_criterea,status)) {
        /* met one of the critea so report it */
        rpt->port_status= status;
        (*(self->exc_callback))(self->callback_context,rpt);
        if (rpt->stream_stats) {
            rpt->stream_stats->reported++;
        }
    }
    /* free report and pkt */
    free_score_info(rpt->score);
    free_spade_event(rpt->pkt);
    free_spade_report(rpt);
}

static void threshold_was_adjusted(void *context,void *mgrref) {
    char message[85];
    spade_pkt_stats adj_period_stats;
    netspade *self= (netspade *)context;
    netspade_detector *detector= (netspade_detector *)mgrref;
    int using_corrscore;
    
    adj_period_stats.scored= detector->enviro.pkt_stats.scored - detector->last_adj_stats.scored;
    adj_period_stats.reported= detector->enviro.pkt_stats.reported - detector->last_adj_stats.reported;
    detector->last_adj_stats= detector->enviro.pkt_stats; // copy over current stats for reference on next call
    
    sprintf(message,"Threshold adjusted to %.4f after %d alerts (of %d)",detector->enviro.thresh,adj_period_stats.reported,adj_period_stats.scored);

    using_corrscore= score_calculator_using_corrscore(&detector->calculator);
    (*(self->adj_callback))(self->callback_context,detector->id,message,using_corrscore);
}


static void netspade_add_net_to_homenet(netspade *self,char *net_str) {
    ll_net *cur=NULL;

    cur= (ll_net *)malloc(sizeof(ll_net));
    cur->next= NULL;
    if (self->homelist_head == NULL) {
        self->homelist_head= cur;
    } else {
        self->homelist_tail->next= cur;
    }
    self->homelist_tail= cur;
    
    if (!cidr_to_netmask(net_str,&cur->netaddr,&cur->netmask)) {
        formatted_spade_msg_send(SPADE_MSG_TYPE_FATAL,self->msg_callback,"Could not interpret homenet network: %s",net_str);
    }
}



void netspade_write_log(netspade *self) {
    FILE *file;
    netspade_detector *detector;

    if (!strcmp(self->outfile,"-")) {
        file= stdout;
    } else {
        file = fopen(self->outfile, "w");
        if (!file) formatted_spade_msg_send(SPADE_MSG_TYPE_FATAL,self->msg_callback,"netspade: unable to open %s",self->outfile);
    }

    fprintf(file,"%ld total packets were processed by spade in this run\n\n",self->total_pkts);
    for (detector= self->detectors; detector != NULL; detector=detector->next) {
        spade_pkt_stats *stats= &detector->enviro.pkt_stats;
        int scored= stats->scored;
        int was_anom= stats->nonexcluded + stats->excluded;
        fprintf(file,"** %s: %s (id=%s) **\n",SPADE_DN_TYPE_MEDDESCR4NUM(detector->report_detection_type),detector->report_scope_str,detector->id);
        fprintf(file,"%d packets were evaluated\n",stats->scored);
        fprintf(file,"  %d (%.2f%%) packets were considered anomalous\n",was_anom,((was_anom/(float)scored)*100));
        if (stats->excluded > 0) 
            fprintf(file,"    %d (%.2f%%) packets were dropped due to configured exclusion\n",stats->excluded,((stats->excluded/(float)scored)*100));
        if (stats->waited > 0) 
            fprintf(file,"    %d (%.2f%%) packets were inserted in the wait queue\n",stats->waited,((stats->waited/(float)scored)*100));
        fprintf(file,"    %d (%.2f%%) packets were reported as alerts\n",stats->reported,((stats->reported/(float)scored)*100));
        if (stats->insuffobsed > 0) 
            fprintf(file,"  %d (%.2f%%) packets did not have enough observations\n",stats->insuffobsed,((stats->insuffobsed/(float)scored)*100));
        if (stats->respchecked > 0) 
            fprintf(file,"  %d packets were checked against the wait queue\n",stats->respchecked);
        fprintf(file,"%d observations were stored\n",score_calculator_get_store_count(&detector->calculator));
        fprintf(file,"%.4f observations are remembered\n",score_calculator_get_obs_count(&detector->calculator));
        score_mgr_file_print_log(&detector->mgr,file);
        fprintf(file,"\n");
    }
    fflush(file);
    
    if (self->stats_to_print != STATS_NONE)
        event_recorder_write_stats(&self->recorder,file,self->stats_to_print,condprinter);
        
    if (file != stdout) {
        fclose(file);
    }
}

void print_conds_line(event_condition_set conds) {
    file_print_conds(stdout,conds);
    printf("\n");
}

void print_conds(event_condition_set conds) {
    file_print_conds(stdout,conds);
}

static void file_print_conds(FILE *f,event_condition_set conds) {
    int first= 1;
    if (SOME_CONDS_MET(conds,EVENT_CONDITION_FALSE)) {
        fprintf(f,"FALSE");
        return;
    }
    fprintf(f,"{");
    if (SOME_CONDS_MET(conds,IS_TCP)) {
        if (!first) { fprintf(f,","); } first=0;
        fprintf(f,"TCP");
    }
    if (SOME_CONDS_MET(conds,IS_UDP)) {
        if (!first) { fprintf(f,","); } first=0;
        fprintf(f,"UDP");
    }
    if (SOME_CONDS_MET(conds,IS_ICMP)) {
        if (!first) { fprintf(f,","); } first=0;
        fprintf(f,"ICMP");
    }
    if (SOME_CONDS_MET(conds,ICMPNOTERR)) {
        if (!first) { fprintf(f,","); } first=0;
        fprintf(f,"ICMPNOTERR");
    }
    if (SOME_CONDS_MET(conds,ICMPERR)) {
        if (!first) { fprintf(f,","); } first=0;
        fprintf(f,"ICMPERR");
    }
    if (SOME_CONDS_MET(conds,IS_UNRCHTCP)) {
        if (!first) { fprintf(f,","); } first=0;
        fprintf(f,"IS_UNRCHTCP");
    }
    if (SOME_CONDS_MET(conds,IS_UNRCHUDP)) {
        if (!first) { fprintf(f,","); } first=0;
        fprintf(f,"IS_UNRCHUDP");
    }
    if (SOME_CONDS_MET(conds,IS_UNRCHICMP)) {
        if (!first) { fprintf(f,","); } first=0;
        fprintf(f,"IS_UNRCHICMP");
    }
    if (SOME_CONDS_MET(conds,NORMAL_RST)) {
        if (!first) { fprintf(f,","); } first=0;
        fprintf(f,"NORMAL_RST");
    }
    if (SOME_CONDS_MET(conds,SYNACK)) {
        if (!first) { fprintf(f,","); } first=0;
        fprintf(f,"SYNACK");
    }
    if (SOME_CONDS_MET(conds,WEIRDFLAGS)) {
        if (!first) { fprintf(f,","); } first=0;
        fprintf(f,"WEIRDFLAGS");
    }
    if (SOME_CONDS_MET(conds,SETUPFLAGS)) {
        if (!first) { fprintf(f,","); } first=0;
        fprintf(f,"SETUP");
    }
    if (SOME_CONDS_MET(conds,ESTFLAGS)) {
        if (!first) { fprintf(f,","); } first=0;
        fprintf(f,"EST");
    }
    if (SOME_CONDS_MET(conds,TEARDOWNFLAGS)) {
        if (!first) { fprintf(f,","); } first=0;
        fprintf(f,"TEARDOWN");
    }
    if (SOME_CONDS_MET(conds,SIP_IN_HOMENET)) {
        if (!first) { fprintf(f,","); } first=0;
        fprintf(f,"SIP_IS_HOME");
    }
    if (SOME_CONDS_MET(conds,SIP_NOT_IN_HOMENET)) {
        if (!first) { fprintf(f,","); } first=0;
        fprintf(f,"!SIP_IS_HOME");
    }
    if (SOME_CONDS_MET(conds,DIP_IN_HOMENET)) {
        if (!first) { fprintf(f,","); } first=0;
        fprintf(f,"DIP_IS_HOME");
    }
    if (SOME_CONDS_MET(conds,DIP_NOT_IN_HOMENET)) {
        if (!first) { fprintf(f,","); } first=0;
        fprintf(f,"!DIP_IS_HOME");
    }
    if (SOME_CONDS_MET(conds,REPR_PKT)) {
        if (!first) { fprintf(f,","); } first=0;
        fprintf(f,"REPR_PKT");
    }
    if (SOME_CONDS_MET(conds,UDPRESP)) {
        if (!first) { fprintf(f,","); } first=0;
        fprintf(f,"UDPRESP");
    }
    if (SOME_CONDS_MET(conds,ICMPRESP)) {
        if (!first) { fprintf(f,","); } first=0;
        fprintf(f,"ICMPRESP");
    }
    if (SOME_CONDS_MET(conds,SYNRESP)) {
        if (!first) { fprintf(f,","); } first=0;
        fprintf(f,"SYNRESP");
    }
    if (SOME_CONDS_MET(conds,ESTRESP)) {
        if (!first) { fprintf(f,","); } first=0;
        fprintf(f,"ESTRESP");
    }
    if (SOME_CONDS_MET(conds,TEARDOWNRESP)) {
        if (!first) { fprintf(f,","); } first=0;
        fprintf(f,"TEARDOWNRESP");
    }
    if (SOME_CONDS_MET(conds,SETUPRESP)) {
        if (!first) { fprintf(f,","); } first=0;
        fprintf(f,"SETUPRESP");
    }
    fprintf(f,"}");
}

int netspade_print_detector_config_details(netspade *self,FILE *f,char *id) {
    netspade_detector *d= detector_for_id(self,id);
    if (d == NULL) return 0;
    
    fprintf(f,"id=%s; detect_type=%s\n",d->id,SPADE_DR_TYPE_SHORT4NUM(d->detect_type));
    fprintf(f,"scorecalc_conds= ");
    file_print_conds(f,d->scorecalc_conds);
    fprintf(f,"; store_conds= ");
    file_print_conds(f,d->store_conds);
    fprintf(f,"\n");

    fprintf(f,"calculator=\n");
    score_calculator_print_config_details(&d->calculator,f,"  ");
    fprintf(f,"mgr=\n");
    score_mgr_print_config_details(&d->mgr,f,"  ");
    
    fprintf(f,"port_report_criterea=");
    port_status_set_file_print(d->port_report_criterea,f);
    fprintf(f,"\n");
    if (d->canceller != NULL) {
        fprintf(f,"canceller=\n");
        packet_resp_canceller_print_config_details(d->canceller,f,"  ");
        fprintf(f,"cancel_open_conds= ");
        file_print_conds(f,d->cancel_open_conds);
        fprintf(f,"; cancel_closed_conds= ");
        file_print_conds(f,d->cancel_closed_conds);
        fprintf(f,"\n");
    }
    
    fprintf(f,"report_detection_type=%d\n",d->report_detection_type);
    return 1;
}

static void process_netspade_xarg(netspade *self,char *str,features feat,xarg_type_t type) {
    xfeatval_link *list,*list_tail;

    list= process_xarg(str,feat,type,self->msg_callback,&list_tail);
    if (list == NULL) return;
    
    /* prepend this list onto the detector */
    list_tail->next= self->rpt_exclude_list;
    self->rpt_exclude_list= list;
}

static void process_detector_xargs(netspade_detector *d,char *xsips,char *xdips,char *xsports,char *xdports) {
    d->rpt_exclude_list= NULL;
    process_detector_xarg(d,xsports,SPORT,XARG_TYPE_UINT);
    process_detector_xarg(d,xdips,DIP,XARG_TYPE_CIDR);
    process_detector_xarg(d,xsips,SIP,XARG_TYPE_CIDR);
    process_detector_xarg(d,xdports,DPORT,XARG_TYPE_UINT);
}

static void process_detector_xarg(netspade_detector *d,char *str,features feat,xarg_type_t type) {
    xfeatval_link *list,*list_tail;

    list= process_xarg(str,feat,type,d->parent->msg_callback,&list_tail);
    if (list == NULL) return;
    
    /* prepend this list onto the detector */
    list_tail->next= d->rpt_exclude_list;
    d->rpt_exclude_list= list;
}

static xfeatval_link *process_xarg(char *str,features feat,xarg_type_t type,spade_msg_fn msg_callback,xfeatval_link **tail) {
    xfeatval_link *list=NULL,*new;
    char *val;
    
    *tail= NULL;

    if (str == NULL || str[0] == '\0') return NULL;
    val= strtok(str,",");
    while (val != NULL) {
        new= new_xfeatval_link(feat,type,val);
        if (new == NULL) {
            if (type == XARG_TYPE_CIDR)
                formatted_spade_msg_send(SPADE_MSG_TYPE_WARNING,msg_callback,"could not parse %s as a IP or network to exclude for detector %s; skipping it");
            else
                formatted_spade_msg_send(SPADE_MSG_TYPE_WARNING,msg_callback,"could not parse %s as an unsigned integer to exclude for detector %s; skipping it");
            continue;
        }
        
        /* append */
        if (list == NULL) {
            list= new;
        } else {
            (*tail)->next= new;
        }
        *tail= new;
        
        val= strtok(NULL,",");
    }
    return list;
}

static xfeatval_link *new_xfeatval_link(features feat,xarg_type_t type,char *val) {
    xfeatval_link *new= (xfeatval_link *)malloc(sizeof(xfeatval_link));
    if (new == NULL) return NULL;
    
    new->feat= feat;
    new->type= type;
    new->next= NULL;
    
    if (type == XARG_TYPE_CIDR) {
        if (!cidr_to_netmask(val,&new->val.cidr.netip,&new->val.cidr.netmask)) {
            free(new);
            return NULL;
        }
    } else { // XARG_TYPE_UINT
        if (val[0] < '0' || val[0] > '9') {
            free(new);
            return NULL;
        }
        new->val.i= atoi(val);
    }
    return new;
}

static int pkt_is_excluded(xfeatval_link *list,spade_event *pkt) {
    xfeatval_link *x;
    for (x= list; x != NULL; x= x->next) {
        u32 pktval= pkt->fldval[x->feat];
        if ((x->type == XARG_TYPE_UINT)
            ? (x->val.i == pktval)
            : ((pktval & x->val.cidr.netmask) == x->val.cidr.netip)) { /* found one to exclude */
            return 1; 
        }
    }
    return 0;
}

static int cidr_to_netmask(char *str,u32 *netip,u32 *netmask) {
    char *sep;
    int masklen;
    struct in_addr net;
    char *strcopy= strdup(str);
    
    if ((sep= strchr(strcopy,'/')) == NULL) {
        masklen= 32;
    } else { 
        *sep= '\0'; // null terminate IP
        masklen = atoi(sep+1);
    }

    if ((masklen >= 0) && (masklen <= 32)) {
        *netmask = (~((u32)0))<<(32-masklen);
    } else {
        free(strcopy);
        return 0;
    }

    /* convert the IP addr into its 32-bit value */
    if ((net.s_addr = inet_addr(strcopy)) ==-1) {
        if (!strcmp(strcopy,"any")) {
            *netmask= 0;
            *netip= 0;
        } else {
            free(strcopy);
            return 0;
        }
    } else {
        *netip = (ntohl((u_long)net.s_addr) & *netmask);
    }
    free(strcopy);
    return 1;
}

/*@}*/

/* $Id: netspade.c,v 1.19 2003/01/17 19:37:00 jim Exp $ */