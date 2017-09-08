/*********************************************************************
netspade.h, distributed as part of Spade v030125.1
Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
copyright (c) 2002 by Silicon Defense (http://www.silicondefense.com/)
Released under GNU General Public License, see the COPYING file included
with the distribution or http://www.silicondefense.com/spice/ for details.

Please send complaints, kudos, and especially improvements and bugfixes to
hoagland@SiliconDefense.com.  As described in GNU General Public License, no
warranty is expressed for this program.
*********************************************************************/

/* Internal version control: $Id: netspade.h,v 1.14 2002/12/20 06:10:03 jim Exp $ */

/*! \file netspade.h
 * \brief 
 *  netspade.h is the header file for the netspade "class"
 * \ingroup netspade_layer
 */

/*! \addtogroup netspade_layer
    @{
*/

#ifndef NETSPADE_H
#define NETSPADE_H

#include "netspade_features.h"
#include "spade_detection_types.h"
#include "score_mgr.h"
#include "spade_event.h"
#include "spade_report.h"
#include "score_calculator.h"
#include "packet_resp_canceller.h"
#include "event_recorder.h"
#include "spade_output.h"


typedef void (*netspade_exc_callback_t)(void *context,spade_report *rpt);
typedef void (*netspade_adj_callback_t)(void *context,char *id,char *mess,int using_corrrscore);

/// the type of xarg_type_t node value; either unsigned int or CIDR
typedef enum {XARG_TYPE_UINT,XARG_TYPE_CIDR} xarg_type_t;

/// an administatively excluded field value; this results from Xdips, Xsports, etc
typedef struct _xfeatval_link {
    features feat; ///< the field the restriction is on
    xarg_type_t type;  /// the type of the value for this restriction
    union {
        int i; /// the value to exclude, if type=XARG_TYPE_UINT
        struct {
            u32 netip; /// the network IP address in the CIDR
            u32 netmask;  /// the netmask in the CIDR
        } cidr; /// the network to exclude, if type=XARG_TYPE_CIDR
    } val;
    struct _xfeatval_link *next; /// the next element in a linked list of this type
} xfeatval_link;

struct _netspade;

/// encapsulates the state specific to a netspade detector
typedef struct _netspade_detector {
    /// the next netspade_detector in a linked list of them
    struct _netspade_detector *next;
    struct _netspade* parent;
    /// the id for this detector
    char *id;

    /// the type of detector this is; value is from spade_detect_types.h
    int detect_type;
    /// the packet conditions under which this detector will calculate the score and assess anomalousness
    event_condition_set scorecalc_conds;
    /// should this detector ignore packets with destination IPs that are broadcast IP addresses
    int exclude_broadcast_dip;
    /// if the detector is doing response waiting, this is the implication of a timeout
    port_status_t thresh_exc_port_impl;

    /// the packet conditions under which this detector will store an event in the probability table
    event_condition_set store_conds;
    /// the packet conditions for which this detector will check for a response in the open direction
    event_condition_set cancel_open_conds;
    /// the packet conditions for which this detector will check for a response in the closed direction
    event_condition_set cancel_closed_conds;
    /// the criterea required for a anomalous event to be reported (versus dropped)
    port_status_set_t port_report_criterea;
    
    /// the libspade entity which calculates anomaly scores
    score_calculator calculator;
    /// the libspade score manager
    score_mgr mgr;
    /// if non-NULL, the packet response canceller in use
    packet_resp_canceller *canceller;

    /// the shared state with the score manager
    spade_enviro enviro;
    /// the packet stats as of the last time the anomaly score was adjusted
    spade_pkt_stats last_adj_stats;
    
    /// a linked list of reports to exclude in this detector; suppliments netspade's global list
    xfeatval_link *rpt_exclude_list;

    /// \brief the detection type we report for this detector
    /// \note eventually, there may be more than one detection type possible from a given detector, so this will need to be generalized
    int report_detection_type;
    /// the string encoding the scope of this detector; used in building reports
    char *report_scope_str; 
} netspade_detector;

/// a link in a linked list of networks
typedef struct _ll_net {
    u32 netaddr; ///< the network address
    u32 netmask; ///< the network mask
    struct _ll_net *next;  ///< the next link in a linked list of networks
} ll_net;

/// a instance of netspade
typedef struct _netspade {
    /// the head of a linked list of detectors contained in this netspade
    netspade_detector *detectors;
    /// the tail of the linked list of detectors
    netspade_detector *detectors_tail;
    /// the packet conditions under which we need to pass an event to our event_recorder
    event_condition_set recorder_needed_conds;
    /// the packet conditions under which we need to do something besides storing a packet
    event_condition_set nonstore_conds;
    /// the the packet conditions that we actually need to calculate for any given packet
    event_condition_set conds_to_calc;

    ll_net *homelist_head; ///< the head a linked list of home networks
    ll_net *homelist_tail; ///< the tail in a linked list of home networks 

    char *checkpoint_file; ///< the name of the file to checkpoint to
    int checkpoint_freq; ///< the frequency (in recorded packet counts) with which to checkpoint

    /// records how many things have been recorded since the last checkpoint
    int records_since_checkpoint;
    /// the last packet time that we passed along to the enties that need it
    time_t last_time_forwarded;
    
    /// the callback to invoke when there is an anomalous event
    netspade_exc_callback_t exc_callback;
    /// the callback to invoke when the threshold has been adjusted in a detector, or NULL if none should be called
    netspade_adj_callback_t adj_callback;
    /// the netspade-user-defined context to provide with the callback
    void *callback_context;
    
    /// a pointer to a routine to call to make a copy of the "native" field of a spade_event, or NULL if none is needed
    /** this is used when a spade_event is being copied for storage in the response buffer (packet reponse canceller) */
    event_native_copier_t pkt_native_copier_callback;
    /// a pointer to a routine to call free a copy of the "native" field of a spade_event, or NULL if none is needed
    /** this is used when a copied spade_event is being freed when it is being removed from the packet reponse canceller */
    event_native_freer_t pkt_native_freer_callback;
    
    xfeatval_link *rpt_exclude_list; ///< a linked list of reports to exclude globally

    event_recorder recorder; ///< our event recorder

    u8 stats_to_print; ///< the statistics to print to the output log file
    char *outfile; ///< the name of the output log file

    int debug_level;  ///< the debug level we are at (bigger is higher/more verbose)
    spade_msg_fn msg_callback; ///< the function to call when we have a text message for the user
    
    int detector_id_nonce;  ///< the default detector id for the last detector that was set up
    unsigned long total_pkts; ///< the total number of packets passed to us
} netspade;


void init_netspade(netspade *self, spade_msg_fn msg_callback, int debug_level);
int init_netspade_from_statefile(netspade *self, char *statefile, spade_msg_fn msg_callback, int debug_level);
netspade *new_netspade(spade_msg_fn msg_callback, int debug_level);
netspade *new_netspade_from_statefile(char *statefile, spade_msg_fn msg_callback, int debug_level,int *succ);

void netspade_set_callbacks(netspade *self, void *context, netspade_exc_callback_t exc_callback, netspade_adj_callback_t adj_callback, event_native_copier_t pkt_native_copier_callback, event_native_freer_t pkt_native_freer_callback);
void netspade_set_checkpointing(netspade *self, char *checkpoint_file, int checkpoint_freq);
void netspade_set_homenet_from_str(netspade *self, char *homenet_str);
void netspade_set_output_stats(netspade *self, int stats_to_print);
void netspade_set_output_stats_from_str(netspade *self, char *str);
int netspade_set_output(netspade *self, char *file, int stats_to_print);
int netspade_set_output_file(netspade *self, char *file);
void netspade_add_rpt_excludes(netspade *self,char *xsips,char *xdips,char *xsports,char *xdports);

char *netspade_new_detector(netspade *self, char *str);

int netspade_set_detector_scaling(netspade *self, char *detectorid, int scale_freq, double scale_factor, double prune_threshold);
char *netspade_setup_detector_adapt_from_str(netspade *self, int adaptmode, char *str);
int netspade_setup_detector_adapt1(netspade *self, char *detectorid, int adapttarget, time_t period, float new_obs_weight, int by_count);
int netspade_setup_detector_adapt2(netspade *self, char *detectorid, double targetspec, double obsper, int NS, int NM, int NL);
int netspade_setup_detector_adapt3(netspade *self, char *detectorid, double targetspec, double obsper, int NO);
int netspade_setup_detector_advise(netspade *self, char *detectorid, int obs_size, int obs_secs);
char *netspade_setup_detector_advise_from_str(netspade *self, char *str);
int netspade_setup_detector_survey(netspade *self, char *detectorid, char *filename, float interval);
char *netspade_setup_detector_survey_from_str(netspade *self, char *str);

void netspade_new_pkt(netspade *self, spade_event *pkt);

void netspade_dump(netspade *self);
void netspade_cleanup(netspade *self);
void netspade_write_log(netspade *self);

char *netspade_detector_scope_str(netspade *self,char *id);

int netspade_print_detector_config_details(netspade *self,FILE *f,char *id);

void print_conds(event_condition_set conds);
void print_conds_line(event_condition_set conds);

/*@}*/

#endif // NETSPADE_H
