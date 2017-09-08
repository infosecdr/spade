/*********************************************************************
thresh_adapter.h, distributed as part of Spade v030125.1
Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
copyright (c) 2002 by Silicon Defense (http://www.silicondefense.com/)
Released under GNU General Public License, see the COPYING file included
with the distribution or http://www.silicondefense.com/spice/ for details.

thresh_adapter.h is the header file for thresh_adapter.c

Please send complaints, kudos, and especially improvements and bugfixes to
hoagland@SiliconDefense.com.  As described in GNU General Public License, no
warranty is expressed for this program.
*********************************************************************/

/* Internal version control: $Id: thresh_adapter.h,v 1.7 2003/01/14 17:45:31 jim Exp $ */

#ifndef THRESH_ADAPTER_H
#define THRESH_ADAPTER_H

/*! \file thresh_adapter.h
 * \brief 
 *  thresh_adapter.h is the header file for thresh_adapter.c
 * \ingroup stmgr
 */

/*! \weakgroup stmgr
    @{
*/

#include "dll_double.h" 
#include "ll_double.h" 
#include "spade_enviro.h" 
#include "spade_output.h"
#include <stdio.h>
#include <time.h>

/// structure to hold the data for adapt mode #1
typedef struct {
    /// the number of alerts that is ideal for the given length of time
    int target;
    /// the length of time in which to ideally produce the given number of alerts; also the interval at which to adjust the report threshold
    time_t period;
    /// the weight to give to the new observation ideal cutoff in determining the new weight
    float new_obs_weight;
    /// adapt by count or by time only
    int by_count;
    
    /// the head of the list of anomaly scores.
    ll_double *top_list;
    /// the current size of this list (0-based)
    int top_list_size;
} adapt1_data;

/// structure to hold the data for adapt mode #2
typedef struct {
    /// the specification of the target
    double targetspec;
    /// the observation period
    double obsper;
    /// the number of short periods in a medium period
    int NS;
    /// the number of medium periods in a long period
    int NM;
    /// the number of long periods to average over
    int NL;
    
    /// the current target based on targetspec
    int target;
    /// latest medium term component
    double mid_anom_comp;
    /// latest long term component
    double long_anom_comp;
    /// an array of heads of observation linked lists
    dll_double **obslists_head;
    /// an array of tails of the observation linked lists
    dll_double **obslists_tail;
    /// an array of the (0-based) size of these lists
    int *obslists_size;
    /// the number of complete observation periods
    int obsper_count;
    /// arrays of short and medium term components used for calculating other components
    double *recScomps,*recMcomps;

    /// the start time of the current observation period
    time_t obsper_start;
    /// which obslist to add to, aka, obsper_count % NS
    int obslist_new_slot;

    // the count of period 2 instances
    int per2_count;
    // the count of period 3 instances
    int per3_count; 
} adapt2_data;

/// structure to hold the data for adapt mode #3
typedef struct {
    /// the specification of the target
    double targetspec;
    /// the observation period
    double obsper;
    /// the number of observation period results to average together
    int NO;
    
    /// the current target based on targetspec
    int target;
    /// array of past observations
    double *hist;
    /// a linked list of anomaly scores from the current period
    ll_double *anoms;
    /// (0-based) size of this list
    int anoms_size;
    /// number of completed observation periods
    int completed_obs_per;
    
    double obssum; ///< the sum of all current elements in the array
} adapt3_data;
 
/// structure to hold the data for adapt mode #4
typedef struct {
    double thresh; ///< the threshold to change to
} adapt4_data;

/// the representation of a threshold adapter
typedef struct {
    /// the adapt mode number
    int adapt_mode;
    /// the adapt-type specific storage; the union is selected by adapt_mode
    union {
        adapt1_data a1;
        adapt2_data a2;
        adapt3_data a3;
        adapt4_data a4;
    } d;
    
    /// adapt by count or by time only
    int adapt_by_count;
    
    /// the total count of packets at the start of the observation period
    int last_total_stats;
    /// how often (in secs) to recalc packet rate and to trigger adapting
    time_t adapt_period; 
    /// how many packet periods have occurred
    int pkt_period_count;
    /// the time this period started
    time_t period_start;
    /// the rate of all packets in the adapt period; used to decide when to adapt
    float period_pkt_rate;
    /// rate of accepted packets in the adapt period; sometimes used to determine target rate of reports
    float period_acc_rate; 
    /// are we done adapting?
    int done;
    /// the function to call to provide a message to the user
    spade_msg_fn msg_callback;
} thresh_adapter;


void init_thresh_adapter(thresh_adapter *self,spade_msg_fn msg_callback);
thresh_adapter *new_thresh_adapter(spade_msg_fn msg_callback);
void thresh_adapter_setup_from_str(thresh_adapter *self,int adaptmode,char *str);
void thresh_adapter_setup_1(thresh_adapter *self, int target, time_t period, float new_obs_weight, int by_count);
void thresh_adapter_setup_2(thresh_adapter *self, double targetspec, double obsper, int NS, int NM, int NL);
void thresh_adapter_setup_3(thresh_adapter *self, double targetspec, double obsper, int NO);
void thresh_adapter_setup_4(thresh_adapter *self, double thresh, double obsper);
void thresh_adapter_start_time(thresh_adapter *self, time_t now);
int thresh_adapter_new_time(thresh_adapter *self, spade_enviro *enviro, double *sugg_thresh);
void thresh_adapter_new_score(thresh_adapter *self, double anom_score);

void thresh_adapter_print_config_details(thresh_adapter *self,FILE *f,char *indent);

/*@}*/
#endif // THRESH_ADAPTER_H
