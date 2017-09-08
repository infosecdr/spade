/*********************************************************************
event_recorder.h, distributed as part of Spade v030125.1
Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
copyright (c) 2002 by Silicon Defense (http://www.silicondefense.com/)
Released under GNU General Public License, see the COPYING file included
with the distribution or http://www.silicondefense.com/spice/ for details.

Please send complaints, kudos, and especially improvements and bugfixes to
hoagland@SiliconDefense.com.  As described in GNU General Public License, no
warranty is expressed for this program.
*********************************************************************/

/* Internal version control: $Id: event_recorder.h,v 1.8 2003/01/23 17:41:21 jim Exp $ */

#ifndef EVENT_RECORDER_H
#define EVENT_RECORDER_H

/*! \file event_recorder.h
 * \brief 
 *  event_recorder.h is the header file for event_recorder.c
 * \ingroup staterec
 */

/*! \addtogroup staterec
    @{
*/

#include "spade_event.h"
#include "spade_prob_table.h"
#include "spade_state.h"
#include "spade_prob_table_types.h"
#include "spade_features.h"

#include <stdio.h>

/// a set of event conditions
/** An event condition is a boolean condition on a spade_event; it is true
    if the condition is satisfied and false otherwise.  All regular event
    conditions are defined by the libspade user.  event_condition_set
    represents a set of conditions which are simulatneously true for an
    event.  This is presently represented as a u32 bit-mask, which is
    operationally very efficient but which has its limits including only
    being able to represent 32 conditions and permitting only boolean
    conditions */
typedef u32 event_condition_set;
/// macro to get at event condition #n
#define EVENT_CONDITION_NUM(n) (1 << (n-1))
/// the special true event condition
#define EVENT_CONDITION_TRUE 0
/// the special false event condition
#define EVENT_CONDITION_FALSE EVENT_CONDITION_NUM(32)

/// are all conditions in the event_condition_set ref met in the testcase event_condition_set
#define ALL_CONDS_MET(testcase,ref) (((testcase) & (ref)) == (ref))
/// is at least one of the conditions in ref met in the testcase
#define SOME_CONDS_MET(testcase,ref) ((testcase) & (ref))
/// add newconds to event_condition_set var
#define ADD_TO_CONDS(var,newconds) ((var) |= (newconds))
/// remove remconds from the event_condition_set var
#define REMOVE_FROM_CONDS(var,remconds) ((var) &= ~remconds)
/// compose a condition set (returned) from N event conditions
#define CONDS_PLUS_CONDS(cond1,cond2) (cond1 | cond2)
#define CONDS_PLUS_2CONDS(cond1,cond2,cond3) (cond1 | cond2 | cond3)
#define CONDS_PLUS_3CONDS(cond1,cond2,cond3,cond4) (cond1 | cond2 | cond3 | cond4)
#define CONDS_PLUS_4CONDS(cond1,cond2,cond3,cond4,cond5) (cond1 | cond2 | cond3 | cond4 | cond5)
#define CONDS_PLUS_5CONDS(cond1,cond2,cond3,cond4,cond5,cond6) (cond1 | cond2 | cond3 | cond4 | cond5 | cond6)
#define CONDS_PLUS_6CONDS(cond1,cond2,cond3,cond4,cond5,cond6,cond7) (cond1 | cond2 | cond3 | cond4 | cond5 | cond6 | cond7)
/// return the event_condition_set formed by removing cond2 from cond1
#define CONDS_MINUS_CONDS(cond1,cond2) (cond1 & ~cond2)
/// test if the condition set indicates false
#define CONDS_NOT_FALSE(conds) (((conds) & EVENT_CONDITION_FALSE) == 0)
/// return the event_condition_set formed by restricting cond1 to only those conditions in cond2
#define ONLY_CONDS(origconds,onlyconds) ((origconds) & onlyconds)


/// structure containing the elements of a table manager
typedef struct _table_mgr {
    spade_prob_table table; ///< the probability table we use
    struct _table_mgr *next; ///< the next table manager in a linked list of them
    time_t last_scale; ///< the last time this table was scaled/pruned
    u32 store_count; ///< the number of events we have stored
    
    feature_list feats; ///< the features we store, in order
    const char **featurenames; ///< direct-index lookup array to map features to their names
    
    event_condition_set conds; ///< the event conditions under which this table is used for storage
    time_t start_time; ///< the time we started recording events
    int scale_freq; ///< how often we scale/prune, in secs
    double scale_factor; ///< when we scale, how much do we do so?; this is the multiplier
    double prune_threshold;  ///< if an observation gets below this size, it gets discarded
    int use_count; ///< how many event files are using this table manager
} table_mgr;

/// structure containing the elements on an event file
typedef struct _evfile {
    /// the table manager that does the storge for this event file
    table_mgr *mgr;
    /// this how many features deep we care about; table manager may store more for other reasons
    int feat_depth;
    /// the features we need stored, in order
    feature_list calc_feats; /*!< \note maybe eventually we should maintain a user-addressable set of these */

    /// the next event file in a linked list of them
    struct _evfile *next;
} evfile;

/// the way a event_recorder user refers to a particular event file
typedef evfile *evfile_ref;

/// the representation for an instance of an event_recorder
typedef struct {
    /// linked list of the table managers that are defined
    table_mgr *tables;
    /// linked list of the event files that are defined
    evfile *files;
    /// the current time
    time_t curtime;
} event_recorder;

/// function type that can be called to print the string version of a set of event conditions to a FILE *
typedef void (*condition_printer_t)(FILE *file,event_condition_set conds);


event_recorder *new_event_recorder(void);
void init_event_recorder(event_recorder *self);

int event_recorder_recover(event_recorder **self, statefile_ref *ref);
int event_recorder_merge_recover(event_recorder *self, statefile_ref *ref);
int event_recorder_checkpoint(event_recorder *self, statefile_ref *ref);

evfile_ref event_recorder_new_event_file(event_recorder *self, feature_list *feats, const char **featurenames, event_condition_set conds, int scale_freq, double scale_factor, double prune_threshold, int fresh_only, feature_list *calc_feats);
evfile_ref *event_recorder_new_event_files(event_recorder *self, int howmany, feature_list feats[], const char **featurenames, event_condition_set conds, int scale_freq, double scale_factor, double prune_threshold, int fresh_only);

void event_recorder_new_time(event_recorder *self, time_t time);
event_condition_set event_recorder_needed_conds(event_recorder *self);
int event_recorder_new_event(event_recorder *self, spade_event *event, event_condition_set matching_conds);
void event_recorder_prune_unused(event_recorder *self);

double event_recorder_get_prob(event_recorder *self, evfile_ref eventfile, spade_event *event,int one_more);
double event_recorder_get_condprob(event_recorder *self, evfile_ref eventfile, spade_event *event, int condcutoff,int one_more);
double event_recorder_get_count(event_recorder *self, evfile_ref eventfile, spade_event *event, int featdepth);
double event_recorder_get_entropy(event_recorder *self,evfile_ref eventfile,spade_event *event,int entropy_prefix_len);

int event_recorder_get_store_count(event_recorder *self, evfile_ref eventfile);
double event_recorder_get_obs_count(event_recorder *self, evfile_ref eventfile);

void event_recorder_write_stats(event_recorder *self, FILE *file, u8 stats_to_print,condition_printer_t condprinter);

void evfile_print_config_details(evfile_ref eventfile,FILE *f,char *indent);
#endif // EVENT_RECORDER_H
