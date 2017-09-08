/*********************************************************************
score_mgr.h, distributed as part of Spade v030125.1
Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
copyright (c) 2002 by Silicon Defense (http://www.silicondefense.com/)
Released under GNU General Public License, see the COPYING file included
with the distribution or http://www.silicondefense.com/spice/ for details.

Please send complaints, kudos, and especially improvements and bugfixes to
hoagland@SiliconDefense.com.  As described in GNU General Public License, no
warranty is expressed for this program.
*********************************************************************/

/* Internal version control: $Id: score_mgr.h,v 1.8 2002/12/20 06:10:03 jim Exp $ */

#ifndef SCORE_MGR_H
#define SCORE_MGR_H

/*! \file score_mgr.h
 * \brief 
 *  score_mgr.h is the header file for score_mgr.c
 * \ingroup stmgr
 */

/*! \weakgroup stmgr
    @{
*/

#include <stdio.h>

#include "thresh_adviser.h"
#include "thresh_adapter.h"
#include "anomscore_surveyer.h"
//#include "spade_state.h"
#include "score_info.h"
#include "spade_event.h"
#include "spade_output.h"


#define ADVISING_OFF     0 ///< threshold advising status indicating the threshold advising was never on
#define ADVISING_RUNNING 1 ///< threshold advising status indicating the threshold advising is on and running
#define ADVISING_DONE    2 ///< threshold advising status indicating the threshold advising was on but has now completed

/// function type for a function to call when a score exceeds the reporting threshold
typedef void (*spade_thresh_exceeded_fn_t)(void *context,void *targetref,spade_event *event,score_info *score);
/// function type for a function to call when a reporting threshold changes
typedef void (*spade_thresh_changed_fn_t)(void *context,void *targetref);

// storage for an instance of a score manager
typedef struct {
    void *mgrref; ///< some sort of identifier of this score manager
    spade_enviro *enviro; ///< environment shared with target user
    
    int adapt_active; ///< 0 is there is no adapting; otherwise the adapt method #
    int advise_status; ///< ADVISING_OFF, ADVISING_RUNNING, or ADVISING_DONE
    int survey_active; ///< true if survey mode is active
    
    thresh_adapter adapter; ///< our threshold adapter module, if threshold adapting is in use
    thresh_adviser adviser; ///< our threshold advising module, if threshold advising is in use
    anomscore_surveyer surveyer; ///< our anomaly score surveyer module, if this is on
        
    /// function to call when we see a score that exceeds the threshold, or NULL if none
    spade_thresh_exceeded_fn_t threshexceeded_callback;
    /// function to call when the reporting threshold changes, or NULL if none
    spade_thresh_changed_fn_t threshchanged_callback;
    void *callback_context; ///< user-provided pointer that is returned as first arg in callback

    spade_msg_fn msg_callback; ///< function to call when there is a message for the user
} score_mgr;

score_mgr *new_score_mgr(void *mgrref, spade_enviro *enviro, void *callback_context, spade_thresh_exceeded_fn_t threshexceeded_callback, spade_thresh_changed_fn_t threshchanged_callback,spade_msg_fn msg_callback);
void init_score_mgr(score_mgr *self, void *mgrref, spade_enviro *enviro, void *callback_context, spade_thresh_exceeded_fn_t threshexceeded_callback, spade_thresh_changed_fn_t threshchanged_callback,spade_msg_fn msg_callback);

void score_mgr_setup_adapt_from_str(score_mgr *self, int adaptmode, char *str);
void score_mgr_setup_adapt1(score_mgr *self, int target, time_t period, float new_obs_weight, int by_count);
void score_mgr_setup_adapt2(score_mgr *self, double targetspec, double obsper, int NS, int NM, int NL);
void score_mgr_setup_adapt3(score_mgr *self, double targetspec, double obsper, int NO);
void score_mgr_setup_adapt4(score_mgr *self, double thresh, double obsper);
void score_mgr_setup_advise(score_mgr *self, int obs_size, int obs_secs);
void score_mgr_setup_advise_from_str(score_mgr *self, char *str);
void score_mgr_setup_survey(score_mgr *self, char *filename, float interval);
void score_mgr_setup_survey_from_str(score_mgr *self, char *str);

int score_mgr_new_time(score_mgr *self, time_t time);
void score_mgr_new_event(score_mgr *self, score_info *score, spade_event *event);

void score_mgr_dump(score_mgr *self);
void score_mgr_cleanup(score_mgr *self);
void score_mgr_file_print_log(score_mgr *self, FILE *file);

void score_mgr_print_config_details(score_mgr *self, FILE *file, char *indent);

/*@}*/
#endif // SCORE_MGR_H
