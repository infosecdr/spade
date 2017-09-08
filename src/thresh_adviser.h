/*********************************************************************
thresh_adviser.h, distributed as part of Spade v030125.1
Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
copyright (c) 2002 by Silicon Defense (http://www.silicondefense.com/)
Released under GNU General Public License, see the COPYING file included
with the distribution or http://www.silicondefense.com/spice/ for details.

Please send complaints, kudos, and especially improvements and bugfixes to
hoagland@SiliconDefense.com.  As described in GNU General Public License, no
warranty is expressed for this program.
*********************************************************************/

/* Internal version control: $Id: thresh_adviser.h,v 1.7 2003/01/14 17:45:31 jim Exp $ */

#ifndef THRESH_ADVISER_H
#define THRESH_ADVISER_H

/*! \file thresh_adviser.h
 * \brief 
 *  thresh_adviser.h is the header file for thresh_adviser.c
 * \ingroup stmgr
 */

/*! \weakgroup stmgr
    @{
*/

#include <stdio.h>
#include "spade_enviro.h"
#include "ll_double.h"
#include "spade_output.h"

/// representation of a threshold adviser
typedef struct {
    int obs_size;  ///< the number of anomalous packets desired
    time_t obs_secs; ///< how long to observe for
    /// head of a linked list of the highest anomaly scores we've seen
    /** this list can be up to tl_obs_size+1 long and is ordered by increasing score; the list is initialized to 0 -> 0 in case we never see enough packets */
    ll_double *top_anom_list; 
    int top_anom_list_size; ///< the number of scores on the list (0-based)
    time_t obs_start_time; ///< the start time of the observation, set after the first packet we see
} thresh_adviser;


void init_thresh_adviser(thresh_adviser *self, int obs_size, int obs_secs, spade_msg_fn msg_callback);
void init_thresh_adviser_from_str(thresh_adviser *self, char *str, spade_msg_fn msg_callback);
thresh_adviser *new_thresh_adviser(int obs_size, int obs_secs, spade_msg_fn msg_callback);
void thresh_adviser_reset(thresh_adviser *self, int obs_size, int obs_secs, spade_msg_fn msg_callback);
void thresh_adviser_start_time(thresh_adviser *self, time_t time);
int thresh_adviser_new_time(thresh_adviser *self, spade_enviro *enviro);
void thresh_adviser_new_score(thresh_adviser *self, double anom_score);
void thresh_adviser_write_advice(thresh_adviser *self, FILE *file);

void thresh_adviser_print_config_details(thresh_adviser *self, FILE *f, char *indent);

/*@}*/
#endif // THRESH_ADVISER_H
