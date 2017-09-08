/*********************************************************************
anomscore_surveyer.h, distributed as part of Spade v030125.1
Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
copyright (c) 2002 by Silicon Defense (http://www.silicondefense.com/)
Released under GNU General Public License, see the COPYING file included
with the distribution or http://www.silicondefense.com/spice/ for details.

anomscore_surveyer.h is the header file for anomscore_surveyer.c

Please send complaints, kudos, and especially improvements and bugfixes to
hoagland@SiliconDefense.com.  As described in GNU General Public License, no
warranty is expressed for this program.
*********************************************************************/

/* Internal version control: $Id: anomscore_surveyer.h,v 1.6 2002/12/19 22:37:10 jim Exp $ */

#ifndef ANOMSCORE_SURVEYER_H
#define ANOMSCORE_SURVEYER_H

/*! \file anomscore_surveyer.h
 * \brief 
 *  anomscore_surveyer.h is the header file for anomscore_surveyer.c
 * \ingroup stmgr
 */

/*! \weakgroup stmgr
    @{
*/

#include "ll_double.h"
#include "spade_enviro.h"
#include "spade_output.h"
#include <time.h>
#include <stdio.h>

/// represents an instance of an anomscore_surveyer
typedef struct {
    /// the number of seconds in the survey interval
    float interval;
    /// the survey file name
    char *filename;

    /// the survey log file handle
    FILE *surveyfile;
    /// the list of anomaly scores for the survey
    ll_double *list;
    /// the length of the list (1-based)
    int list_len;
    /// the suvery period number (starts with 1)
    int period;
    
    /// the start time for this survey interval
    time_t interval_start_time;
    /// the number of packets seen in this survey period so far
    int rec_count;
} anomscore_surveyer;


int init_anomscore_surveyer(anomscore_surveyer *self, char *filename, float interval,spade_msg_fn msg_callback);
int init_anomscore_surveyer_from_str(anomscore_surveyer *self,char *str,spade_msg_fn msg_callback);
anomscore_surveyer *new_anomscore_surveyer(char *filename, float interval,spade_msg_fn msg_callback);
void anomscore_surveyer_flush(anomscore_surveyer *self);
void anomscore_surveyer_shutdown(anomscore_surveyer *self);
void anomscore_surveyer_new_time(anomscore_surveyer *self, spade_enviro *enviro);
void anomscore_surveyer_new_score(anomscore_surveyer *self, double anom_score);

void anomscore_surveyer_print_config_details(anomscore_surveyer *self,FILE *f,char *indent);

/*@}*/
#endif // ANOMSCORE_SURVEYER_H
