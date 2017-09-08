/*********************************************************************
score_mgr.c, distributed as part of Spade v030125.1
Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
copyright (c) 2002 by Silicon Defense (http://www.silicondefense.com/)
Released under GNU General Public License, see the COPYING file included
with the distribution or http://www.silicondefense.com/spice/ for details.

Please send complaints, kudos, and especially improvements and bugfixes to
hoagland@SiliconDefense.com.  As described in GNU General Public License, no
warranty is expressed for this program.
*********************************************************************/


/*! \file score_mgr.c
 * \brief 
 *  score_mgr.c contains the "class" score_mgr which is a spade
 *  probability table along with a reporting threshold and the
 *  other accompaniments of applying the Spade approach to somewhere.
 * \ingroup stmgr
 */

/*! \addtogroup stmgr Score and threshold management
 * \brief this group contains objects to manaage anomaly scores and reporting thresholds
 * \ingroup libspade
    @{
*/

#include "score_mgr.h"
#include "strtok.h"
#include <stdio.h>
#include <stdlib.h>

score_mgr *new_score_mgr(void *mgrref,spade_enviro *enviro,void *callback_context,spade_thresh_exceeded_fn_t threshexceeded_callback,spade_thresh_changed_fn_t threshchanged_callback,spade_msg_fn msg_callback) {
    score_mgr *new= (score_mgr *)malloc(sizeof(score_mgr));
    init_score_mgr(new,mgrref,enviro,callback_context,threshexceeded_callback,threshchanged_callback,msg_callback);
    return new;
}

/* caller must set enviro->thresh already; we'll keep a pointer to the enviro */
void init_score_mgr(score_mgr *self,void *mgrref,spade_enviro *enviro, void *callback_context, spade_thresh_exceeded_fn_t threshexceeded_callback, spade_thresh_changed_fn_t threshchanged_callback,spade_msg_fn msg_callback) {
    self->mgrref= mgrref;
    self->enviro= enviro;

    self->threshexceeded_callback= threshexceeded_callback;
    self->threshchanged_callback= threshchanged_callback;
    self->callback_context= callback_context != NULL ? callback_context : self;
    
    self->msg_callback= msg_callback;
   
    self->adapt_active= 0;
    self->advise_status= ADVISING_OFF;
    self->survey_active= 0;
}

void score_mgr_setup_adapt_from_str(score_mgr *self,int adaptmode,char *str) {
    self->adapt_active= 1;
    init_thresh_adapter(&self->adapter,self->msg_callback);
    thresh_adapter_setup_from_str(&self->adapter,adaptmode,str);
}

void score_mgr_setup_adapt1(score_mgr *self,int target, time_t period, float new_obs_weight, int by_count) {
    self->adapt_active= 1;
    init_thresh_adapter(&self->adapter,self->msg_callback);
    thresh_adapter_setup_1(&self->adapter,target,period,new_obs_weight,by_count);
}

void score_mgr_setup_adapt2(score_mgr *self,double targetspec, double obsper, int NS, int NM, int NL) {
    self->adapt_active= 2;
    init_thresh_adapter(&self->adapter,self->msg_callback);
    thresh_adapter_setup_2(&self->adapter,targetspec,obsper,NS,NM,NL);
}

void score_mgr_setup_adapt3(score_mgr *self,double targetspec, double obsper, int NO) {
    self->adapt_active= 3;
    init_thresh_adapter(&self->adapter,self->msg_callback);
    thresh_adapter_setup_3(&self->adapter,targetspec,obsper,NO);
}

void score_mgr_setup_adapt4(score_mgr *self,double thresh, double obsper) {
    self->adapt_active= 4;
    init_thresh_adapter(&self->adapter,self->msg_callback);
    thresh_adapter_setup_4(&self->adapter,thresh,obsper);
}

void score_mgr_setup_advise(score_mgr *self,int obs_size, int obs_secs) {
    self->advise_status= ADVISING_RUNNING;
    init_thresh_adviser(&self->adviser,obs_size,obs_secs,self->msg_callback);
}

void score_mgr_setup_advise_from_str(score_mgr *self,char *str) {
    self->advise_status= ADVISING_RUNNING;
    init_thresh_adviser_from_str(&self->adviser,str,self->msg_callback);
}

void score_mgr_setup_survey(score_mgr *self,char *filename,float interval) {
    self->survey_active= 1;
    init_anomscore_surveyer(&self->surveyer,filename,interval,self->msg_callback);
}

void score_mgr_setup_survey_from_str(score_mgr *self,char *str) {
    self->survey_active= 1;
    init_anomscore_surveyer_from_str(&self->surveyer,str,self->msg_callback);
}



int score_mgr_new_time(score_mgr *self,time_t time) {
    int advising_completed= 0;
    // a new second
    self->enviro->now= time;

    // tell our helpers
    if (self->adapt_active) {
        double new_thresh;
        if (thresh_adapter_new_time(&self->adapter,self->enviro,&new_thresh)) {
            // there is a new threshold
            self->enviro->thresh= new_thresh;
            if (self->threshchanged_callback != NULL)
                (*(self->threshchanged_callback))(self->callback_context,self->mgrref);
        }
    }
    if (self->advise_status == ADVISING_RUNNING) {
        if (thresh_adviser_new_time(&self->adviser,self->enviro)) {
            // advising period has completed
            self->advise_status= ADVISING_DONE;
            advising_completed= 1;
        }
    }
    if (self->survey_active) anomscore_surveyer_new_time(&self->surveyer,self->enviro);
    return advising_completed;
}

void score_mgr_new_event(score_mgr *self,score_info *score,spade_event *event) {
    double mainscore= score_info_mainscore(score);

    //if (self->debug_level > 1) printf("%p: packet #%d: %.4f\n",self,self->enviro->pkt_stats.scored,mainscore);
    if (self->enviro->thresh >= 0.0 && mainscore >= self->enviro->thresh) {
        if (self->threshexceeded_callback != NULL)
            (*(self->threshexceeded_callback))(self->callback_context,self->mgrref,event,score);
    }

    if (self->adapt_active) thresh_adapter_new_score(&self->adapter,mainscore);
    if (self->advise_status == ADVISING_RUNNING) thresh_adviser_new_score(&self->adviser,mainscore);
    if (self->survey_active) anomscore_surveyer_new_score(&self->surveyer,mainscore);
}

void score_mgr_dump(score_mgr *self) 
{
    if (self->survey_active) anomscore_surveyer_flush(&self->surveyer);
}

void score_mgr_cleanup(score_mgr *self) 
{
    score_mgr_dump(self);
}

void score_mgr_file_print_log(score_mgr *self,FILE *file) {
    if (self->advise_status != ADVISING_OFF) thresh_adviser_write_advice(&self->adviser,file);
}

void score_mgr_print_config_details(score_mgr *self, FILE *f, char *indent) {
    char indent2[100];
    sprintf(indent2,"%s  ",indent);
    fprintf(f,"%scurrent thresh=%.4f\n",indent,self->enviro->thresh);
    if (self->adapt_active) {
        fprintf(f,"%sadapt_active=%d:\n",indent,self->adapt_active);
        thresh_adapter_print_config_details(&self->adapter,f,indent2);
    }
    if (self->advise_status != ADVISING_OFF) {
        fprintf(f,"%sadvise_status=%s:\n",indent,self->adapt_active == ADVISING_RUNNING ? "ADVISING_RUNNING" : "ADVISING_DONE");
        thresh_adviser_print_config_details(&self->adviser,f,indent2);
    }
    if (self->survey_active) {
        fprintf(f,"%ssurvey_active=\n",indent);
        anomscore_surveyer_print_config_details(&self->surveyer,f,indent2);
    }
}

/*@}*/
/* $Id: score_mgr.c,v 1.6 2002/12/19 22:37:10 jim Exp $ */