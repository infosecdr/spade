/*********************************************************************
thresh_adviser.c, distributed as part of Spade v030125.1
Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
copyright (c) 2002 by Silicon Defense (http://www.silicondefense.com/)
Released under GNU General Public License, see the COPYING file included
with the distribution or http://www.silicondefense.com/spice/ for details.

Please send complaints, kudos, and especially improvements and bugfixes to
hoagland@SiliconDefense.com.  As described in GNU General Public License, no
warranty is expressed for this program.
*********************************************************************/

/*! \file thresh_adviser.c
 * \brief 
 *  thresh_adviser.c contains a "class" thresh_adviser which takes
 *  observations of Spade anomaly scores and provides a recommendation
 *  about how to set the threshold to achieve a target rate.
 * \ingroup stmgr
 */

/*! \weakgroup stmgr
    @{
*/

#include "thresh_adviser.h"
#include "strtok.h"
#include "ll_double.h"
#include <stdlib.h>

void init_thresh_adviser(thresh_adviser *self,int obs_size,int obs_secs,spade_msg_fn msg_callback) {
    self->obs_size= obs_size;
    self->obs_secs= obs_secs;
    
    /* init list to contain just 0; this is to let us assume the list is not
       empty elsewhere */
    self->top_anom_list= (ll_double *)malloc(sizeof(ll_double));
    self->top_anom_list->next= NULL;
    self->top_anom_list->val= 0.0;
    self->top_anom_list_size= 1;
    
    self->obs_start_time= (time_t)0;
}

void init_thresh_adviser_from_str(thresh_adviser *self,char *str,spade_msg_fn msg_callback) {
    int obs_size=200,hours=24;
    void *args[2];
    time_t obs_secs;

    args[0]= &obs_size;
    args[1]= &hours;
    fill_args_space_sep(str,"i:target;i:obsper",args,msg_callback);

    obs_secs= (time_t)(hours*3600);
    init_thresh_adviser(self,obs_size,obs_secs,msg_callback);
}

thresh_adviser *new_thresh_adviser(int obs_size,int obs_secs,spade_msg_fn msg_callback) {
    thresh_adviser *new= (thresh_adviser *)malloc(sizeof(thresh_adviser));
    init_thresh_adviser(new,obs_size,obs_secs,msg_callback);
    return new;
}

void thresh_adviser_reset(thresh_adviser *self,int obs_size,int obs_secs,spade_msg_fn msg_callback) {
    free_ll_double_list(self->top_anom_list);
    init_thresh_adviser(self,obs_size,obs_secs,msg_callback);
}

void thresh_adviser_start_time(thresh_adviser *self,time_t time) {
    self->obs_start_time= time;
}

int thresh_adviser_new_time(thresh_adviser *self,spade_enviro *enviro) {
    if (self->obs_start_time == 0) { /* first time and start time not given */
        self->obs_start_time= enviro->now;
    } else if (enviro->now > (self->obs_start_time + self->obs_secs)) {
        return 1;
    }
    return 0;
}

void thresh_adviser_new_score(thresh_adviser *self,double anom_score) {
    ll_double *new,*prev,*l;
    
    if (self->top_anom_list_size <= self->obs_size) {
        new= (ll_double *)malloc(sizeof(ll_double));
        self->top_anom_list_size++;
    } else if (anom_score > self->top_anom_list->val) {
        if (self->top_anom_list->next == NULL ||
            (self->top_anom_list->next != NULL && anom_score < self->top_anom_list->next->val)) {
            self->top_anom_list->val= anom_score; /* can just replace first */
            return;
        }
        new= self->top_anom_list;
        self->top_anom_list= self->top_anom_list->next;
    } else {
        return;
    }
    new->val= anom_score;
    for (prev= self->top_anom_list, l=self->top_anom_list->next; l != NULL && anom_score > l->val; prev=l,l=l->next);
    /* add between prev and l */
    prev->next= new;
    new->next= l;   

    return; // not done yet
}

void thresh_adviser_write_advice(thresh_adviser *self,FILE *file) {
    ll_double *n;
    double obs_hours= self->obs_secs/3600.0;

    if (!self->obs_size || self->top_anom_list_size <= 1) return;

    fprintf(file,"Threshold learning results: top %d anomaly scores over %.5f hours\n",self->top_anom_list_size-1,obs_hours);
    fprintf(file,"  Suggested threshold based on observation: %.6f\n",(self->top_anom_list->val+self->top_anom_list->next->val)/2);
    fprintf(file,"  Top scores: %.5f",self->top_anom_list->next->val);
    for (n=self->top_anom_list->next->next; n != NULL; n=n->next) {
        fprintf(file,",%.5f",n->val);
    }
    fprintf(file,"\n  First runner up is %.5f, so use threshold between %.5f and %.5f for %.3f packets/hr\n",self->top_anom_list->val,self->top_anom_list->val,self->top_anom_list->next->val,(self->top_anom_list_size/obs_hours));    
}

void thresh_adviser_print_config_details(thresh_adviser *self, FILE *f, char *indent) {
    fprintf(f,"%sobs_size=%d; obs_secs=%d\n",indent,self->obs_size,(int)self->obs_secs);
}

/*@}*/
/* $Id: thresh_adviser.c,v 1.5 2002/12/19 22:37:10 jim Exp $ */
