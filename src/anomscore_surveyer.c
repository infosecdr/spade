/*********************************************************************
anomscore_surveyer.c, distributed as part of Spade v030125.1
Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
copyright (c) 2002 by Silicon Defense (http://www.silicondefense.com/)
Released under GNU General Public License, see the COPYING file included
with the distribution or http://www.silicondefense.com/spice/ for details.

Please send complaints, kudos, and especially improvements and bugfixes to
hoagland@SiliconDefense.com.  As described in GNU General Public License, no
warranty is expressed for this program.
*********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "anomscore_surveyer.h"
#include "strtok.h"
#include "ll_double.h"

/*! \file anomscore_surveyer.c
 * \brief 
 *  anomscore_surveyer.c contains a class to do a survey of anomaly scores
 * \ingroup stmgr
 */

/*! \addtogroup stmgr Score and threshold management
    @{
*/

static double survey_ostat(anomscore_surveyer *self, double loc);

int init_anomscore_surveyer(anomscore_surveyer *self,char *filename,float interval,spade_msg_fn msg_callback) {
    if (filename == NULL) filename="-";
    if (!strcmp(filename,"-")) {
        self->surveyfile= stdout;
    } else {
        self->surveyfile= fopen(filename,"w");
    }
    if (!self->surveyfile) return 0;

    self->interval= interval;
    self->filename= strdup(filename);
    self->list= NULL;
    self->list_len= 0;
    self->period= 1;
    self->interval_start_time= (time_t)0;
    self->rec_count= 0;
    
    fprintf(self->surveyfile,"%.2f minute interval #\tPacket Count\tMedian Anom\t90th Percentile Anom\t99th Percentile Anom\n",self->interval/60.0);

    return 1;
}

int init_anomscore_surveyer_from_str(anomscore_surveyer *self,char *str,spade_msg_fn msg_callback) {
    char filename[400]= "-";
    float interval=60.0;
    void *args[2];

    args[0]= &filename;
    args[1]= &interval;
    fill_args_space_sep(str,"s400:surveyfile;f:interval",args,msg_callback);

    interval*= 60.0;
    return init_anomscore_surveyer(self,filename,interval,msg_callback);
}

anomscore_surveyer *new_anomscore_surveyer(char *filename,float interval,spade_msg_fn msg_callback) {
    anomscore_surveyer *new= (anomscore_surveyer *)malloc(sizeof(anomscore_surveyer));
    init_anomscore_surveyer(new,filename,interval,msg_callback);
    return new;
}

void anomscore_surveyer_flush(anomscore_surveyer *self) {
    fflush(self->surveyfile);
}

void anomscore_surveyer_shutdown(anomscore_surveyer *self) {
    fclose(self->surveyfile);
}

void anomscore_surveyer_new_time(anomscore_surveyer *self,spade_enviro *enviro) {
    while (enviro->now > (self->interval_start_time + self->interval)) {
        if (self->interval_start_time == 0) { /* first packet */
            self->interval_start_time= enviro->now;
        } else {
            fprintf(self->surveyfile,"%d\t%d\t%.6f\t%.6f\t%.6f\n",self->period,self->rec_count,survey_ostat(self,0.5),survey_ostat(self,0.9),survey_ostat(self,0.99));
            fflush(self->surveyfile);
            if (self->list) 
                free_ll_double_list(self->list);
            self->list= NULL;
            self->list_len= 0;
            self->rec_count=0;
            self->period++;
            self->interval_start_time+= (long) self->interval;
        }
    }
}

void anomscore_surveyer_new_score(anomscore_surveyer *self,double anom_score) {
    ll_double *new,*prev,*next;

    new= new_ll_double(anom_score);
    
    if (self->list == NULL) {
        self->list= new;
        self->list_len= 1;
    } else {
        if (anom_score < self->list->val) { /* add at head */
            new->next= self->list;
            self->list= new;
        } else {
            for (prev= self->list, next=self->list->next; next != NULL && anom_score > next->val; prev=next,next=next->next);
            /* add between prev and next */
            prev->next= new;
            new->next= next;    
        }
        self->list_len++;
    }

    self->rec_count++;
}   

static double survey_ostat(anomscore_surveyer *self,double loc) {
    ll_double *pos;
    int p;
    double fromnext;
    double posnum;
    
    if (self->list_len == 0) return 0.0;
    posnum= loc*(double)self->list_len + (1.0-loc);/* = (self->list_len-1)*loc+1 */

    for (p= 1, pos=self->list; p <= posnum && pos->next != NULL; p++,pos=pos->next);
    fromnext= posnum-(double)(p-1);
    if (fromnext == 0.0 || pos->next == NULL) { /* got it exactly */
        return pos->val;
    } else {
        return (pos->val*(1-fromnext))+(pos->next->val*fromnext);
    }
}

void anomscore_surveyer_print_config_details(anomscore_surveyer *self,FILE *f,char *indent) {
    fprintf(f,"%sinterval=%.2f; filename=%s\n",indent,self->interval,self->filename);
}

/*@}*/
/* $Id: anomscore_surveyer.c,v 1.5 2002/12/19 22:37:10 jim Exp $ */
