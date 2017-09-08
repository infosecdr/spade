/*********************************************************************
score_calculator.c, distributed as part of Spade v030125.1
Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
copyright (c) 2002 by Silicon Defense (http://www.silicondefense.com/)
Released under GNU General Public License, see the COPYING file included
with the distribution or http://www.silicondefense.com/spice/ for details.

Please send complaints, kudos, and especially improvements and bugfixes to
hoagland@SiliconDefense.com.  As described in GNU General Public License, no
warranty is expressed for this program.
*********************************************************************/

/*! \file score_calculator.c
 * \brief 
 *  score_calculator.c contains a module to store the details about how
 *  to calculate an anomaly score
 * \ingroup scoreprod
 */

/*! \addtogroup scoreprod Anomaly score production
 * \brief this group contains objects to produce and represent anomaly scores
 * \ingroup libspade
    @{
*/

#include <stdlib.h>
#include <math.h>
#include "score_calculator.h"
#include "event_recorder.h"
#include "spade_features.h"

/*#define LOG10 2.30258509299 */
#define LOG2 0.69314718056

static table_use_specs *new_evfiles_specs(void);

score_calculator *new_score_calculator(int prodcount,feature_list feats[],const char **featurenames,event_condition_set conds,int scale_freq,double scale_factor,double prune_threshold,event_recorder *recorder,feature_list *calc_feats) {
    score_calculator *new= (score_calculator *)malloc(sizeof(score_calculator));
    init_score_calculator(new,prodcount,feats,featurenames,conds,scale_freq,scale_factor,prune_threshold,recorder,calc_feats);
    return new;
}

void init_score_calculator(score_calculator *self,int prodcount,feature_list feats[],const char **featurenames,event_condition_set conds,int scale_freq,double scale_factor,double prune_threshold,event_recorder *recorder,feature_list *calc_feats) {
    init_score_calculator_clear(self,recorder);
    self->prodcount= prodcount;
    if (prodcount == 1) {
        self->evfile= event_recorder_new_event_file(self->recorder,&feats[0],featurenames,conds,scale_freq,scale_factor,prune_threshold,0,calc_feats);
    } else {
        self->evfiles= event_recorder_new_event_files(self->recorder,prodcount,feats,featurenames,conds,scale_freq,scale_factor,prune_threshold,0);
    }
}

score_calculator *new_score_calculator_clear(event_recorder *recorder) {
    score_calculator *new= (score_calculator *)malloc(sizeof(score_calculator));
    init_score_calculator_clear(new,recorder);
    return new;
}

void init_score_calculator_clear(score_calculator *self,event_recorder *recorder) {
    self->prodcount= -1;
    self->evfile= NULL;
    self->evfiles= NULL;
    self->cond_prefix_len= 0;
    self->use_corrscore= 1;
    self->calc_relscore= 0;
    self->calc_rawscore= 0;
    self->mainpref= PREF_NOSCORE;
    self->min_obs_prefix_len= 0;
    self->min_obs_count= 0.0;
    self->max_entropy= -1;
    self->recorder= recorder;
    self->evfiles_data= NULL;
}

void score_calculator_set_features(score_calculator *self,int prodcount,feature_list feats[],feature_list *calc_feats,const char **featurenames) {
    int i;
    if (self->evfiles_data == NULL) self->evfiles_data= new_evfiles_specs();
    self->evfiles_data->prodcount= prodcount;
    self->evfiles_data->feats= (feature_list*)malloc(sizeof(feature_list)*prodcount);
    for (i= 0; i < prodcount; i++)
        self->evfiles_data->feats[i]= feats[i];
    if (calc_feats == NULL)
        self->evfiles_data->calc_feats.num= 0;
    else
        self->evfiles_data->calc_feats= *calc_feats; /* copy over */
    self->evfiles_data->featurenames= featurenames;
}

void score_calculator_set_storage_conditions(score_calculator *self,event_condition_set conds) {
    if (self->evfiles_data == NULL) self->evfiles_data= new_evfiles_specs();
    self->evfiles_data->conds= conds;
}

void score_calculator_set_scaling(score_calculator *self,int scale_freq,double scale_factor,double prune_threshold) {
    if (self->evfiles_data == NULL) self->evfiles_data= new_evfiles_specs();
    self->evfiles_data->scale_freq= scale_freq;
    self->evfiles_data->scale_factor= scale_factor;
    self->evfiles_data->prune_threshold= prune_threshold;
}

void score_calculator_init_complete(score_calculator *self) {
    table_use_specs *d;
    
    if (self->evfiles_data == NULL) return; /* nothing to do */
    d= self->evfiles_data;
    if (d->feats== NULL) { /* no feature lists provided */
        d->feats= (feature_list *)malloc(1*sizeof(feature_list));
        d->feats[0].num= 1;
        d->feats[0].feat[0]= 0;
        d->prodcount= 1;
    }
    
    self->prodcount= d->prodcount;
    if (d->prodcount == 1) {
        self->evfile= event_recorder_new_event_file(self->recorder,&d->feats[0],d->featurenames,d->conds,d->scale_freq,d->scale_factor,d->prune_threshold,0,(d->calc_feats.num==0 ?NULL:&d->calc_feats));
    } else {
        self->evfiles= event_recorder_new_event_files(self->recorder,d->prodcount,d->feats,d->featurenames,d->conds,d->scale_freq,d->scale_factor,d->prune_threshold,0);
    }
    free(self->evfiles_data->feats);
    free(self->evfiles_data);
    self->evfiles_data= NULL;
}

void score_calculator_set_condcutoff(score_calculator *self,int cond_prefix_len)
{
    self->cond_prefix_len= cond_prefix_len;
}

void score_calculator_set_relscore(score_calculator *self, int calc_relscore, int rel_is_main) {
    self->calc_relscore= calc_relscore;
    if (rel_is_main) self->mainpref= PREF_RELSCORE;
}

void score_calculator_set_rawscore(score_calculator *self, int calc_rawscore, int raw_is_main) {
    self->calc_rawscore= calc_rawscore;
    if (raw_is_main) self->mainpref= PREF_RAWSCORE;
}

void score_calculator_set_corrscore(score_calculator *self, int use_corrscore) {
    self->use_corrscore= use_corrscore;
}

void score_calculator_set_min_obs(score_calculator *self,int featlist_prefix_len,int min_obs_count) {
    self->min_obs_prefix_len= featlist_prefix_len;
    self->min_obs_count= (double)min_obs_count;
}

void score_calculator_set_low_entropy_domain(score_calculator *self, int val_prefix_len, double max_entropy) {
    self->max_entropy= max_entropy;
    self->entropy_prefix_len= val_prefix_len;
}

void score_calculator_cleanup(score_calculator *self) {
    if (self->prodcount > 0 && self->evfiles != NULL) free(self->evfiles);
    self->prodcount= -1;
}

int score_calculator_using_corrscore(score_calculator *self) {
    return self->use_corrscore || (self->prodcount > 0) || !self->calc_rawscore;
}

score_info *score_calculator_calc_event_score(score_calculator *self,spade_event *event,score_info* storage,int *enoughobs) {
    int prodidx;
    double prob;
    double rawscore= NO_SCORE;
    double relscore= NO_SCORE;
    *enoughobs= 1;
    
    if (self->prodcount < 0) score_calculator_init_complete(self);
            
    if (self->prodcount > 1) { /* multiply together the straight maximally conditioned probabilities and return absolute score */
        prob= 1;
        for (prodidx= 0; prodidx < self->prodcount; prodidx++)
            prob*= event_recorder_get_condprob(self->recorder,self->evfiles[prodidx],event,-1,1);
        rawscore= -1*(log(prob)/LOG2);
    } else {
        if (self->min_obs_count > 0) {
            double count= event_recorder_get_count(self->recorder,self->evfile,event,self->min_obs_prefix_len);
            if ((count+1) < self->min_obs_count) {
                *enoughobs= 0;
                return NULL;
            }
        }
        if (self->max_entropy > 0) {
            double entropy;
            entropy= event_recorder_get_entropy(self->recorder,self->evfile,event,self->entropy_prefix_len);
            if (entropy > self->max_entropy) return NULL;
        }
        prob= event_recorder_get_condprob(self->recorder,self->evfile,event,self->cond_prefix_len,1);
        if (self->calc_rawscore) { // calculate raw anomaly score
            if (self->use_corrscore) { // use the scores that are computed as adverstised
                rawscore= -1.0*(log(prob)/LOG2);
            } else { // use the old, incorrectly computed joint score
                rawscore= -1.0*log(prob/LOG2);
            }
        }
        if (self->calc_relscore) { // calculate relative anomaly score
            double basecount= event_recorder_get_count(self->recorder,self->evfile,event,self->cond_prefix_len)+1;
            double ratio= log(prob)/log(1/basecount);
            relscore= ratio; /* *ratio; */
        }
    }
    if (storage == NULL)
        return new_score_info(self->mainpref,relscore,rawscore,self->use_corrscore);
    else {
        init_score_info(storage,self->mainpref,relscore,rawscore,self->use_corrscore);
        return storage;
    }
}


int score_calculator_get_store_count(score_calculator *self) {
    evfile_ref f= (self->prodcount > 1) ? self->evfiles[0] : self->evfile;
    return event_recorder_get_store_count(self->recorder,f);
}

double score_calculator_get_obs_count(score_calculator *self) {
    evfile_ref f= (self->prodcount > 1) ? self->evfiles[0] : self->evfile;
    return event_recorder_get_obs_count(self->recorder,f);
}

static table_use_specs *new_evfiles_specs() {
    table_use_specs *new= (table_use_specs *)malloc(sizeof(table_use_specs));
    new->prodcount= 1;
    new->feats= NULL;
    new->calc_feats.num= 0;
    new->featurenames= NULL;
    new->conds= 0;
    new->scale_freq= -1;
    new->scale_factor= 1;
    new->prune_threshold= 0;
    return new;
}

void score_calculator_print_config_details(score_calculator *self,FILE *f,char *indent) {
    char indent2[100],indent3[100];
    sprintf(indent2,"%s  ",indent);
    sprintf(indent3,"%s  ",indent2);
    if (self->prodcount < 0) score_calculator_init_complete(self);

    fprintf(f,"%sprodcount=%d:\n",indent,self->prodcount);
    if (self->prodcount == 1) {
        fprintf(f,"%sevfile:\n",indent2);
        evfile_print_config_details(self->evfile,f,indent3);
        
        fprintf(f,"%scond_prefix_len=%d\n",indent2,self->cond_prefix_len);
        fprintf(f,"%smainpref=%s; calc_rawscore=%d; calc_relscore=%d; use_corrscore=%d\n",indent2,scorepref_str(self->mainpref),self->calc_rawscore,self->calc_relscore,self->use_corrscore);
        
        if (self->min_obs_count > 0)
            fprintf(f,"%smin_obs_count=%.4f; min_obs_prefix_len=%d\n",indent2,self->min_obs_count,self->min_obs_prefix_len);
    } else {
        int i;
        for (i=0; i < self->prodcount; i++) {
            fprintf(f,"%sevfiles[%d]:\n",indent2,i);
            evfile_print_config_details(self->evfiles[i],f,indent3);
        }
    }
}

/*@}*/
/* $Id: score_calculator.c,v 1.6 2002/12/19 22:37:10 jim Exp $ */