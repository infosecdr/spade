/*********************************************************************
event_recorder.c, distributed as part of Spade v030125.1
Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
copyright (c) 2002 by Silicon Defense (http://www.silicondefense.com/)
Released under GNU General Public License, see the COPYING file included
with the distribution or http://www.silicondefense.com/spice/ for details.

event_recorder.c contains the "class" event_recorder which is manages a set
  of spade_prob_tables to accomplish user specified goals.  This trys to 
  avoid creating more tables that are needed for the set of goals.

Please send complaints, kudos, and especially improvements and bugfixes to
hoagland@SiliconDefense.com.  As described in GNU General Public License, no
warranty is expressed for this program.
*********************************************************************/

/*! \file event_recorder.c
 * \brief 
 *  event_recorder.c contains the "class" event_recorder which is
 *  manages a set of spade_prob_tables to accomplish user specified goals.
 *  This trys to avoid creating more tables that are needed for the set of
 *  goals.
 * \ingroup staterec
 */

/*! \addtogroup staterec Spade state recording
 * \brief this group contains objects the maintain accumulated Spade
 *  observation state
 * \ingroup libspade
    @{
*/


#include "event_recorder.h"
#include "spade_state.h"
#include "spade_features.h"

#include <stdlib.h>
#include <string.h>

static evfile *new_evfile(table_mgr *mgr,int feat_depth,feature_list *calc_feats);
static table_mgr *new_table_mgr(feature_list *feats, const char **featurenames, event_condition_set conds, int scale_freq, double scale_factor, double prune_threshold, time_t curtime);
static int table_mgr_recover(statefile_ref *ref, table_mgr **mgr);
static int table_mgr_checkpoint(table_mgr *mgr, statefile_ref *ref);
static int table_mgr_is_compatable(table_mgr *mgr, feature_list *feats, const char **featurenames, event_condition_set conds, int scale_freq, double scale_factor, double prune_threshold);
static void table_mgr_new_time(table_mgr *mgr, time_t time);
static void free_table_mgr(table_mgr *mgr);
static void table_mgr_write_stats(table_mgr *mgr, FILE *file, u8 stats_to_print,condition_printer_t condprinter);
static void table_mgr_print_config_details(table_mgr *mgr, FILE *f, char *indent);
static void file_print_feature_list(feature_list *feats, FILE *f, const char **featurenames);

#define feats_to_calc_with(evf) ( (evf->calc_feats.num > 0) ? (&(evf->calc_feats)) : (&(evf->mgr->feats)) )

#define map_event_to_val_arr(featmap,size,event,val) { \
    int featidx; \
    for (featidx= 0; featidx < size; featidx++) { \
        val[featidx]= event->fldval[featmap[featidx]]; \
    } \
}

event_recorder *new_event_recorder() {
    event_recorder *new= (event_recorder *)malloc(sizeof(event_recorder));
    init_event_recorder(new);
    return new;
}

void init_event_recorder(event_recorder *self) {
    self->tables= NULL;
    self->files= NULL;
    self->curtime= (time_t)0;
}

int event_recorder_recover(event_recorder **self,statefile_ref *ref) {
    *self= new_event_recorder();
    if (*self == NULL) return 0;
    return event_recorder_merge_recover(*self,ref);
}

int event_recorder_merge_recover(event_recorder *self,statefile_ref *ref) {
    int i,count;
    table_mgr *mgr;
    if (!spade_state_recover_u32(ref,&count)) return 0;
    for (i= 0; i < count; i++) {
        if (!table_mgr_recover(ref,&mgr)) return 0;
        /* add manager into list by prepending*/
        mgr->next= self->tables;
        self->tables= mgr;
    }
    return 1;
}

int event_recorder_checkpoint(event_recorder *self,statefile_ref *ref) {
    table_mgr *mgr;
    u32 count= 0;
    for (mgr= self->tables; mgr != NULL; mgr=mgr->next) count++;
    
    spade_state_checkpoint_u32(ref,count);
    for (mgr= self->tables; mgr != NULL; mgr=mgr->next) {
        if (!table_mgr_checkpoint(mgr,ref)) return 0;
    }
    return 1;
}

evfile_ref event_recorder_new_event_file(event_recorder *self,feature_list *feats,const char **featurenames,event_condition_set conds,int scale_freq,double scale_factor,double prune_threshold,int fresh_only, feature_list *calc_feats) {
    table_mgr *mgr=NULL;
    evfile *eventfile;
    
    /**** find a compatable table manager, extending or creating if needed ****/
    if (!fresh_only) {
        for (mgr= self->tables; mgr != NULL; mgr=mgr->next) {
            if (table_mgr_is_compatable(mgr,feats,featurenames,conds,scale_freq,scale_factor,prune_threshold)) break;
        }
        if (mgr != NULL) {
            /* reusing a table manager, but some tweaking may be required */
            if (mgr->feats.num < feats->num) /* need to extend features */
                mgr->feats= *feats; /* copy whole struct */
            if (!mgr->use_count) {
                mgr->scale_freq= scale_freq;
                mgr->scale_factor= scale_factor;
                mgr->prune_threshold= prune_threshold;
            }
        }
    }
    
    if (mgr == NULL) {
        /* NOTE: we could go through tables again looking for compatable shared leading features to save on a table and save double-recording of leading features, but that seeking code is a little hairy and it would require recording "skip" information when getting an event */
        mgr= new_table_mgr(feats,featurenames,conds,scale_freq,scale_factor,prune_threshold,self->curtime);
        if (mgr == NULL) return NULL;
        /* add manager into list by prepending*/
        mgr->next= self->tables;
        self->tables= mgr;
    }
    mgr->use_count++;
        
    /**** find a compatable evfile, creating if needed ****/
    for (eventfile= self->files; eventfile != NULL; eventfile=eventfile->next) {
        if (eventfile->mgr != mgr) continue;
        if (eventfile->feat_depth != feats->num)
            continue;
        if ((calc_feats == NULL) && eventfile->calc_feats.num > 0) continue;
        if (calc_feats != NULL) {
            int i;
            if (eventfile->calc_feats.num == 0) /* calc_feats is off */
                continue;
            if (eventfile->feat_depth == calc_feats->num)
                continue;
            for (i= 0; i < eventfile->feat_depth; i++)
                if (eventfile->calc_feats.feat[i] != calc_feats->feat[i]) break;
            if (i < eventfile->feat_depth) continue;
        }
        break; // all matched
    }
    
    if (eventfile == NULL) {
        eventfile= new_evfile(mgr,feats->num,calc_feats);
        if (eventfile == NULL) return NULL;
        /* add eventfile into list by prepending*/
        eventfile->next= self->files;
        self->files= eventfile;
    }
    
    return (evfile_ref)eventfile;
}

evfile_ref *event_recorder_new_event_files(event_recorder *self,int howmany,feature_list feats[],const char **featurenames,event_condition_set conds,int scale_freq,double scale_factor,double prune_threshold,int fresh_only) {
    int i;
    evfile_ref *arr= (evfile_ref *)malloc(sizeof(evfile_ref)*howmany);
    if (arr == NULL) return NULL;

    for (i= 0; i < howmany; i++)
        arr[i]= event_recorder_new_event_file(self,&feats[i],featurenames,conds,scale_freq,scale_factor,prune_threshold,fresh_only,NULL);

    return arr;
}

void event_recorder_new_time(event_recorder *self, time_t time) {
    table_mgr *mgr;
    self->curtime= time;
    /* check for scaling */
    for (mgr= self->tables; mgr != NULL; mgr=mgr->next) {
        if (mgr->use_count) table_mgr_new_time(mgr,time);
    }
}

event_condition_set event_recorder_needed_conds(event_recorder *self) {
    table_mgr *mgr;
    event_condition_set needed_conds= 0;
    /* record which conditions we require events for */
    for (mgr= self->tables; mgr != NULL; mgr=mgr->next)
        ADD_TO_CONDS(needed_conds,mgr->conds); /* NOTE: some information loss here, so might get passed unneeded events; can represent more precisely as a or-ed list of masks */
    return needed_conds;
}

int event_recorder_new_event(event_recorder *self, spade_event *event, event_condition_set matching_conds) {
    table_mgr *mgr;
    int updates= 0;
    for (mgr= self->tables; mgr != NULL; mgr=mgr->next) {
        if (ALL_CONDS_MET(matching_conds,mgr->conds)) { /* all of mgr's conditions are met by event */
            u32 val[MAX_NUM_FEATURES];
            feature_list *l= &mgr->feats;
            map_event_to_val_arr(l->feat,l->num,event,val);
            increment_Njoint_count(&mgr->table,l->num,l->feat,val,0);
            mgr->store_count++;
            updates++;
        }
    }
    return updates;
}

void event_recorder_prune_unused(event_recorder *self) {
    table_mgr *mgr,*prev=NULL;
    for (mgr= self->tables; mgr != NULL; mgr=mgr->next) {
        if (!mgr->use_count) {
            if (prev == NULL)
                self->tables= mgr->next;
            else 
                prev->next= mgr->next;
            free_table_mgr(mgr);
        } else {
            prev= mgr;
        }
    }
}

double event_recorder_get_prob(event_recorder *self,evfile_ref eventfile,spade_event *event,int one_more) {
    u32 val[MAX_NUM_FEATURES];
    feature_list *l=  &eventfile->mgr->feats;
    /* calculate the joint probability to the depth indicated in the evfile */
    map_event_to_val_arr(feats_to_calc_with(eventfile)->feat,eventfile->feat_depth,event,val);
    return one_more ?
        prob_Njoint_Ncond_plus_one(&eventfile->mgr->table,eventfile->feat_depth,l->feat,val,0) :
        prob_Njoint_Ncond(&eventfile->mgr->table,eventfile->feat_depth,l->feat,val,0);
}

double event_recorder_get_condprob(event_recorder *self,evfile_ref eventfile,spade_event *event,int condcutoff,int one_more) {
    u32 val[MAX_NUM_FEATURES];
    feature_list *l= &eventfile->mgr->feats;
    if (condcutoff < 0) condcutoff+= eventfile->feat_depth; /* condition cutoff specified from end */
    /* calculate the joint probability to the depth indicated in the evfile and conditioned to the indicated level */
    map_event_to_val_arr(feats_to_calc_with(eventfile)->feat,eventfile->feat_depth,event,val);
    return one_more ?
        prob_Njoint_Ncond_plus_one(&eventfile->mgr->table,eventfile->feat_depth,l->feat,val,condcutoff) :
        prob_Njoint_Ncond(&eventfile->mgr->table,eventfile->feat_depth,l->feat,val,condcutoff);
}

double event_recorder_get_count(event_recorder *self,evfile_ref eventfile,spade_event *event,int featdepth) {
    u32 val[MAX_NUM_FEATURES];
    feature_list *l=  &eventfile->mgr->feats;
    /* calculate the joint probability to the depth indicated in the evfile and conditioned to the indicated level */
    map_event_to_val_arr(feats_to_calc_with(eventfile)->feat,featdepth,event,val);
    return jointN_count(&eventfile->mgr->table,featdepth,l->feat,val);
}

double event_recorder_get_entropy(event_recorder *self,evfile_ref eventfile,spade_event *event,int entropy_prefix_len) {
    u32 val[MAX_NUM_FEATURES];
    feature_list *l=  &eventfile->mgr->feats;
    map_event_to_val_arr(feats_to_calc_with(eventfile)->feat,entropy_prefix_len,event,val);
    return spade_prob_table_entropy(&eventfile->mgr->table,entropy_prefix_len,l->feat,val);
}

int event_recorder_get_store_count(event_recorder *self, evfile_ref eventfile) {
    return eventfile->mgr->store_count;
}

double event_recorder_get_obs_count(event_recorder *self, evfile_ref eventfile) {
    return jointN_count(&eventfile->mgr->table,0,eventfile->mgr->feats.feat,NULL);
}

void event_recorder_write_stats(event_recorder *self,FILE *file,u8 stats_to_print,condition_printer_t condprinter) {
    table_mgr *mgr;
    for (mgr= self->tables; mgr != NULL; mgr=mgr->next) {
        table_mgr_write_stats(mgr,file,stats_to_print,condprinter);
    }
}

static evfile *new_evfile(table_mgr *mgr,int feat_depth,feature_list *calc_feats) {
    evfile *new= (evfile *)malloc(sizeof(evfile));
    if (new == NULL) return NULL;
    new->mgr= mgr;
    new->feat_depth= feat_depth;
    if (calc_feats == NULL)
        new->calc_feats.num= 0;
    else
        new->calc_feats= *calc_feats; /* copy struct over */
    new->next= NULL;
    return new;
}

static table_mgr *new_table_mgr(feature_list *feats,const char **featurenames,event_condition_set conds,int scale_freq,double scale_factor,double prune_threshold,time_t curtime) {
    int num_featurenames;
    table_mgr *new= (table_mgr *)malloc(sizeof(table_mgr));
    if (new == NULL) return NULL;
    
    init_spade_prob_table(&new->table,featurenames,0);
    new->next= NULL;
    new->last_scale= (time_t)0;
    
    new->feats= *feats; // make copy
    for (num_featurenames= 0; featurenames[num_featurenames] != NULL; num_featurenames++);
    new->featurenames= (const char **)malloc(sizeof(const char *)*(num_featurenames+1));
    if (new->featurenames != NULL) {
        int i;
        for (i= 0; featurenames[i] != NULL; i++) {
            new->featurenames[i]= strdup(featurenames[i]);
        }
        new->featurenames[i]= NULL;
    }
    
    new->conds= conds;
    new->start_time= curtime;
    new->scale_freq= scale_freq;
    new->scale_factor= scale_factor;
    new->prune_threshold= prune_threshold;
    new->use_count= 0;
    new->store_count= 0;
    return new;
}

static int table_mgr_recover(statefile_ref *ref,table_mgr **mgr) {
    u8 count= 0;

    feature_list feats;
    const char **featurenames;
    event_condition_set conds;
    int scale_freq;
    double scale_factor;
    double prune_threshold;
    time_t start_time;
    
    time_t last_scale;

    if (!(spade_state_recover_u32(ref,(u32 *)&conds)
        && spade_state_recover_u8(ref,(u8 *)&feats.num)
        && spade_state_recover_arr(ref,(u8 **)&feats.feat,feats.num,1)
        && spade_state_recover_u8(ref,(u8 *)&count)
    )) return 0;
    
    featurenames= (const char **)malloc(sizeof(const char *)*(count+1));
    if (featurenames == NULL) return 0;
    if (!spade_state_recover_str_arr(ref,(char **)featurenames,count)) return 0;
    featurenames[count]= NULL;
    
    if (!(spade_state_recover_u32(ref,(u32 *)&scale_freq)
        && spade_state_recover_double(ref,&scale_factor)
        && spade_state_recover_double(ref,&prune_threshold)
        && spade_state_recover_time_t(ref,&start_time)
    )) return 0;

    *mgr= new_table_mgr(&feats,featurenames,conds,scale_freq,scale_factor,prune_threshold,start_time);

    if (!spade_state_recover_time_t(ref,&last_scale)) return 0;
    /* we choose not to record the recovered last_scale; it would cause repeated immediate scaling to make up for lost time; not want we want most of the time */

    return spade_prob_table_recover(ref,&(*mgr)->table); /* does not effect featurenames of the table */
}

static int table_mgr_checkpoint(table_mgr *mgr,statefile_ref *ref) {
    u8 count= 0;
    for (count= 0; mgr->featurenames[count] != NULL; count++);
    
    return spade_state_checkpoint_u32(ref,(u32)mgr->conds)
        && spade_state_checkpoint_u8(ref,(u8)mgr->feats.num)
        && spade_state_checkpoint_arr(ref,(u8 *)mgr->feats.feat,mgr->feats.num,1)
        && spade_state_checkpoint_u8(ref,(u8)count)
        && spade_state_checkpoint_str_arr(ref,(char **)mgr->featurenames,count)
    
        && spade_state_checkpoint_u32(ref,(u32)mgr->scale_freq)
        && spade_state_checkpoint_double(ref,mgr->scale_factor)
        && spade_state_checkpoint_double(ref,mgr->prune_threshold)
        && spade_state_checkpoint_time_t(ref,mgr->start_time)
        && spade_state_checkpoint_time_t(ref,mgr->last_scale)    

        && spade_prob_table_checkpoint(ref,&mgr->table);
}

static int table_mgr_is_compatable(table_mgr *mgr,feature_list *feats,const char **featurenames,event_condition_set conds,int scale_freq,double scale_factor,double prune_threshold) {
    int i,cmp_featlen;

    if (mgr->conds != conds) return 0;
    
    if (mgr->use_count) { /* we'll waive these checks if an orphan */
        //if (mgr->start_time != self->curtime) return 0;
        if (mgr->scale_freq != scale_freq) return 0;
        if (mgr->scale_factor != scale_factor) return 0;
        if (mgr->prune_threshold != prune_threshold) return 0;
    }
    
    for (i= 0; featurenames[i] != NULL; i++)
        if (strcmp(mgr->featurenames[i],featurenames[i])) return 0;

    if (mgr->feats.num < feats->num) {
        if (!spade_prob_table_is_empty(&mgr->table)) return 0; /* can only extend if empty */
        cmp_featlen= mgr->feats.num;
    } else {
        cmp_featlen= feats->num;
    }
    for (i= 0; i < cmp_featlen; i++)
        if (mgr->feats.feat[i] != feats->feat[i]) return 0;

    return 1; /* found a compatable table manager */
}

static void table_mgr_new_time(table_mgr *mgr,time_t time) {
    if (mgr->scale_freq > 0) {
        while (time - mgr->last_scale > mgr->scale_freq) {
            if (mgr->last_scale == (time_t)0) { /* never have scaled before */
                mgr->last_scale= time;
            } else {
                //if (self->debug_level > 1) printf("scaling by %f at time %d; discarding at %f\n",mgr->scale_factor,(int)time,mgr->prune_threshold);
                scale_and_prune_table(&mgr->table,mgr->scale_factor,mgr->prune_threshold);
                mgr->last_scale+= mgr->scale_freq;  /* lets pretend we did this right on time */
                //if (self->debug_level > 1) printf("done with scale/prune\n");
            }
        }
    }
}

static void free_table_mgr(table_mgr *mgr) {
    int i;
    /* need to reset mgr->table */
    for (i= 0; mgr->featurenames[i] != NULL; i++) {
        free((char *)mgr->featurenames[i]);
    }
    free((char *)mgr->featurenames);
    free(mgr);
}

static void table_mgr_write_stats(table_mgr *mgr,FILE *file,u8 stats_to_print,condition_printer_t condprinter) {
    fprintf(file,"** table for ");
    if (condprinter != NULL)
        (*condprinter)(file,mgr->conds);
    else
        fprintf(file," %x",mgr->conds);
    fprintf(file," **\n");
    fprintf(file,"Recorded is: P(");
    file_print_feature_list(&mgr->feats,file,mgr->featurenames);
    fprintf(file,")\n");
    fprintf(file,"Scaling freqency: %d; Scaling factor: %.5f; Pruning Threshold=%.5f\n",mgr->scale_freq,mgr->scale_factor,mgr->prune_threshold);
    fprintf(file,"Start time: %d; Last time scaled: %d\n",(int)mgr->start_time,(int)mgr->last_scale);
    spade_prob_table_write_stats(&mgr->table,file,stats_to_print);
    fprintf(file,"\n");
}

void evfile_print_config_details(evfile_ref eventfile,FILE *f,char *indent) {
    char indent2[100];
    sprintf(indent2,"%s  ",indent);
    fprintf(f,"%smgr=\n",indent);
    table_mgr_print_config_details(eventfile->mgr,f,indent2);
    fprintf(f,"%sfeat_depth=%d\n",indent,eventfile->feat_depth);
    if (eventfile->calc_feats.num > 0) {
        fprintf(f,"%scalc_feats=",indent);
        file_print_feature_list(&eventfile->calc_feats,f,eventfile->mgr->featurenames);
        fprintf(f,"\n");
    }
}

static void table_mgr_print_config_details(table_mgr *mgr,FILE *f,char *indent) {
    fprintf(f,"%sfeats=",indent);
    file_print_feature_list(&mgr->feats,f,mgr->featurenames);
    fprintf(f,"\n%sconds=%x\n",indent,mgr->conds);
    fprintf(f,"%sscale_freq=%d; scale_factor=%.5f; prune_threshold=%.5f\n",indent,mgr->scale_freq,mgr->scale_factor,mgr->prune_threshold);
}

static void file_print_feature_list(feature_list* feats,FILE *f,const char **featurenames) {
    int i;
    for (i= 0; i < feats->num; i++) {
        if (i != 0) fprintf(f,",");
        fprintf(f,"%s",featurenames[feats->feat[i]]);
    }
}
/* $Id: event_recorder.c,v 1.8 2002/12/19 22:37:10 jim Exp $ */