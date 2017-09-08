/*********************************************************************
thresh_adapter.c, distributed as part of Spade v030125.1
Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
copyright (c) 2002 by Silicon Defense (http://www.silicondefense.com/)
Released under GNU General Public License, see the COPYING file included
with the distribution or http://www.silicondefense.com/spice/ for details.

Please send complaints, kudos, and especially improvements and bugfixes to
hoagland@SiliconDefense.com.  As described in GNU General Public License, no
warranty is expressed for this program.
*********************************************************************/

/*! \file thresh_adapter.c
 * \brief 
 *  thresh_adapter.c contains a "class" thresh_adapter which implements
 *  several ways to adapt a Spade threshold to hit a certain target
 * \ingroup stmgr
 */

/*! \weakgroup stmgr
    @{
*/

#include "thresh_adapter.h"
#include "strtok.h"
#include "ll_double.h"
#include "dll_double.h"
#include <stdlib.h>
#include <stdio.h>
#include <math.h>

static void thresh_adapter_setup_1_from_str(thresh_adapter *self,char *str);
static void thresh_adapter_setup_2_from_str(thresh_adapter *self,char *str);
static void thresh_adapter_setup_3_from_str(thresh_adapter *self,char *str);
static void thresh_adapter_setup_4_from_str(thresh_adapter *self,char *str);
static void thresh_adapter_new_pkt_rate(thresh_adapter *self, spade_enviro *enviro);
static void thresh_adapter_2_new_pkt_rate(thresh_adapter *self, spade_enviro *enviro);
static void thresh_adapter_3_new_pkt_rate(thresh_adapter *self, spade_enviro *enviro);
static float grab_new_thresh_1(thresh_adapter *self, spade_enviro *enviro);
static float grab_new_thresh_2(thresh_adapter *self, spade_enviro *enviro);
static float calc_new_thresh_2(thresh_adapter *self, spade_enviro *enviro);
static double thresh_from_obslists(adapt2_data *data);
static double anom_ave(double a[], int size);
static void reset_obslist(adapt2_data *data, int slot);
static float grab_new_thresh_3(thresh_adapter *self, spade_enviro *enviro);
static float grab_new_thresh_4(thresh_adapter *self,spade_enviro *enviro);
static void thresh_adapter_1_new_score(thresh_adapter *self, double anom_score);
static void thresh_adapter_2_new_score(thresh_adapter *self, double anom_score);
static void thresh_adapter_3_new_score(thresh_adapter *self, double anom_score);

void init_thresh_adapter(thresh_adapter *self,spade_msg_fn msg_callback) {
    self->adapt_mode= 0;
    self->period_start= (time_t)0;
    self->pkt_period_count= 0;
    self->last_total_stats= 0;
    self->period_pkt_rate= 100000000.0;
    self->period_acc_rate= 100000000.0;
    self->done= 0;
    self->msg_callback= msg_callback;
}

thresh_adapter *new_thresh_adapter(spade_msg_fn msg_callback) {
    thresh_adapter *new= (thresh_adapter *)malloc(sizeof(thresh_adapter));
    init_thresh_adapter(new,msg_callback);
    return new;
}

void thresh_adapter_setup_from_str(thresh_adapter *self,int adaptmode,char *str) {
    switch (adaptmode) {
        case 1: thresh_adapter_setup_1_from_str(self,str); break;
        case 2: thresh_adapter_setup_2_from_str(self,str); break;
        case 3: thresh_adapter_setup_3_from_str(self,str); break;
        case 4: thresh_adapter_setup_4_from_str(self,str); break;
    }
}

void thresh_adapter_setup_1(thresh_adapter *self,int target,time_t period,float new_obs_weight,int by_count) {
    adapt1_data *data= &self->d.a1;

    self->adapt_mode= 1;
    self->adapt_period= period;
    self->adapt_by_count= by_count;
    
    data->target= target;
    data->period= period;
    data->new_obs_weight= new_obs_weight;
    data->by_count= by_count;
    
    /* init list to contain 0 and 0; this is to let us assume the list has a
       bottom and runner-up elsewhere */
    data->top_list= (ll_double *)malloc(sizeof(ll_double));
    data->top_list->val= 0.0;
    data->top_list->next= (ll_double *)malloc(sizeof(ll_double));
    data->top_list->next->val= 0.0;
    data->top_list->next->next= NULL;
    data->top_list_size= 1;
}

static void thresh_adapter_setup_1_from_str(thresh_adapter *self,char *str) {
    int target=20,by_count=1;
    float hours=2,new_obs_weight=0.5;
    void *args[4];
    time_t period;

    args[0]= &target;
    args[1]= &hours;
    args[2]= &new_obs_weight;
    args[3]= &by_count;
    fill_args_space_sep(str,"i:target;f:obsper;f:newweight;b:bycount",args,self->msg_callback);

    period= (time_t)(hours*3600);
    thresh_adapter_setup_1(self,target,period,new_obs_weight,by_count);
}


void thresh_adapter_setup_2(thresh_adapter *self,double targetspec,double obsper,int NS,int NM,int NL) {
    int i;

    adapt2_data *data= &self->d.a2;

    self->adapt_mode= 2;
    self->adapt_period= (time_t)(obsper+0.5);
    self->adapt_by_count= 1;
    
    data->targetspec= targetspec;
    data->obsper= obsper;
    data->NS= NS;
    data->NM= NM;
    data->NL= NL;
    
    /* 10000000 packets per hour is an overestimate but ensures we keep enough during the first period */
    data->target= (int) floor(0.5+ (targetspec >= 1 ? targetspec*(obsper/3600.0) : ((10000000/3600.0)*obsper)*targetspec));
    if (data->target==0) data->target= 1; /* ensure at least 1 long */

    data->obslists_head= (dll_double **)malloc(NS * sizeof(dll_double *));
    data->obslists_tail= (dll_double **)malloc(NS * sizeof(dll_double *));
    data->obslists_size= (int *)malloc(NS * sizeof(int));
    for (i= 0; i < NS; i++) {
        data->obslists_head[i]= new_dll_double(0.0);
        data->obslists_tail[i]= new_dll_double(0.0);
        data->obslists_head[i]->next= data->obslists_tail[i];
        data->obslists_tail[i]->prev= data->obslists_head[i];
        data->obslists_size[i]= 1;
    }
    data->obsper_count= 0;
    data->recScomps= (double *)malloc(NM * sizeof(double));
    data->recMcomps= (double *)malloc(NL * sizeof(double));
    
    data->mid_anom_comp= 0;
    data->long_anom_comp= 0;

    data->obslist_new_slot= 0;
    
    data->per2_count=0;
    data->per3_count=0;
}

static void thresh_adapter_setup_2_from_str(thresh_adapter *self,char *str) {
    double targetspec=0.01,obsper=15;
    int NS=4,NM=24,NL=7;
    void *args[4];

    args[0]= &targetspec;
    args[1]= &obsper;
    args[2]= &NS;
    args[3]= &NM;
    args[4]= &NL;
    fill_args_space_sep(str,"d:target;d:obsper;i:NS;i:NM;i:NL",args,self->msg_callback);

    obsper*= 60;
    thresh_adapter_setup_2(self,targetspec,obsper,NS,NM,NL);
}

void thresh_adapter_setup_3(thresh_adapter *self,double targetspec,double obsper,int NO) {
    adapt3_data *data= &self->d.a3;

    self->adapt_mode= 3;
    self->adapt_period= (time_t)(obsper+0.5);
    self->adapt_by_count= 1;
    
    data->targetspec= targetspec;
    data->NO= NO;
    
    /* 10000 packets per hour is our pure guess as to the rate of packets.
       Is there a better way to figure out how many packets to note for our
       first interval when we want a percent of packets? */
    data->target= (int) floor(0.5+ (targetspec >= 1 ? targetspec*(obsper/3600.0) : ((10000/3600.0)*obsper)*targetspec));
    if (data->target==0) data->target= 1;

    data->hist= (double *)malloc(sizeof(double)*NO);
    
    /* init list to contain 0 and 0; this is to let us assume the list
       has a bottom and runner-up elsewhere */
    data->anoms= (ll_double *)malloc(sizeof(ll_double));
    data->anoms->val= 0.0;
    data->anoms->next= (ll_double *)malloc(sizeof(ll_double));
    data->anoms->next->val= 0.0;
    data->anoms->next->next= NULL;
    data->anoms_size= 1;
    data->completed_obs_per= 0;
    data->obssum= 0;
}

static void thresh_adapter_setup_3_from_str(thresh_adapter *self,char *str) {
    double targetspec=0.01,obsper=60;
    int NO=168;
    void *args[3];

    args[0]= &targetspec;
    args[1]= &obsper;
    args[2]= &NO;
    fill_args_space_sep(str,"d:target;d:obsper;i:numper",args,self->msg_callback);
    obsper*= 60;
    thresh_adapter_setup_3(self,targetspec,obsper,NO);
}

void thresh_adapter_setup_4(thresh_adapter *self,double thresh,double obsper) {
    adapt4_data *data= &self->d.a4;

    self->adapt_mode= 4;
    self->adapt_period= (time_t)(obsper+0.5);
    self->adapt_by_count= 0;
    
    data->thresh= thresh;
}

static void thresh_adapter_setup_4_from_str(thresh_adapter *self,char *str) {
    double thresh=0.8,obsper=60;
    void *args[2];

    args[0]= &thresh;
    args[1]= &obsper;
    fill_args_space_sep(str,"d:thresh;d:obsper",args,self->msg_callback);
    obsper*= 60;
    thresh_adapter_setup_4(self,thresh,obsper);
}


void thresh_adapter_start_time(thresh_adapter *self,time_t now) {
    //self->obs_start_time= now;
    self->period_start= now;
}

int thresh_adapter_new_time(thresh_adapter *self,spade_enviro *enviro,double *sugg_thresh) {
    int adapt_now= 0;
    int new_period= 0;
    if (self->done) return 0;
    
    if (self->period_start == (time_t)0) { /* first time called and start time not given */
        self->period_start= enviro->now;
        return 0;
    }

    while (enviro->now > (self->period_start + self->adapt_period)) {
        new_period= 1;
        thresh_adapter_new_pkt_rate(self,enviro);
    }

    if (self->adapt_by_count && (self->pkt_period_count >= 1)) {
        if ((*(enviro->total_pkts) - self->last_total_stats) >= self->period_pkt_rate) {
            adapt_now= 1;
        }
    } else {
        if (new_period) {
            adapt_now= 1;
        }
    }
    
    if (adapt_now) {
        self->last_total_stats= *(enviro->total_pkts);
        switch (self->adapt_mode) {
        case 1: *sugg_thresh= grab_new_thresh_1(self,enviro); break;
        case 2: *sugg_thresh= grab_new_thresh_2(self,enviro); break;
        case 3: *sugg_thresh= grab_new_thresh_3(self,enviro); break;
        case 4: *sugg_thresh= grab_new_thresh_4(self,enviro); break;
        }
    
        return 1;
    }
    return 0;
}

static void thresh_adapter_new_pkt_rate(thresh_adapter *self,spade_enviro *enviro) {
    self->pkt_period_count++;
    self->period_pkt_rate= *(enviro->total_pkts)/(float)self->pkt_period_count;
    self->period_acc_rate= enviro->pkt_stats.scored/(float)self->pkt_period_count;
    self->period_start+= self->adapt_period;

    switch (self->adapt_mode) {
    //case 1: thresh_adapter_1_new_pkt_rate(self,enviro); break;
    case 2: thresh_adapter_2_new_pkt_rate(self,enviro); break;
    case 3: thresh_adapter_3_new_pkt_rate(self,enviro); break;
    }
}

static void thresh_adapter_2_new_pkt_rate(thresh_adapter *self,spade_enviro *enviro) {
    adapt2_data *data= &self->d.a2;
    dll_double *l;
    
    data->target= (int) floor(0.5+ (data->targetspec >= 1 ? data->targetspec*(self->adapt_period/3600.0) : data->targetspec*self->period_acc_rate));
    if (data->target==0) data->target= 1; /* ensure at least 1 long */
    
    //if (self->debug_level) printf("new target is %d\n",data->target);
    
    if (data->obsper_count == 0) {
        data->obsper_count++;
        data->obslist_new_slot= data->obsper_count % data->NS;
        if (data->obslists_size[0] > data->target) { /* remove excess */
            int i;
            for (i= data->target, l=data->obslists_head[0]; i < data->obslists_size[0]; i++,l=l->next);
            l->prev->next= NULL;
            l->prev= NULL;
            free_dll_double_list(data->obslists_head[0]);
            data->obslists_head[0]= l;
        }
    }
}

static void thresh_adapter_3_new_pkt_rate(thresh_adapter *self,spade_enviro *enviro) {
    adapt3_data *data= &self->d.a3;
    ll_double *prev,*newstart;
    int i;

    data->target= (int) floor(0.5+ (data->targetspec >= 1 ? data->targetspec*(data->obsper/3600.0) : data->targetspec*self->period_acc_rate));
    if (data->target==0) data->target= 1;
    //if (self->debug_level) printf("new target is %d\n",data->target);
    
    if (data->completed_obs_per == 0) {
        if (data->anoms_size > data->target) { /* remove excess */
            for (i= data->target, prev=data->anoms; (i+1) < data->anoms_size; i++,prev=prev->next);
            newstart= prev->next;
            prev->next= NULL;
            free_ll_double_list(data->anoms);
            data->anoms= newstart;
        }
    }
}

static float grab_new_thresh_1(thresh_adapter *self,spade_enviro *enviro) {
    ll_double *l;
    float new_thresh;
    adapt1_data *data= &self->d.a1;
    double obs_thresh= (data->top_list->val + data->top_list->next->val)/2;
    //if (self->debug_level) printf("observed recent ideal threshold is %.4f\n",obs_thresh);
    if (enviro->thresh < 0.0) { /* started up with no reporting */
        new_thresh= obs_thresh;
    } else {
        new_thresh= (1-data->new_obs_weight)*enviro->thresh + data->new_obs_weight*obs_thresh;
    }
    
    //if (self->debug_level) printf("new threshold is %.4f\n",new_thresh); 
    
    for (l=data->top_list; l != NULL; l=l->next)  l->val= 0.0;
    
    return new_thresh;
}

static float grab_new_thresh_2(thresh_adapter *self,spade_enviro *enviro) {
    int new_thresh= calc_new_thresh_2(self,enviro);
    adapt2_data *data= &self->d.a2;

    data->obsper_count++;
    data->obslist_new_slot= data->obsper_count % data->NS;
    reset_obslist(data,data->obslist_new_slot);

    return new_thresh;
}

static float calc_new_thresh_2(thresh_adapter *self,spade_enviro *enviro) {
    adapt2_data *data= &self->d.a2;
    double rec_anom_comp= thresh_from_obslists(data);

    //if (self->debug_level) printf("* New recent anom observation (#%d) is %.5f\n",data->obsper_count,rec_anom_comp);
    if (data->obsper_count < (data->NS-1)) {
        return rec_anom_comp; /* haven't observed mid or long yet */
    }
    if (((data->obsper_count+1) % data->NS) == 0) { /* time to add new mid */
        data->recScomps[data->per2_count % data->NM]= rec_anom_comp;
        //if (self->debug_level) printf("data->recScomps[%d]:= %.5f\n",data->per2_count % data->NM,rec_anom_comp);
        data->per2_count++;
        data->mid_anom_comp= anom_ave(data->recScomps,((data->per2_count < data->NM)?data->per2_count:data->NM));
        //if (self->debug_level) printf("** New mid anom component (#%d) is %.5f\n",data->per2_count-1,data->mid_anom_comp);
        if (data->per2_count < (data->NM-1)) {
            return (rec_anom_comp+data->mid_anom_comp)/2.0; /* haven't observed long yet */
        }
        if ((data->per2_count % data->NM) == 0) { /* time to add new long */
            data->recMcomps[data->per3_count % data->NL]= data->mid_anom_comp;
            //if (self->debug_level) printf("data->recMcomps[%d]:= %.5f\n",data->per3_count % data->NL,data->mid_anom_comp);
            data->per3_count++; 
            data->long_anom_comp= anom_ave(data->recMcomps,((data->per3_count < data->NL)?data->per3_count:data->NL));
            //if (self->debug_level) printf("*** New long anom component (#%d) is %.5f\n",data->per3_count-1,data->long_anom_comp);
        }
    }
    if (data->per2_count < data->NM) {
        return (rec_anom_comp+data->mid_anom_comp)/2.0; /* haven't observed long yet */
    }
    return (rec_anom_comp+data->mid_anom_comp+data->long_anom_comp)/3.0;
}

static double thresh_from_obslists(adapt2_data *data) {
    dll_double **pos= (dll_double **)malloc(data->NS * sizeof(dll_double *));
    int i,c,maxpos=-1;
    double max,last_score=0.0,before_last_score=0.0;
    if (0) { /*(self->debug_level > 1) {*/
        dll_double *l;
        printf("thresh_from_obslists: finding score that is #%d highest in:\n",data->target);
        for (i= 0; i < data->NS; i++) {
            printf("  slot %d: %.5f",i,data->obslists_head[i]->val);
            for (l=data->obslists_head[i]->next; l != NULL; l=l->next) {
                printf(" -> %.5f",l->val);
            }
            printf("\n");
        }
    }
    for (i= 0; i < data->NS; i++) { /* init pos's to be the list tails */
        pos[i]= data->obslists_tail[i];
    }
    for (c= 1; c <= data->target+1; c++) {
        max= -1;
        for (i= 0; i < data->NS; i++) {
            if (pos[i] != NULL) {
                if (max < pos[i]->val) {
                    max= pos[i]->val;
                    maxpos= i;
                }
                
            }
        }
        if (max == -1) {/* should only happen if we don't have enough packets recorded */
            free(pos);
            return last_score; 
        }
        pos[maxpos]= pos[maxpos]->prev; /* we extracted the tail, so put prev here now */
        before_last_score= last_score;
        last_score= max; /* in case this is the last */
    }
    free(pos);
    return (before_last_score+last_score)/2.0;
}

static double anom_ave(double a[],int size) {
    double sum= 0.0;
    int i;
    if (0) { // self->debug_level) {
        printf("anom_ave: taking average of (%.5f",a[0]);
        for (i=1; i < size; i++) printf(",%.5f",a[i]);
        printf(")\n");
    }
    for (i=0; i < size; i++) sum+= a[i];
    return sum/(double)size;
}

static void reset_obslist(adapt2_data *data,int slot) {
    dll_double *first= data->obslists_head[slot];
    dll_double *second= first->next;
    if (second->next != NULL) free_dll_double_list(second->next);
    first->val= 0.0;
    second->val= 0.0;
    second->next= NULL;
    data->obslists_tail[slot]= second;
    data->obslists_size[slot]= 1;
}


static float grab_new_thresh_3(thresh_adapter *self,spade_enviro *enviro) {
    ll_double *l;
    int slot;
    float new_thresh;
    adapt3_data *data= &self->d.a3;
    double obs_thresh= (data->anoms->val + data->anoms->next->val)/2;
    
    //if (self->debug_level) printf("observed recent ideal threshold for adapt3 is %.4f\n",obs_thresh);
    
    slot= data->completed_obs_per % data->NO;
    data->completed_obs_per++;
    if (data->completed_obs_per > data->NO) data->obssum-= data->hist[slot]; /* kicking a score out */
    data->hist[slot]= obs_thresh;
    data->obssum+= obs_thresh;
    
    if (0) { // self->debug_level > 1) {
        int i;
        printf("data->hist= [");
        printf("%.4f",data->hist[0]);
        for (i= 1; i < data->NO && i < data->completed_obs_per; i++) {
            printf(",%.4f",data->hist[i]);
        }
        printf("]\n");
    }
    
    new_thresh= data->obssum/((data->completed_obs_per >= data->NO)?data->NO:data->completed_obs_per);  
    //if (self->debug_level) printf("new threshold is %.4f\n",new_thresh); 
    
    for (l=data->anoms; l != NULL; l=l->next)  l->val= 0.0;
    
    return new_thresh;
}

static float grab_new_thresh_4(thresh_adapter *self,spade_enviro *enviro) {
    adapt4_data *data= &self->d.a4;
    self->done= 1;
    return data->thresh;
}




void thresh_adapter_new_score(thresh_adapter *self,double anom_score) {
    if (self->done) return;
    switch (self->adapt_mode) {
    case 1: thresh_adapter_1_new_score(self,anom_score); break;
    case 2: thresh_adapter_2_new_score(self,anom_score); break;
    case 3: thresh_adapter_3_new_score(self,anom_score); break;
    }
}

static void thresh_adapter_1_new_score(thresh_adapter *self,double anom_score) {
    ll_double *new,*prev,*l;
    adapt1_data *data= &self->d.a1;
        
    /* add anomaly score to list if it is high enough */
    if (data->top_list_size <= data->target) {
        new= (ll_double *)malloc(sizeof(ll_double));
        data->top_list_size++;
    } else if (anom_score > data->top_list->val) {
        if (anom_score < data->top_list->next->val) {
            data->top_list->val= anom_score; /* can just replace first */
            return;
        }
        new= data->top_list;
        data->top_list= data->top_list->next;
    } else {
        return;
    }
    new->val= anom_score;
    for (prev= data->top_list, l=data->top_list->next; l != NULL && anom_score > l->val; prev=l,l=l->next);
    /* add between prev and l */
    prev->next= new;
    new->next= l;
}

static void thresh_adapter_2_new_score(thresh_adapter *self,double anom_score) {
    dll_double *new,*prev,*l;
    adapt2_data *data= &self->d.a2;
    double score= anom_score;
    int slot= data->obslist_new_slot;

    if (data->obslists_size[slot] < data->target) {
        new= new_dll_double(score);
        data->obslists_size[slot]++;
    } else if (score > data->obslists_head[slot]->val) {
        if (score < data->obslists_head[slot]->next->val) {
            data->obslists_head[slot]->val= score; /* can just replace first in place*/
            return;
        }
        new= data->obslists_head[slot];
        new->val= score;
        data->obslists_head[slot]= data->obslists_head[slot]->next;
        new->next->prev= NULL;
    } else {
        return;
    }
    for (l=data->obslists_head[slot]->next; l != NULL && score > l->val; l=l->next);
    /* add between l->prev and l */
    prev= (l == NULL) ? data->obslists_tail[slot] : l->prev;
    prev->next= new;
    new->prev= prev;
    new->next= l;
    if (l == NULL) {
        data->obslists_tail[slot]= new;
    } else {
        l->prev= new;
    }
}



static void thresh_adapter_3_new_score(thresh_adapter *self,double anom_score) {
    adapt3_data *data= &self->d.a3;
    ll_double *prev,*next,*new;

    /* add anomaly score to list if it is high enough */
    if (data->anoms_size <= data->target) {
        new= new_ll_double(anom_score);
        data->anoms_size++;
    } else if (anom_score > data->anoms->val) {
        if (anom_score < data->anoms->next->val) {
            data->anoms->val= anom_score; /* can just replace first */
            return;
        }
        new= data->anoms;
        new->val= anom_score;
        data->anoms= data->anoms->next;
    } else {
        return;
    }
    for (prev= data->anoms, next=data->anoms->next; next != NULL && anom_score > next->val; prev=next,next=next->next);
    /* add between prev and next */
    prev->next= new;
    new->next= next;
}

void thresh_adapter_print_config_details(thresh_adapter *self,FILE *f,char *indent) {
    char indent2[100];
    sprintf(indent2,"%s  ",indent);
    
    fprintf(f,"%sadapt_mode=%d\n",indent,self->adapt_mode);
    fprintf(f,"%sadapt_period=%d; adapt_by_count=%d\n",indent,(int)self->adapt_period,self->adapt_by_count);

    switch (self->adapt_mode) {
    case 1:
        fprintf(f,"%starget=%d; period=%d; new_obs_weight=%.3f\n",indent,self->d.a1.target,(int)self->d.a1.period,self->d.a1.new_obs_weight);
        break;
    case 2:
        fprintf(f,"%stargetspec=%.3f; obsper=%d\n",indent,self->d.a2.targetspec,(int)self->d.a2.obsper);
        fprintf(f,"%sNS=%d; NM=%d; NL=%d\n",indent,self->d.a2.NS,self->d.a2.NM,self->d.a2.NL);
        break;
    case 3:
        fprintf(f,"%stargetspec=%.3f; obsper=%d; NO=%d\n",indent,self->d.a3.targetspec,(int)self->d.a3.obsper,self->d.a3.NO);
        break;
    case 4:
        fprintf(f,"%sthresh=%.3f\n",indent,self->d.a4.thresh);
        break;
    }
}

/*@}*/
/* $Id: thresh_adapter.c,v 1.5 2002/12/19 22:37:10 jim Exp $ */
