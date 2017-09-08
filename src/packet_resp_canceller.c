/*********************************************************************
packet_resp_canceller.c, distributed as part of Spade v030125.1
Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
copyright (c) 2002 by Silicon Defense (http://www.silicondefense.com/)
Released under GNU General Public License, see the COPYING file included
with the distribution or http://www.silicondefense.com/spice/ for details.

packet_resp_canceller.c implements the "class" packet_resp_canceller which
  buffers spade reports for a period of time, awaiting information that
  the port is open

Please send complaints, kudos, and especially improvements and bugfixes to
hoagland@SiliconDefense.com.  As described in GNU General Public License, no
warranty is expressed for this program.
*********************************************************************/

/*! \file packet_resp_canceller.c
 * \ingroup netspade_layer
 * \brief 
 *  packet_resp_canceller.c implements the "class" packet_resp_canceller
 *  which buffers spade reports for a period of time, awaiting information
 *  that the port is open
 */

/*! \addtogroup netspade_layer
    @{
*/

#include <stdlib.h>
#include <stdio.h>
#include <netinet/in.h>
#include "spade_report.h"
#include "netspade_features.h"
#include "packet_resp_canceller.h"

//static void lt_extract(packet_resp_canceller *self, prc_link *todel, prc_link *prev, u16 hash1, u32 hash2);
static void ltl_extract(prc_lookup_table *lt, prc_link *todel, prc_link *prev, u16 hash1, u32 hash2);
static int lt_delete_report(prc_lookup_table *lt, spade_report *rpt);
static prc_link *new_prc_link(spade_report *rpt);
static void free_prc_ttl_list(prc_link *head);
//static void free_prc_link(prc_link *l);
static prc_lookup_table2 *new_prc_lookup_table2(void);
static void init_prc_lookup_table2(prc_lookup_table2 *t);
static void free_prc_lookup_table2(prc_lookup_table2 *t);
static void free_prc_lookup_table2_clean(prc_lookup_table2 *t);

#define u8_right_rotate(i,bits) ((i >> bits) | ((i & ((1 << bits)-1)) << (8-bits)))

#define calc_hash1(sport,dport) ((sport ^ dport) & LOOKUP_TABLE1_MASK)
#define calc_hash2(sip,dip,hash) { \
    u32 _tmp= sip ^ dip; \
    u8 _tmp1= _tmp & LOOKUP_TABLE2_MASK; \
    u8 _tmp2= (_tmp & LOOKUP_TABLE2_MASK) >> 8; \
    u8 _tmp3= (_tmp & LOOKUP_TABLE2_MASK) >> 16; \
    u8 _tmp4= (_tmp & LOOKUP_TABLE2_MASK) >> 24; \
    hash= _tmp1 \
        ^  u8_right_rotate(_tmp2,2) \
        ^  u8_right_rotate(_tmp3,4) \
        ^  u8_right_rotate(_tmp4,6); \
}

/// free list of allocated prc_lookup_table2s
prc_lookup_table2 *prc_lookup_table2_freelist= NULL;
/// free list of allocated prc_links
prc_link *prc_link_freelist= NULL;

//int disp_hashinfo= 0;

void init_packet_resp_canceller(packet_resp_canceller *self,int wait_secs,prc_report_status_fn status_callback,void *callback_context,port_status_t timeout_implication) {
    int i;
    
    self->tt.num_buckets= wait_secs+1;
    self->tt.last_timeout= (time_t)0;
    self->tt.arr= (prc_list *)malloc(sizeof(prc_list)*self->tt.num_buckets);
    for (i= 0; i <= wait_secs; i++) {
        self->tt.arr[i].head= NULL;
        self->tt.arr[i].tail= NULL;
    }
    
    for (i= 0; i < LOOKUP_TABLE1_SIZE; i++) self->lt.arr[i]= NULL;
    
    self->status_callback= status_callback;
    self->callback_context= callback_context;
    self->timeout_implication= timeout_implication;
}

packet_resp_canceller *new_packet_resp_canceller(int wait_secs,prc_report_status_fn status_callback,void *callback_context,port_status_t timeout_implication) {
    packet_resp_canceller *new= (packet_resp_canceller *)malloc(sizeof(packet_resp_canceller));
    init_packet_resp_canceller(new,wait_secs,status_callback,callback_context,timeout_implication);
    return new;
}

void free_packet_resp_canceller(packet_resp_canceller *self) {
    int i;
    /* free all the prc_link's */
    for (i=0; i < self->tt.num_buckets; i++)
        if (self->tt.arr[i].head != NULL)
            free_prc_ttl_list(self->tt.arr[i].head);
    
    /* free the timeout table's array */
    free(self->tt.arr);
    
    /* free all the prc_lookup_table2's */
    for (i=0; i < LOOKUP_TABLE1_SIZE; i++)
        if (self->lt.arr[i] != NULL)
            free_prc_lookup_table2(self->lt.arr[i]);

    /* free ourself */
    free(self);
}

void packet_resp_canceller_new_time(packet_resp_canceller *self,time_t now) {
    int i;
    prc_link *l;
    int count= now - self->tt.last_timeout;
    //if (self->debug_level > 1) printf("packet_resp_canceller_new_time(%p,%d)\n",self,(int)now);
    if (count > self->tt.num_buckets) count= self->tt.num_buckets;
    for (i=1; i <= count; i++) {
        int slot= (self->tt.last_timeout+i) % self->tt.num_buckets;
        if (self->tt.arr[slot].head != NULL) {
            for (l= self->tt.arr[slot].head; l != NULL; l= l->ttl_next) {
                if (l->rpt != NULL) {
                    /* send the report as closed and delete this from the lookup table */
                    (*self->status_callback)(self->callback_context,l->rpt,self->timeout_implication);
                    lt_delete_report(&self->lt,l->rpt);
                }
            }
            free_prc_ttl_list(self->tt.arr[slot].head);
            self->tt.arr[slot].head= NULL;
            self->tt.arr[slot].tail= NULL;
        }
    }
    self->tt.last_timeout= now;
}

void packet_resp_canceller_add_report(packet_resp_canceller *self,spade_report *rpt) {
    spade_event *pkt= rpt->pkt;
    u16 hash1;
    u32 hash2;
    prc_lookup_table2 *t2;
    prc_link *new;
    int slot;
    /*if (self->debug_level) printf("packet_resp_canceller_add_report(%p,%p %.2f %8x:%d %8x:%d)\n",self,rpt,rpt->pkt->time,rpt->pkt->fldval[SIP],rpt->pkt->fldval[SPORT],rpt->pkt->fldval[DIP],rpt->pkt->fldval[DPORT]);*/
    
    if ((pkt->fldval[IPPROTO] == IPPROTO_TCP) || (pkt->fldval[IPPROTO] == IPPROTO_UDP))
        hash1= calc_hash1(pkt->fldval[SPORT],pkt->fldval[DPORT]);
    else
        hash1= calc_hash1(pkt->fldval[SIP],pkt->fldval[DIP]);
    //if (disp_hashinfo) printf(": addrep hash1(%d,%d) => %d\n",pkt->fldval[SPORT],pkt->fldval[DPORT],hash1);
    if (self->lt.arr[hash1] == NULL) self->lt.arr[hash1]= new_prc_lookup_table2();
    t2= self->lt.arr[hash1];
    calc_hash2(pkt->fldval[SIP],pkt->fldval[DIP],hash2);
    //if (disp_hashinfo) printf(": addrep hash2(%08x,%08x) => %d\n",pkt->fldval[SIP],pkt->fldval[DIP],hash2);
    new= new_prc_link(rpt);
    if (t2->arr[hash2] == NULL) { // first entry here
        t2->num_used++;
    } else {
        new->ltl_next= t2->arr[hash2];
    }
    t2->arr[hash2]= new;
    
    // append in time table
    slot= ((int)pkt->time) % self->tt.num_buckets;
    if (self->tt.arr[slot].tail == NULL) {
        self->tt.arr[slot].head= new;
    } else {
        self->tt.arr[slot].tail->ttl_next= new;
    }
    self->tt.arr[slot].tail= new;
    //fflush(stdout);
}

void packet_resp_canceller_note_response(packet_resp_canceller *self,port_status_t implied_status,u32 sip,u16 sport,u32 dip,u16 dport,int portless) {
    prc_link *l,*prev,*next,*newprev;
    u32 hash2;
    prc_lookup_table2 *t2;
    u16 hash1= portless ? calc_hash1(sip,dip) : calc_hash1(sport,dport);
    //if (disp_hashinfo) printf(": noteresp hash1(%d,%d) => %d\n",sport,dport,hash1);
    /*if (self->debug_level) printf("packet_resp_canceller_note_response(%p,%s,%8x:%d %8x:%d,%d)\n",self,PORT_STATUS_AS_STR(implied_status),sip,sport,dip,dport,portless);*/
    
    if (self->lt.arr[hash1] == NULL) return;
    t2= self->lt.arr[hash1];
    calc_hash2(sip,dip,hash2);
    //if (disp_hashinfo) printf(": noteresp hash2(%08x,%08x) => %d\n",sip,dip,hash2);
    if (t2->arr[hash2] == NULL) return;
    for (l= t2->arr[hash2], prev=NULL; l != NULL; prev=newprev,l=next) {
        next= l->ltl_next; /* in case this link is removed */
        newprev= l;
        if (l->rpt == NULL) continue; /* shouldn't happen */
        if (l->rpt->pkt->fldval[SIP] != sip) continue;
        if (l->rpt->pkt->fldval[DIP] != dip) continue;
        if (l->rpt->pkt->fldval[SPORT] != sport) continue;
        if (l->rpt->pkt->fldval[DPORT] != dport) continue;
        /* found a match */
        ltl_extract(&self->lt,l,prev,hash1,hash2);
        (*self->status_callback)(self->callback_context,l->rpt,implied_status);
        l->rpt= NULL; /* mark as deleted from lookup table */
        newprev= prev;
        /* check for more matches */
    }
    //fflush(stdout);
}

#if 0 // not currently needed
static void lt_extract(packet_resp_canceller *self,prc_link *todel,prc_link *prev,u16 hash1,u32 hash2) {
    ltl_extract(&self->lt,todel,prev,hash1,hash2);
}
#endif

static void ltl_extract(prc_lookup_table *lt,prc_link *todel,prc_link *prev,u16 hash1,u32 hash2) {
    if (prev == NULL) {
        if (todel->ltl_next == NULL) {
            lt->arr[hash1]->arr[hash2]= NULL;
            lt->arr[hash1]->num_used--;
            if (lt->arr[hash1]->num_used == 0) {
                free_prc_lookup_table2_clean(lt->arr[hash1]);
                lt->arr[hash1]= NULL;
            }
        } else {
            lt->arr[hash1]->arr[hash2]= todel->ltl_next;
        }
    } else {
        prev->ltl_next= todel->ltl_next;
    }
}

static int lt_delete_report(prc_lookup_table *lt,spade_report *rpt) {
    prc_link *l,*prev;
    u32 hash2;
    prc_lookup_table2 *t2;
    spade_event *pkt= rpt->pkt;
    u16 hash1;
    if ((pkt->fldval[IPPROTO] == IPPROTO_TCP) || (pkt->fldval[IPPROTO] == IPPROTO_UDP))
        hash1= calc_hash1(pkt->fldval[SPORT],pkt->fldval[DPORT]);
    else
        hash1= calc_hash1(pkt->fldval[SIP],pkt->fldval[DIP]);
    
    if (lt->arr[hash1] == NULL) return 0;
    t2= lt->arr[hash1];
    calc_hash2(pkt->fldval[SIP],pkt->fldval[DIP],hash2);
    if (t2->arr[hash2] == NULL) return 0;
    for (l= t2->arr[hash2], prev=NULL; l != NULL && l->rpt != rpt; prev=l,l=l->ltl_next);
    if (l == NULL) return 0; /* no match */
    ltl_extract(lt,l,prev,hash1,hash2);
    return 1;
}

static prc_link *new_prc_link(spade_report *rpt) {
    prc_link *new;
    if (prc_link_freelist == NULL) {
        new= (prc_link *)malloc(sizeof(prc_link));
        if (new == NULL) return NULL;
    } else {
        new= prc_link_freelist;
        prc_link_freelist= prc_link_freelist->ttl_next;
    }
    new->rpt= rpt;
    new->ltl_next= NULL;    
    new->ttl_next= NULL;    
    return new;
}

static void free_prc_ttl_list(prc_link *head) {
    prc_link *tail;
    if (head == NULL) return;
    for (tail= head; tail->ttl_next != NULL; tail= tail->ttl_next);
    tail->ttl_next= prc_link_freelist;
    prc_link_freelist= head;  
}

#if 0 // not currently needed
static void free_prc_link(prc_link *l) {
    if (l == NULL) return;
    l->ttl_next= prc_link_freelist;
    prc_link_freelist= l;  
}
#endif 

static prc_lookup_table2 *new_prc_lookup_table2() {
    prc_lookup_table2 *new;
    
    if (prc_lookup_table2_freelist == NULL) {
        new= (prc_lookup_table2 *)malloc(sizeof(prc_lookup_table2));
        if (new == NULL) return NULL;
        init_prc_lookup_table2(new);
    } else {
        new= prc_lookup_table2_freelist;
        prc_lookup_table2_freelist= (prc_lookup_table2 *)prc_lookup_table2_freelist->arr[0];
        /* items on freelist are pre-inited for efficiency except for arr[0] */
        new->arr[0]= NULL;
    }
    return new;
}

static void init_prc_lookup_table2(prc_lookup_table2 *t) {
    int i;
    t->num_used= 0;
    for (i= 0; i < LOOKUP_TABLE2_SIZE; i++) t->arr[i]= NULL;
}

static void free_prc_lookup_table2(prc_lookup_table2 *t) {    
    init_prc_lookup_table2(t);
    free_prc_lookup_table2_clean(t);
}

/* t is expected to be cleaned up to to an empty state */
static void free_prc_lookup_table2_clean(prc_lookup_table2 *t) {    
    if (t == NULL) return;
    t->arr[0]= (prc_link *)prc_lookup_table2_freelist;
    prc_lookup_table2_freelist= t;  
}

void packet_resp_canceller_print_config_details(packet_resp_canceller *self,FILE *f,char *indent) {
    fprintf(f,"%swait=%d; timeout_implication=%s\n",indent,self->tt.num_buckets,PORT_STATUS_AS_STR(self->timeout_implication));
}

/*@}*/

/* $Id: packet_resp_canceller.c,v 1.10 2003/01/14 17:45:31 jim Exp $ */

