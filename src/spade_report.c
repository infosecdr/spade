/*********************************************************************
spade_report.c, distributed as part of Spade v030125.1
Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
copyright (c) 2002 by Silicon Defense (http://www.silicondefense.com/)
Released under GNU General Public License, see the COPYING file included
with the distribution or http://www.silicondefense.com/spice/ for details.

Please send complaints, kudos, and especially improvements and bugfixes to
hoagland@SiliconDefense.com.  As described in GNU General Public License, no
warranty is expressed for this program.
*********************************************************************/


#include <stdlib.h>
#include <string.h>
#include "spade_report.h"

/*! \file spade_report.c
 * \ingroup netspade_layer
 * \brief 
 *  spade_report.c contains routines for spade_report allocation, initing, and
 *  recycling; spade_report reprents a report that Spade is making
 */

/*! \addtogroup netspade_layer
    @{
*/

/* creation and recycling routines for spade_report's */
spade_report *spade_report_freelist=NULL;

spade_report *new_spade_report(spade_event *pkt,score_info *score, int detect_type, char *detectorid,const char *detect_type_str,char *scope_str,spade_pkt_stats *stream_stats,port_status_t port_status) {
    spade_report *new;
    if (spade_report_freelist != NULL) {
        new= spade_report_freelist;
        spade_report_freelist= new->next;
    } else {
        new= (spade_report *)malloc(sizeof(spade_report));
    }
    
    new->pkt= pkt;
    new->score=score;
    new->detect_type= detect_type;
    new->detectorid= detectorid;
    new->stream_stats= stream_stats;
    new->port_status= port_status;
    new->detect_type_str= detect_type_str;
    if (scope_str != NULL)
        strncpy(new->scope_str,scope_str,200);
    else
        new->scope_str[0]= '\0';
    new->next= NULL;
    return new;
}

void free_spade_report(spade_report *rpt) {
    rpt->next= spade_report_freelist;
    spade_report_freelist= rpt;
}

void free_spade_reports(spade_report *start) {
    spade_report *end,*next;
    for (end= start, next=start->next; next != NULL; end=next,next=next->next);
    end->next= spade_report_freelist;
    spade_report_freelist= start;
}

void port_status_set_file_print(port_status_set_t set,FILE *f) {
    int first= 1;
    int i;
    fprintf(f,"{");
    if ((set & 0xFFF) == 0xFFF)
        fprintf(f,"*ALL*");
    else {
        for (i=0; i < 16; i++) {
            if (PS_IN_SET(set,i)) {
                if (!first) { fprintf(f,","); }
                first=0;
                fprintf(f,"%s",PORT_STATUS_AS_STR(i));
            }
        }
    }
    fprintf(f,"}");
}

/*@}*/

/* $Id: spade_report.c,v 1.7 2002/12/19 22:37:10 jim Exp $ */
