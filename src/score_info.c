/*********************************************************************
score_info.c, distributed as part of Spade v030125.1
Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
copyright (c) 2002 by Silicon Defense (http://www.silicondefense.com/)
Released under GNU General Public License, see the COPYING file included
with the distribution or http://www.silicondefense.com/spice/ for details.

Please send complaints, kudos, and especially improvements and bugfixes to
hoagland@SiliconDefense.com.  As described in GNU General Public License, no
warranty is expressed for this program.
*********************************************************************/

#include <stdlib.h>
#include "score_info.h"

/*! \file score_info.c
 * \brief 
 *  score_info.c contains routines for score_info allocation, initing,
 *  and recycling and access; score_info reprents computed anomaly
 *  score(s)
 * \ingroup scoreprod
 */

/*! \addtogroup scoreprod
    @{
*/


/// free list of allocated score_infos
score_info *score_info_freelist=NULL;

/* creation and recycling routines for score_info's */

score_info *new_score_info(scorepref main,double relscore,double rawscore,int corrscore_used) {
    score_info *new;
    if (score_info_freelist != NULL) {
        new= score_info_freelist;
        score_info_freelist= new->next;
    } else {
        new= (score_info *)malloc(sizeof(score_info));
    }
    init_score_info(new,main,relscore,rawscore,corrscore_used);
    return new;
}

void init_score_info(score_info *i,scorepref main,double relscore,double rawscore,int corrscore_used) {
    i->main= main;
    i->relscore= relscore;
    i->rawscore= rawscore;
    i->corrscore_used= corrscore_used;
}

score_info *score_info_clone(score_info *i) {
    return new_score_info(i->main,i->relscore,i->rawscore,i->corrscore_used);
}

void free_score_info(score_info *i) {
    i->next= score_info_freelist;
    score_info_freelist= i;
}

void free_score_infos(score_info *start) {
    score_info *end,*next;
    for (end= start, next=start->next; next != NULL; end=next,next=next->next);
    end->next= score_info_freelist;
    score_info_freelist= start;
}

double score_info_mainscore(score_info *i) {
    return i->main == PREF_RAWSCORE ? i->rawscore : i->relscore;
}

double score_info_relscore(score_info *i) {
    return i->relscore;
}

double score_info_rawscore(score_info *i) {
    return i->rawscore;
}

int score_info_raw_is_corrscore(score_info *i) {
    return i->corrscore_used;
}

scorepref score_info_main_pref(score_info *i) {
    return i->main;
}


const char *scorepref_str(scorepref pref) {
    switch (pref) {
    case PREF_NOSCORE: return "NOSCORE";
    case PREF_RAWSCORE: return "RAWSCORE";
    case PREF_RELSCORE: return "RELSCORE";
    default: return "undefined";
    }
}

/*@}*/
/* $Id: score_info.c,v 1.6 2003/01/14 17:45:31 jim Exp $ */

