/*********************************************************************
ll_double.c, distributed as part of Spade v030125.1
Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
copyright (c) 2002 by Silicon Defense (http://www.silicondefense.com/)
Released under GNU General Public License, see the COPYING file included
with the distribution or http://www.silicondefense.com/spice/ for details.

lease send complaints, kudos, and especially improvements and bugfixes to
hoagland@SiliconDefense.com.  As described in GNU General Public License, no
warranty is expressed for this program.
*********************************************************************/

/*! \file ll_double.c
 * \brief
 *  contains routines for ll_double allocation, initing, and
 *  recycling; ll_doubles are singly linked list of doubles
 * \ingroup libspade_util
 */

/*! \addtogroup libspade_util
    @{
*/

#include <stdlib.h>
#include "ll_double.h"

/// free list of allocated ll_doubles
ll_double *free_link_list=NULL;

/* creation and recycling routines for ll_double's */

ll_double *new_ll_double(double val) {
    ll_double *link;
    if (free_link_list != NULL) {
        link= free_link_list;
        free_link_list= link->next;
    } else {
        link= (ll_double *)malloc(sizeof(ll_double));
    }
    link->val= val;
    link->next= NULL;
    return link;
}

void free_ll_double_list(ll_double *start) {
    ll_double *end,*next;
    for (end= start, next=start->next; next != NULL; end=next,next=next->next);
    end->next= free_link_list;
    free_link_list= start;
}

/*@}*/

/* $Id: ll_double.c,v 1.6 2003/01/14 17:45:31 jim Exp $ */
