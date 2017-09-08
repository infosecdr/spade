/*********************************************************************
dll_double.c, distributed as part of Spade v030125.1
Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
copyright (c) 2002 by Silicon Defense (http://www.silicondefense.com/)
Released under GNU General Public License, see the COPYING file included
with the distribution or http://www.silicondefense.com/spice/ for details.

Please send complaints, kudos, and especially improvements and bugfixes to
hoagland@SiliconDefense.com.  As described in GNU General Public License, no
warranty is expressed for this program.
*********************************************************************/

#include <stdlib.h>
#include "dll_double.h"

/*! \file dll_double.c
 * \brief 
 *  dll_double.c contains routines for dll_double allocation, initing,
 *  and recycling; dll_doubles are doubly linked list of doubles
 * \ingroup libspade_util
 */

/*! \addtogroup libspade_util Spade library utilities
 * \brief this group contains general utility objects in libspade
 * \ingroup libspade
    @{
*/

/// free list of dll_doubles
dll_double *free_dlink_list= NULL;

/* creation and recycling routines for dll_double's */

dll_double *new_dll_double(double val) {
    dll_double *link;
    if (free_dlink_list != NULL) {
        link= free_dlink_list;
        free_dlink_list= link->next;
    } else {
        link= (dll_double *)malloc(sizeof(dll_double));
    }
    link->val= val;
    link->prev= NULL;
    link->next= NULL;
    return link;
}

void free_dll_double_list(dll_double *start) {
    dll_double *end;
    for (end= start; end->next != NULL; end=end->next);
    end->next= free_dlink_list;
    free_dlink_list= start;
}

/*@}*/
/* $Id: dll_double.c,v 1.5 2003/01/14 17:45:31 jim Exp $ */