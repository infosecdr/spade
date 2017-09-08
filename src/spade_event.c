/*********************************************************************
spade_event.c, distributed as part of Spade v030125.1
Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
copyright (c) 2002 by Silicon Defense (http://www.silicondefense.com/)
Released under GNU General Public License, see the COPYING file included
with the distribution or http://www.silicondefense.com/spice/ for details.

Please send complaints, kudos, and especially improvements and bugfixes to
hoagland@SiliconDefense.com.  As described in GNU General Public License, no
warranty is expressed for this program.
*********************************************************************/

#include <stdlib.h>
#include "spade_event.h"

/*! \file spade_event.c
 * \brief 
 *  spade_event.c contains routines for spade_event allocation, initing,
 *  and recycling; spade_event reprents an event that Spade is processing
 * \ingroup libspade_misc
 */

/*! \addtogroup libspade Spade library
 * \brief This group contains the objects in libspade, which provides core
 *  routines for Spade-like detection
*/
 
/*! \addtogroup libspade_misc Spade library misc
 * \brief this group contains miscellaneous objects in libspade
 * \ingroup libspade
 * @{
*/

/// free list of allocated spade_events
spade_event *spade_event_freelist=NULL;

/* creation and recycling routines for spade_event's */

spade_event *new_spade_event() {
    spade_event *new;
    if (spade_event_freelist != NULL) {
        new= spade_event_freelist;
        spade_event_freelist= (spade_event *)new->native;
    } else {
        new= (spade_event *)malloc(sizeof(spade_event));
    }
    new->native= NULL;
    new->native_freer= NULL;
    return new;
}

spade_event *spade_event_clone(spade_event *e,event_native_copier_t native_copier,event_native_freer_t native_freer) {
    spade_event *clone= new_spade_event();
    *clone= *e; /* copy data */
    if (native_copier != NULL)
        clone->native= (*native_copier)(e->native);
    clone->native_freer= native_freer;
    return clone;
}

void free_spade_event(spade_event *e) {
    if (e->native_freer != NULL) (*(e->native_freer))(e->native);
    e->native= (void *)spade_event_freelist;
    spade_event_freelist= e;
}

/*@}*/

/* $Id: spade_event.c,v 1.6 2003/01/14 17:45:31 jim Exp $ */

