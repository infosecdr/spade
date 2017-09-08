/*********************************************************************
spade_event.h, distributed as part of Spade v030125.1
Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
copyright (c) 2002 by Silicon Defense (http://www.silicondefense.com/)
Released under GNU General Public License, see the COPYING file included
with the distribution or http://www.silicondefense.com/spice/ for details.

Please send complaints, kudos, and especially improvements and bugfixes to
hoagland@SiliconDefense.com.  As described in GNU General Public License, no
warranty is expressed for this program.
*********************************************************************/

/* Internal version control: $Id: spade_event.h,v 1.7 2002/12/21 01:25:39 jim Exp $ */

#ifndef SPADE_EVENT_H
#define SPADE_EVENT_H

/*! \file spade_event.h
 * \brief 
 *  spade_event.h contains the type declaration for the spade_event struct 
 *  and the interface to the associated functions
 * \ingroup libspade_misc
 */

/*! \addtogroup libspade_misc
    @{
*/

#include "spade_prob_table_types.h"

/// function type to make a copy of a spade_event's "native" field
typedef void *(*event_native_copier_t)(void *native);
/// function type to free a copy of a spade_event's "native" field
typedef void (*event_native_freer_t)(void *native);

/// the representation of an event that is being given to libspade
typedef struct {
    /// the features, indexed by feature number (libspade-user assigned)
    valtype fldval[MAX_NUM_FEATURES];
    /// the time the event occurred
    double time;
    /// the origin of the event, in user defined terms
    u32 origin;

    /// a field the user may use to maintain a reference to its own representation of the event
    void *native;
    /// used internally, at times this field may be set to point to a routine to free the native copy
    event_native_freer_t native_freer;
} spade_event;

spade_event *new_spade_event(void);
spade_event *spade_event_clone(spade_event *e, event_native_copier_t native_copier, event_native_freer_t native_freer);
void free_spade_event(spade_event *e);

/*@}*/

#endif // SPADE_EVENT_H
