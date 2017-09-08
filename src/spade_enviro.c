/*********************************************************************
spade_enviro.c, distributed as part of Spade v030125.1
Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
copyright (c) 2002 by Silicon Defense (http://www.silicondefense.com/)
Released under GNU General Public License, see the COPYING file included
with the distribution or http://www.silicondefense.com/spice/ for details.

Please send complaints, kudos, and especially improvements and bugfixes to
hoagland@SiliconDefense.com.  As described in GNU General Public License, no
warranty is expressed for this program.
*********************************************************************/

#include <stdlib.h>
#include "spade_enviro.h"

/*! \file spade_enviro.c
 * \brief 
 *  spade_enviro.c contains routines for spade_enviro allocation,
 *  and initing
 * \ingroup stmgr
 */

/*! \weakgroup stmgr
    @{
*/

spade_enviro *new_spade_enviro(double thresh,unsigned long *total_pkts_ptr) {
    spade_enviro *new= (spade_enviro *)malloc(sizeof(spade_enviro));
    if (new == NULL) return NULL;
    init_spade_enviro(new,thresh,total_pkts_ptr);
    return new;
}

void init_spade_enviro(spade_enviro *self,double thresh,unsigned long *total_pkts_ptr) {
    self->now= (time_t)0;
    self->thresh= thresh;
    self->total_pkts= total_pkts_ptr;
    self->pkt_stats.scored= 0;
    self->pkt_stats.respchecked= 0;
    self->pkt_stats.excluded= 0;
    self->pkt_stats.nonexcluded= 0;
    self->pkt_stats.reported= 0;
    self->pkt_stats.waited= 0;
    self->pkt_stats.insuffobsed= 0;
}

/*@}*/
/* $Id: spade_enviro.c,v 1.4 2002/12/19 22:37:10 jim Exp $ */
