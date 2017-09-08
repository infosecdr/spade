/*********************************************************************
spade_enviro.h, distributed as part of Spade v030125.1
Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
copyright (c) 2002 by Silicon Defense (http://www.silicondefense.com/)
Released under GNU General Public License, see the COPYING file included
with the distribution or http://www.silicondefense.com/spice/ for details.

Please send complaints, kudos, and especially improvements and bugfixes to
hoagland@SiliconDefense.com.  As described in GNU General Public License, no
warranty is expressed for this program.
*********************************************************************/

/* Internal version control: $Id: spade_enviro.h,v 1.8 2002/12/21 01:25:39 jim Exp $ */

#ifndef SPADE_ENVIRO_H
#define SPADE_ENVIRO_H

/*! \file spade_enviro.h
 * \brief 
 *  spade_enviro.h contains the type declaration for the spade_enviro
 *  struct
 * \ingroup stmgr
 */

/*! \weakgroup stmgr
    @{
*/


#include <time.h>

/// various counts of the disposition of events; yes, this should be in netspade, not libspade because it violates abstractions
typedef struct {
    int scored;      ///< count of all packets scored 
    int respchecked; ///< count of all packets checked as a response
    int reported;    ///< count of all packets reported
    int excluded;    ///< count of all packets not reported due to configured exclusion
    int nonexcluded; ///< count of all packets that were anomalous but not excluded
    int waited;      ///< count of all packets added to the wait queue
    int insuffobsed; ///< count of packets with insufficient obsercations
} spade_pkt_stats;


/// shared state between libspade and its user
typedef struct {
    time_t now; ///< the time of the last packet added

    /// the threshold at which anomolous events are reported
    double thresh;
    
    unsigned long *total_pkts; ///< pointer to read-only count of all packets seen
    spade_pkt_stats pkt_stats; ///< packet disposition counts
} spade_enviro;

spade_enviro *new_spade_enviro(double thresh,unsigned long *total_pkts_ptr);
void init_spade_enviro(spade_enviro *self,double thresh,unsigned long *total_pkts_ptr);

/*@}*/
#endif // SPADE_ENVIRO_H
