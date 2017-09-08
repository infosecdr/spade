/*********************************************************************
ll_double.h, distributed as part of Spade v030125.1
Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
copyright (c) 2002 by Silicon Defense (http://www.silicondefense.com/)
Released under GNU General Public License, see the COPYING file included
with the distribution or http://www.silicondefense.com/spice/ for details.

Please send complaints, kudos, and especially improvements and bugfixes to
hoagland@SiliconDefense.com.  As described in GNU General Public License, no
warranty is expressed for this program.
*********************************************************************/

#ifndef LL_DOUBLE_H
#define LL_DOUBLE_H

/*! \file ll_double.h
 * \brief
 *  ll_double.h is the header file for ll_double.c
 * \ingroup libspade_util
 */

/*! \addtogroup libspade_util
    @{
*/

/// a link in a singly linked list of doubles
typedef struct _ll_double {
    double val; ///< the value
    struct _ll_double *next; ///< the next in the list
} ll_double;

ll_double *new_ll_double(double val);
void free_ll_double_list(ll_double *start);

/*@}*/
#endif  /* ! LL_DOUBLE_H */

/* $Id: ll_double.h,v 1.5 2002/12/20 06:10:03 jim Exp $ */
