/*********************************************************************
dll_double.h, distributed as part of Spade v030125.1
Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
copyright (c) 2002 by Silicon Defense (http://www.silicondefense.com/)
Released under GNU General Public License, see the COPYING file included
with the distribution or http://www.silicondefense.com/spice/ for details.

Please send complaints, kudos, and especially improvements and bugfixes to
hoagland@SiliconDefense.com.  As described in GNU General Public License, no
warranty is expressed for this program.
*********************************************************************/

#ifndef DLL_DOUBLE_H
#define DLL_DOUBLE_H

/*! \file dll_double.h
 * \brief 
 *  dll_double.h is the header file for dll_double.c.
 * \ingroup libspade_util
 */

/*! \addtogroup libspade_util
    @{
*/

/// a link in a doubly linked list of doubles
typedef struct _dll_double {
    double val; ///< the value
    struct _dll_double *prev; ///< the previous item on the linked list
    struct _dll_double *next; ///< the next item on the linked list
} dll_double;

dll_double *new_dll_double(double val);
void free_dll_double_list(dll_double *start);


#endif  /* ! DLL_DOUBLE_H */


/* $Id: dll_double.h,v 1.4 2002/12/19 22:37:10 jim Exp $ */
