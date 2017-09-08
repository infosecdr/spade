/*********************************************************************
spade_features.h, distributed as part of Spade v030125.1
Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
copyright (c) 2002 by Silicon Defense (http://www.silicondefense.com/)
Released under GNU General Public License, see the COPYING file included
with the distribution or http://www.silicondefense.com/spice/ for details.

Please send complaints, kudos, and especially improvements and bugfixes to
hoagland@SiliconDefense.com.  As described in GNU General Public License, no
warranty is expressed for this program.
*********************************************************************/

/* Internal version control: $Id: spade_features.h,v 1.9 2002/12/21 01:25:39 jim Exp $ */

#ifndef SPADE_FEATURES_H
#define SPADE_FEATURES_H

/*! \file spade_features.h
 * \brief 
 *  spade_features.h is a set of type declarations around a spade feature
 * \ingroup staterec
 */

/*! \addtogroup staterec
    @{
*/

#include <limits.h>

#define MAX_U32 0xFFFFFFFF ///< the largest number that can be represented in a u32
#define MAX_U16 0xFFFF     ///< the largest number that can be represented in a u16
#define MAX_U8  0xFF       ///< the largest number that can be represented in a u8

/* search to find a type to be u32 */
// u32 is a unsigned (exactly) 32 bit integer
#if USHRT_MAX == MAX_U32
typedef unsigned short u32;
#elif UINT_MAX == MAX_U32
typedef unsigned int u32;
#elif ULONG_MAX == MAX_U32
typedef unsigned long u32;
#else
#error could not find a 4 byte int to be u32 in types.h
#endif

/* search to find a type to be u16 */
// u16 is a unsigned (exactly) 16 bit integer
#if USHRT_MAX == MAX_U16
typedef unsigned short u16;
#elif UINT_MAX == MAX_U16
typedef unsigned int u16;
#elif ULONG_MAX == MAX_U16
typedef unsigned long u16;
#else
#error could not find a 2 byte int to be u16 in types.h
#endif

/* search to find a type to be u8 */
/* u8 is a unsigned (exactly) 8 bit integer */
#if UCHAR_MAX == MAX_U8
typedef unsigned char u8;
#elif USHRT_MAX == MAX_U8
typedef unsigned short u8;
#elif UINT_MAX == MAX_U8
typedef unsigned int u8;
#else
#error could not find a 1 byte int to be u8 in types.h
#endif


/// the maximum number of features libspade can handle
#define MAX_NUM_FEATURES 8

typedef u8 features; ///< type of the index represting the features we are storing the prob table about

/// this represents a sorted list of up to MAX_NUM_FEATURES features
typedef struct {
    u8 num;  ///< how many featrues are in the list
    features feat[MAX_NUM_FEATURES]; ///< 0-based array storing the features
} feature_list;

#endif // SPADE_FEATURES_H
