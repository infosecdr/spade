/*********************************************************************
netspade_features.h, distributed as part of Spade v030125.1
Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
copyright (c) 2002 by Silicon Defense (http://www.silicondefense.com/)
Released under GNU General Public License, see the COPYING file included
with the distribution or http://www.silicondefense.com/spice/ for details.

netspade_features.h is contains the features definitions for netspade

Please send complaints, kudos, and especially improvements and bugfixes to
hoagland@SiliconDefense.com.  As described in GNU General Public License, no
warranty is expressed for this program.
*********************************************************************/

/* Internal version control: $Id: netspade_features.h,v 1.9 2002/12/20 06:10:03 jim Exp $ */

#ifndef NETSPADE_FEATURES_H
#define NETSPADE_FEATURES_H

#include "spade_features.h"

/*! \file netspade_features.h
 * \ingroup netspade_layer
 * \brief 
 *  netspade_features.h is contains the features definitions for netspade
 */

/*! \addtogroup netspade_layer
    @{
*/


#define SIP             0 ///< the source IP netspade feature
#define DIP             1 ///< the dest IP netspade feature
#define SPORT           2 ///< the source port netspade feature
#define DPORT           3 ///< the dest port netspade feature
#define IPPROTO         4 ///< the IP protocol netspade feature
#define TCPFLAGS        5 ///< the TCP flags netspade feature
#define ICMPTYPE        6 ///< the ICMP type netspade feature
#define ICMPTYPECODE    7 ///< the ICMP type&code netspade feature

/// \brief the number of netspade features defined
/// \note must be no more than MAX_NUM_FEATURES in spade_features.h
//#define NETSPADE_NUM_FEATURES 6
#define NETSPADE_NUM_FEATURES 8
extern const char *featurenames[NETSPADE_NUM_FEATURES+1];

/// used for the IPPROTO file when we don't know the IP protocol
#define IPPROTO_UNKNOWN (u32)-1;

/// the value for the "origin" field in spade_event when the header was at the top level of the packet
#define PKTORIG_TOP     1
/// the value for the "origin" field in spade_event when the header was enclosed in an unreachable packet
#define PKTORIG_UNRCH   2

/*@}*/

#endif // NETSPADE_FEATURES_H
