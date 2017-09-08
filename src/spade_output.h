/*********************************************************************
spade_output.h, distributed as part of Spade v030125.1
Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
copyright (c) 2002 by Silicon Defense (http://www.silicondefense.com/)
Released under GNU General Public License, see the COPYING file included
with the distribution or http://www.silicondefense.com/spice/ for details.

Please send complaints, kudos, and especially improvements and bugfixes to
hoagland@SiliconDefense.com.  As described in GNU General Public License, no
warranty is expressed for this program.
*********************************************************************/

/* Internal version control: $Id: spade_output.h,v 1.3 2002/12/21 01:25:39 jim Exp $ */

#ifndef SPADE_OUTPUT_H
#define SPADE_OUTPUT_H

/*! \file spade_output.h
 * \brief 
 *  spade_output.h contains some declarations regarding Spade
 *  message output
 * \ingroup libspade_misc
 */

/** \addtogroup libspade_misc
    @{
*/

#include <stdarg.h>

/// the max length of a message from Spade
#define MAX_SPADE_MSG_LEN 1000

/// enum listing the different messages types from Spade to the user
typedef enum {
    SPADE_MSG_TYPE_STATUS,  ///< message is providing routine status information, e.g., from starting up
    SPADE_MSG_TYPE_INFO,    ///< the message is merely informational
    SPADE_MSG_TYPE_DEBUG,   ///< it is a debugging message
    SPADE_MSG_TYPE_WARNING, ///< the message is a warning
    SPADE_MSG_TYPE_FATAL    ///< fatal error
} spade_message_type;

/// function type for a spade message callback function
typedef void (*spade_msg_fn)(spade_message_type msg_type,const char *str);

void default_spade_msg_fn(spade_message_type msg_type,const char *str);

void formatted_spade_msg_send(spade_message_type msg_type,spade_msg_fn msg_fn,const char *format,...);

/*@}*/

#endif // SPADE_OUTPUT_H
