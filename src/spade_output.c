/*********************************************************************
spade_output.c, distributed as part of Spade v030125.1
Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
copyright (c) 2002 by Silicon Defense (http://www.silicondefense.com/)
Released under GNU General Public License, see the COPYING file included
with the distribution or http://www.silicondefense.com/spice/ for details.

Please send complaints, kudos, and especially improvements and bugfixes to
hoagland@SiliconDefense.com.  As described in GNU General Public License, no
warranty is expressed for this program.
*********************************************************************/

#include <stdarg.h>
#include <stdio.h>
#include "spade_output.h"

/*! \file spade_output.c
 * \brief 
 *  spade_output.c contains the definition of default_spade_msg_fn
 * \ingroup libspade_misc
 */

/*! \addtogroup libspade_misc
    @{
*/

void default_spade_msg_fn(spade_message_type msg_type,const char *str) {
    switch (msg_type) {
    case SPADE_MSG_TYPE_FATAL:
        fprintf(stderr, "%s", str);
        exit(1);
    case SPADE_MSG_TYPE_WARNING:
        fprintf(stderr, "%s", str);
        break;
    default:
        printf("%s", str);
        break;
    }
}

void formatted_spade_msg_send(spade_message_type msg_type,spade_msg_fn msg_fn,const char *format,...) {
    char buf[MAX_SPADE_MSG_LEN+1];
    va_list ap;
    va_start(ap, format);
    
    vsnprintf(buf, MAX_SPADE_MSG_LEN, format, ap);
    (*msg_fn)(msg_type,buf);
    va_end(ap);
}

/*@}*/

/* $Id: spade_output.c,v 1.3 2002/12/19 22:37:10 jim Exp $ */
