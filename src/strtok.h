/*********************************************************************
strtok.h, distributed as part of Spade v030125.1
Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
copyright (c) 2002 by Silicon Defense (http://www.silicondefense.com/)
Released under GNU General Public License, see the COPYING file included
with the distribution or http://www.silicondefense.com/spice/ for details.

Please send complaints, kudos, and especially improvements and bugfixes to
hoagland@SiliconDefense.com.  As described in GNU General Public License, no
warranty is expressed for this program.
*********************************************************************/

#ifndef STRTOK_H
#define STRTOK_H

/*! \file strtok.h
 * \brief
 *  strtok.h is the header file for strtok.c.
 * \ingroup libspade_util
 */

/*! \addtogroup libspade_util
    @{
*/

#include "spade_output.h"

int fill_args_space_sep(char *str,char *format,void *args[],spade_msg_fn msg_callback);
char *extract_str_arg_space_sep(char *str,char *argname);
int terminate_first_tok(char *str,char *sepchars,char **head,char *oldchar);

/*@}*/
#endif // STRTOK_H

/* $Id: strtok.h,v 1.5 2002/12/19 22:37:10 jim Exp $ */
