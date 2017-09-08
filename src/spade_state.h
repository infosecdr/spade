/*********************************************************************
spade_state.h, distributed as part of Spade v030125.1
Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
copyright (c) 2002 by Silicon Defense (http://www.silicondefense.com/)
Released under GNU General Public License, see the COPYING file included
with the distribution or http://www.silicondefense.com/spice/ for details.

Please send complaints, kudos, and especially improvements and bugfixes to
hoagland@SiliconDefense.com.  As described in GNU General Public License, no
warranty is expressed for this program.
*********************************************************************/

#ifndef SPADE_STATE_H
#define SPADE_STATE_H

/*! \file spade_state.h
 * \brief 
 *  spade_state.h is the header file for spade_state.c.
 * \ingroup staterec
 */

/*! \addtogroup staterec
    @{
*/

#include <stdio.h>
#include <time.h>

/// a handle for ths user on a currently active state recovery file
typedef struct {
    FILE *f; ///< the file pointer
} statefile_ref;


statefile_ref *spade_state_begin_checkpointing(char *filename, char *appname, u8 app_cur_fvers);
int spade_state_end_checkpointing(statefile_ref *s);
int spade_state_checkpoint_str(statefile_ref *s, char *str);
int spade_state_checkpoint_arr(statefile_ref *s, void *arr, int len, int elsize);
int spade_state_checkpoint_str_arr(statefile_ref *s, char **arr, int len);
int spade_state_checkpoint_u32(statefile_ref *s, u32 val);
int spade_state_checkpoint_u8(statefile_ref *s, u8 val);
int spade_state_checkpoint_time_t(statefile_ref *s, time_t val);
int spade_state_checkpoint_double(statefile_ref *s,double val);
int spade_state_end_section(statefile_ref *s);

statefile_ref *spade_state_begin_recovery(char *filename, int min_app_fvers, char **appname, u8 *file_app_fvers);
int spade_state_end_recovery(statefile_ref *s);
int spade_state_recover_check_end_of_section(statefile_ref *s, int *res);
int spade_state_recover_arr(statefile_ref *s, void *arr, int len, int elsize);
int spade_state_recover_str_arr(statefile_ref *s, char **arr, int len);
int spade_state_recover_u32(statefile_ref *s, u32 *val);
int spade_state_recover_u8(statefile_ref *s, u8 *val);
int spade_state_recover_time_t(statefile_ref *s, time_t *val);
int spade_state_recover_double(statefile_ref *s, double *val);
int spade_state_recover_str(statefile_ref *s, char **str);
int spade_state_recover_str_to_buff(statefile_ref *s, char *buff, int maxlen);

#endif // SPADE_STATE_H

/* $Id: spade_state.h,v 1.6 2003/01/14 17:45:31 jim Exp $ */
