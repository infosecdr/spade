/*********************************************************************
snort_spade.h, distributed as part of Spade v030125.1
Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
copyright (c) 2002 by Silicon Defense (http://www.silicondefense.com/)
Released under GNU General Public License, see the COPYING file included
with the distribution or http://www.silicondefense.com/spice/ for details.

Please send complaints, kudos, and especially improvements and bugfixes to
hoagland@SiliconDefense.com.  As described in GNU General Public License, no
warranty is expressed for this program.
*********************************************************************/

/* Internal version control: $Id: snort_spade.h,v 1.5 2002/12/19 22:37:10 jim Exp $ */

#ifndef __SNORT_SPADE_H__
#define __SNORT_SPADE_H__

/*! \file snort_spade.h
 * \brief 
 *  snort_spade.h is the header file for snort_spade.c
 */

/*! \addtogroup snort_spade
 * @{
*/

void SetupSpade();
void SpadeInit(u_char *argsstr);
void PreprocSpade(Packet *p);
void SpadeHomenetInit(u_char *args);
void SpadeDetectInit(u_char *args);
void SpadeStatInit(u_char *args);
void SpadeThreshadviseInit(u_char *args);
void SpadeAdaptInit(u_char *args);
void SpadeAdapt2Init(u_char *args);
void SpadeAdapt3Init(u_char *args);
void SpadeSurveyInit(u_char *args);
void SpadeCatchSig(int signal, void *arg);

#endif // __SNORT_SPADE_H__
