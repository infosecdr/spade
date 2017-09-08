/*********************************************************************
score_info.h, distributed as part of Spade v030125.1
Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
copyright (c) 2002 by Silicon Defense (http://www.silicondefense.com/)
Released under GNU General Public License, see the COPYING file included
with the distribution or http://www.silicondefense.com/spice/ for details.

Please send complaints, kudos, and especially improvements and bugfixes to
hoagland@SiliconDefense.com.  As described in GNU General Public License, no
warranty is expressed for this program.
*********************************************************************/

/* Internal version control: $Id: score_info.h,v 1.6 2002/12/20 06:10:03 jim Exp $ */

#ifndef SCORE_INFO_H
#define SCORE_INFO_H

/*! \file score_info.h
 * \brief 
 *  score_info.h contains the type declaration for the score_info
 *  struct and the interface to the associated functions
 * \ingroup scoreprod
 */

/*! \addtogroup scoreprod
    @{
*/

/// a special double indicating that there is no anomaly score
#define NO_SCORE (double)-1

/// enum containing the possible preferences among types of anomaly scores
typedef enum {PREF_NOSCORE,PREF_RAWSCORE,PREF_RELSCORE} scorepref;

const char *scorepref_str(scorepref pref);

/// stores information about a anomaly scoring result
typedef struct _score_info {
    scorepref main; ///< the preference for which available score to use as the main score
    double relscore; ///< the relative anomaly score, or NO_SCORE
    double rawscore; ///< the raw anomaly score, or NO_SCORE
    int corrscore_used; ///< if the raw anomaly score was computed, was it computed correctly
    
    struct _score_info *next; ///< the next score_info in a list of them
} score_info;

score_info *new_score_info(scorepref main, double relscore, double rawscore, int corrscore_used);
void init_score_info(score_info *i, scorepref main, double relscore, double rawscore, int corrscore_used);
score_info *score_info_clone(score_info *i);
void free_score_info(score_info *i);
void free_score_infos(score_info *start);

double score_info_mainscore(score_info *i);
double score_info_relscore(score_info *i);
double score_info_rawscore(score_info *i);
int score_info_raw_is_corrscore(score_info *i);
scorepref score_info_main_pref(score_info *i);

/*@}*/
#endif // SCORE_INFO_H
