/*********************************************************************
score_calculator.h, distributed as part of Spade v030125.1
Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
copyright (c) 2002 by Silicon Defense (http://www.silicondefense.com/)
Released under GNU General Public License, see the COPYING file included
with the distribution or http://www.silicondefense.com/spice/ for details.

Please send complaints, kudos, and especially improvements and bugfixes to
hoagland@SiliconDefense.com.  As described in GNU General Public License, no
warranty is expressed for this program.
*********************************************************************/

/* Internal version control: $Id: score_calculator.h,v 1.8 2002/12/20 06:10:03 jim Exp $ */

#ifndef SCORE_CALCULATOR_H
#define SCORE_CALCULATOR_H

/*! \file score_calculator.h
 * \brief 
 *  score_calculator.h is the header file for score_calculator.c
 * \ingroup scoreprod
 */

/*! \addtogroup scoreprod
    @{
*/

#include <stdio.h>
#include "spade_features.h"
#include "event_recorder.h"
#include "score_info.h"

/// a structure containing the various components describing how a probability table is going to be used
typedef struct {
    int prodcount; ///< the number of conditional probabilities to multiply
    feature_list *feats; ///< if prodcount > 1, the array of feature lists to use; space is dynamically allocated 
    feature_list calc_feats; ///< if prodcount=1, the list of features for the table
    const char **featurenames; ///< direct-index lookup array to map features to their names
    event_condition_set conds; ///< the event conditions under which the table will be used for storage
    int scale_freq; ///< how often the table will be scaled/pruned, in secs
    double scale_factor; ///< when we scale, how much do we do so by
    double prune_threshold; ///< if an observation gets below this size, it will be discarded
} table_use_specs;

/// an instance of a score calculator
typedef struct {
    int prodcount; ///< the number of conditional probabilities to multiply
    evfile_ref *evfiles; ///< if prodcount > 1, array of evfile's in the event recorder storing the tables needed for each probability
    evfile_ref evfile; ///< if we only have one prob, we store store the evfile here
    int calc_rawscore; ///< should the raw anonamaly score be calculated
    int calc_relscore; ///< should the relative anonamaly score be calculated
    scorepref mainpref; ///< the preferred score type to store
    int use_corrscore; ///< correctly compute the raw anomaly score?
    int cond_prefix_len; ///< how far into feats should we use as the denominator for calculating the probability
    int min_obs_prefix_len; ///< if > 0, we require a min observation, this is how far into feats the spec is for
    double min_obs_count; ///< the minimum observation count
    double max_entropy; ///< if >= 0, we are using a selection critea based on maximum entropy under the values of a certain feature
    int entropy_prefix_len; ///< the depth of the run-up to the value field when using max entropy selection criterea
    table_use_specs *evfiles_data; ///< parameters to evfiles while being set up
    event_recorder *recorder; ///< a pointer to the event recorder where the events are stored 
} score_calculator;

score_calculator *new_score_calculator(int prodcount, feature_list prod_cond[], const char **featurenames, event_condition_set conds, int scale_freq, double scale_factor, double prune_threshold, event_recorder *recorder, feature_list *calc_feats);
void init_score_calculator(score_calculator *self, int prodcount, feature_list prod_cond[], const char **featurenames, event_condition_set conds, int scale_freq, double scale_factor, double prune_threshold, event_recorder *recorder, feature_list *calc_feats);
score_calculator *new_score_calculator_clear(event_recorder *recorder);
void init_score_calculator_clear(score_calculator *self, event_recorder *recorder);

void score_calculator_set_features(score_calculator *self, int prodcount, feature_list prod_cond[], feature_list *calc_feats, const char **featurenames);
void score_calculator_set_storage_conditions(score_calculator *self, event_condition_set conds);
void score_calculator_set_scaling(score_calculator *self, int scale_freq, double scale_factor, double prune_threshold);
void score_calculator_init_complete(score_calculator *self);

void score_calculator_set_condcutoff(score_calculator *self, int cond_prefix_len);
void score_calculator_set_relscore(score_calculator *self, int calc_relscore, int rel_is_main);
void score_calculator_set_rawscore(score_calculator *self, int calc_rawscore, int raw_is_main);
void score_calculator_set_corrscore(score_calculator *self, int use_corrscore);
void score_calculator_set_min_obs(score_calculator *self, int featlist_prefix_len, int min_obs_count);
void score_calculator_set_low_entropy_domain(score_calculator *self, int val_prefix_len, double max_entropy);
void score_calculator_cleanup(score_calculator *self);

int score_calculator_using_corrscore(score_calculator *self);
int score_calculator_using_relscore(score_calculator *self);

score_info *score_calculator_calc_event_score(score_calculator *self, spade_event *event, score_info *storage,int *enoughobs);

int score_calculator_get_store_count(score_calculator *self);
double score_calculator_get_obs_count(score_calculator *self);

void score_calculator_print_config_details(score_calculator *self,FILE *f,char *indent);

/*@}*/
#endif // SCORE_CALCULATOR_H
