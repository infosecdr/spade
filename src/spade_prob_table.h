/*********************************************************************
spade_prob_table.h, distributed as part of Spade v030125.1
Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
copyright (c) 2002 by Silicon Defense (http://www.silicondefense.com/)
Released under GNU General Public License, see the COPYING file included
with the distribution or http://www.silicondefense.com/spice/ for details.

Please send complaints, kudos, and especially improvements and bugfixes to
hoagland@SiliconDefense.com.  As described in GNU General Public License, no
warranty is expressed for this program.
*********************************************************************/

#ifndef SPADE_PROB_TABLE_H
#define SPADE_PROB_TABLE_H

/*! \file spade_prob_table.h
 * \brief 
 *  spade_prob_table.h is the header file for spade_prob_table.c.
 * \ingroup staterec
 */

/*! \addtogroup staterec
    @{
*/

#include "spade_features.h"
#include "spade_prob_table_types.h"
#include "spade_state.h"

#include <stdio.h>

/// a spade probability table, represented by some number of nested trees
typedef struct {
    mindex root[MAX_NUM_FEATURES]; ///< top level tree roots in an array indexed by the feature type of the top level tree
    const char **featurenames;     ///< user provided pointer to array of the string names of the features, used for output
} spade_prob_table;

/// an element in a data structure representing a set of doubles indexed by a list of features
typedef struct _featcomb {
    struct _featcomb *next[MAX_NUM_FEATURES]; ///< pointers to the next level of structure, indexed by feature
    double val[MAX_NUM_FEATURES];  ///< the values stored; indexed by the final feature in the list
} *featcomb;

#define STATS_NONE          0x00  ///< no statistics
#define STATS_ENTROPY       0x01  ///< entropy statistics
#define STATS_UNCONDPROB    0x02  ///< unconditional probabilities
#define STATS_CONDPROB      0x04  ///< conditional probabilities

#define PROBRESULT_NO_RECORD (double)-1.0 ///< a special probability value denoting the probability denominator was 0


void init_spade_prob_table(spade_prob_table *self,const char **featurenames,int recovering);
spade_prob_table *new_spade_prob_table(const char **featurenames);

int spade_prob_table_is_empty(spade_prob_table *self);

void increment_simple_count(spade_prob_table *self, features type1, valtype val1);
void increment_2joint_count(spade_prob_table *self, features type1, valtype val1, features type2, valtype val2, int skip);
void increment_3joint_count(spade_prob_table *self, features type1, valtype val1, features type2, valtype val2, features type3, valtype val3, int skip);
void increment_4joint_count(spade_prob_table *self, features type1, valtype val1, features type2, valtype val2, features type3, valtype val3, features type4, valtype val4, int skip);
void increment_Njoint_count(spade_prob_table *self,int size,features type[],valtype val[],int skip);

double prob_simple(spade_prob_table *self, features type1, valtype val1);
double prob_2joint(spade_prob_table *self, features type1, valtype val1, features type2, valtype val2);
double prob_Njoint(spade_prob_table *self, int size, features type[], valtype val[]);
double prob_Njoint_Ncond(spade_prob_table *self, int size, features type[], valtype val[], int condoffset);
double prob_Njoint_Ncond_plus_one(spade_prob_table *self, int size, features type[], valtype val[], int condoffset);
double prob_cond1(spade_prob_table *self, features type, valtype val, features ctype, valtype cval);
double prob_cond2(spade_prob_table *self, features type, valtype val, features ctype1, valtype cval1, features ctype2, valtype cval2);
double prob_cond3(spade_prob_table *self, features type, valtype val, features ctype1, valtype cval1, features ctype2, valtype cval2, features ctype3, valtype cval3);
double one_prob_simple(spade_prob_table *self,features type1);

double jointN_count(spade_prob_table *self,int size,features type[], valtype val[]);

double spade_prob_table_entropy(spade_prob_table *self, int size, features type[], valtype val[]);

void scale_and_prune_table(spade_prob_table *self, double factor, double threshold);

float feature_trees_stats(spade_prob_table *self, features f, float *amind, float *amaxd, float *aaved, float *awaved);

void spade_prob_table_write_stats(spade_prob_table *self,FILE *file,u8 stats_to_print);
void write_feat_val_list(spade_prob_table *self,FILE *f, int depth, features feats[], valtype vals[]);
void write_all_uncond_probs(spade_prob_table *self, FILE *f);
void write_all_cond_probs(spade_prob_table *self, FILE *f);
featcomb calc_all_entropies(spade_prob_table *self);
void write_all_entropies(spade_prob_table *self,FILE *f, featcomb c);

void print_spade_prob_table(spade_prob_table *self);
int sanity_check_spade_prob_table(spade_prob_table *self);


int spade_prob_table_checkpoint(statefile_ref *s,spade_prob_table *self);
int spade_prob_table_recover(statefile_ref *s,spade_prob_table *self);


#endif // SPADE_PROB_TABLE_H

/* $Id: spade_prob_table.h,v 1.7 2003/01/08 19:59:54 jim Exp $ */
