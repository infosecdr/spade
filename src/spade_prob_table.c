/*********************************************************************
spade_prob_table.c, distributed as part of Spade v030125.1
Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
copyright (c) 2002 by Silicon Defense (http://www.silicondefense.com/)
Released under GNU General Public License, see the COPYING file included
with the distribution or http://www.silicondefense.com/spice/ for details.

Please send complaints, kudos, and especially improvements and bugfixes to
hoagland@SiliconDefense.com.  As described in GNU General Public License, no
warranty is expressed for this program.
*********************************************************************/

#include "spade_prob_table.h"
#include "spade_features.h"
#include <limits.h>
#include <stdlib.h>
#include <math.h>

/*! \file spade_prob_table.c,
 * \brief 
 *  spade_prob_table.c contains all the routines to build and maintain the
 *  tree structure that Spade uses to maintain its probability tables.  It
 *  also contains the access functions.
 * \ingroup staterec
 */

/*! \addtogroup staterec
    @{
*/

/* return the standard wait time for an interior node given the counts on 
   its children */
#define wait_time(c1,c2) (min_int(max_int(10,ceil(c1>c2?(2*c2-c1):(2*c1-c2))),MAX_U16))

// static mindex find_nexttree_of_type(mindex leaf,features type) {
#define find_nexttree_of_type_macro(_leaf,_type,_res) { \
    mindex _t; \
    _res= TNULL; \
    for (_t=leafnexttree(_leaf); _t != TNULL; _t=treenext(_t)) { /* make common case quick */ \
        if (treetype(_t) == _type) { \
            _res=_t; \
            break; \
        } \
    } \
}

/* return the leaf below this interior or leaf [encoded] node else TNULL */
//static mindex find_leaf_in_subtree(dmindex encchild,valtype val) {
#define find_leaf_in_subtree_macro(_encchild,_val,_res) { \
    mindex _child; \
    \
    _res= TNULL; \
    while (_encchild != TNULL) { \
        if (isleaf(_encchild)) { \
            _child= encleaf2mindex(_encchild); \
            if (_val == leafvalue(_child)) { /* found the leaf */ \
                _res= _child; \
                break; \
            } else { /* leaf not present */ \
                break; \
            } \
        } else { \
            _child= _encchild; \
        } \
        \
        if (_val <= intsortpt(_child)) { /* go left */ \
            _encchild= intleft(_child); \
        } else { /* go right */ \
            _encchild= intright(_child); \
        } \
    } \
}

//static mindex find_leaf(mindex tree,valtype val) {
#define find_leaf_macro(_tree,_val,_res) { \
    mindex _leaf; \
    mindex _root=treeroot(_tree); \
    _res= TNULL; \
    if (_root != TNULL) { \
        find_leaf_in_subtree_macro(_root,_val,_leaf); \
        _res= _leaf; \
    } \
}


static int min_int(int a, int b);
static int max_int(int a, int b);
static double tree_value_prob(mindex tree, valtype val);
static mindex find_nexttree_of_type(mindex leaf, features type);
static mindex get_nexttree_of_type(mindex leaf, features type);
static mindex incr_tree_value_count(mindex tree, valtype newval);
static mindex increment_value_count(mindex node, valtype val);
static mindex add_node_above_to_right(mindex node, valtype val);
static mindex add_node_above_to_left(mindex node, valtype val);
static mindex add_node_between(mindex node, valtype val);
static void rebalance_subtree(mindex encnode);
static int out_of_balance(mindex node);
static void free_all_in_tree(mindex tree);
static void free_all_in_subtree(dmindex encnode);
static void scale_and_prune_tree(mindex tree, double factor, double threshold);
static dmindex scale_and_prune_subtree(dmindex encnode, double factor, double threshold, double *change, valtype *newrightmost);
static valtype largest_val(mindex node);
static mindex dup_intnode(mindex node);
static mindex find_leaf(mindex tree, valtype val);
static unsigned int feature_tree_stats(mindex tree, features f, unsigned int *smind, unsigned int *smaxd, float *saved, float *swaved, unsigned int *snum_leaves);
static unsigned int feature_subtree_stats(mindex encnode, features f, unsigned int *smind, unsigned int *smaxd, float *saved, float *swaved, unsigned int *snum_leaves);
static unsigned int tree_stats(mindex tree, unsigned int *mind, unsigned int *maxd, float *aved, float *waved);
static double tree_count(mindex tree);
static unsigned int num_leaves(mindex tree);
static unsigned int num_subtree_leaves(mindex encnode);
static unsigned int tree_depth_total(mindex tree);
static unsigned int subtree_depth_total(mindex encnode, unsigned int depth);
static double weighted_tree_depth_total(mindex tree);
static double weighted_subtree_depth_total(mindex encnode, unsigned int depth);
static void tree_min_max_depth(mindex tree, unsigned int *mind, unsigned int *maxd);
static void subtree_min_max_depth(mindex encnode, unsigned int *mind, unsigned int *maxd, unsigned int depth);
static void write_all_tree_uncond_probs(spade_prob_table *self,FILE *f, mindex tree, int depth, features feats[], valtype vals[], double treesum);
static void write_all_subtree_uncond_probs(spade_prob_table *self,FILE *f, dmindex encnode, int depth, features feats[], valtype vals[], double treesum);
static void write_all_tree_cond_probs(spade_prob_table *self,FILE *f, mindex tree, int depth, features feats[], valtype vals[]);
static void write_all_subtree_cond_probs(spade_prob_table *self,FILE *f, dmindex encnode, int depth, features feats[], valtype vals[], double treesum);
static void inc_featurecomb(featcomb C, double val, int depth, features feats[]);
static featcomb create_featurecomb(int depth, double val);
static void scale_all_featurecomb(featcomb c, double factor);
static void add_all_tree_entrsum(featcomb c, mindex tree, int depth, features feats[], double totsum);
static void add_all_subtree_entrsum(featcomb c, dmindex encnode, int depth, features feats[], double treesum, double totsum);
static void write_all_entropies2(spade_prob_table *self,FILE *f, featcomb c, int depth, features feats[]);
static void write_feature_names(spade_prob_table *self,FILE *f, int depth, features feats[]);
static void printtree(spade_prob_table *self,mindex tree, char *ind);
static void printtree2(spade_prob_table *self,dmindex encnode, char *ind);
static void printtree2_shallow(dmindex encnode);
static int sanity_check_tree(mindex tree);
static int sanity_check_subtree(dmindex encnode);
static mindex find_leaf2(spade_prob_table *self, features type1, valtype val1, features type2, valtype val2);
static mindex find_leaf3(spade_prob_table *self, features type1, valtype val1, features type2, valtype val2, features type3, valtype val3);
static double calc_tree_entropy(mindex tree);
static double calc_subtree_entropy(mindex node,double prob_base);


#ifndef LOG2
/*#define LOG2 log(2);*/
#define LOG2 ((double)0.693147180559945)
#endif

void init_spade_prob_table(spade_prob_table *self,const char **featurenames,int recovering) {
    int i;
    if (!recovering) {
        init_mem();
    
        for (i=0; i < MAX_NUM_FEATURES; i++) {
            self->root[i]= TNULL;
        }
    }
    self->featurenames= featurenames;
}

spade_prob_table *new_spade_prob_table(const char **featurenames) {
    spade_prob_table *new= (spade_prob_table *)malloc(sizeof(spade_prob_table));
    init_spade_prob_table(new,featurenames,0);
    return new;
}

int spade_prob_table_is_empty(spade_prob_table *self) {
    int i;
    for (i=0; i < MAX_NUM_FEATURES; i++) {
        if (self->root[i] != TNULL) return 0;
    }
    return 1;
}

static int min_int(int a,int b) {
    return a < b ? a : b;
}

static int max_int(int a,int b) {
    return a > b ? a : b;
}

void increment_simple_count(spade_prob_table *self,features type1,valtype val1) {
    if (self->root[type1] == TNULL) {
        self->root[type1]= new_treeinfo(type1);
    }
    incr_tree_value_count(self->root[type1],val1);
}

/* assumes type1 and type2 are in a consistant order */
void increment_2joint_count(spade_prob_table *self,features type1,valtype val1,features type2,valtype val2,int skip) {
    mindex leaf1,tree2;
    
    if (skip >= 1) {
        /* this should always find something and self->root[type1] should be non-NULL since has been marked before */
        leaf1= find_leaf(self->root[type1],val1);
    } else {
        if (self->root[type1] == TNULL) {
            self->root[type1]= new_treeinfo(type1);
        }
        leaf1= incr_tree_value_count(self->root[type1],val1);
    }
    tree2= get_nexttree_of_type(leaf1,type2);
    incr_tree_value_count(tree2,val2);
}

void increment_3joint_count(spade_prob_table *self,features type1,valtype val1,features type2,valtype val2,features type3,valtype val3,int skip) {
    mindex leaf1,leaf2,tree2,tree3;
    
    if (skip >= 1) {
        /* this should always find something and self->root[type1] should be non-NULL since has been marked before */
        leaf1= find_leaf(self->root[type1],val1);
    } else {
        if (self->root[type1] == TNULL) {
            self->root[type1]= new_treeinfo(type1);
        }
        leaf1= incr_tree_value_count(self->root[type1],val1);
    }
    tree2= get_nexttree_of_type(leaf1,type2);
    /* skip case: find_leaf should always find something since has been marked before */
    leaf2= skip >= 2 ? find_leaf(tree2,val2) : incr_tree_value_count(tree2,val2);
    tree3= get_nexttree_of_type(leaf2,type3);
    incr_tree_value_count(tree3,val3);
}

void increment_4joint_count(spade_prob_table *self,features type1,valtype val1,features type2,valtype val2,features type3,valtype val3,features type4,valtype val4,int skip) {
    mindex leaf1,leaf2,leaf3,tree2,tree3,tree4;
    
    if (skip >= 1) {
        /* this should always find something and self->root[type1] should be non-NULL since has been marked before */
        leaf1= find_leaf(self->root[type1],val1);
    } else {
        if (self->root[type1] == TNULL) {
            self->root[type1]= new_treeinfo(type1);
        }
        leaf1= incr_tree_value_count(self->root[type1],val1);
    }
    tree2= get_nexttree_of_type(leaf1,type2);
    /* skip case: find_leaf should always find something since has been marked before */
    leaf2= skip >= 2 ? find_leaf(tree2,val2) : incr_tree_value_count(tree2,val2);
    tree3= get_nexttree_of_type(leaf2,type3);
    /* skip case: find_leaf should always find something since has been marked before */
    leaf3= skip >= 3 ? find_leaf(tree3,val3) : incr_tree_value_count(tree3,val3);
    tree4= get_nexttree_of_type(leaf3,type4);
    incr_tree_value_count(tree4,val4);
}

void increment_Njoint_count(spade_prob_table *self,int size,features type[],valtype val[],int skip) {
    mindex leaf,tree;
    int i;
    
    if (self->root[type[0]] == TNULL) {
        self->root[type[0]]= new_treeinfo(type[0]);
    }
    tree= self->root[type[0]];
    for (i= 1; i < size; i++) {
        /* skip case: find_leaf should always find something since has been here before */
        if (skip >= i) 
            find_leaf_macro(tree,val[i-1],leaf)
        else 
            leaf= incr_tree_value_count(tree,val[i-1]);
        tree= get_nexttree_of_type(leaf,type[i]);
    }
    incr_tree_value_count(tree,val[size-1]);
}

/*****************************************************/

double prob_simple(spade_prob_table *self,features type1,valtype val1) {
    if (self->root[type1] == TNULL) return PROBRESULT_NO_RECORD; /* this feature was not counted */
    return tree_value_prob(self->root[type1],val1);
}

/* return the probabilty of the value in the tree; assumes tree is not TNULL */
static double tree_value_prob(mindex tree,valtype val) {
    mindex root=treeroot(tree);
    mindex leaf;
    find_leaf_in_subtree_macro(root,val,leaf);
    if (leaf == TNULL) return PROBRESULT_NO_RECORD;
    return leafcount(leaf)/count_or_sum(root);
}

double prob_cond1(spade_prob_table *self,features type,valtype val,features ctype,valtype cval) {
    mindex condleaf,tree,leaf;
    if (self->root[ctype] == TNULL) {
        return PROBRESULT_NO_RECORD; /* denominator would be 0 */
    }
    condleaf= find_leaf(self->root[ctype],cval);
    if (condleaf == TNULL) return PROBRESULT_NO_RECORD; /* denominator would be 0 */
    find_nexttree_of_type_macro(condleaf,type,tree);
    if (tree == TNULL) {
        return 0.0; /* numerator would be 0 */
    }
    leaf= find_leaf(tree,val);
    if (leaf == TNULL) return 0.0; /* numerator would be 0 */
    return leafcount(leaf)/leafcount(condleaf);
}

double prob_cond2(spade_prob_table *self,features type,valtype val,features ctype1,valtype cval1,features ctype2,valtype cval2) {
    mindex condleaf,leaf,tree;
    condleaf= find_leaf2(self,ctype1,cval1,ctype2,cval2);
    if (condleaf == TNULL) return PROBRESULT_NO_RECORD; /* denominator would be 0 */
    find_nexttree_of_type_macro(condleaf,type,tree);
    if (tree == TNULL) {
        return 0.0; /* numerator would be 0 */
    }
    leaf= find_leaf(tree,val);
    if (leaf == TNULL) return 0.0; /* numerator would be 0 */
    return leafcount(leaf)/leafcount(condleaf);
}

double prob_cond3(spade_prob_table *self,features type,valtype val,features ctype1,valtype cval1,features ctype2,valtype cval2,features ctype3,valtype cval3) {
    mindex condleaf,leaf,tree;
    condleaf= find_leaf3(self,ctype1,cval1,ctype2,cval2,ctype3,cval3);
    if (condleaf == TNULL) return PROBRESULT_NO_RECORD; /* denominator would be 0 */
    find_nexttree_of_type_macro(condleaf,type,tree);
    if (tree == TNULL) {
        return 0.0; /* numerator would be 0 */
    }
    leaf= find_leaf(tree,val);
    if (leaf == TNULL) return 0.0; /* numerator would be 0 */
    return leafcount(leaf)/leafcount(condleaf);
}


double prob_2joint(spade_prob_table *self,features type1,valtype val1,features type2,valtype val2) {
    mindex tree,leaf;
    double totcount;
    if (self->root[type1] == TNULL) {
        return PROBRESULT_NO_RECORD; /* denominator would be 0 */
    }
    totcount= tree_count(self->root[type1]);
    leaf= find_leaf(self->root[type1],val1);
    if (leaf == TNULL) return 0.0; /* numerator would be 0 */
    find_nexttree_of_type_macro(leaf,type2,tree);
    if (tree == TNULL) {
        return 0.0; /* numerator would be 0 */
    }
    leaf= find_leaf(tree,val2);
    if (leaf == TNULL) return 0.0; /* numerator would be 0 */
    return leafcount(leaf)/totcount;
}

double prob_Njoint(spade_prob_table *self,int size,features type[],valtype val[]) {
    mindex tree=self->root[type[0]],leaf;
    double totcount;
    int i;
    if (tree == TNULL) return PROBRESULT_NO_RECORD; /* denominator would be 0 */
    totcount= tree_count(tree);
    for (i=1;i < size; i++) {
        leaf= find_leaf(tree,val[i-1]);
        if (leaf == TNULL) return 0.0; /* numerator would be 0 */
        tree= find_nexttree_of_type(leaf,type[i]);
        if (tree == TNULL) return 0.0; /* numerator would be 0 */
    }
    leaf= find_leaf(tree,val[size-1]);
    if (leaf == TNULL) return 0.0; /* numerator would be 0 */
    return leafcount(leaf)/totcount;
}

double prob_Njoint_Ncond(spade_prob_table *self,int size,features type[],valtype val[],int condbase) {
    mindex tree=self->root[type[0]],leaf;
    double basecount=1; /* initialized to keep compiler happy */
    int i;
    if (tree == TNULL) return PROBRESULT_NO_RECORD; /* denominator would be 0 */
    if (condbase == 0) basecount= tree_count(tree);
    for (i=1;i < size; i++) {
        find_leaf_macro(tree,val[i-1],leaf);
        if (condbase == i) basecount= leafcount(leaf);
        if (leaf == TNULL) {
            if (condbase < i) return PROBRESULT_NO_RECORD; /* denominator would be 0 */
            else return 0.0; /* numerator would be 0 */
        }
        tree= find_nexttree_of_type(leaf,type[i]);
        if (tree == TNULL) {
            if (condbase < i) return PROBRESULT_NO_RECORD; /* denominator would be 0 */
            else return 0.0; /* numerator would be 0 */
        }
    }
    find_leaf_macro(tree,val[size-1],leaf);
    if (leaf == TNULL) return 0.0; /* numerator would be 0 */
    return leafcount(leaf)/basecount;
}

double prob_Njoint_Ncond_plus_one(spade_prob_table *self,int size,features type[],valtype val[],int condbase) {
    mindex tree=self->root[type[0]],leaf;
    double basecount=-1;
    int i;
    /* pretend the table has one more observation for numerator and numerator */
    if (tree == TNULL) return 1; /* natural denominator is 0 */
    if (condbase == 0) basecount= tree_count(tree)+1;
    for (i=1;i < size; i++) {
        find_leaf_macro(tree,val[i-1],leaf);
        if (condbase == i) basecount= leafcount(leaf)+1;
        if (leaf == TNULL) {
            if (condbase < i) return 1; /* natural denominator is 0  */
            else return 1/basecount; /* natural numerator is 0 */
        }
        tree= find_nexttree_of_type(leaf,type[i]);
        if (tree == TNULL) {
            if (condbase < i) return 1; /* natural denominator is 0  */
            else return 1/basecount; /* natural numerator is 0 */
        }
    }
    find_leaf_macro(tree,val[size-1],leaf);
    if (leaf == TNULL) return 1/basecount; /* natural numerator is 0 */
    return (leafcount(leaf)+1)/basecount;
}

/* return what the probability would be if some instance of the indicated feature had a count of 1 */
double one_prob_simple(spade_prob_table *self,features type1) {
    mindex root;
    if (self->root[type1] == TNULL) return PROBRESULT_NO_RECORD; /* denominator would be 0 */
    root= treeroot(self->root[type1]);
    return 1/count_or_sum(root);
}

/*****************************************************/

double jointN_count(spade_prob_table *self,int size,features type[], valtype val[]) {
    mindex tree=self->root[type[0]],leaf;
    int i;
    if (tree == TNULL || treeroot(tree) == TNULL) {
        return 0.0;
    }
    if (size == 0) {
        return count_or_sum(treeroot(tree));
    }
    for (i=1;i < size; i++) {
        find_leaf_macro(tree,val[i-1],leaf);
        if (leaf == TNULL) return 0.0;
        tree= find_nexttree_of_type(leaf,type[i]);
        if (tree == TNULL) {
            return 0.0;
        }
    }
    find_leaf_macro(tree,val[size-1],leaf);
    if (leaf == TNULL) return 0.0;
    return leafcount(leaf);
}

/*****************************************************/

double spade_prob_table_entropy(spade_prob_table *self,int depth,features type[], valtype val[]) {
    mindex tree=self->root[type[0]],leaf;
    int i;
    //printf("H(%s",self->featurenames[type[0]]);
    if (tree == TNULL) {
        return 0.0;
    }
    for (i=1;i <= depth; i++) {
        find_leaf_macro(tree,val[i-1],leaf);
        if (leaf == TNULL) return 0.0;
        tree= find_nexttree_of_type(leaf,type[i]);
        if (tree == TNULL) {
            return 0.0;
        }
        //printf("=%d,%s",val[i-1],self->featurenames[type[i]]);
    }
    //printf(")= ");
    if (treeH(tree) < 0 || treeH_wait(tree) == 0) {
        /* need to recalculate entropy */
        int wait= count_or_sum(treeroot(tree)) * 0.1;
        treeH_wait(tree)= wait > 10000 ? 10000 : (wait < 100 ? 100 : wait);
        treeH(tree)= calc_tree_entropy(tree);
        //printf("*");
    }
    //printf("%.4f\n",treeH(tree));
    return treeH(tree);
}

static double calc_tree_entropy(mindex tree) {
    mindex root= treeroot(tree);
    return calc_subtree_entropy(root,count_or_sum(root));
}

static double calc_subtree_entropy(mindex node,double prob_base) {
    double prob;
    if (isleaf(node)) {
        prob= leafcount(encleaf2mindex(node))/prob_base;
        return -1*prob*(log(prob)/LOG2);
    } else { /* recurse */
        return calc_subtree_entropy(intleft(node),prob_base) +
               calc_subtree_entropy(intright(node),prob_base);
    }
}

/*****************************************************/
static mindex find_nexttree_of_type(mindex leaf,features type) {
    mindex t;
    for (t=leafnexttree(leaf); t != TNULL; t=treenext(t)) { /* make common case quick */
        if (treetype(t) == type) {
            return t;
        }
    }
    return TNULL;
}

static mindex get_nexttree_of_type(mindex leaf,features type) {
    mindex t;
    for (t=leafnexttree(leaf); t != TNULL; t=treenext(t)) { /* make common case quick */
        if (treetype(t) == type) {
            return t;
        }
    }
    t= leafnexttree(leaf);
    if (t == TNULL) {
        leafnexttree(leaf)= new_treeinfo(type);
        return leafnexttree(leaf);
    }
    for (; t != TNULL; t=treenext(t)) {
        if (treenext(t) == TNULL) { /* we are at end */
            treenext(t)= new_treeinfo(type);
            return treenext(t);
        }
    }
    return TNULL; /* just to keep cc -Wall from complaining :) */
}

/* increment the count of instance of val in the tree and return the leaf updated */
static mindex incr_tree_value_count(mindex tree,valtype newval) {
    mindex root=treeroot(tree);
    if (treeH_wait(tree)) treeH_wait(tree)--;
    if (root == TNULL) {
        mindex newleaf=new_leaf(newval);
        treeroot(tree)= asleaf(newleaf);
        return newleaf;
    }
    if (isleaf(root)) {
        mindex leaf= encleaf2mindex(root);
        valtype curval= leafvalue(leaf);
        
        if (curval == newval) {
            leafcount(leaf)++;
            return leaf;
        } else {
            mindex newleaf= new_leaf(newval); /* count is 1 */
            mindex node= new_int();
            intsum(node)= leafcount(leaf)+1;
            
            if (curval < newval) {
                intleft(node)= asleaf(leaf);
                intright(node)= asleaf(newleaf);
                intsortpt(node)= curval;
            } else {
                intleft(node)= asleaf(newleaf);
                intright(node)= asleaf(leaf);
                intsortpt(node)= newval;
            }
            /* no rebalancing possible now, so just set wait time to standard */
            intwait(node)= wait_time(1,leafcount(leaf));
            treeroot(tree)= node;
            return newleaf;
        }
    } else {
        return increment_value_count(root,newval);
    }
}

/* increment the sum for this interior node and the counts and sums for subtrees containing the given value and return the leaf node for the value */
static mindex increment_value_count(mindex node,valtype val) {
    mindex child,res;
    dmindex encchild;

    /* TODO: optimize by making non-recursive (note: not tail-recursive) */
    if (val <= intsortpt(node)) { /* going left */
        encchild= intleft(node);
    } else { /* going right */
        encchild= intright(node);
    }
    
    if (isleaf(encchild)) {
        child= encleaf2mindex(encchild);
        if (val == leafvalue(child)) { /* found the leaf */
            intsum(node)++;
            leafcount(child)++; 
            res= child;
        } else { /* need to add the leaf */
            if (val > leafvalue(child)) { /* higher than right node */
                res= add_node_above_to_right(node,val);
            } else if (val <= intsortpt(node)) { /* lower than left node */
                res= add_node_above_to_left(node,val);
            } else { /* in between */
                res= add_node_between(node,val);
            }
            /* note: "node" may have different children now */
        }
    } else { /* recurse */
        child= encchild;
        intsum(node)++;
        res= increment_value_count(child,val);
    }
    
    intwait(node)--;
    if (intwait(node) == 0) {/*printf("** rebalancing %X since got to 0 **\n",node);*/rebalance_subtree(node);}
    
    return res;
}

/* conceptually add a node 'node' and with a new leaf for val to right; return new leaf */
static mindex add_node_above_to_right(mindex node,valtype val) {
    mindex leaf= new_leaf(val); /* count is 1 */
    /* to keep things local (esp since don't have parent node), make the new intnode like 'node' */
    mindex newint= dup_intnode(node);
    
    /* now reshape 'node' to have newint on left and leaf on right */
    intleft(node)= newint;
    intright(node)= asleaf(leaf);
    intsum(node)++; /* sum on newint + count on leaf */
    intsortpt(node)= largest_val(newint);

    rebalance_subtree(node);
    
    return leaf;
}

/* conceptually add a node 'node' and with a new leaf for val to left; return new leaf */
static mindex add_node_above_to_left(mindex node,valtype val) {
    mindex leaf= new_leaf(val); /* count is 1 */
    /* to keep things local (esp since don't have parent node), make the new intnode like 'node' */
    mindex newint= dup_intnode(node);
    
    /* now reshape 'node' to have newint on right and leaf on left */
    intright(node)= newint;
    intleft(node)= asleaf(leaf);
    intsum(node)++; /* sum on newint + count on leaf */
    intsortpt(node)= val; /* val is largest value on left side */

    rebalance_subtree(node);
    
    return leaf;
}

/*  */
static mindex add_node_between(mindex node,valtype val) {
    mindex leaf= new_leaf(val); /* count is 1 */

    mindex newint= new_int();
    intsortpt(newint)= val; /* val is largest value on left side */
    intleft(newint)= asleaf(leaf);
    intright(newint)= intright(node);
    intsum(newint)= count_or_sum(intright(node))+1;
    intright(node)= newint;
    intsum(node)++; /* counts stayed the same except adding 1 */
    
    rebalance_subtree(newint);
    
    return leaf;
}

#if 0 /* not currently needed, prob not tested */
/* regardless of wait counts, start rebalancing this tree from the root */
static void rebalance_tree(mindex tree) {
    mindex root=treeroot(tree);
    if (root == TNULL) return;
    rebalance_subtree(root);
}
#endif

/* if given a leaf, do nothing.  Otherwise consider it time to try to rebalance this tree and recurse on new or moved interior nodes; reset the wait count on the node */
static void rebalance_subtree(mindex encnode) {
    mindex node,left,right;
    int changed;

    if (isleaf(encnode)) return;
    node= encnode;

    do {
#ifdef NO_REBALANCE
break;
#endif
/*printf("rebalance_subtree(%X):",encnode);printtree2_shallow(encnode);
printf("\n",encnode);*/
        changed= 0;
        left= intleft(node);
        right= intright(node);
        
        if ((left != TNULL) && (right != TNULL) && out_of_balance(node)) {
            double lct=count_or_sum(left);
            double rct=count_or_sum(right);
            mindex left2,right2,newright,newleft;
            double l2ct,r2ct,newsum;
            double unbalanced_amount;
            if (lct > rct) {
                if (!isleaf(left)) {
                    left2= intleft(left);
                    right2= intright(left);
                    l2ct= count_or_sum(left2);
                    r2ct= count_or_sum(right2);
                    newsum= r2ct+rct; /* sum for right interior node */
                    unbalanced_amount= lct-rct;
                    if (fabs(l2ct-newsum) < unbalanced_amount*0.999) { /* if improves balance */
/*printf("[rotating %X right improves balance (%f,%f) [%f]",node,l2ct,newsum,fabs(l2ct-newsum));
printf(" < (%f,%f)*0.999 [%f]\n",lct,rct,unbalanced_amount*0.999);*/
                        /* rotate right */
                        /* recycle "left" interior node into one for right */ 
                        newright= left;
                        intsortpt(newright)= largestval(right2);
                        intleft(newright)= right2;
                        intright(newright)= right;
                        intsum(newright)= newsum;
                        /* update "node" */
                        intsortpt(node)= largestval(left2);
                        intleft(node)= left2;
                        intright(node)= newright;
                        /* count stays the same */
                        rebalance_subtree(newright);
                        changed= 1;
                    } else {
                        mindex pprl,prl,rl,lrl,n;
                        double rlct;
                        valtype prl_largest;
                        /*printf("rotating %X right would not improve balance (%.2f,%.2f) vs (%.2f,%.2f)\n",node,l2ct,newsum,lct,rct);*/
                        /* find first node on the right edge of the "right2" tree that is smaller than unbalanced_amount (if any); also the parent (plr) and grandparent (pplr) */
                        for (pprl= left,prl= right2; !isleaf(prl) && count_or_sum(intright(prl)) >= unbalanced_amount; pprl= prl,prl=intright(prl));
                        if (!isleaf(prl)) {
                            rl= intright(prl);
                            /*printf("  so moving right of %X (%X) to left side\n",prl,rl);*/
                            prl_largest= intsortpt(prl);
                            rlct= count_or_sum(rl);
                            lrl= intleft(prl);
                            
                            /* intsortpt(pprl) remains same */
                            intright(pprl)= lrl;
                            /* rl is now out of right of tree and prl can be recycled */
                            /* use prl for node on right of "node", containing rl and "right" */
                            newright= prl;
                            intsortpt(newright)= largestval(rl);
                            intleft(newright)= rl;
                            intright(newright)= right;
                            intsum(newright)= rct+count_or_sum(rl);
                            intright(node)= newright;
                            intsortpt(node)= prl_largest;
                            /* update sums from left to pprl (inclusive) to reflect loss (rlct) of the node rl */
                            for (n=left; 1; n=intright(n)) {
                                intsum(n)-= rlct;
                                if (n == pprl) break;
                            }
                            rebalance_subtree(newright);
                            changed= 1;
                        } /*else { printf("  and hit leaf (%X) before hitting node smaller than %.2f\n",encleaf2mindex(prl),unbalanced_amount);}*/
                    }
                } /*else {printf("%X cannot be rotated right since left is a leaf node\n",node);}*/
            } else {
                if (!isleaf(right)) {
                    left2= intleft(right);
                    right2= intright(right);
                    l2ct= count_or_sum(left2);
                    r2ct= count_or_sum(right2);
                    newsum= lct+l2ct; /* sum for right interior node */
                    unbalanced_amount= rct-lct;
                    if (fabs(r2ct-newsum) < unbalanced_amount*0.999) { /* if improves balance */
/*printf("[rotating %X left improves balance (%f,%f) [%f]",node,r2ct,newsum,fabs(r2ct-newsum));
printf(" < (%f,%f)*0.999 [%f]]\n",rct,lct,unbalanced_amount*0.999);*/
                        /* rotate left */
                        /* transform "right" interior node into one for left */
                        newleft= right;
                        intsortpt(newleft)= largestval(left);
                        intleft(newleft)= left;
                        intright(newleft)= left2;
                        intsum(newleft)= newsum;
                        /* update "node" */
                        intsortpt(node)= largestval(left2);
                        intleft(node)= newleft;
                        intright(node)= right2;
                        /* count stays the same */
                        rebalance_subtree(newleft);
                        changed= 1;
                    } else {
                        mindex pplr,plr,lr,rlr,n;
                        double lrct;
                        valtype lr_largest;
                        /*printf("rotating %X left would not improve balance (%.2f,%.2f) vs (%.2f,%.2f)\n",node,r2ct,newsum,rct,lct);*/
                        /* find first node on the left edge of the "left2" tree that is smaller than unbalanced_amount (if any); also the parent (plr) and grandparent (pplr) */
                        for (pplr= right,plr= left2; !isleaf(plr) && count_or_sum(intleft(plr)) >= unbalanced_amount; pplr= plr,plr=intleft(plr));
                        if (!isleaf(plr)) {
                            lr= intleft(plr);
                            /*printf("  so moving left of %X (%X) to right side\n",plr,lr);*/
                            lr_largest= intsortpt(plr);
                            lrct= count_or_sum(lr);
                            rlr= intright(plr);
                            
                            intsortpt(pplr)= largestval(rlr);
                            intleft(pplr)= rlr;
                            /* lr is now out of right of tree and plr can be recycled */
                            /* use plr for node on left of node, containing left and lr */
                            newleft= plr;
                            intsortpt(newleft)= largestval(left);
                            intleft(newleft)= left;
                            intright(newleft)= lr;
                            intsum(newleft)= lct+count_or_sum(lr);
                            intleft(node)= newleft;
                            intsortpt(node)= lr_largest;
                            /* update sums from right to pplr (inclusive) to reflect loss (lrct) of the node lr */
                            for (n=right; 1; n=intleft(n)) {
                                intsum(n)-= lrct;
                                if (n == pplr) break;
                            }
                            rebalance_subtree(newleft);
                            changed= 1;
                        }/* else { printf("  and hit leaf (%X) before hitting node smaller than %.2f\n",encleaf2mindex(plr),unbalanced_amount);}*/
                    }
                }/* else {printf("%X cannot be rotated left since right is a leaf node\n",node);}*/
            }
        }/* else {printf("%X is not out of balance\n",node);}*/
    } while (changed);
    
    /* note: right and left of node may have changed */

    /* reset the wait count */
    intwait(node)= wait_time(count_or_sum(intleft(node)),count_or_sum(intright(node)));
}

static int out_of_balance(mindex node) {
    double lct=count_or_sum(intleft(node));
    double rct=count_or_sum(intright(node));
    return (fabs(lct-rct) > 1) && (((rct>lct)?rct/lct:lct/rct)>=2.0);
}

static void free_all_in_tree(mindex tree) {
/*printf("free_all_in_tree(%X)\n",tree);*/
    if (tree != TNULL) {
        if (treeroot(tree) != TNULL) free_all_in_subtree(treeroot(tree));
        free_treeinfo(tree);
    }
}

static void free_all_in_subtree(dmindex encnode) {
    mindex node,t,next;
/*printf("free_all_in_subtree(%X)\n",encnode);*/
    if (isleaf(encnode)) {
        node= encleaf2mindex(encnode);
        for (t=leafnexttree(node); t != TNULL; t=next) {
            next= treenext(t);
            free_all_in_tree(t);
        }
        free_leaf(node);
    } else {
        node= encnode;
        if (intleft(node) != TNULL) free_all_in_subtree(intleft(node));
        if (intright(node) != TNULL) free_all_in_subtree(intright(node));
        free_int(node);
    }   
}

void scale_and_prune_table(spade_prob_table *self,double factor,double threshold) {
    int i;
    for (i=0; i < MAX_NUM_FEATURES; i++) {
        if (self->root[i] != TNULL) scale_and_prune_tree(self->root[i],factor,threshold);
    }
}

static void scale_and_prune_tree(mindex tree,double factor,double threshold) {
    double change;
    valtype newrightmost;
    if (treeroot(tree) != TNULL) treeroot(tree)= scale_and_prune_subtree(treeroot(tree),factor,threshold,&change,&newrightmost);
}

static dmindex scale_and_prune_subtree(dmindex encnode,double factor,double threshold,double *change,valtype *newrightmost) {
    mindex node,t;
    int a_leaf= isleaf(encnode);

    /* scale ourselves */
    if (a_leaf) {
        node= encleaf2mindex(encnode);
        leafcount(node)*= factor;
    } else {
        node= encnode;
        intsum(node)*= factor; /* should really get this by adding otherwise there is some drift */
    }
    
    /* if we get too small, delete us and return TNULL and how much weight we had */
    if (count_or_sum(encnode) < threshold) {
/*printf("Deleting %X:\n",encnode);printtree2(encnode,"");printf("\n");*/
        *change= count_or_sum(encnode);
        *newrightmost= NOT_A_SORTPT; /* we don't have the info */
        free_all_in_subtree(encnode);
        return TNULL;
    }
    
    /* scale below us and react to reported changes */
    if (a_leaf) {
        *change= 0.0;
        *newrightmost= NOT_A_SORTPT;
                
        for (t=leafnexttree(node); t != TNULL; t=treenext(t)) {
            scale_and_prune_tree(t,factor,threshold);
        }
    } else {
        dmindex left,right;
        double mychange,reduced=0.0;
        left= intleft(node);
        right= intright(node);
        
        if (left != TNULL) {
            valtype leftnewrightmost; /* we want this to update our sortpt, if there is a change, and the rightmost has changed */
            intleft(node)= scale_and_prune_subtree(left,factor,threshold,change,&leftnewrightmost);
            if (*change > 0.0) {
                reduced+= *change;
                if (leftnewrightmost != NOT_A_SORTPT) intsortpt(node)= leftnewrightmost; /* there is a new rightmost on left side */
            }
        }
        if (right != TNULL) {
            intright(node)= scale_and_prune_subtree(right,factor,threshold,&mychange,newrightmost);
            if (mychange > 0.0) {
                reduced+= mychange;
            }
        } else {
            *newrightmost= NOT_A_SORTPT;
        }
        *change= reduced;
        
        left= intleft(node);
        right= intright(node);
        if (right == TNULL && left != TNULL) *newrightmost= largestval(left);
        
        if (left == TNULL || right == TNULL) { /* at least one child is gone, so delete self and return whats left */
            free_int(node);
            if (left == TNULL) {
                return right; /* might be TNULL */
            } else {
                return left;
            }
        } else { /* nothing deleted at this level */
            intsum(node)-= reduced;
        }
    }
    return encnode;
}


/* return the largest value found below this interior node */
/* note: sometimes called from the macro function largestval(node) */
static valtype largest_val(mindex node) {
    dmindex encright= intright(node);
    if (isleaf(encright)) {
        return eleafval(encright);
    } else {
        return largest_val(encright);
    }
}

/* make a new intermediate node identical to the give one */
static mindex dup_intnode(mindex node) {
    mindex newint= new_int();
    intsortpt(newint)= intsortpt(node);
    intleft(newint)= intleft(node);
    intright(newint)= intright(node);
    intsum(newint)= intsum(node);
    intwait(newint)= intwait(node);
    return newint;
}


/* return the leaf representing val in the tree else TNULL */
static mindex find_leaf(mindex tree,valtype val) {
    mindex leaf;
    mindex root=treeroot(tree);
    if (root == TNULL) {
        return TNULL;
    }
    find_leaf_in_subtree_macro(root,val,leaf);
    return leaf;
}

/* return the leaf representing val2 in the tree of type2 below the leaf representing val1 top level tree of type1 else TNULL */
static mindex find_leaf2(spade_prob_table *self,features type1,valtype val1,features type2,valtype val2) {
    mindex leaf,tree;
    if (self->root[type1] == TNULL) {
        return TNULL; /* actually this is an undefined case; this feature was not counted */
    }
    leaf= find_leaf(self->root[type1],val1);
    if (leaf == TNULL) return TNULL;
    find_nexttree_of_type_macro(leaf,type2,tree);
    if (tree == TNULL) return TNULL; /* actually this is an undefined case; this feature was not counted */
    return find_leaf(tree,val2);
}

/* return the leaf representing val3 in the tree of type3 below the leaf representing val2 in the tree of type2 below the leaf representing val1 top level tree of type1 else TNULL */
static mindex find_leaf3(spade_prob_table *self,features type1,valtype val1,features type2,valtype val2,features type3,valtype val3) {
    mindex leaf,tree;
    if (self->root[type1] == TNULL) {
        return TNULL; /* actually this is an undefined case; this feature was not counted */
    }
    leaf= find_leaf(self->root[type1],val1);
    if (leaf == TNULL) return TNULL;
    find_nexttree_of_type_macro(leaf,type2,tree);
    if (tree == TNULL) return TNULL; /* actually this is an undefined case; this feature was not counted */
    leaf= find_leaf(tree,val2);
    if (leaf == TNULL) return TNULL;
    find_nexttree_of_type_macro(leaf,type3,tree);
    if (tree == TNULL) return TNULL; /* actually this is an undefined case; this feature was not counted */
    return find_leaf(tree,val3);
}


/*****************************************************/

float feature_trees_stats(spade_prob_table *self,features f,float *amind,float *amaxd,float *aaved,float *awaved) {
    unsigned int tot_num_leaves=0,tot_mind=0,tot_maxd=0,tree_count=0;
    float tot_aved=0.0,tot_waved=0.0;
    unsigned int sum_num_leaves,sum_mind,sum_maxd;
    float sum_aved,sum_waved;
    int i;
    for (i=0; i < MAX_NUM_FEATURES; i++) {
        if (self->root[i] != TNULL) {
            tree_count+= feature_tree_stats(self->root[i],f,&sum_mind,&sum_maxd,&sum_aved,&sum_waved,&sum_num_leaves);
            tot_num_leaves+= sum_num_leaves;
            tot_mind+= sum_mind;
            tot_maxd+= sum_maxd;
            tot_aved+= sum_aved;
            tot_waved+= sum_waved;
        }
    }
    if (tree_count == 0) return 0; /* no non-empty trees of this type */
    *amind= tot_mind/((float)tree_count);
    *amaxd= tot_maxd/((float)tree_count);
    *aaved= tot_aved/((float)tree_count);
    *awaved= tot_waved/((float)tree_count);
    return tot_num_leaves/((float)tree_count);
}

static unsigned int feature_tree_stats(mindex tree,features f,unsigned int *smind,unsigned int *smaxd,float *saved,float *swaved,unsigned int *snum_leaves) {
    unsigned int tree_count= 0;
    dmindex root= treeroot(tree);
    if (root != TNULL) {
        tree_count= feature_subtree_stats(root,f,smind,smaxd,saved,swaved,snum_leaves);
        if (treetype(tree) == f) {
            /* gather stats from this tree */
            unsigned int mind,maxd;
            float aved,waved;
            *snum_leaves+= tree_stats(tree,&mind,&maxd,&aved,&waved);
            *smind+= mind;
            *smaxd+= maxd;
            *saved+= aved;
            *swaved+= waved;
            tree_count++;
        }
    }
    return tree_count;
}

static unsigned int feature_subtree_stats(mindex encnode,features f,unsigned int *smind,unsigned int *smaxd,float *saved,float *swaved,unsigned int *snum_leaves) {
    mindex node,t;
    unsigned int new_smind,new_smaxd,new_snum_leaves;
    float new_saved,new_swaved;
    
    unsigned int tree_count= 0;
    *smind= *smaxd= *snum_leaves= 0;
    *saved= *swaved= 0.0;
    
    if (isleaf(encnode)) {
        node= encleaf2mindex(encnode);

        for (t=leafnexttree(node); t != TNULL; t=treenext(t)) {
            tree_count+= feature_tree_stats(t,f,&new_smind,&new_smaxd,&new_saved,&new_swaved,&new_snum_leaves);
            *smind+= new_smind;
            *smaxd+= new_smaxd;
            *saved+= new_saved;
            *swaved+= new_swaved;
            *snum_leaves+= new_snum_leaves;
        }
    } else {
        node= encnode;
        if (intleft(node) != TNULL) {
            tree_count+= feature_subtree_stats(intleft(node),f,&new_smind,&new_smaxd,&new_saved,&new_swaved,&new_snum_leaves);
            *smind+= new_smind;
            *smaxd+= new_smaxd;
            *saved+= new_saved;
            *swaved+= new_swaved;
            *snum_leaves+= new_snum_leaves;
        }
        if (intright(node) != TNULL) {
            tree_count+= feature_subtree_stats(intright(node),f,&new_smind,&new_smaxd,&new_saved,&new_swaved,&new_snum_leaves);
            *smind+= new_smind;
            *smaxd+= new_smaxd;
            *saved+= new_saved;
            *swaved+= new_swaved;
            *snum_leaves+= new_snum_leaves;
        }
    }
    return tree_count;
}

static unsigned int tree_stats(mindex tree,unsigned int *mind,unsigned int *maxd,float *aved,float *waved) {
    unsigned int num_leafs= num_leaves(tree);
    unsigned int tot= tree_depth_total(tree);
    double wtot= weighted_tree_depth_total(tree);
    tree_min_max_depth(tree,mind,maxd);
    *aved= (float)tot/num_leafs;    
    *waved= wtot/tree_count(tree);  
/*printf("tree_stats results for tree %X: min depth=%u; max depth=%u; ave depth=%.2f; w. ave depth=%.2f; # vals repr=%u\n",tree,*mind,*maxd,*aved,*waved,num_leafs);*/
    return num_leafs;
}

static double tree_count(mindex tree) {
    mindex root=treeroot(tree);
    if (root == TNULL) {
        return 0.0;
    }
    return count_or_sum(root);
}

static unsigned int num_leaves(mindex tree) {
    mindex root=treeroot(tree);
    if (root == TNULL) {
        return 0;
    }
    return num_subtree_leaves(root);
}

static unsigned int num_subtree_leaves(mindex encnode) {
    if (isleaf(encnode)) {
        return 1;
    } else {
        int count= 0;
        if (intleft(encnode) != TNULL) count+=num_subtree_leaves(intleft(encnode));
        if (intright(encnode) != TNULL) count+=num_subtree_leaves(intright(encnode));
        return count;
    }
}

static unsigned int tree_depth_total(mindex tree) {
    mindex root=treeroot(tree);
    if (root == TNULL) {
        return 0;
    }
    return subtree_depth_total(root,0);
}

static unsigned int subtree_depth_total(mindex encnode,unsigned int depth) {
    depth++;
    if (isleaf(encnode)) {
        return depth;
    } else {
        int count= 0;
        if (intleft(encnode) != TNULL) count+=subtree_depth_total(intleft(encnode),depth);
        if (intright(encnode) != TNULL) count+=subtree_depth_total(intright(encnode),depth);
        return count;
    }
}

static double weighted_tree_depth_total(mindex tree) {
    mindex root=treeroot(tree);
    if (root == TNULL) {
        return 0;
    }
    return weighted_subtree_depth_total(root,0);
}

static double weighted_subtree_depth_total(mindex encnode,unsigned int depth) {
    depth++;
    if (isleaf(encnode)) {
        return depth*leafnode(encleaf2mindex(encnode)).count;
    } else {
        double count= 0;
        if (intleft(encnode) != TNULL) count+=weighted_subtree_depth_total(intleft(encnode),depth);
        if (intright(encnode) != TNULL) count+=weighted_subtree_depth_total(intright(encnode),depth);
        return count;
    }
}


static void tree_min_max_depth(mindex tree,unsigned int *mind,unsigned int *maxd) {
    mindex root=treeroot(tree);
    
    if (root == TNULL) {
        *mind= *maxd= 0;
    } else {
        *mind= MAX_U32; /* this is the num of leaf vals, so a safe min */
        *maxd= 0;
        subtree_min_max_depth(root,mind,maxd,0);
    }
}

static void subtree_min_max_depth(mindex encnode,unsigned int *mind,unsigned int *maxd,unsigned int depth) {
    depth++;
    if (isleaf(encnode)) {
        if (*mind > depth) {
            *mind= depth;
        }
        if (*maxd < depth) {
            *maxd= depth;
        }
    } else {
        if (intleft(encnode) != TNULL) subtree_min_max_depth(intleft(encnode),mind,maxd,depth);
        if (intright(encnode) != TNULL) subtree_min_max_depth(intright(encnode),mind,maxd,depth);
    }
}

/*****************************************************/
/*****************************************************/
void spade_prob_table_write_stats(spade_prob_table *self,FILE *file,u8 stats_to_print) {
    featcomb H;

    if (stats_to_print & STATS_ENTROPY) {
        H= calc_all_entropies(self);
        write_all_entropies(self,file,H);
    }
    if (stats_to_print & STATS_UNCONDPROB) write_all_uncond_probs(self,file);
    if (stats_to_print & STATS_CONDPROB) write_all_cond_probs(self,file);
}

/* print to the given FILE the given features and values in the form <self->featurenames>=<value>, separated by commas; depth is the depth to look in the arrays */
void write_feat_val_list(spade_prob_table *self,FILE *f,int depth,features feats[],valtype vals[]) {
    int i;
    if (depth == 0) return;
    fprintf(f,"%s=%u",self->featurenames[feats[0]],vals[0]);
    for (i=1; i < depth; i++) {
        fprintf(f,",%s=%d",self->featurenames[feats[i]],vals[i]);
    }
}

/* write a display of all unconditional probabilities to the given FILE */
void write_all_uncond_probs(spade_prob_table *self,FILE *f) {
    int i;
    features feats[MAX_NUM_FEATURES];
    valtype vals[MAX_NUM_FEATURES];
    for (i=0; i < MAX_NUM_FEATURES; i++) {
        if (self->root[i] != TNULL) write_all_tree_uncond_probs(self,f,self->root[i],0,feats,vals,count_or_sum(tree(self->root[i]).root));
    }
}

/* write a display of all uncond probabilities rooted at this tree to the given FILE; depth is the last depth completed */
static void write_all_tree_uncond_probs(spade_prob_table *self,FILE *f,mindex tree,int depth,features feats[],valtype vals[],double treesum) {
    dmindex root= treeroot(tree);
    if (root == TNULL) return;
    feats[depth]= treetype(tree);
    depth++;
    write_all_subtree_uncond_probs(self,f,root,depth,feats,vals,treesum);
}

/* write a display of all uncond probabilities below this interior or leaf node (as encoded) to the given FILE; depth is the depth that we are at */
static void write_all_subtree_uncond_probs(spade_prob_table *self,FILE *f,dmindex encnode,int depth,features feats[],valtype vals[],double treesum) {
    mindex node,t;

    if (isleaf(encnode)) {
        node= encleaf2mindex(encnode);
        vals[depth-1]= leafvalue(node);
        fprintf(f,"P(");
        write_feat_val_list(self,f,depth,feats,vals);
        fprintf(f,")= %.12f\n",leafcount(node)/treesum);
        
        for (t=leafnexttree(node); t != TNULL; t=treenext(t)) {
            write_all_tree_uncond_probs(self,f,t,depth,feats,vals,treesum);
        }
    } else {
        node= encnode;
        if (intleft(node) != TNULL) write_all_subtree_uncond_probs(self,f,intleft(node),depth,feats,vals,treesum);
        if (intright(node) != TNULL) write_all_subtree_uncond_probs(self,f,intright(node),depth,feats,vals,treesum);
    }
}

/*****************************************************/

/* write a display of all conditional probabilities to the given FILE */
void write_all_cond_probs(spade_prob_table *self,FILE *f) {
    int i;
    features feats[MAX_NUM_FEATURES];
    valtype vals[MAX_NUM_FEATURES];
    for (i=0; i < MAX_NUM_FEATURES; i++) {
        if (self->root[i] != TNULL) write_all_tree_cond_probs(self,f,self->root[i],0,feats,vals);
    }
}

/* write a display of all conditional probabilities rooted at this tree to the given FILE; depth is the last depth completed */
static void write_all_tree_cond_probs(spade_prob_table *self,FILE *f,mindex tree,int depth,features feats[],valtype vals[]) {
    dmindex root= treeroot(tree);
    if (root == TNULL) return;
    feats[depth]= treetype(tree);
    depth++;
    write_all_subtree_cond_probs(self,f,root,depth,feats,vals,count_or_sum(root));
}

/* write a display of all conditional probabilities below this interior or leaf node (as encoded) to the given FILE; depth is the depth that we are at */
static void write_all_subtree_cond_probs(spade_prob_table *self,FILE *f,dmindex encnode,int depth,features feats[],valtype vals[],double treesum) {
    mindex node,t;

    if (isleaf(encnode)) {
        node= encleaf2mindex(encnode);
        vals[depth-1]= leafvalue(node);
        if (depth > 1) {
            fprintf(f,"P(%s=%u|",self->featurenames[feats[depth-1]],vals[depth-1]);
            write_feat_val_list(self,f,depth-1,feats,vals);
            fprintf(f,")= %.12f\n",leafcount(node)/treesum);
        }
        
        for (t=leafnexttree(node); t != TNULL; t=treenext(t)) {
            write_all_tree_cond_probs(self,f,t,depth,feats,vals);
        }
    } else {
        node= encnode;
        if (intleft(node) != TNULL) write_all_subtree_cond_probs(self,f,intleft(node),depth,feats,vals,treesum);
        if (intright(node) != TNULL) write_all_subtree_cond_probs(self,f,intright(node),depth,feats,vals,treesum);
    }
}

/*****************************************************/

#if 0 /* not currently needed, prob not tested */
static void write_featurecomb(featcomb C,double val,int depth,features feats[]) {
    int i;
    featcomb c= C;
    for (i=0; i < (depth-1); i++) {
        c= c->next[feats[i]];
    }
    c->val[feats[depth-1]]= val;
}
#endif

static void inc_featurecomb(featcomb C,double val,int depth,features feats[]) {
    int i;
    featcomb c= C;
    for (i=0; i < (depth-1); i++) {
        c= c->next[feats[i]];
    }
    c->val[feats[depth-1]]+= val;
}

static featcomb create_featurecomb(int depth,double val) {
    int i;
    featcomb root= (featcomb)malloc(sizeof(struct _featcomb));
    if (root == NULL) return NULL;
    for (i=0; i < MAX_NUM_FEATURES; i++) {
        root->val[i]= val;
        if (depth > 1) {
            root->next[i]= create_featurecomb(depth-1,val);
        } else {
            root->next[i]= NULL;
        }
    }
    return root;
}

static void scale_all_featurecomb(featcomb c,double factor) {
    int i;
    for (i=0; i < MAX_NUM_FEATURES; i++) {
        c->val[i]*= factor;
        if (c->next[i] != NULL) scale_all_featurecomb(c->next[i],factor);
    }
}

featcomb calc_all_entropies(spade_prob_table *self) {
    features feats[MAX_NUM_FEATURES];
    featcomb H= create_featurecomb(MAX_NUM_FEATURES,0.0);
    int i;
    for (i=0; i < MAX_NUM_FEATURES; i++) {
        if (self->root[i] != TNULL) {
            add_all_tree_entrsum(H,self->root[i],0,feats,tree_count(self->root[i]));
        }
    }
    return H;
}

static void add_all_tree_entrsum(featcomb c,mindex tree,int depth,features feats[],double totsum) {
    dmindex root= treeroot(tree);
    if (root == TNULL) return;
    feats[depth]= treetype(tree);
    depth++;
    add_all_subtree_entrsum(c,root,depth,feats,count_or_sum(root),totsum);
}

static void add_all_subtree_entrsum(featcomb c,dmindex encnode,int depth,features feats[],double treesum,double totsum) {
    mindex node,t;

    if (isleaf(encnode)) {
        double mysumcomp,myprob,condprob;
        node= encleaf2mindex(encnode);
        myprob= leafcount(node)/totsum;
        if (depth > 1) {
            condprob= leafcount(node)/treesum;
            mysumcomp= -1*myprob*(log(condprob)/LOG2);
            /*printf("H[");
            write_feature_names(stdout,depth,feats);
            printf("]+=%f (-%f*(log(%f)/log2); myprob=%f/%f\n",mysumcomp,myprob,condprob,leafcount(node),totsum);*/
        } else {
            mysumcomp= -1*myprob*(log(myprob)/LOG2);
        }
        inc_featurecomb(c,mysumcomp,depth,feats);
        
        for (t=leafnexttree(node); t != TNULL; t=treenext(t)) {
            add_all_tree_entrsum(c,t,depth,feats,totsum);
        }
    } else {
        node= encnode;
        if (intleft(node) != TNULL) add_all_subtree_entrsum(c,intleft(node),depth,feats,treesum,totsum);
        if (intright(node) != TNULL) add_all_subtree_entrsum(c,intright(node),depth,feats,treesum,totsum);
    }
}

void write_all_entropies(spade_prob_table *self,FILE *f,featcomb c) {
    int i;
    features feats[MAX_NUM_FEATURES];
    for (i=0; i < MAX_NUM_FEATURES; i++) {
        if (c->val[i] > 0) {
            fprintf(f,"H(%s)=%.8f\n",self->featurenames[i],c->val[i]);
        }
    }
    for (i=0; i < MAX_NUM_FEATURES; i++) {
        if (c->next[i] != NULL) {
            feats[0]= i;
            write_all_entropies2(self,f,c->next[i],1,feats);
        }
    }
}

static void write_all_entropies2(spade_prob_table *self,FILE *f,featcomb c,int depth,features feats[]) {
    int i;
    for (i=0; i < MAX_NUM_FEATURES; i++) {
        if (c->val[i] > 0) {
            fprintf(f,"H(%s|",self->featurenames[i]);
            write_feature_names(self,f,depth,feats);
            fprintf(f,")=%.8f\n",c->val[i]);
        }
    }
    for (i=0; i < MAX_NUM_FEATURES; i++) {
        if (c->next[i] != NULL) {
            feats[depth]= i;
            write_all_entropies2(self,f,c->next[i],depth+1,feats);
        }
    }
}

/* print to the given FILE the given features separated by commas; depth is the depth to look in the array */
static void write_feature_names(spade_prob_table *self,FILE *f,int depth,features feats[]) {
    int i;
    if (depth == 0) return;
    fprintf(f,"%s",self->featurenames[feats[0]]);
    for (i=1; i < depth; i++) {
        fprintf(f,",%s",self->featurenames[feats[i]]);
    }
}

/*****************************************************/

void print_spade_prob_table(spade_prob_table *self) {
    int i;
    for (i=0; i < MAX_NUM_FEATURES; i++) {
        if (self->root[i] != TNULL) {
            printtree(self,self->root[i],"");
        }
    }
}

static void printtree(spade_prob_table *self,mindex tree,char *ind) {
    mindex t;
    for (t=tree; t != TNULL; t=treenext(t)) {
        printf("%sTree %X of %s: ",ind,t,self->featurenames[treetype(t)]);
        printtree2(self,treeroot(t),ind);
        printf("\n");
    }
}

static void printtree2(spade_prob_table *self,dmindex encnode,char *ind) {
    mindex node;
    char myind[4*MAX_NUM_FEATURES+1];
    if (encnode == TNULL) {
        printf("NULL");
    } else if (isleaf(encnode)) {
        node=encleaf2mindex(encnode);
        printf("{%X: %dx%.2f",node,leafvalue(node),leafcount(node));
        if (leafnexttree(node) != TNULL) {
            sprintf(myind,"    %s",ind);
            printf(" ->{{\n");
            printtree(self,leafnexttree(node),myind);
            printf("%s}}",ind);
        }
        printf("}");
    } else {
        node= encnode;
        printf("[%X: <=%d (%.2f) W=%d ",node,intsortpt(node),intsum(node),intwait(node));
        printtree2(self,intleft(node),ind);
        printf(" ");
        printtree2(self,intright(node),ind);
        printf("]");
    }
}

#if 0 /* not currently needed, prob not tested */
static void printtree_shallow(spade_prob_table *self,mindex tree) {
    printf("Tree %X of %s: ",tree,self->featurenames[treetype(tree)]);
    printtree2_shallow(treeroot(tree));
    printf("\n");
}
#endif

static void printtree2_shallow(dmindex encnode) {
    mindex node;
    if (encnode == TNULL) {
        printf("NULL");
    } else if (isleaf(encnode)) {
        node=encleaf2mindex(encnode);
        printf("{%X: %dx%.2f",node,leafvalue(node),leafcount(node));
        printf("}");
    } else {
        node= encnode;
        printf("[%X: <=%d (%.2f) ",node,intsortpt(node),intsum(node));
        printtree2_shallow(intleft(node));
        printf(" ");
        printtree2_shallow(intright(node));
        printf("]");
    }
}

/*****************************************************/

int sanity_check_spade_prob_table(spade_prob_table *self) {
    int i,numerrs=0;
    for (i=0; i < MAX_NUM_FEATURES; i++) {
        if (self->root[i] != TNULL) {
            numerrs+= sanity_check_tree(self->root[i]);
        }
    }
    return numerrs;
}

static int sanity_check_tree(mindex tree) {
    dmindex root= treeroot(tree);
    int numerrs= 0;
    if (treetype(tree) >= MAX_NUM_FEATURES) {
        fprintf(stderr,"*** integrity check failure: type of %X is not valid (%d)\n",tree,treetype(tree));
        numerrs++;
    }
    if (treeroot(tree) != TNULL) {
        numerrs+= sanity_check_subtree(root);
    }
    return numerrs;
}

static int sanity_check_subtree(dmindex encnode) {
    int numerrs= 0;
    mindex node,t;
    double count,sum;
    
    if (isleaf(encnode)) {
        node= encleaf2mindex(encnode);
        count= leafcount(node);
        if (count <= 0.0) {
            fprintf(stderr,"*** integrity check failure: count on leaf %X is negative or 0 (%f)\n",node,count);
            numerrs++;
        }
        for (t=leafnexttree(node); t != TNULL; t=treenext(t)) {
            /* can check if our count is approx that of the root's child */
            numerrs+= sanity_check_tree(t);
        }
    }  else {
        dmindex left,right;
        node= encnode;
        sum= intsum(node);
        left= intleft(node);
        right= intright(node);
        if ((left != TNULL) && (right != TNULL)) {
            double lct= count_or_sum(left);
            double rct= count_or_sum(right);
            double ratio= (lct+rct)/sum;
            if (ratio < 0.999 || ratio > 1.001) {
                fprintf(stderr,"*** integrity check failure: sum on interior node %X (%f) does not match sum/counts on leaves (%f+%f)\n",node,sum,lct,rct);
                numerrs++;
            }
        }
        if (left == TNULL) {
            fprintf(stderr,"*** integrity check failure: left of interior node %X is TNULL\n",node);
            numerrs++;
        } else {
            numerrs+= sanity_check_subtree(left);
        }
        if (right == TNULL) {
            fprintf(stderr,"*** integrity check failure: right of interior node %X is TNULL\n",node);
            numerrs++;
        } else {
            numerrs+= sanity_check_subtree(right);
        }
        if ((left != TNULL) && (right != TNULL)) {
            if (largestval(left) != intsortpt(node)) {
                fprintf(stderr,"*** integrity check failure: sortpoint on interior node %X (%d) does not match largest value on left (%d)\n",node,intsortpt(node),largestval(left));
                numerrs++;
            }
        }   
    }
    return numerrs;
}


int spade_prob_table_checkpoint(statefile_ref *s,spade_prob_table *self) {
    return spade_state_checkpoint_arr(s,self->root,MAX_NUM_FEATURES,sizeof(mindex));
}

int spade_prob_table_recover(statefile_ref *s,spade_prob_table *self) {
    return spade_state_recover_arr(s,&self->root,MAX_NUM_FEATURES,sizeof(mindex));
}

/* $Id: spade_prob_table.c,v 1.10 2002/12/19 22:37:10 jim Exp $ */
