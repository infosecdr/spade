/*********************************************************************
spade_prob_table_types.h, distributed as part of Spade v030125.1
Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
copyright (c) 2002 by Silicon Defense (http://www.silicondefense.com/)
Released under GNU General Public License, see the COPYING file included
with the distribution or http://www.silicondefense.com/spice/ for details.

Please send complaints, kudos, and especially improvements and bugfixes to
hoagland@SiliconDefense.com.  As described in GNU General Public License, no
warranty is expressed for this program.
*********************************************************************/

#ifndef SPADE_PROB_TABLE_TYPES_H
#define SPADE_PROB_TABLE_TYPES_H

/*! \file spade_prob_table_types.h
 * \brief 
 *  spade_prob_table_types.h is the header file for spade_prob_table_types.c.
 * \ingroup staterec
 */

/*! \addtogroup staterec
    @{
*/

#include "spade_features.h"

/// index type into tree memory block data structures
typedef u32 mindex;

/// dmindex is a mindex used with top bit indicating if one of two datatypes is present
typedef u32 dmindex;

/// the type of the values of the features
/** \note right now, we assume all features can be contained in a u32 and can be sorted as unsigned ints; we may need to extend this someday */
typedef u32 valtype;


/// a tree root
typedef struct _treeroot {
    mindex next;      ///< the next tree root in a list
    dmindex root;     ///< root node of the tree, if top bit is 1, it is a leafnode, otherwise it is a interior node
    features type;    ///< the feature that is being represented in this tree
    double entropy;   ///< the last calculated entropy in this tree; < 0 if it has not been calculated
    u16 entropy_wait; ///< the number of additions to the tree to wait till recalculating the entropy; only valid if entropy >= 0
} treeroot;

/// an interior node in the tree
typedef struct _intnode {
    double sum;     ///< the sum of the counts underneath this node in the tree
    valtype sortpt; ///< the highest value on the left side of this node
    dmindex left;   ///< the left node; if top bit is 1, it is a leafnode
    dmindex right;  ///< the right node; if top bit is 1, it is a leafnode
    u16 wait;       ///< the number of additions to the subtree to wait before checking for reblancing
} intnode;

/// a leaf node of the tree
typedef struct _leafnode {
    double count;    ///< the count on this node
    valtype value;   ///< the value this node represents
    mindex nexttree; ///< the first in a linked list of trees anchored from this leaf node
} leafnode;

#define isleaf(node) (node & DMINDEXMASK)
#define asleaf(leaf) (leaf | DMINDEXMASK)
#define encleaf2mindex(node) (node ^ DMINDEXMASK)
/* arg is a dmindex; if it denotes a leaf, return the count on that leaf
   otherwise return the sum on the interior node */ 
#define count_or_sum(node) (isleaf(node) ? leafnode(encleaf2mindex(node)).count : intnode(node).sum)
#define eleafval(leaf) leafnode(encleaf2mindex(leaf)).value
#define largestval(node) (isleaf(node) ? eleafval(node) : largest_val(node))
#define treetype(t) tree(t).type
#define treeroot(t) tree(t).root
#define treenext(t) tree(t).next
#define treeH(t) tree(t).entropy
#define treeH_wait(t) tree(t).entropy_wait
#define intleft(node) intnode(node).left
#define intright(node) intnode(node).right
#define intsum(node) intnode(node).sum
#define intsortpt(node) intnode(node).sortpt
#define intwait(node) intnode(node).wait
#define leafcount(leaf) leafnode(leaf).count
#define leafvalue(leaf) leafnode(leaf).value
#define leafnexttree(leaf) leafnode(leaf).nexttree


/* defaults unless recovering from a checkpoint */
#define DEFAULT_ROOT_BLOCK_BITS 10
#define DEFAULT_INT_BLOCK_BITS 9
#define DEFAULT_LEAF_BLOCK_BITS 10

/* these number of blocks are used
   unless file recovering from already uses more blocks */
#define DEFAULT_MAX_ROOT_BLOCKS 4500
#define DEFAULT_MAX_INT_BLOCKS 12000
#define DEFAULT_MAX_LEAF_BLOCKS 9000

#define bits2blocksize(b) (1 << b)

#define ROOT_BLOCK_SIZE bits2blocksize(ROOT_BLOCK_BITS)
#define ROOT_BLOCK_MASK ((1 << ROOT_BLOCK_BITS) -1)
#define tree(i) ROOT_M[i>>ROOT_BLOCK_BITS][i&ROOT_BLOCK_MASK]
#define root_index(p,i) ((p<<ROOT_BLOCK_BITS)+i)

#define INT_BLOCK_SIZE bits2blocksize(INT_BLOCK_BITS)
#define INT_BLOCK_MASK ((1 << INT_BLOCK_BITS) -1)
#define intnode(i) INT_M[i>>INT_BLOCK_BITS][i&INT_BLOCK_MASK]
#define intnode_index(p,i) ((p<<INT_BLOCK_BITS)+i)

#define LEAF_BLOCK_SIZE bits2blocksize(LEAF_BLOCK_BITS)
#define LEAF_BLOCK_MASK ((1 << LEAF_BLOCK_BITS) -1)
#define leafnode(i) LEAF_M[i>>LEAF_BLOCK_BITS][i&LEAF_BLOCK_MASK]
#define leafnode_index(p,i) ((p<<LEAF_BLOCK_BITS)+i)

#define rfreenext(n) (n).next
#define ifreenext(n) (n).left
#define lfreenext(n) (n).nexttree

/* something of valtype that cannot be a sortpt */
#define NOT_A_SORTPT ((u32)MAX_U32)

#define TNULL (mindex)-1
#define DMINDEXMASK ((dmindex)(1 << (sizeof(dmindex)*8-1)))

extern treeroot **ROOT_M;
extern intnode **INT_M;
extern leafnode **LEAF_M;
extern mindex root_freelist;
extern mindex int_freelist;
extern mindex leaf_freelist;

void init_mem();
void allocate_mem_blocks();
int reallocate_ptr_array(void ***arrptr,int oldsize,int newsize);

mindex new_treeinfo(features type);
void free_treeinfo(mindex f);
mindex new_int();
void free_int(mindex f);
mindex new_leaf(valtype val);
void free_leaf(mindex f);

extern unsigned char ROOT_BLOCK_BITS;
extern unsigned char INT_BLOCK_BITS;
extern unsigned char LEAF_BLOCK_BITS;
extern unsigned int MAX_ROOT_BLOCKS;
extern unsigned int MAX_INT_BLOCKS;
extern unsigned int MAX_LEAF_BLOCKS;

#endif // SPADE_PROB_TABLE_TYPES_H

/* $Id: spade_prob_table_types.h,v 1.8 2003/01/08 19:59:54 jim Exp $ */
