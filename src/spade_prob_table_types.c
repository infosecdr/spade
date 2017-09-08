/*********************************************************************
spade_prob_table_types.c, distributed as part of Spade v030125.1
Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
copyright (c) 2002 by Silicon Defense (http://www.silicondefense.com/)
Released under GNU General Public License, see the COPYING file included
with the distribution or http://www.silicondefense.com/spice/ for details.

Please send complaints, kudos, and especially improvements and bugfixes to
hoagland@SiliconDefense.com.  As described in GNU General Public License, no
warranty is expressed for this program.
*********************************************************************/

/*! \file spade_prob_table_types.c
 * \brief 
 *  spade_prob_table_types.c is a module containing the memory management
 *  for the main 3 data types used by the spade_prob_table "class".
 * \ingroup staterec
 */

/*! \addtogroup staterec
    @{
*/

#include <stdio.h>
#include <stdlib.h>
#include "spade_prob_table_types.h"

treeroot **ROOT_M;
intnode **INT_M;
leafnode **LEAF_M;

mindex root_freelist;
mindex int_freelist;
mindex leaf_freelist;

unsigned char ROOT_BLOCK_BITS;
unsigned char INT_BLOCK_BITS;
unsigned char LEAF_BLOCK_BITS;
unsigned int MAX_ROOT_BLOCKS;
unsigned int MAX_INT_BLOCKS;
unsigned int MAX_LEAF_BLOCKS;

static void reset_mem();

/* initialize the memory manager */
void init_mem() {
    static int spade_prob_table_mem_inited= 0;
    reset_mem();

    if (spade_prob_table_mem_inited) return; /* already inited */
    spade_prob_table_mem_inited= 1;
    
    allocate_mem_blocks();
}

static void reset_mem() {
    ROOT_BLOCK_BITS= DEFAULT_ROOT_BLOCK_BITS;
    INT_BLOCK_BITS= DEFAULT_INT_BLOCK_BITS;
    LEAF_BLOCK_BITS= DEFAULT_LEAF_BLOCK_BITS;
    MAX_ROOT_BLOCKS= DEFAULT_MAX_ROOT_BLOCKS;
    MAX_INT_BLOCKS= DEFAULT_MAX_INT_BLOCKS;
    MAX_LEAF_BLOCKS= DEFAULT_MAX_LEAF_BLOCKS;

    root_freelist=TNULL;
    int_freelist=TNULL;
    leaf_freelist=TNULL;
}

void allocate_mem_blocks() {
    unsigned int i;

    ROOT_M=(treeroot **)malloc(sizeof(treeroot *)*MAX_ROOT_BLOCKS);
    for (i=0; i < MAX_ROOT_BLOCKS; i++) ROOT_M[i]= NULL;
    INT_M=  (intnode **)malloc(sizeof(intnode *)*MAX_INT_BLOCKS);
    for (i=0; i < MAX_INT_BLOCKS; i++) INT_M[i]= NULL;
    LEAF_M=(leafnode **)malloc(sizeof(leafnode *)*MAX_LEAF_BLOCKS);
    for (i=0; i < MAX_LEAF_BLOCKS; i++) LEAF_M[i]= NULL;
}

int reallocate_ptr_array(void ***arrptr,int oldsize,int newsize) {
    unsigned int i;
    void **arr= NULL;

    arr= (void **)realloc(arr,sizeof(void *)*newsize);
    if (arr == NULL) return 0;
    for (i=oldsize; i < newsize; i++) arr[i]= NULL;
    *arrptr= arr;
    return 1;
}

/* allocate a new treeroot node with the give feature type and return it */
mindex new_treeinfo(features type) {
    mindex root;
    int i,p;
    if (root_freelist == TNULL) { /* need to allocate a new block */
        /* find first unused block */
        for (p=0; p < MAX_ROOT_BLOCKS && (ROOT_M[p] != NULL); p++) {}
        if (p == MAX_ROOT_BLOCKS) {
            fprintf(stderr,"exhausted all %d blocks of %d treeroots; exiting; you might want to increase DEFAULT_MAX_ROOT_BLOCKS or DEFAULT_ROOT_BLOCK_BITS in params.h or wherever it is defined\n",MAX_ROOT_BLOCKS,ROOT_BLOCK_SIZE);
            printf("next free root: %X; int: %X, leaf: %X\n",root_freelist,int_freelist,leaf_freelist);
            exit(1);
        }
        ROOT_M[p]= (treeroot *)calloc(ROOT_BLOCK_SIZE,sizeof(treeroot));
        if (ROOT_M[p] == NULL) {
            fprintf(stderr,"Out of memory! in allocation of new treeroot block; exiting");
            exit(2);
        }
        /* add new slots to freelist */
        root_freelist= root_index(p,0);
        for (i=0; i < (ROOT_BLOCK_SIZE-1); i++) {
#ifdef EXTRA_MARK_FREE
            ROOT_M[p][i].root= TNULL;
#endif
            rfreenext(ROOT_M[p][i])= root_index(p,i+1);
        }
#ifdef EXTRA_MARK_FREE
        ROOT_M[p][ROOT_BLOCK_SIZE-1].root= TNULL;
#endif
        rfreenext(ROOT_M[p][ROOT_BLOCK_SIZE-1])= TNULL;
    }
    /* give out the head and make its next the new head */
    root= root_freelist;
    root_freelist= rfreenext(tree(root_freelist));
    treetype(root)= type;
    treeroot(root)= TNULL;
    treenext(root)= TNULL;
    treeH(root)= -1;
    treeH_wait(root)= 0;
    return root;
}

/* free the treeroot node given */
void free_treeinfo(mindex f) {
#ifdef EXTRA_MARK_FREE
    treeroot(f)= TNULL;
#endif
    /* add it to the start of the list */
    rfreenext(tree(f))= root_freelist;
    root_freelist= f;
}


/* allocate a new intnode node and return it */
mindex new_int() {
    mindex res;
    int i,p;
    if (int_freelist == TNULL) { /* need to allocate a new block */
        /* find first unused block */
        for (p=0; p < MAX_INT_BLOCKS && (INT_M[p] != NULL); p++) {}
        if (p == MAX_INT_BLOCKS) {
            fprintf(stderr,"exhausted all %d blocks of %d intnodes; exiting; you might want to increase DEFAULT_MAX_INT_BLOCKS or DEFAULT_INT_BLOCK_BITS in params.h or wherever it is defined\n",MAX_INT_BLOCKS,INT_BLOCK_SIZE);
            printf("next free root: %X; int: %X, leaf: %X\n",root_freelist,int_freelist,leaf_freelist);
            exit(1);
        }
        INT_M[p]= (intnode *)calloc(INT_BLOCK_SIZE,sizeof(intnode));
        if (INT_M[p] == NULL) {
            fprintf(stderr,"Out of memory! in allocation of new intnode block; exiting");
            exit(2);
        }
        /* add new slots to freelist */
        int_freelist= intnode_index(p,0);
        for (i=0; i < (INT_BLOCK_SIZE-1); i++) {
#ifdef EXTRA_MARK_FREE
            INT_M[p][i].sum= -1;
#endif
            ifreenext(INT_M[p][i])= intnode_index(p,i+1);
        }
#ifdef EXTRA_MARK_FREE
        INT_M[p][INT_BLOCK_SIZE-1].sum= -1;
#endif
        ifreenext(INT_M[p][INT_BLOCK_SIZE-1])= TNULL;
    }
    /* give out the head and make its next the new head */
    res= int_freelist;
    int_freelist= ifreenext(intnode(int_freelist));
    intleft(res)= intright(res)= TNULL;
    intsum(res)=0;
    intsortpt(res)= NOT_A_SORTPT;
    intwait(res)= 999;
    return res;
}

/* free the intnode node given */
void free_int(mindex f) {
#ifdef EXTRA_MARK_FREE
    intsum(f)= -1;
#endif
    /* add it to the start of the list */
    ifreenext(intnode(f))= int_freelist;
    int_freelist= f;
}

/* allocate a new leafnode node and return it */
mindex new_leaf(valtype val) {
    mindex res;
    int i,p;
    if (leaf_freelist == TNULL) { /* need to allocate a new block */
        /* find first unused block */
        for (p=0; p < MAX_LEAF_BLOCKS && (LEAF_M[p] != NULL); p++) {}
        if (p == MAX_LEAF_BLOCKS) {
            fprintf(stderr,"exhausted all %d blocks of %d leafnodes; exiting; you might want to increase DEFAULT_LEAF_ROOT_BLOCKS or DEFAULT_LEAF_BLOCK_BITS in params.h or wherever it is defined\n",MAX_LEAF_BLOCKS,LEAF_BLOCK_SIZE);
            printf("next free root: %X; int: %X, leaf: %X\n",root_freelist,int_freelist,leaf_freelist);
            exit(1);
        }
        LEAF_M[p]= (leafnode *)calloc(LEAF_BLOCK_SIZE,sizeof(leafnode));
        if (LEAF_M[p] == NULL) {
            fprintf(stderr,"Out of memory! in allocation of new leafnode block; exiting");
            exit(2);
        }
        /* add new slots to freelist */
        leaf_freelist= leafnode_index(p,0);
        for (i=0; i < (LEAF_BLOCK_SIZE-1); i++) {
#ifdef EXTRA_MARK_FREE
            LEAF_M[p][i].count= -1;
#endif
            lfreenext(LEAF_M[p][i])= leafnode_index(p,i+1);
        }
#ifdef EXTRA_MARK_FREE
        LEAF_M[p][LEAF_BLOCK_SIZE-1].count= -1;
#endif
        lfreenext(LEAF_M[p][LEAF_BLOCK_SIZE-1])= TNULL;
    }
    /* give out the head and make its next the new head */
    res= leaf_freelist;
    leaf_freelist= lfreenext(leafnode(leaf_freelist));
    leafvalue(res)= val;
    leafcount(res)= 1;
    leafnexttree(res)= TNULL;
    return res;
}

/* free the leafnode node given */
void free_leaf(mindex f) {
#ifdef EXTRA_MARK_FREE
    leafcount(f)= -1;
#endif
    /* add it to the start of the list */
    lfreenext(leafnode(f))= leaf_freelist;
    leaf_freelist= f;
}

/* $Id: spade_prob_table_types.c,v 1.5 2002/12/19 22:37:10 jim Exp $ */
