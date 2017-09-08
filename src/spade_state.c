/*********************************************************************
spade_state.c, distributed as part of Spade v030125.1
Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
copyright (c) 2002 by Silicon Defense (http://www.silicondefense.com/)
Released under GNU General Public License, see the COPYING file included
with the distribution or http://www.silicondefense.com/spice/ for details.

Please send complaints, kudos, and especially improvements and bugfixes to
hoagland@SiliconDefense.com.  As described in GNU General Public License, no
warranty is expressed for this program.
*********************************************************************/

/*! \file spade_state.c
 * \brief 
 *  spade_state.c contains a module to assist with checkpoint and recovery
 *  of a Spade application; it is intimate with the spade_prob_table_types
 *  module
 * \ingroup staterec
 */

/*! \addtogroup staterec
    @{
*/

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>

#include "spade_features.h"
#include "spade_prob_table_types.h"
#include "spade_state.h"

#define CUR_FVERS 5

/// treeroot structure used in file checkpoint version 4 and earlier
typedef struct {
    mindex next;  ///< the next tree root in a list
    dmindex root; ///< root node of the tree, if top bit is 1, it is a leafnode, otherwise it is a interior node
    features type;///< the feature that is being represented in this tree
} upto_v4_treeroot;


statefile_ref *spade_state_begin_checkpointing(char *filename,char *appname,u8 app_cur_fvers) {
    statefile_ref *s= (statefile_ref *)malloc(sizeof(statefile_ref));
    char v='v';
    u8 fvers= CUR_FVERS,uc;
    double d= 1234.56789;
    u32 l= 0x01020304;
    u32 i,blocks_used;
    u8 numfeat= MAX_NUM_FEATURES;

    errno=0;
    s->f= fopen(filename,"wb");
    if (errno) {
        perror(filename);
        free(s);
        return NULL;
    }

    fwrite(&v,sizeof(v),1,s->f);
    fwrite(&fvers,1,1,s->f);
    spade_state_checkpoint_str(s,appname);
    fwrite(&app_cur_fvers,1,1,s->f);
    
    uc= sizeof(u16);
    fwrite(&uc,sizeof(uc),1,s->f);
    uc= sizeof(u32);
    fwrite(&uc,sizeof(uc),1,s->f);
    uc= sizeof(double);
    fwrite(&uc,sizeof(uc),1,s->f);
    
    /* + the integer 0x01020304 (16,909,060) as a 4 byte unsigned int, to indicate the endianness of this file */
    fwrite(&l,4,1,s->f);
    /* + the number 1234.56789 as a double (sizeof(double)) [to verify that doubles are binary compatable] */
    fwrite(&d,sizeof(d),1,s->f);

    fwrite(&numfeat,sizeof(numfeat),1,s->f);

    /* write out tree library state */
        /* treeroot type state */
    fwrite(&ROOT_BLOCK_BITS,sizeof(ROOT_BLOCK_BITS),1,s->f);
    for (blocks_used= 0; ROOT_M[blocks_used] != NULL; blocks_used++) {}
    fwrite(&blocks_used,sizeof(blocks_used),1,s->f);
    for (i= 0; i < blocks_used; i++) {
        fwrite(ROOT_M[i],sizeof(treeroot),ROOT_BLOCK_SIZE,s->f);
    }
    fwrite(&root_freelist,sizeof(root_freelist),1,s->f);

        /* intnode type state */
    fwrite(&INT_BLOCK_BITS,sizeof(INT_BLOCK_BITS),1,s->f);
    for (blocks_used= 0; INT_M[blocks_used] != NULL; blocks_used++) {}
    fwrite(&blocks_used,sizeof(blocks_used),1,s->f);
    for (i= 0; i < blocks_used; i++) {
        fwrite(INT_M[i],sizeof(intnode),INT_BLOCK_SIZE,s->f);
    }
    fwrite(&int_freelist,sizeof(int_freelist),1,s->f);

        /* leafnode type state */
    fwrite(&LEAF_BLOCK_BITS,sizeof(LEAF_BLOCK_BITS),1,s->f);
    for (blocks_used= 0; LEAF_M[blocks_used] != NULL; blocks_used++) {}
    fwrite(&blocks_used,sizeof(blocks_used),1,s->f);
    for (i= 0; i < blocks_used; i++) {
        fwrite(LEAF_M[i],sizeof(leafnode),LEAF_BLOCK_SIZE,s->f);
    }
    fwrite(&leaf_freelist,sizeof(leaf_freelist),1,s->f);

    return s;
}

int spade_state_end_checkpointing(statefile_ref *s) {
    fclose(s->f);
    free(s);
    return 1;
}

int spade_state_checkpoint_str(statefile_ref *s,char *str) {
    u16 len=strlen(str);
    fwrite(&len,2,1,s->f);
    fwrite(str,sizeof(char),strlen(str),s->f);
    return 1;
}

int spade_state_checkpoint_arr(statefile_ref *s,void *arr,int len,int elsize) {
    fwrite(arr,elsize,len,s->f);
    return 1;
}

int spade_state_checkpoint_str_arr(statefile_ref *s,char **arr,int len) {
    int i;
    for (i=0; i < len; i++)
        if (!spade_state_checkpoint_str(s,arr[i])) return 0;
    return 1;
}

int spade_state_checkpoint_u32(statefile_ref *s,u32 val) {
    fwrite(&val,4,1,s->f);
    return 1;
}

int spade_state_checkpoint_u8(statefile_ref *s,u8 val) {
    fwrite(&val,1,1,s->f);
    return 1;
}

int spade_state_checkpoint_time_t(statefile_ref *s,time_t val) {
    return spade_state_checkpoint_u32(s,val);
}

int spade_state_checkpoint_double(statefile_ref *s,double val) {
    fwrite(&val,sizeof(double),1,s->f);
    return 1;
}

int spade_state_end_section(statefile_ref *s) {
    u16 nul= 0x0000;
    fwrite(&nul,2,1,s->f);
    return 1;
}

#define PREMATURE_END_CHECK(count,minsize) if (count < minsize) { \
        fprintf(stderr,"Premature end in Spade recovery file %s; not recovering from it\n",filename); \
        fclose(s->f); \
        return NULL; \
    }

#define CORRUPT_FILE_CHECK(testres,whatwentwrong) \
    if (testres) { \
        fprintf(stderr,"Corrupt Spade recovery file %s: %s; not recovering from it\n",filename,whatwentwrong); \
        fclose(s->f); \
        return NULL; \
    }


statefile_ref *spade_state_begin_recovery(char *filename,int min_app_fvers,char **appname,u8 *file_app_fvers) {
    statefile_ref *s= (statefile_ref *)malloc(sizeof(statefile_ref));
    unsigned char uc,fvers;
    char v;
    unsigned int i,blocks_used;
    int count;
    u8 numfeat;
    double d;
    u32 l;
    
    init_mem();
    
    if (s == NULL) return NULL;
    
    errno=0;
    s->f= fopen(filename,"rb");
    if (errno) { /* file prob does not exist */
        return NULL;
    }
    
    count= fread(&v,sizeof(v),1,s->f);
    PREMATURE_END_CHECK(count,1);
    if (v == 'v') { /* format version # encoded */
        count= fread(&fvers,1,1,s->f);
        PREMATURE_END_CHECK(count,1);
    } else { /* format version #0; only diff from version 1 is that the version # is listed */
        fvers= 0;
    }
    if (fvers < 4) {
        fprintf(stderr,"This version of the Spade state recover procedure cannot read file %s since has format version %d; this routine can recover version 4 onwards; sorry\n",filename,fvers);
        fclose(s->f);
        return NULL;
    }
    if (fvers > CUR_FVERS) {
        fprintf(stderr,"This version of the Spade state recover procedure cannot read file %s since has format version %d; this routine can only handle up to version %d\n",filename,fvers,CUR_FVERS);
        fclose(s->f);
        return NULL;
    }
    spade_state_recover_str(s,appname);
    count= fread(file_app_fvers,1,1,s->f);
    PREMATURE_END_CHECK(count,1);
    if (*file_app_fvers < min_app_fvers) {
        fprintf(stderr,"Spade state recover failed on file %s: application %s version was %d but at least version %d was required\n",filename,*appname,*file_app_fvers,min_app_fvers);
        fclose(s->f);
        return NULL;
    }

    count= fread(&uc,sizeof(uc),1,s->f);
    PREMATURE_END_CHECK(count,1);
    if (sizeof(u16) != uc) {
        fprintf(stderr,"u16 type size from recovery file (%s) (%d bytes) does not match current size (%d bytes)\n",filename,uc,(int)sizeof(u16));
        fclose(s->f);
        return NULL;
    }
    count= fread(&uc,sizeof(uc),1,s->f);
    PREMATURE_END_CHECK(count,1);
    if (sizeof(u32) != uc) {
        fprintf(stderr,"u32 type size from recovery file (%s) (%d bytes) does not match current size (%d bytes)\n",filename,uc,(int)sizeof(u32));
        fclose(s->f);
        return NULL;
    }
    count= fread(&uc,sizeof(uc),1,s->f);
    PREMATURE_END_CHECK(count,1);
    if (sizeof(double) != uc) {
        fprintf(stderr,"double type size from recovery file (%s) (%d bytes) does not match current size (%d bytes)\n",filename,uc,(int)sizeof(double));
        fclose(s->f);
        return NULL;
    }
    
    /* ========= read in encoding and sanity check things ========== */
    /* + the integer 0x01020304 (16,909,060) as a 4 byte unsigned int, to indicate the endianness of this file */
    count= fread(&l,sizeof(l),1,s->f);
    PREMATURE_END_CHECK(count,1);
    if (l != 0x01020304) {
        fprintf(stderr,"recovery file (%s) was produced with a different byte ordering (got 0x%x where expecting 0x01020304); you will need to convert the file\n",filename,l);
        return NULL;
    }

    /* + the number 1234.56789 as a double (sizeof(double)) [to verify that doubles are binary compatable] */
    count= fread(&d,sizeof(d),1,s->f);
    PREMATURE_END_CHECK(count,1);
    if (d > 1234.58 || d < 1234.55) {
        fprintf(stderr,"recovery file (%s) was produced with a different double representation (got %f where expecting something close to 1234.56789); you will need to convert the file\n",filename,d);
        return NULL;
    }

    count= fread(&numfeat,1,1,s->f);
    PREMATURE_END_CHECK(count,1);
    if (numfeat > MAX_NUM_FEATURES) {
        fprintf(stderr,"recovery file (%s) has a higher number of features (%d) than we allow (%d); you will need to increase MAX_NUM_FEATURES\n",filename,numfeat,MAX_NUM_FEATURES);
        return NULL;
    }

    count= fread(&ROOT_BLOCK_BITS,sizeof(ROOT_BLOCK_BITS),1,s->f);
    PREMATURE_END_CHECK(count,1);
    CORRUPT_FILE_CHECK(ROOT_BLOCK_BITS < 3,"stored ROOT_BLOCK_BITS is too small");
    
    /* use the max block size for this run unless there is more stored in the file */
    count= fread(&blocks_used,sizeof(blocks_used),1,s->f);
    PREMATURE_END_CHECK(count,1);
    if (blocks_used > DEFAULT_MAX_ROOT_BLOCKS) {
        reallocate_ptr_array((void ***)&ROOT_M,DEFAULT_MAX_ROOT_BLOCKS,blocks_used);
        MAX_ROOT_BLOCKS= blocks_used;
    }
    
    if (fvers >= 5) { // can read block of treeroots directly
        for (i= 0; i < blocks_used; i++) {
            ROOT_M[i]= (treeroot *)malloc(sizeof(treeroot)*ROOT_BLOCK_SIZE);
            count= fread(ROOT_M[i],sizeof(treeroot),ROOT_BLOCK_SIZE,s->f);
            PREMATURE_END_CHECK(count,ROOT_BLOCK_SIZE);
        }
    } else { // need to translate treeroot struct from treeroot_orig to treeroot
        int j;
        upto_v4_treeroot *origblock= (upto_v4_treeroot *)malloc(sizeof(upto_v4_treeroot)*ROOT_BLOCK_SIZE);
        for (i= 0; i < blocks_used; i++) {
            ROOT_M[i]= (treeroot *)malloc(sizeof(treeroot)*ROOT_BLOCK_SIZE);
            count= fread(origblock,sizeof(upto_v4_treeroot),ROOT_BLOCK_SIZE,s->f);
            PREMATURE_END_CHECK(count,ROOT_BLOCK_SIZE);
            for (j=0; j < ROOT_BLOCK_SIZE; j++) {
                // look at original structure and initialize new from it
                ROOT_M[i][j].next= origblock[j].next;
                ROOT_M[i][j].root= origblock[j].root;
                ROOT_M[i][j].type= origblock[j].type;
                ROOT_M[i][j].entropy= -1;
            }
        }
        free(origblock);
    }

    count= fread(&root_freelist,sizeof(root_freelist),1,s->f);
    PREMATURE_END_CHECK(count,1);
    
    
    count= fread(&INT_BLOCK_BITS,sizeof(INT_BLOCK_BITS),1,s->f);
    PREMATURE_END_CHECK(count,1);
    CORRUPT_FILE_CHECK(INT_BLOCK_BITS < 3,"stored INT_BLOCK_BITS is too small");
    
    /* use the max block size for this run unless there is more stored in the file */
    count= fread(&blocks_used,sizeof(blocks_used),1,s->f);
    PREMATURE_END_CHECK(count,1);
    if (blocks_used > DEFAULT_MAX_INT_BLOCKS) {
        reallocate_ptr_array((void ***)&INT_M,DEFAULT_MAX_INT_BLOCKS,blocks_used);
        MAX_INT_BLOCKS= blocks_used;
    }
    
    for (i= 0; i < blocks_used; i++) {
        INT_M[i]= (intnode *)malloc(sizeof(intnode)*INT_BLOCK_SIZE);
        count= fread(INT_M[i],sizeof(intnode),INT_BLOCK_SIZE,s->f);
        PREMATURE_END_CHECK(count,INT_BLOCK_SIZE);
    }

    count= fread(&int_freelist,sizeof(int_freelist),1,s->f);
    PREMATURE_END_CHECK(count,1);
    
    
    count= fread(&LEAF_BLOCK_BITS,sizeof(LEAF_BLOCK_BITS),1,s->f);
    PREMATURE_END_CHECK(count,1);
    CORRUPT_FILE_CHECK(LEAF_BLOCK_BITS < 3,"stored LEAF_BLOCK_BITS is too small");
    
    /* use the max block size for this run unless there is more stored in the file */
    count= fread(&blocks_used,sizeof(blocks_used),1,s->f);
    PREMATURE_END_CHECK(count,1);
    if (blocks_used > DEFAULT_MAX_LEAF_BLOCKS) {
        reallocate_ptr_array((void ***)LEAF_M,DEFAULT_MAX_LEAF_BLOCKS,blocks_used);
        MAX_LEAF_BLOCKS= blocks_used;
    }
    
    for (i= 0; i < blocks_used; i++) {
        LEAF_M[i]= (leafnode *)malloc(sizeof(leafnode)*LEAF_BLOCK_SIZE);
        count= fread(LEAF_M[i],sizeof(leafnode),LEAF_BLOCK_SIZE,s->f);
        PREMATURE_END_CHECK(count,LEAF_BLOCK_SIZE);
    }
    
    count= fread(&leaf_freelist,sizeof(leaf_freelist),1,s->f);
    PREMATURE_END_CHECK(count,1);
    
    return s;
}

int spade_state_end_recovery(statefile_ref *s) {
    fclose(s->f);
    free(s);
    return 1;
}

int spade_state_recover_check_end_of_section(statefile_ref *s,int *res) {
    u16 c;
    int count= fread(&c,2,1,s->f);
    if (!count) return 0;
    
    *res= (c == 0x0000);
    if (!*res) fseek(s->f,-2,SEEK_CUR);
    return 1;
}

int spade_state_recover_arr(statefile_ref *s,void *arr,int len,int elsize) {
    int count= fread(arr,elsize,len,s->f);
    return count == len;
}

int spade_state_recover_str_arr(statefile_ref *s,char **arr,int len) {
    int i;
    for (i=0; i < len; i++)
        if (!spade_state_recover_str(s,&arr[i])) return 0;
    return 1;
}

int spade_state_recover_u32(statefile_ref *s,u32 *val) {
    int count= fread(val,4,1,s->f);
    return count == 1;
}

int spade_state_recover_u8(statefile_ref *s,u8 *val) {
    int count= fread(val,1,1,s->f);
    return count == 1;
}

int spade_state_recover_time_t(statefile_ref *s,time_t *val) {
    return spade_state_recover_u32(s,(u32 *)val);
}

int spade_state_recover_double(statefile_ref *s,double *val) {
    int count= fread(val,sizeof(double),1,s->f);
    return count == 1;
}


int spade_state_recover_str(statefile_ref *s,char **str) {
    u16 len;
    int count= fread(&len,2,1,s->f);
    if (!count) return 0;
    *str= (char *)malloc(sizeof(char)*(len+1));
    if (*str == NULL) return 0;
    
    count= fread(*str,sizeof(char),len,s->f);
    (*str)[count]= '\0';
    if (count < len) return 0;
    return 1;
}

int spade_state_recover_str_to_buff(statefile_ref *s,char *buff,int maxlen) {
    u16 len,readlen;
    int count= fread(&len,2,1,s->f);
    if (!count) return 0;
    readlen= len > (maxlen-1) ? maxlen-1 : len;
    count= fread(buff,sizeof(char),readlen,s->f);
    if (count < readlen) return 0;
    buff[readlen]= '\0';
    
    while (readlen < len) { /* discard extra */
        char c;
        count= fread(&c,sizeof(char),1,s->f);
        if (!count) return 0;
        readlen++;
    }
    return 1;
}


/* $Id: spade_state.c,v 1.7 2003/01/14 17:45:31 jim Exp $ */
