/*********************************************************************
strtok.c, distributed as part of Spade v030125.1
Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
copyright (c) 2002 by Silicon Defense (http://www.silicondefense.com/)
Released under GNU General Public License, see the COPYING file included
with the distribution or http://www.silicondefense.com/spice/ for details.

Please send complaints, kudos, and especially improvements and bugfixes to
hoagland@SiliconDefense.com.  As described in GNU General Public License, no
warranty is expressed for this program.
*********************************************************************/


/*! \file strtok.c
 * \brief
 *  strtok.c contains a module providing string parsing functionality
 * \ingroup libspade_util
 */

/*! \addtogroup libspade_util
    @{
*/

#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "strtok.h"

/// a record for an argument we are set to expect
typedef struct _argspec {
    /// the next argspec in a linked list
    struct _argspec *next;
    /// an indication of what type of argument value we are expecting and how to interpret it
    /** 'c' indicates a single character, 's' a string, 'd' a double,
        'f' a float, 'l' a long int, 'i' and int, and 'b' a boolean */
    char type;
    /// if we are expecting a sting, the maximum number of charecters that should be read
    int maxlen;
    /// for matching unlabeled argument values, this is the position number we are expect our value to be in
    int argpos;
    /// up to 5 strings we accept as our argument name; list is terminated by a '\0' in the first char of the first unused array slot
    char labels[5][50];
} argspec;

argspec *argspec_freelist= NULL;

static argspec *new_argspec(char format, int argpos);
static void free_argspecs(argspec *head);
//static void free_argspec(argspec *spec);
static argspec *parse_argspec_format(char *format);

int strtok_space_sep(char *str,char **after) {
    char *p= str;
    int len= 0;
    if (p == NULL) return 0;
    while (*p != '\0' && !isspace((int)*p)) {
        p++;
        len++;
    }
    while (*p != '\0' && isspace((int)*p)) p++;
    *after= p;
    return len;
}

static argspec *new_argspec(char format,int argpos) {
    argspec *new;
    if (argspec_freelist == NULL) {
        new= (argspec *)malloc(sizeof(argspec));
    } else {
        new= argspec_freelist;
        argspec_freelist= argspec_freelist->next;
    }
    new->next= NULL;
    new->type= format;
    new->maxlen= 0;
    new->argpos= argpos;
    new->labels[0][0]= '\0';
    return new;
}

static void free_argspecs(argspec *head) {
    argspec *last;
    if (head == NULL) return;
    for (last= head; last->next != NULL; last=last->next);
    last->next= argspec_freelist;
    argspec_freelist= head;
}

#if 0
static void free_argspec(argspec *spec) {
    if (spec == NULL) return;
    spec->next= argspec_freelist;
    argspec_freelist= spec;
}
#endif

static argspec *parse_argspec_format(char *format) {
    char errstr[100]= "\0";
    char *f= format;
    argspec *spec,*spechead=NULL,*spectail=NULL;
    int argpos= 0;
    char *rem;
    
    while (f != NULL && *f != '\0') {
        // parse new arg
        argpos++;
        if (*f != 'c' && *f != 's' && *f != 'd' && *f != 'f' && *f != 'l' && *f != 'i' && *f != 'b') {
            sprintf(errstr,"invalid arg letter: %c",*f);
            break;
        }
        spec= new_argspec(*f,argpos);
        f++;
        if (isdigit(*f)) {
            spec->maxlen= strtol(f,&f,10);
        }
        if (*f == ':') {
            int count= 0;
            f++;
            while (isspace((int)*f)) f++;
            rem= f;
            f= strchr(rem,';');
            do {
                int len= 0;
                if (*rem == ',') rem++;
                while (isspace((int)*rem)) rem++;
                while (*rem != '\0' && !isspace((int)*rem) && *rem != ',' && *rem != ';' && len < 50) {
                    spec->labels[count][len]= *rem;
                    rem++;
                    len++;
                }
                spec->labels[count][len]= '\0';
                while (isspace((int)*rem)) rem++;
                count++;
                if (count < 5) spec->labels[count][0]= '\0';
            } while (count < 5 && *rem == ',');
        }
        if (f != NULL) {
            while (isspace((int)*f)) f++;
            if (*f == ';') f++;
            while (isspace((int)*f)) f++;
        }
        if (spechead == NULL) {
            spechead= spectail= spec;
        } else {
            spectail->next= spec;
            spectail= spec;
        }
    }
    if (errstr[0] != '\0') { // an error occurred
        fprintf(stderr,"syntax error in spec format: %s: \"%s\"",errstr,format);
        free_argspecs(spechead);
        return NULL;
    }
    return spechead;
}

int fill_args_space_sep(char *str,char *format,void *args[],spade_msg_fn msg_callback) {
    int i,arrfilepos;
    char *next,*seppos,*labelhead,*valhead,*after;
    char oldchar;
    int copylen,len,labellen;
    char *strcopy= strdup(str);
    char *head= strcopy;
    int argpos= 0;
    int count= 0;
    int no_pos_based= 0;
    argspec *curspec,*spec;
    argspec *argspecs;
    argspec *pb_spec;
    
    if (*format == '$') {
        no_pos_based= 1;
        format++;
    }
    argspecs= parse_argspec_format(format);
    pb_spec= argspecs;

    while (head != NULL) {
        argpos++;
        len= strtok_space_sep(head,&next);
        if (len == 0) break;
        after= head+len;
        oldchar= *after;
        *after= '\0'; // temporarily null terminate head
        
        seppos= strchr(head,'=');
        if (seppos == NULL) { // boolean label-based spec else position based spec
            valhead= head;
            labelhead= head;
            labellen= len;
        } else { // label-based spec or else string position based spec that contains a '='
            /* search for matching spec label */
            labelhead= head;
            labellen= seppos-labelhead;
            valhead= seppos+1;
        }
        
        /* look for label-based-spec */
        curspec= NULL;
        for (spec= argspecs; curspec == NULL && spec != NULL; spec= spec->next) {
            if (seppos == NULL && spec->type != 'b') continue;
            for (i=0; i < 5; i++) {
                if (spec->labels[i][0] == '\0') break;
                if (!strncmp(spec->labels[i],labelhead,labellen) && strlen(spec->labels[i]) == labellen) {
                    curspec= spec;
                    break;
                }
            }
        }
        if (curspec == NULL) { // must be position based spec
            if (!no_pos_based || pb_spec == NULL) {
                if (seppos != NULL) { // must be string position based spec that contains a '='
                    valhead= head; /* reset value start to start of arg */
                }
                while ((pb_spec->next != NULL) && (pb_spec->argpos < argpos)) pb_spec=pb_spec->next;
            }
            if (no_pos_based || pb_spec == NULL || (seppos != NULL && pb_spec->type != 's') || pb_spec->argpos != argpos) {
                formatted_spade_msg_send(SPADE_MSG_TYPE_WARNING,msg_callback,"Warning: option \"%s\" not understood in \"%s\"; ignoring it",labelhead,str);
                *(head+len)= oldchar; // restore orig char
                head= next;
                continue; // no match; ignore
            }
            curspec= pb_spec;
        } else {
            if (seppos == NULL) { /* a boolean with no '=' */
                valhead= NULL;
            }
        }
            
        arrfilepos= curspec->argpos-1;
        switch (curspec->type) {
            case 'i':
                *((int *)args[arrfilepos])= atoi(valhead);
                break;
            case 'l':
                *((long *)args[arrfilepos])= atol(valhead);
                break;
            case 'f':
                *((float *)args[arrfilepos])= (float)atof(valhead);
                break;
            case 'd':
                *((double *)args[arrfilepos])= atof(valhead);
                break;
            case 'c':
                *((char *)args[arrfilepos])= *valhead;
                break;
            case 'b':
            {
                int bool;
                if (valhead == NULL) {
                    bool= 1;
                } else {
                    if (!strcmp(valhead,"yes") || !strcmp(valhead,"true") || !strcmp(valhead,"on")) {
                        bool= 1;
                    } else if  (!strcmp(valhead,"no") || !strcmp(valhead,"false") || !strcmp(valhead,"off")) {
                        bool= 0;
                    } else {
                        bool= atoi(valhead);
                    }
                }
                *((int *)args[arrfilepos])= bool;
                break;
            }
            case 's':
                copylen= after-valhead;
                if (curspec->maxlen) {
                    if (len > curspec->maxlen) copylen=curspec->maxlen;
                }
                strncpy((char *)args[arrfilepos],valhead,copylen);
                ((char *)args[arrfilepos])[copylen]= '\0';
                break;
            default:
                args[arrfilepos]= NULL;
                break;
        }
        
        *after= oldchar; // restore orig char
        count++;
        head= next;
    }
    free(strcopy);
    free_argspecs(argspecs);
    return count;
}

char *extract_str_arg_space_sep(char *str,char *argname) {
    char *after;
    char *val,*valhead;
    int vallen,copylen;
    char *head= str;
    int arglen= strlen(argname);
    char *strafter= str+strlen(str);
    while ((head=strstr(head,argname)) != NULL) {
        if (head != str && !isspace((int)*(head-1)))
            continue;
        after= head+arglen;
        if (*(head+arglen) != '=')
            continue;
            
        /* found it */
        /* put in a str */
        valhead= after+1;
        after= valhead;
        while (*after != '\0' && !isspace((int)*after)) after++;
        vallen= (after-valhead);
        val= (char *)malloc(sizeof(char)*(vallen+1));
        strncpy(val,valhead,vallen);
        *(val+vallen)= '\0';
        
        /* now remove it from the str */
        while (*after != '\0' && isspace((int)*after)) after++;
        copylen= strafter-after+1; /* includes the terminating \0 */
        memmove(head,after,copylen);
        
        return val;
    }
    return NULL;
}

int terminate_first_tok(char *str,char *sepchars,char **head,char *oldchar) {
    char *p= str;
    int len;
    
    do {
        char *sep= strpbrk(p,sepchars);
        if (sep == NULL) {
            if (*p == '\0') return 0;
            len= strlen(p);
        } else {
            len= sep- p;
        }
        if (len > 0) {
            if (sep != NULL) {
                *oldchar= *sep;
                *sep= '\0';
            } else {
                *oldchar= '\0';
            }
            *head= p;
        } else {
            p++;
        }
    } while (len == 0);
    
    return len;
}

/*@}*/
/* $Id: strtok.c,v 1.8 2003/01/14 17:45:31 jim Exp $ */
