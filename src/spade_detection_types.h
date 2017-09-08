/*********************************************************************
spade_detection_types.h, distributed as part of Spade v030125.1
Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
copyright (c) 2002 by Silicon Defense (http://www.silicondefense.com/)
Released under GNU General Public License, see the COPYING file included
with the distribution or http://www.silicondefense.com/spice/ for details.

Please send complaints, kudos, and especially improvements and bugfixes to
hoagland@SiliconDefense.com.  As described in GNU General Public License, no
warranty is expressed for this program.
*********************************************************************/

#ifndef SPADE_DETECTION_TYPES_H
#define SPADE_DETECTION_TYPES_H


/*! \file spade_detection_types.h
 * \ingroup netspade_layer
 * \brief 
 *  spade_detection_types.h contains constants, strings, and conversion macros
 *  for spade detection types and detector types
 */

/*! \addtogroup netspade_layer
    @{
*/


/* detector types (each spade detector is of a certain type) */
#define SPADE_DR_TYPE_UNKNOWN       0
#define SPADE_DR_TYPE_CLOSED_DPORT  1
#define SPADE_DR_TYPE_DEAD_DEST     2
#define SPADE_DR_TYPE_ODD_DPORT     3
#define SPADE_DR_TYPE_ODD_TYPECODE  4
#define SPADE_DR_TYPE_ODD_PORTDEST  5

/// map a detector type plus an relative detector number to the corresponding detector number
#define SPADE_DN_TYPE_FOR_DR_TYPE(num,index) ((num << 8) + index)

/// map detector type number to a short strings representing it
#define SPADE_DR_TYPE_SHORT4NUM(num) \
    ((num == SPADE_DR_TYPE_CLOSED_DPORT) ? "closed-dport" \
    :(num == SPADE_DR_TYPE_DEAD_DEST) ? "dead-dest" \
    :(num == SPADE_DR_TYPE_ODD_DPORT) ? "odd-dport" \
    :(num == SPADE_DR_TYPE_ODD_TYPECODE) ? "odd-typecode" \
    :(num == SPADE_DR_TYPE_ODD_PORTDEST) ? "odd-port-dest" \
    :"?" \
    )

/// map short strings representing a detector type to its number
#define SPADE_DR_TYPE_NUM4SHORT(str) \
    ((!strcmp(str,"closed-dport")) ? SPADE_DR_TYPE_CLOSED_DPORT \
    :(!strcmp(str,"dead-dest")) ? SPADE_DR_TYPE_DEAD_DEST \
    :(!strcmp(str,"odd-dport")) ? SPADE_DR_TYPE_ODD_DPORT \
    :(!strcmp(str,"odd-typecode")) ? SPADE_DR_TYPE_ODD_TYPECODE \
    :(!strcmp(str,"odd-port-dest")) ? SPADE_DR_TYPE_ODD_PORTDEST \
    :SPADE_DR_TYPE_UNKNOWN \
    )


/* detection types (a detector type can have multiple detection types) */
#define SPADE_DN_TYPE_UNKNOWN       0
#define SPADE_DN_TYPE_CLOSED_DPORT  ((SPADE_DR_TYPE_CLOSED_DPORT << 8) +0)
#define SPADE_DN_TYPE_ODD_OPEN_DPORT  ((SPADE_DR_TYPE_CLOSED_DPORT << 8) +1)
#define SPADE_DN_TYPE_ODD_DPORT  ((SPADE_DR_TYPE_CLOSED_DPORT << 8) +2)
#define SPADE_DN_TYPE_NONLIVE_DEST  ((SPADE_DR_TYPE_DEAD_DEST << 8) +0)
#define SPADE_DN_TYPE_SRC_ODD_DPORT ((SPADE_DR_TYPE_ODD_DPORT << 8) +0)
#define SPADE_DN_TYPE_ODD_TYPECODE  ((SPADE_DR_TYPE_ODD_TYPECODE << 8) +0)
#define SPADE_DN_TYPE_ODD_PORTDEST_LOWH  ((SPADE_DR_TYPE_ODD_PORTDEST << 8) +0)
//#define SPADE_DN_TYPE_ODD_PORTDEST_HIGHH  ((SPADE_DR_TYPE_ODD_PORTDEST << 8) +1)

/// map a detector type number to the detection type number
#define SPADE_DR_TYPE_FOR_DN_TYPE(num) (num >> 8)

/// obtain the default detection type number for a detector type number
#define DEFAULT_DN_TYPE_FOR_DR_TYPE(num) SPADE_DN_TYPE_FOR_DR_TYPE(num,0)

/// map detction type to very brief strings denoting the detection type
#define SPADE_DN_TYPE_BRIEF4NUM(num) \
    ((num == SPADE_DN_TYPE_CLOSED_DPORT) ? "CD" \
    :(num == SPADE_DN_TYPE_ODD_OPEN_DPORT) ? "ROD" \
    :(num == SPADE_DN_TYPE_ODD_DPORT) ? "RD" \
    :(num == SPADE_DN_TYPE_NONLIVE_DEST) ? "DD" \
    :(num == SPADE_DN_TYPE_SRC_ODD_DPORT) ? "OD" \
    :(num == SPADE_DN_TYPE_ODD_TYPECODE) ? "OT" \
    :(num == SPADE_DN_TYPE_ODD_PORTDEST_LOWH) ? "PD" \
    :"?" \
    )

/// map detction type very brief strings to the detection type number
#define SPADE_DN_TYPE_NUM4BRIEF(str) \
    ((!strcmp(str,"CD")) ? SPADE_DN_TYPE_CLOSED_DPORT \
    ((!strcmp(str,"ROD")) ? SPADE_DN_TYPE_ODD_OPEN_DPORT \
    ((!strcmp(str,"RD")) ? SPADE_DN_TYPE_ODD_DPORT \
    :(!strcmp(str,"DD")) ? SPADE_DN_TYPE_NONLIVE_DEST \
    :(!strcmp(str,"OD")) ? SPADE_DN_TYPE_SRC_ODD_DPORT \
    :(!strcmp(str,"OT")) ? SPADE_DN_TYPE_ODD_TYPECODE \
    :(!strcmp(str,"PD")) ? SPADE_DN_TYPE_ODD_PORTDEST_LOWH \
    :SPADE_DN_TYPE_UNKNOWN \
    )

/// map detction type to medium-length strings describing the detection done
#define SPADE_DN_TYPE_MEDDESCR4NUM(num) \
    ((num == SPADE_DN_TYPE_CLOSED_DPORT) ? "Closed dest port used" \
    :(num == SPADE_DN_TYPE_ODD_OPEN_DPORT) ? "Rare but open dest port used" \
    :(num == SPADE_DN_TYPE_ODD_DPORT) ? "Rare dest port used" \
    :(num == SPADE_DN_TYPE_NONLIVE_DEST) ? "Non-live dest used" \
    :(num == SPADE_DN_TYPE_SRC_ODD_DPORT) ? "Source used odd dest port" \
    :(num == SPADE_DN_TYPE_ODD_TYPECODE) ? "Odd ICMP type/code found" \
    :(num == SPADE_DN_TYPE_ODD_PORTDEST_LOWH) ? "Source used odd dest for port" \
    :"?" \
    )

/// map the medium-length strings describing the detection done to the detection type number
#define SPADE_DN_TYPE_NUM4MEDDESCR(str) \
    ((!strcmp(str,"Closed dest port used")) ? SPADE_DN_TYPE_CLOSED_DPORT \
    :(!strcmp(str,"Rare but open dest port used")) ? SPADE_DN_TYPE_ODD_OPEN_DPORT \
    :(!strcmp(str,"Rare dest port used")) ? SPADE_DN_TYPE_ODD_DPORT \
    :(!strcmp(str,"Non-live dest used")) ? SPADE_DN_TYPE_NONLIVE_DEST \
    :(!strcmp(str,"Source used odd dest port")) ? SPADE_DN_TYPE_SRC_ODD_DPORT \
    :(!strcmp(str,"Odd ICMP type/code found")) ? SPADE_DN_TYPE_ODD_TYPECODE \
    :(!strcmp(str,"Source used odd dest for port")) ? SPADE_DN_TYPE_ODD_PORTDEST_LOWH \
    :SPADE_DN_TYPE_UNKNOWN \
    )
    
/*@}*/

/* $Id: spade_detection_types.h,v 1.5 2002/12/21 01:25:39 jim Exp $ */

#endif // SPADE_DETECTION_TYPES_H
