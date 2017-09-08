/*********************************************************************
spade_report.h, distributed as part of Spade v030125.1
Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
copyright (c) 2002 by Silicon Defense (http://www.silicondefense.com/)
Released under GNU General Public License, see the COPYING file included
with the distribution or http://www.silicondefense.com/spice/ for details.

spade_report.h contains the type declaration for the spade_report struct 
  and the interface to the associated functions

Please send complaints, kudos, and especially improvements and bugfixes to
hoagland@SiliconDefense.com.  As described in GNU General Public License, no
warranty is expressed for this program.
*********************************************************************/

/* Internal version control: $Id: spade_report.h,v 1.7 2003/01/08 19:59:54 jim Exp $ */

#ifndef SPADE_REPORT_H
#define SPADE_REPORT_H

/*! \file spade_report.h
 * \ingroup netspade_layer
 * \brief 
 *  spade_report.h contains the type declaration for the spade_report struct 
 *  and the interface to the associated functions
 */

/*! \addtogroup netspade_layer
    @{
*/

#include "spade_enviro.h"
#include "spade_event.h"
#include "score_info.h"
#include <stdio.h>

/// a mask for the bits of a port_status_t that represent belief strength
#define PORT_STRENGTH_MASK 0x003
/// a mask for the bits of a port_status_t that represent the port status
#define PORT_BASE_MASK (0xFFF & ~PORT_STRENGTH_MASK)

/// mask off the port status part of a port_status_t
#define PORT_BASE(status) ((status) & PORT_BASE_MASK)
/// mask off the belief strength part of a port_status_t
#define PORT_STRENGTH(status) ((status) & PORT_STRENGTH_MASK)

/// representation of a definate strength belief in port status
#define PORT_STRENGTH_DEFINATE 0x002
/// representation of a "likely" strength belief in port status
#define PORT_STRENGTH_LIKELY 0x001
/// representation of a "probably" strength belief in port status
#define PORT_STRENGTH_PROBABLY 0x000

/// port status part of a port_status_t when it is open
#define PORT_OPEN_BASE (1<<2)
/// port status part of a port_status_t when it is closed
#define PORT_CLOSED_BASE (2<<2)

/// an enum of value that represents our preception of a port's status
/** the integer value is based on a combination of port status and strength of belief */
typedef enum {
    /// we don't know the port's status
    PORT_UNKNOWN=0,
    /// we think the port is probably open
    PORT_PROBOPEN       =PORT_OPEN_BASE  |PORT_STRENGTH_PROBABLY,
    /// we think the port is likely open
    PORT_LIKELYOPEN     =PORT_OPEN_BASE  |PORT_STRENGTH_LIKELY,
    /// we think the port is definately open
    PORT_OPEN           =PORT_OPEN_BASE  |PORT_STRENGTH_DEFINATE,
    /// we think the port is probably closed
    PORT_PROBCLOSED     =PORT_CLOSED_BASE|PORT_STRENGTH_PROBABLY,
    /// we think the port is likely closed
    PORT_LIKELYCLOSED   =PORT_CLOSED_BASE|PORT_STRENGTH_LIKELY,
    /// we think the port is definately closed
    PORT_CLOSED         =PORT_CLOSED_BASE|PORT_STRENGTH_DEFINATE
} port_status_t;

#define PORT_STATUS_AS_STR(status) (status == PORT_UNKNOWN ? "PORT_UNKNOWN" \
    : (status == PORT_PROBOPEN) ? "PORT_PROBOPEN" \
    : (status == PORT_LIKELYOPEN) ? "PORT_LIKELYOPEN" \
    : (status == PORT_OPEN) ? "PORT_OPEN" \
    : (status == PORT_PROBCLOSED) ? "PORT_PROBCLOSED" \
    : (status == PORT_LIKELYCLOSED) ? "PORT_LIKELYCLOSED" \
    : (status == PORT_PROBOPEN) ? "PORT_PROBOPEN" \
    : (status == PORT_CLOSED) ? "PORT_CLOSED" \
    : "UNDEFINED" \
    )

/// data type for representing a set of port statuses
/** the value is based on a bit mask, where the bit position is determined by the value of the port_status_t */
typedef u16 port_status_set_t;
/// port_status_set_t value when the set is empty
#define PS_EMPTY_SET (port_status_set_t)0
/// port_status_set_t value when the set consists of just the given port_status_t value
#define PS_STATUS_MASK(status) (1 << (status))
/// port_status_set_t value when the set consists of the given port_status_t value and stronger beliefs
#define PS_STATUS_MASK_WITH_STRONGER(status) ((status) == PORT_UNKNOWN ? 0xFFF \
    : PS_STATUS_MASK(status) \
        | (PORT_STRENGTH(status) < PORT_STRENGTH_LIKELY \
            ? (PS_STATUS_MASK(PORT_BASE(status)|PORT_STRENGTH_LIKELY)) \
            : 0 ) \
        | (PORT_STRENGTH(status) < PORT_STRENGTH_DEFINATE \
            ? (PS_STATUS_MASK(PORT_BASE(status)|PORT_STRENGTH_DEFINATE)) \
            : 0 ) \
    )
/// initialize a port_status_set_t variable to contatin just the given port_status_t value
#define PS_INIT_SET(set,status) (set= PS_STATUS_MASK(status))
/// initialize a port_status_set_t variable to contatin of the given port_status_t value and stronger beliefs
#define PS_INIT_SET_WITH_STRONGER(set,status) (set= PS_STATUS_MASK_WITH_STRONGER(status))
/// add the given port_status_t to a port_status_set_t stored in the given variable
#define PS_ADD_TO_SET(set,status) (set|= PS_STATUS_MASK(status))
/// add the given port_status_t and stronger beliefs to a port_status_set_t stored in the given variable
#define PS_ADD_TO_SET_WITH_STRONGER(set,status) (set|= PS_STATUS_MASK_WITH_STRONGER(status))
/// test if the given port_status_t in the given port_status_set_t
#define PS_IN_SET(set,status) (set & PS_STATUS_MASK(status))

void port_status_set_file_print(port_status_set_t set,FILE *f);

/// the representation of a Spade report internally and to the libnetspade user
typedef struct _spade_report {
    /// the detector type triggering this spade report (from spade_detection_types.h)
    int detect_type;
    /// the detector id of the spade detector that is sending this report
    char *detectorid;
    /// pointer to the packet (originally provided by the libspade user) this report is about
    spade_event *pkt;
    /// pointer to the calculated packet anomaly score(s)
    score_info *score;
    /// current port status
    port_status_t port_status;
    /// string representing the detection type employed
    const char *detect_type_str;
    /// string representing the detectors scope
    char scope_str[200];
    /// pointer to stream statistics
    spade_pkt_stats *stream_stats;
    /// the next spade report in a list of them
    struct _spade_report *next;
} spade_report;

spade_report *new_spade_report(spade_event *pkt,score_info *score, int detect_type, char *detectorid,const char *detect_type_str,char *scope_str,spade_pkt_stats *stream_stats,port_status_t port_status);
void free_spade_report(spade_report *rpt);
void free_spade_reports(spade_report *rpt);

#define spade_report_mainscore(rpt) (rpt != NULL ? score_info_mainscore(rpt->score) : NO_SCORE)
#define spade_report_relscore(rpt) (rpt != NULL ? score_info_relscore(rpt->score) : NO_SCORE)
#define spade_report_rawscore(rpt) (rpt != NULL ? score_info_rawscore(rpt->score) : NO_SCORE)
#define spade_report_raw_is_corrscore(rpt) (score_info_raw_is_corrscore(rpt->score))
#define spade_report_main_pref(rpt) (score_info_main_pref(rpt->score))

/*@}*/

#endif // SPADE_REPORT_H
