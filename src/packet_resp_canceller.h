/*********************************************************************
packet_resp_canceller.h, distributed as part of Spade v030125.1
Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
copyright (c) 2002 by Silicon Defense (http://www.silicondefense.com/)
Released under GNU General Public License, see the COPYING file included
with the distribution or http://www.silicondefense.com/spice/ for details.

Please send complaints, kudos, and especially improvements and bugfixes to
hoagland@SiliconDefense.com.  As described in GNU General Public License, no
warranty is expressed for this program.
*********************************************************************/

#ifndef PACKET_RESP_CANCELLER_H
#define PACKET_RESP_CANCELLER_H

/*! \file packet_resp_canceller.h
 * \ingroup netspade_layer
 * \brief 
 *  packet_resp_canceller.h is the header file for packet_resp_canceller.c.
 */

/*! \addtogroup netspade_layer
    @{
*/

#include "spade_report.h"
#include <time.h>

/// function type for a callback for a packet response canceller to report the status of a report
typedef void (*prc_report_status_fn)(void *context,spade_report *rpt,port_status_t status);

/// a two-way link used to store reports in the packet response canceller
typedef struct _prc_link {
    spade_report *rpt; /*!< the report being stored */
    struct _prc_link *ltl_next; /*!< next link in a lookup table list */
    struct _prc_link *ttl_next; /*!< next link in a time table list */
} prc_link;

/// a list of prc_link's
typedef struct {
    prc_link *head;  ///< the head
    prc_link *tail;  ///< the tail
} prc_list;

/// the packet response canceller time-based table
typedef struct {
    prc_list *arr; ///< an array of buckets, each holding the reports for a given second
    int num_buckets; ///< how many buckets are there
    time_t last_timeout; ///< when was the last time a timeout was checked for
} prc_time_table;

#define LOOKUP_TABLE1_BITS 12 ///< how many bits are in the key to the first level lookup table
#define LOOKUP_TABLE2_BITS 8 ///< how many bits are in the key to the second level lookup tables
#define LOOKUP_TABLE1_SIZE (1 << LOOKUP_TABLE1_BITS) ///< the number of elements in the first level lookup hash table
#define LOOKUP_TABLE2_SIZE (1 << LOOKUP_TABLE2_BITS) ///< the number of elements in the second level lookup hash tables
#define LOOKUP_TABLE1_MASK (LOOKUP_TABLE1_SIZE -1) ///< mask used in the hash function for the first level lookup table
#define LOOKUP_TABLE2_MASK (LOOKUP_TABLE2_SIZE -1) ///< mask used in the hash function for the second level lookup tables

/// a second level lookup table
/** this table maps a report to a unsorted linked list of stored reports */
typedef struct {
    prc_link *arr[LOOKUP_TABLE2_SIZE]; ///< a second level hash table, each bucket hold a set reports
    int num_used; ///< the number of slots in the hash table that are presently used
} prc_lookup_table2;

/// the first level lookup table
/** this table maps a report to a second level hash table */
typedef struct {
    prc_lookup_table2 *arr[LOOKUP_TABLE1_SIZE]; ///< a second level hash table, each bucket holds a second level lookup table
} prc_lookup_table;

/// an instance of a packet response canceller, which implements a packet response buffer
typedef struct {
    prc_lookup_table lt; ///< the lookup table, used for quick access to a given report
    prc_time_table tt;  ///< the time-based table, used for quick access to the reports from a given second
    port_status_t timeout_implication;  ///< the implication for when a report times out
    prc_report_status_fn status_callback;  ///< the function to call with report status
    void *callback_context; ///< context to provide with the callback on report status
} packet_resp_canceller;


void init_packet_resp_canceller(packet_resp_canceller *self,int wait_secs,prc_report_status_fn status_callback,void *callback_context,port_status_t timeout_implication);
packet_resp_canceller *new_packet_resp_canceller(int wait_secs,prc_report_status_fn status_callback,void *callback_context,port_status_t timeout_implication);
void free_packet_resp_canceller(packet_resp_canceller *self);

void packet_resp_canceller_new_time(packet_resp_canceller *self,time_t time);

void packet_resp_canceller_add_report(packet_resp_canceller *self,spade_report *rpt);
void packet_resp_canceller_note_response(packet_resp_canceller *self,port_status_t implied_status,u32 sip,u16 sport,u32 dip,u16 dport,int portless);

void packet_resp_canceller_print_config_details(packet_resp_canceller *self,FILE *f,char *indent);

/*@}*/

#endif  /* ! PACKET_RESP_CANCELLER_H */


/* $Id: packet_resp_canceller.h,v 1.7 2002/12/21 01:25:39 jim Exp $ */
