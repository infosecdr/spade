/*
To: snort-devel@lists.sourceforge.net
From: James Hoagland <hoagland@SiliconDefense.com>
Cc: hoagland@SiliconDefense.com
Subject: [Snort-devel] New internal facility: packet cloning
Date: Sun, 29 Sep 2002 20:31:08 -0700

Greetings all,

I have written some new Snort internal functionality that should help current and future Snort detectors (e.g., preprocessors) do better detection and/or more complete and standard reporting.  That functionality is creating a copy of a Packet.

Some background first, as I understand it (correct me if I am mistaken).  A Packet is the Snort data structure that contains the parsed fields of a packet that libpcap presents to Snort.  It is Snort's standard representation of a packet and so is used throughout the program.  It is given to preprocessors and Snort's signature based detector as one in a stream of packets.  When these detectors wish to report on a packet, they typically pass the Packet to the alert/log facilities (e.g., alert file or database) that the user has configured.  However, sometimes detectors use different output means than the standard ones that the user configured.  For example, spp_portscan and spp_portscan2 and their packet logs.  (There could be others.)

I cannot say for sure why these two do not use the standard output mechanism.  But one barrier is the combination of the fact that the output mechanisms can only output a Packet structure and the fact that the Packet that is given to the detectors does not persist beyond that call into that detector.  Specifically, there is only one Packet that Snort has in memory at a time.  Regardless of the reason, the effect is that the user does not have the control they might like over the place where packets are stored.  For example, they cannot have portscan packets (as reported by spp_portscan) be logged to the database.  So this suggests that in order to give this flexibility to the user, the simplest thing is to provide the detector with a means of holding onto a Packet beyond its invocation.  However, this functionality does not exist in Snort and, given the complexity, it can be daunting for the detector writer to do write it themselves.

The class of detectors that this will help is those that do not want to immediately report on a packet.  Often this will be because they want to wait for future information contained on the packet stream. For example, they want to eliminate a potential false positive.  And we know that false positives can be a barrier to effective use of Snort (and other IDSs).  So, providing the copying functionality, while not getting rid of false positives and promoting more standard packet reporting, can be enabling towards these goals.


Okay, enough for the motivational speech. :)  Its working code that gets things done in open source.  So, it is attached.  At least it is working in my tests; I need others to test it our as well since, e.g., I do not have access to FDDI network packet to try it on.  And I am not an expert on the Packet data structure.  But I know much more about it now, given frequent consultation with decode.[ch].

This is what is attached:

1) packets.c: the code that implements ClonePacket() and FreePacket().

2) packet.h:  I'll let you guess what role this serves. :)

3) snort+pclone.patch:  A patch against snort 1.9.0beta6 that puts packets.[ch] into the Snort source.  In addition, the patch includes a hack of a preprocessor, spp_pcopytest, that uses the cloning code. It makes clones of 100 packets on the packet stream at a time before pushing them to the standard output facilities.  For reference, the original packets are spit out as they are received.  The original should match the clone (as they do in all my tests).  Run it as "src/snort -c etc/pcopytest.conf".

Implementation notes.  There were other ways that this can be approached.  My goal was for it to be efficient and with only localized changes (e.g., no changes to Packet).  There are some other notes in the source.

Snort notes.  There might be a couple small snags when using cloned packets.  One that I noticed is an (now) incorrect assumption that there will only be one call to PrintNetData between each packet acquisition.  (The workaround it to manually flush its cache.)  If some output mechanism makes a hardcoded reference to "the" Packet, that will be broken.  And if anything else makes the assumption that PrintNetData did, that would be broken.


My main motivation for doing this is that the next generation version of Spade will need this functionality to reduce false positives and to accurately detect new scan types.  I could have this functionality internal to Spade, but I'd rather it be a general Snort internal facility that can be used anywhere in Snort.  If someone can implement this better, go for it.  But the functionality of a Packet persisting across calls to a preprocessor is something that I'll be needing in the not-too-distant future.

If anyone has any questions/concerns/comments/fixes, let me know.

Sorry for the length of this message.

Kind regards,

  Jim

P.s. I do not think that Packet cloning is covered by any US federal or state stature, so at least we are safe that way. :)
*/

#include <pcap.h>
#include <stdlib.h>
#include <string.h>
#include "decode.h"
#include "snort.h"
#include "packets.h"

typedef struct _PacketClone
{
    Packet p; /* our packet; the address of this must be the same as
                 the address of the structure */
    struct pcap_pkthdr pkth; /* the pcap packet header to be included
                                in the above packet */
    u_int8_t *pkt; /* storage space for the packet data */
    int pkt_alloc_size; /* how much space is allocated there */
    struct _PacketClone *next;
} PacketClone;

PacketClone *free_packets; /* freelist of normal sized PacketClones */
PacketClone *free_oz_packets; /* freelist of oversized PacketClones */

#define ADJUST_PKT_INDEX_FIELD(to_p,from_p,field) \
    if ((from_p)->field) \
        (to_p)->field= (void *)((to_p)->pkt + \
           ((unsigned long)(from_p)->field - (unsigned long)(from_p)->pkt));
    
#define ADJUST_OPTIONS_DATA_FIELD(to_p,from_p,field,index) \
    if ((from_p)->field[index].data) \
        (to_p)->field[index].data= ((to_p)->pkt + \
            ((unsigned long)(from_p)->field[index].data - \
             (unsigned long)(from_p)->pkt));


/* the normal (minimum) size packet length to allocate; based on pcap snap length */
#define NORMAL_ALLOC_PACKETLEN (pv.pkt_snaplen ? pv.pkt_snaplen : SNAPLEN)
/* sometimes we'll need more that the snap length (e.g., with stream4_reassemble 
   packets), so here's how we calculate how big; oversized allocations get up to
   63 bytes extra added on at end to make their reuse more likely. */
#define PACKET_ALLOC_SIZE(min) \
    (min < NORMAL_ALLOC_PACKETLEN \
    ? NORMAL_ALLOC_PACKETLEN \
    : (((min+63) >> 6) << 6))

/*
 * Function: ClonePacket(Packet *p)
 *
 * Purpose: Make a copy of a decoded packet struct (Packet) so that the
 *          contents of a Packet can survive beyond a call to pcap for a
 *          new packet
 *
 * Arguments: p   => pointer to the decoded packet struct to clone
 *
 * Returns: a pointer to the copied Packet
 *
 * Notes: this function and FreePacket participate in a recycling program
 *        for Packets to minimize malloc calls.  ssnptr and state fields not
 *        copied but set to NULL instead.
 */
Packet *ClonePacket(Packet *p)
{
    PacketClone *clone,*prev,*here;
    Packet *cp;
    int i;
    int packet_alloc_size= PACKET_ALLOC_SIZE(p->pkth->len);
    int oversized= packet_alloc_size > NORMAL_ALLOC_PACKETLEN;
    
    /* get storage for the Packet */
    if (free_packets != NULL || free_oz_packets != NULL)
    {
        if (oversized) {
            /* draw from oversize list else the regular list */
            if (free_oz_packets != NULL) {
                prev= NULL;
                here= free_oz_packets;
                while (here->next != NULL) {
                    if (here->pkt_alloc_size >= packet_alloc_size) break;
                    prev= here;
                    here= here->next;
                }
                clone= here;
                if (prev != NULL)
                    prev->next= here->next;
                else
                    free_oz_packets= here->next;
            } else {
                clone= free_packets;
                free_packets= free_packets->next;
            }
            /* get bigger memory chunk if needed */
            if (clone->pkt_alloc_size < packet_alloc_size) {
                free(clone->pkt);
                clone->pkt= (u_int8_t *)calloc(packet_alloc_size,sizeof(u_int8_t));
                if (clone->pkt == NULL) /* must be out of memory */
                {
                    free(clone);
                    return NULL;
                }
                clone->pkt_alloc_size= packet_alloc_size;
            }
        } else {
            /* draw from regular list else the oversize list */
            if (free_packets != NULL) {
                clone= free_packets;
                free_packets= free_packets->next;
            } else {
                clone= free_oz_packets;
                free_oz_packets= free_oz_packets->next;
            }
        }
    } else {
        clone= (PacketClone *)calloc(1,sizeof(PacketClone));
        if (clone == NULL) return NULL; /* must be out of memory */
        
        clone->pkt= (u_int8_t *)calloc(packet_alloc_size,sizeof(u_int8_t));
        if (clone->pkt == NULL) /* must be out of memory */
        {
            free(clone);
            return NULL;
        }
        clone->pkt_alloc_size= packet_alloc_size;
    }
    
    /* make a copy of the Packet p into cp */
    cp= &clone->p;
    *cp= *p; /* this will get everything except the pointers */
    
    /* copy the pcap header */
    cp->pkth= &clone->pkth; /* we use the PacketClone storage space rather
                               than malloc */
    *cp->pkth= *(p->pkth);
    
    /* copy the packet data */
    cp->pkt= clone->pkt;
    memcpy(cp->pkt,p->pkt,p->pkth->len);
    
    /* set the Packet fields which are just pointers into the packet data
       (i.e., just about all of them) */
    /* many of these fields are NULL, so let's use some knowledge about 
       the relationship between fields to avoid trying to adjust; of course
       this means that this must be maintained */
    if (p->fddihdr) {
        ADJUST_PKT_INDEX_FIELD(cp,p,fddihdr);
        ADJUST_PKT_INDEX_FIELD(cp,p,fddisaps);
        ADJUST_PKT_INDEX_FIELD(cp,p,fddisna);
        ADJUST_PKT_INDEX_FIELD(cp,p,fddiiparp);
        ADJUST_PKT_INDEX_FIELD(cp,p,fddiother);
    }
    if (p->trh) {
        ADJUST_PKT_INDEX_FIELD(cp,p,trh);
        ADJUST_PKT_INDEX_FIELD(cp,p,trhllc);
        ADJUST_PKT_INDEX_FIELD(cp,p,trhmr);
    }
    ADJUST_PKT_INDEX_FIELD(cp,p,sllh);
    ADJUST_PKT_INDEX_FIELD(cp,p,pfh);
    ADJUST_PKT_INDEX_FIELD(cp,p,eh);
    ADJUST_PKT_INDEX_FIELD(cp,p,vh);
    ADJUST_PKT_INDEX_FIELD(cp,p,ehllc);
    ADJUST_PKT_INDEX_FIELD(cp,p,ehllcother);
    ADJUST_PKT_INDEX_FIELD(cp,p,wifih);
    ADJUST_PKT_INDEX_FIELD(cp,p,ah);
    if (p->eplh) {
        ADJUST_PKT_INDEX_FIELD(cp,p,eplh);
        ADJUST_PKT_INDEX_FIELD(cp,p,eaph);
        ADJUST_PKT_INDEX_FIELD(cp,p,eaptype);
        ADJUST_PKT_INDEX_FIELD(cp,p,eapolk);
    }
    if (p->iph) {
        ADJUST_PKT_INDEX_FIELD(cp,p,iph);
        ADJUST_PKT_INDEX_FIELD(cp,p,ip_options_data);
        /* get the ones inside decoded options too */
        for (i= 0; i < p->ip_option_count; i++)
            ADJUST_OPTIONS_DATA_FIELD(cp,p,ip_options,i);
        if (p->tcph) {
            ADJUST_PKT_INDEX_FIELD(cp,p,tcph);
            ADJUST_PKT_INDEX_FIELD(cp,p,tcp_options_data);
            for (i= 0; i < p->tcp_option_count; i++)
                ADJUST_OPTIONS_DATA_FIELD(cp,p,tcp_options,i);
        } else if (p->icmph) {
            ADJUST_PKT_INDEX_FIELD(cp,p,icmph);
            ADJUST_PKT_INDEX_FIELD(cp,p,orig_iph);
            ADJUST_PKT_INDEX_FIELD(cp,p,orig_udph);
            ADJUST_PKT_INDEX_FIELD(cp,p,orig_tcph);
            ADJUST_PKT_INDEX_FIELD(cp,p,orig_icmph);
        } else
            ADJUST_PKT_INDEX_FIELD(cp,p,udph);
    }
    ADJUST_PKT_INDEX_FIELD(cp,p,ext); /* is this used anywhere? */
    ADJUST_PKT_INDEX_FIELD(cp,p,data);

    /* we don't copy these over */
    cp->ssnptr= NULL;
    cp->state= NULL;

    return cp;
}

/*
 * Function: FreePacket(Packet *p)
 *
 * Purpose: Free a Packet created by ClonePacket
 *
 * Arguments: p   => pointer to the decoded packet struct to free
 *
 * Returns: nada
 *
 * Notes: this function and FreePacket participate in a recycling program
 *        for Packets to minimize malloc calls.
 */
void FreePacket(Packet *p)
{
    PacketClone *pc= (PacketClone *)p; /* assumes pc has same addr as p */
    if (pc->pkt_alloc_size > NORMAL_ALLOC_PACKETLEN) {
        pc->next= free_oz_packets;
        free_oz_packets= pc;
    } else {
        pc->next= free_packets;
        free_packets= pc;
    }
    /* note: pc->pkt remains allocated. */
}
