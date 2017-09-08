/* part of the packet cloning patch by Jim Hoagland, Silicon Defense
 (hoagland@silicondefense.com).  Hopefully this or equivalent functionality
 will become a standard part of the Snort source. */

#ifndef __PACKETS_H__
#define __PACKETS_H__

Packet *ClonePacket(Packet *p);
void FreePacket(Packet *p);

#endif // __PACKETS_H__
