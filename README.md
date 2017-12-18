This is the Staticstical Packet Anomaly Detection Engine (SPADE), the formerly popular (circa 2001-2003) plug-in for snort (mostly) to help find packets that might be part of a (possibly stealthy) portscan.

Other than this README.md, the contents of this repo are the original Spade code for the version released 2003-01-25.  For the (quite thorough) original README, see README.Spade.

This paper describes in detail the sophisticated approach being used: 

*  Practical Automated Detection of Stealthy Portscans
*  Journal of Computer Security, Volume 10:1-2. 2002
*  http://hoagland.org/papers/Practical%20automated%20detection%20of%20stealthy%20portscans.pdf

This code is around 9-10k lines and manages its own memory.  As a Snort plug-in, this needs to be very efficient since it is called on all network packets.

Not sure if this is the last version produced by Silicon Defense or not; it was from a few months before the company went under.  I was the creator and maintainer of the project.

