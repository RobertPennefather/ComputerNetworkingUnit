/*
    From comp.lang.c Wed Nov  7 16:07:00 1990
    From: ron@scocan.sco.COM (Ron Irvine)
    Subject: CRC-16 in C
    Date: 5 Nov 90 22:31:57 GMT
    Originator: ron@capri
 */


/* crc16 - DDCMP and Bisync (16 bit)
 *	x^16 + x^15 + x^2 + 1
 */

#define	POLY_CRC16	0xa001
#define	INIT_CRC16	0

/* a bit at a time */

unsigned short checksum_crc16(unsigned char *in, int length)
{
	register unsigned short crc, bit;
	register int i;

	crc = INIT_CRC16;
	while(length-- > 0) {
		for (i=1; i <= 0x80; i<<=1) {
			bit = (((*in)&i)?0x8000:0);
			if (crc & 1) bit ^= 0x8000;
			crc >>= 1;
			if (bit) crc ^= (int)(POLY_CRC16);
  		}
		++in;
	}
	return crc;
}
