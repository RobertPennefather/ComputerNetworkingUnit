
/* Calculate the Internet Protocol family checksum algorithm.
   This code is taken from Steven's "Unix Network Programming" pp454-455.

   The algorithm is simple, using a 32-bit accumulator (sum),
   we add sequential 16-bit words to it, and at the end, fold back
   all the carry bits from the top 16 bits into the lower 16 bits.
 */

int checksum_internet(unsigned short *ptr, int nbytes)
{
    long                sum;
    unsigned short      oddbyte, answer;

    sum = 0L;
    while(nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }

    if(nbytes == 1) {   /* mop up an odd byte if necessary */
        oddbyte = 0;    /* make sure that the top byte is zero */
        *((unsigned char *)&oddbyte) = *(unsigned char *)ptr; /* 1 byte only */
        sum += oddbyte;
    }

    /* Now add back carry outs from top 16 bits to lower 16 bits */
    sum = (sum >> 16) + (sum & 0xffff); /* add hi-16 to lo-16 */
    sum += (sum >> 16);                 /* add carry bits */
    answer  = ~sum;     /* one's complement, then truncate to 16 bits */

    return(answer);
}

