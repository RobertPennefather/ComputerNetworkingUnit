//  Compile me with:
//      cc -std=c99 -Wall -Werror -pedantic -o lab1q1-a lab1q1-a.c

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>

#include <time.h>
#include <sys/time.h>
#include <sys/param.h>


/*  We use textual inclusion here to obtain the checksum files - saves
 typing, and the need for more complicated compilation and linking.
 
 DON'T DO THIS IN MORE SIGNIFICANT PROGRAMS.
 */

#include "./checksum_ccitt.c"
#include "./checksum_crc16.c"
#include "./checksum_internet.c"


//  VALUES DEFINING THE 'SIZE' OF OUR EXPERIMENTS
#define FRAMESIZE       100
#define NFRAMES         1000000


//  CORRUPT A FRAME WITH A BURST ERROR
void corrupt_frame(unsigned char frame[], int length)
{
#define MIN_BURSTLENGTH         10
#define MAX_BURSTLENGTH         100
    int nbits           = (length * NBBY);
    while(true) {
        int     b0      = rand() % nbits;
        int     b1      = rand() % nbits;
        int	burst	= b1 - b0;
        
        if(burst >= MIN_BURSTLENGTH && burst <= MAX_BURSTLENGTH) {
            for(int b=b0 ; b<b1 ; ++b) {
                int     byte    = b / NBBY;
                int     bit     = b % NBBY;
                
                frame[byte]     = (frame[byte] | (1UL << bit));
            }
            break;
        }
    }
}

//  TIMES THE EXECUTION OF SECTIONS OF CODE IN MICROSECONDS
int64_t timing(bool start)
{
    static      struct timeval startw, endw;
    int64_t     usecs   = 0;
    
    if(start) {
        gettimeofday(&startw, NULL);
    }
    else {
        gettimeofday(&endw, NULL);
        usecs   =
        (endw.tv_sec  - startw.tv_sec)*1000000 +
        (endw.tv_usec - startw.tv_usec);
    }
    return usecs;
}


// PERFORM 'NFRAMES' TESTS OF THE PROVIDED CHECKSUM FUNCTION, REPORT RESULTS
void evaluate(unsigned short (*fn)(), char *name)
{
    unsigned char       frame[FRAMESIZE];
    int                 nfailures = 0, checksum;
    
    //  START TIMING
    timing(true);
    
    //  PERFORM TESTS FOR A LARGE NUMBER OF FRAMES
    for(int n=0 ; n<NFRAMES ; ++n) {
        
        //  POPULATE THE FRAMRE WITH RANDOM BYTES
        for(int i=0 ; i<FRAMESIZE ; ++i)
            frame[i] = rand() % 256;
        
        //  CALCULATE THE CHECKSUM BEFORE "TRANSMISSION"
        checksum        = (*fn)(frame, FRAMESIZE);
        
        //  CORRUPT THE FRAME (FAKE TRANSMISSION)
        corrupt_frame(frame, FRAMESIZE);
        
        //  IF THE BEFORE AND AFTER CHECKSUMS MATCH, WE HAVE A FAILURE.
        if(checksum == (*fn)(frame, FRAMESIZE))
            ++nfailures;
    }
    
    //  REPORT RESULTS AND THE TIME TAKEN
    printf("%18s: %5d failures (%6.4f%%), %6lld msecs\n",
           name, nfailures, nfailures*100.0 / NFRAMES, timing(false)/1000);
}


int main(void)
{
    extern void         srand(unsigned int seed);
    
    /*  We must ensure that our tests for each checksum algorithm are performed
     with the same data - otherwise the comparison will be unfair.
     We do this be re-initializing the random number generator each time */
    
    printf("Generating random data, framesize=%d, #frames=%d\n",
           FRAMESIZE, NFRAMES);
    
    /*  The following 3 calls to evaluate() pass the address of a checksum function
     as their first parameter.  This "trick" is a bit advanced, so for a bit
     more typing, we could make a call to each checksum function for each frame.
     */
    srand(getpid());
    evaluate(checksum_ccitt,    "checksum_ccitt");
    
    srand(getpid());
    evaluate(checksum_crc16,    "checksum_crc16");
    
    srand(getpid());
    evaluate((unsigned short (*)())checksum_internet,   "checksum_internet");
    
    exit(EXIT_SUCCESS);
}
