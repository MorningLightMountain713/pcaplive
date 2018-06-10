#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include <errno.h>

#define BUFFERLEN 65536
#define DEBUG 0
#ifdef DEBUG
  #define DEBUG_PRINT(fmt, ...) \
          do { if (DEBUG) fprintf(stderr, "%s:%d:%s(): " fmt, __FILE__, \
                                  __LINE__, __func__, __VA_ARGS__); } while (0)
#else
  #define DEBUG_PRINT(fmt, ...)
#endif

typedef int bpf_int32;
typedef int bpf_u_int32;

struct pcap_timeval {
    bpf_int32 tv_sec;           /* seconds */
    bpf_int32 tv_usec;          /* microseconds */
};


struct pcap_sf_pkthdr {
    struct pcap_timeval ts;     /* time stamp */
    bpf_u_int32 caplen;         /* length of portion present */
    bpf_u_int32 len;            /* length this packet (off wire) */
};

struct pcap_file_header {
  bpf_u_int32 magic;
  u_short version_major;
  u_short version_minor;
  bpf_int32 thiszone; /* gmt to local correction */
  bpf_u_int32 sigfigs;  /* accuracy of timestamps */
  bpf_u_int32 snaplen;  /* max length saved portion of each pkt */
  bpf_u_int32 linktype; /* data link type (LINKTYPE_*) */
};

struct  ether_header {
  u_char  ether_dhost[6];
  u_char  ether_shost[6];
  u_short ether_type;
};


void hexDump (char *desc, void *addr, FILE *dest, int len) {
    int i;
    unsigned char buff[17];
    unsigned char *pc = (unsigned char*)addr;

    // Output description if given.
    if (desc != NULL)
        fprintf (dest, "%s:\n", desc);

    if (len == 0) {
        fprintf(dest, "  ZERO LENGTH\n");
        return;
    }
    if (len < 0) {
        fprintf(dest, "  NEGATIVE LENGTH: %i\n",len);
        return;
    }

    // Process every byte in the data.
    for (i = 0; i < len; i++) {
        // Multiple of 16 means new line (with line offset).

        if ((i % 16) == 0) {
            // Just don't print ASCII for the zeroth line.
            if (i != 0)
                fprintf (dest, "  %s\n", buff);

            // Output the offset.
            fprintf (dest, "  %04x ", i);
        }

        // Now the hex code for the specific character.
        fprintf (dest, " %02x", pc[i]);

        // And store a printable ASCII character for later.
        if ((pc[i] < 0x20) || (pc[i] > 0x7e))
            buff[i % 16] = '.';
        else
            buff[i % 16] = pc[i];
        buff[(i % 16) + 1] = '\0';
    }

    // Pad out last line if not exactly 16 characters.
    while ((i % 16) != 0) {
        fprintf (dest, "   ");
        i++;
    }

    // And print the final ASCII bit.
    fprintf (dest, "  %s\n", buff);
    fflush(dest);
}

int
check_for_header(unsigned char *buf, struct pcap_file_header *fhdr){

  memcpy(fhdr, buf, sizeof *fhdr);
  // printf("%x\n%d\n%d\n%d\n%d\n%d\n%d\n", fhdr->magic, fhdr->version_major, fhdr->version_minor, fhdr->thiszone, fhdr->sigfigs, fhdr->snaplen, fhdr->linktype);
  if (fhdr->magic != 0xa1b2c3d4) {
    fwrite(fhdr, 1, 24, stdout);
    return 0;
  }
  //printf("%d", sizeof *fhdr);
  //fwrite("\n", 1, 1, stdout);
  //fwrite(fhdr, 1, 24, stdout);
  //fwrite("\n", 1, 1, stdout);
  return 1;
}


int read_file(int *fd){
  //int fd = open("/tmp/capper", O_RDONLY);
  unsigned char *buf;

  int flags = fcntl(*fd, F_GETFL, 0);
  fcntl(*fd, F_SETFL, flags | O_NONBLOCK);

  buf = malloc(BUFFERLEN);
  // fread(buf, BUFFERLEN, 1, fdopen(fd, "r"));
  printf("bytes read: %d\nbuffer length: %d\n", (int) read(*fd, buf, BUFFERLEN), BUFFERLEN);
  free(buf);
  return 0;
}

int synthesis_pcap_header(){
  struct pcap_file_header fhdr;
  fhdr.magic = 0xa1b2c3d4;
  fhdr.version_major = 2;
  fhdr.version_minor = 4;
  fhdr.thiszone = 0;
  fhdr.sigfigs = 0;
  fhdr.snaplen = 262144;
  fhdr.linktype = 1;
  fwrite(&fhdr, 1, sizeof fhdr, stdout);
  fflush(stdout);
  return 1;
}


int has_pcap_header(int *fd, struct pcap_file_header *fhdr){
  if (read(*fd, fhdr, sizeof *fhdr) != sizeof *fhdr){
    return -1;
  }
  if (fhdr->magic != 0xa1b2c3d4) {
    // unsigned char const *p = fhdr;
    // for(i=0;i < sizeof *fhdr;i++){
    //   printf("%02x\n", p[i]);
    // }
    return 0;
  }
  // printf("%x\n%u\n%u\n%u\n%u\n%u\n%u\naddress: %u\n", fhdr->magic, fhdr->version_major, fhdr->version_minor, fhdr->thiszone, fhdr->sigfigs, fhdr->snaplen, fhdr->linktype, fhdr);
  return 1;
}

int snapto_packet(int *fd,
                  int *counter,
                  unsigned char *pkt_buf,
                  int *buf_len)
{
  struct pcap_sf_pkthdr pkthdr;
  unsigned long time_now;
  struct ether_header ethhdr;
  int bytes_read = 0;
  int caplen;


  pkthdr.ts.tv_sec = 0;
  pkthdr.ts.tv_usec = 0;
  time_now = (unsigned long)time(NULL);
  // printf("sizeof hdr: %u\n", sizeof *pkthdr);

  // means we didn't find a decent packet of the first iteration, so we advance out pointer by 1 byte and try again. smh.


    //hexDump ("packet header", buf, sizeof *pkthdr -1);

    memcpy(&pkthdr, pkt_buf, sizeof(pkthdr));
    //pkthdr = (struct pcap_sf_pkthdr *) pkt_buf;

    //hexDump ("packet header pkthdr", pkthdr, sizeof *pkthdr);


    //fread(pkthdr + (sizeof *pkthdr -1), 1, 1, fp);
    //++buf;
    //hexDump ("packet header pkthdr", pkthdr, sizeof *pkthdr);



  //fwrite(&pkthdr, 1, sizeof pkthdr, stdout);
  // printf("time now: %u\n", time_now);
  // printf("one week ago: %u\n", time_now - 604800);
  // printf("one week ahead: %u\n", time_now + 604800);
  // printf("seconds: %d\n", pkthdr->ts.tv_sec);
  // printf("micros: %d\n", pkthdr->ts.tv_usec);
  // printf("caplen: %d\n", pkthdr->caplen);
  // printf("len: %d\n", pkthdr->len);

  if ((pkthdr.ts.tv_sec < (time_now - 604800) || pkthdr.ts.tv_sec > (time_now + 604800)) || (pkthdr.ts.tv_usec > 1000000 || pkthdr.ts.tv_usec < 0)) {
    // means our packet is shit

    // do this so we can load the rest of the file header into the packet header struct
    // if(*counter < (sizeof *fhdr - sizeof *pkthdr)){
    // ++*counter;
    // ++pkt_buf;
    // //sleep(1);
    // //hexDump ("pkt_buf", pkt_buf, sizeof *pkthdr);
    // snapto_packet(fp, counter, pkthdr, fhdr, pkt_buf, buf_len);
    // return 0;
    //return 0;
    //memcpy(tmp_buf +  sizeof *pkthdr -1, pkt_buf , 1);
    //hexDump ("pkt_buf", pkt_buf, sizeof *pkthdr);
    //sleep(1);
    //}
    if(*buf_len <= sizeof(pkthdr)){
      // if the buffer is = to packet header read buffer to 64 bytes
    read(*fd, pkt_buf + sizeof pkthdr, (64 - *buf_len));
    *buf_len = 64;
    }
    //printf("bufferlen:%d\n", *buf_len);
    //hexDump("new_pkt_buf", pkt_buf, 64);

    DEBUG_PRINT("%s\n", "Advancing one byte...");
    memmove(pkt_buf, pkt_buf + 1, 63);
    //++pkt_buf;
    --*buf_len;
    //pkthdr = (struct pcap_sf_pkthdr *) tmp_buf;

    snapto_packet(fd, counter, pkt_buf, buf_len);
    return 0;
  }
  else {
        // this packet is lit. Just need to have a peak and see if we have ethertype.

    //printf("found a decent timestamp\n");

      //fwrite(pkthdr, 1, sizeof *pkthdr, stdout);
      // need to do this otherwise it starts modifying the pointed to value which I thought was weird.
      caplen = pkthdr.caplen;
      //buf = malloc(pkthdr->caplen);

      //printf("ethernet header: %d\n", sizeof ethhdr);
      memcpy(&ethhdr, pkt_buf + sizeof(pkthdr), 14);
      //ethhdr = (struct ether_header *) pkt_buf;
      //ethhdr + sizeof *pkthdr;
      //hexDump("ethernet_hdr", &ethhdr, sizeof ethhdr);
      // check for ethertype to see if its a real packet or garbage.
      // this needs to have more than 0x8100 in real life but for testing is ok
      if(ntohs(ethhdr.ether_type) != 0x8100){
        // we need to do stuff here instead of just recursing again, otherwise we end up here in infinite loop and segfault. The below is just copied from above, should really fix this.
        if(*buf_len <= sizeof(pkthdr)){
          // if the buffer gets to 16, read another 48
        read(*fd, pkt_buf + sizeof(pkthdr), (64 - *buf_len));
        *buf_len = 64;
        }
        //printf("bufferlen:%d\n", *buf_len);
        //hexDump("new_pkt_buf", pkt_buf, 64);
        memmove(pkt_buf, pkt_buf + 1, 63);
        //++pkt_buf;
        --*buf_len;
        snapto_packet(fd, counter, pkt_buf, buf_len);
        return 0;
      }
      // this means we hvae a legit packet. Need to look at more ethertypes above.


      //printf("before while loop. Bytes read: %d caplen: %d len: %d buf_len: %d\n", bytes_read, pkthdr->caplen, pkthdr->len, *buf_len);
      //printf("pkthdr size: %d\n", sizeof *pkthdr);
      //printf("buflen: %d\n", *buf_len);
      //fwrite(pkthdr, 1, sizeof *pkthdr, stdout);
            DEBUG_PRINT("Snaptopacket Timestamp: %d Micros: %d Caplen: %d\n", pkthdr.ts.tv_sec, pkthdr.ts.tv_usec, pkthdr.caplen);
      while(bytes_read < (sizeof(pkthdr) + caplen)){
        DEBUG_PRINT("bytes read start loop: %d, buf len: %d\n", bytes_read, *buf_len);
        if((sizeof(pkthdr) + caplen) < *buf_len){
          fwrite(pkt_buf, 1, (sizeof(pkthdr) + caplen), stdout);
          break;
        }


        //printf("bytes read: %d\n", bytes_read);
        //printf("unread bytes: %d\n", (sizeof *pkthdr + caplen) - bytes_read);
        fwrite(pkt_buf, 1, *buf_len, stdout);
        bytes_read += *buf_len;
        *buf_len =0;

        if((sizeof(pkthdr) + caplen) - bytes_read < 64){


          // should only ever get here once
          //printf("Reading %d bytes\n", (sizeof *pkthdr + caplen) - bytes_read);
          read(*fd, pkt_buf, (sizeof(pkthdr) + caplen) - bytes_read);
          fwrite(pkt_buf, 1, (sizeof(pkthdr) + caplen) - bytes_read, stdout);
          //printf("caplen: %d\n", caplen);

          bytes_read += ((sizeof(pkthdr) + caplen) - bytes_read);
          DEBUG_PRINT("final bytes read: %d\n", bytes_read);
          //printf("bytes_read new value: %d\n", bytes_read);
          *buf_len = 0;
          break;
        }

        //printf("bytes read: %d\n", bytes_read);
        read(*fd, pkt_buf, 64);
        fwrite(pkt_buf, 1, 64, stdout);
        bytes_read += 64;
        *buf_len = 0;
      }
      ++*counter;
      DEBUG_PRINT("%s\n", "End of snapto");
      //printf("We have done good packet things, returning\n");
      return 0;





    // printf("caplen: %u\n", pkthdr.caplen);
    // printf("len: %u\n", pkthdr.len);
    // printf("seconds: %u\n", pkthdr.ts.tv_sec);
    // printf("micros: %u\n", pkthdr.ts.tv_usec);
    //we have just found first packet.
  }

}

int read_one_packet(int *fd, int *counter, int *read_buf, unsigned char *buf){
  // int flags = fcntl(*fd, F_GETFL, 0);
  // fcntl(*fd, F_SETFL, flags | O_NONBLOCK);

  struct pcap_sf_pkthdr pkthdr = {.caplen = 0,
                                  .ts.tv_sec = 0,
                                  .ts.tv_usec = 0};

  DEBUG_PRINT("%s\n", "Start of read one packet");
  int bytes_read;
  unsigned long time_now = (unsigned long)time(NULL);
  // we are fighting for read / write time with tcpdump. Can't just read in the header as the write process is always blocking. We need to gobble up what we can when we can. Maybe?
  //read her up to 4096 if she empty
  DEBUG_PRINT("Buffer size: %d\n", *read_buf);
  if(*read_buf < sizeof(pkthdr)){
    bytes_read = read(*fd, (buf + *read_buf), (BUFFERLEN - *read_buf));
    DEBUG_PRINT("*read_buf < sizeof pkthdr, Bytes read: %d\n", bytes_read);
    if(bytes_read == -1){
      DEBUG_PRINT("Oh dear, something went wrong with read()! %s\n",   strerror(errno));
      usleep(1000000);
      return -1;
    }
    if(bytes_read == 0){
      usleep(10000);
      DEBUG_PRINT("%s\n", "Nothing to read, having a nap for a bit...");
      return -1;
    }
    *read_buf += bytes_read;
    if(*read_buf < sizeof(pkthdr)){
      DEBUG_PRINT("%s\n", "we shouldn't be here...");
      // if we didn't read enough bytes go again. We should never get here though. ??
      return -1;
    }
  }
  memcpy(&pkthdr, buf, sizeof(pkthdr));


  if((pkthdr.caplen > 65565 || pkthdr.caplen <= 0) || ((pkthdr.ts.tv_sec < (time_now - 604800) || pkthdr.ts.tv_sec > (time_now + 604800)) || (pkthdr.ts.tv_usec >= 1000000 || pkthdr.ts.tv_usec < 0))){

    DEBUG_PRINT("%s\n", "Found some bad data. STOP");
    DEBUG_PRINT("caplen: %u\n", pkthdr.caplen);
    DEBUG_PRINT("len: %u\n", pkthdr.len);
    DEBUG_PRINT("seconds: %u\n", pkthdr.ts.tv_sec);
    DEBUG_PRINT("micros: %u\n", pkthdr.ts.tv_usec);
    hexDump("entirebuffer", buf, stderr, *read_buf);
    return -1;
    // DEBUG_PRINT("Timestamp: %d Caplen: %d\n", pkthdr.ts.tv_sec, pkthdr.caplen);
    //     // unsigned char *pkt_buf = NULL;
    // pkt_buf = calloc(1, 64);
    // //hexDump("emptybuf", pkt_buf, stdout, 64);
    // //hexDump("pkthdr", &pkthdr, stdout, sizeof pkthdr);
    // memcpy(pkt_buf, &pkthdr, sizeof(pkthdr));
    // memmove(pkt_buf, pkt_buf + 1, sizeof(pkthdr) -1);
    // fread(pkt_buf + sizeof(pkthdr) -1, 1, 1, fp);
    // //hexDump("buffer", pkt_buf, stdout, 64);
    // int buf_len = sizeof(pkthdr);
    //     // snapto_packet(fp, counter, pkt_buf, &buf_len);
    // free (pkt_buf);
  }

  // ** need to do some packet analysis here to make sure packet is good **
  DEBUG_PRINT("Timestamp: %d Caplen: %d\n", pkthdr.ts.tv_sec, pkthdr.caplen);

  // allocate some memory to our buffer
  //buf = malloc(sizeof pkthdr + pkthdr.caplen);

  // if(buf != NULL ) {
  //   DEBUG_PRINT("memory address: %p\n", (void *)buf);
  // }
  // // copy the header into our buffer
  // DEBUG_PRINT("memcpy pointer %p\n",(void *)memcpy(buf, &pkthdr, sizeof pkthdr));
  //   // hexDump("packet header", buf, sizeof pkthdr);
  if(*read_buf < (sizeof(pkthdr) + pkthdr.caplen)){
    DEBUG_PRINT("read_buf smaller than packet @ %d bytes\n", *read_buf);
    bytes_read = read(*fd, (buf + *read_buf), (BUFFERLEN - *read_buf));
    if(bytes_read == -1){
      DEBUG_PRINT("Oh dear, something went wrong with read()! %s\n",   strerror(errno));
            usleep(1000000);
            return -1;
    }
    if(bytes_read == 0){
      usleep(10000);
      DEBUG_PRINT("%s\n", "nothing read. errrr.");
            return -1;
    }
    *read_buf += bytes_read;
    DEBUG_PRINT("Did some reading, new size: %d\n", *read_buf);
        // This is dirty. Should fix this up at some point.
    while(*read_buf <= sizeof(pkthdr) + pkthdr.caplen){
      read(*fd, buf, 1);
      DEBUG_PRINT("%s\n", "Read one byte as there wasn't enough data. Need to fix this");
            ++*read_buf;
    }
  }
  DEBUG_PRINT("about to write %d bytes\n", (int) (sizeof pkthdr + pkthdr.caplen));
  // maybe this should be swapped around? i.e one block of x bytes since its already known
  fwrite(buf, sizeof pkthdr + pkthdr.caplen, 1, stdout);
  fflush(stdout);
  // we've just written bytes, so need to move the buffer.
  memmove(buf, buf + (sizeof(pkthdr) + pkthdr.caplen), *read_buf - (sizeof(pkthdr) + pkthdr.caplen));
  *read_buf -= (sizeof(pkthdr) + pkthdr.caplen);
  //read(*fd, buf + sizeof pkthdr, pkthdr.caplen);
   //hexDump ("header + packet", buf, sizeof pkthdr + pkthdr.caplen);
  // write out the header + packet in one hit

  // don't let stdout buffer, flush it after each packet

  // clean up after ourselves
  //free(buf);
  //fflush(stdout); // should just use setvbuf and set to non buffering.
  DEBUG_PRINT("caplen: %u\n", pkthdr.caplen);
  DEBUG_PRINT("len: %u\n", pkthdr.len);
  DEBUG_PRINT("seconds: %u\n", pkthdr.ts.tv_sec);
  DEBUG_PRINT("micros: %u\n", pkthdr.ts.tv_usec);
  DEBUG_PRINT("Packet number: %u\n\n", *counter);
    ++*counter;
  return 0;
}

int main(int argc, char *argv[]){


  if( argc != 2){
    printf("Incorrect arguments\n");
    return -1;
  }
  int packet_counter = 1;
  int buf_len = 0;
  int has_header;
  int read_buf = 0;
  //FILE *fp;
  unsigned char *buf = NULL;
  int fd = open("/tmp/capper", O_RDONLY);
  //fp = fopen(argv[1], "r");
  struct pcap_file_header fhdr;
  unsigned char *pkt_buf = NULL;
  //read_file(&fd);
    // make snapto method if the header is missing.
    //read_file();
    // buf = malloc(sizeof &fhdr);
    //synthesis_pcap_header(fp, &fhdr);
    has_header = has_pcap_header(&fd, &fhdr);
    if  (has_header == -1){
      perror("read error");
      return -1;
    }
    else if (has_header == 1) {
      // printf("found header");
      //fflush(stdout);
      // hexDump ("header", &fhdr, sizeof fhdr);

      fwrite(&fhdr, 1, sizeof fhdr, stdout);


      // for (i = 1; i <= 10; i++) {
      // while(packet_counter < 600){
      //   read_one_packet(fp, &packet_counter);
      // }
      buf = malloc(BUFFERLEN);
      while (read_one_packet(&fd, &packet_counter, &read_buf, buf) == 0){
        //sleep(1);
        ;
      }
      return 0;
    }
    else { // no header
      //printf("no header\n");
      //fflush(stdout);

      synthesis_pcap_header();

      // at this point you have already read 24 bytes and found its not the header. So you need to add them to the start of the buffer so you can read them again.

      pkt_buf = calloc(64,1);
      memcpy(pkt_buf, &fhdr, sizeof(fhdr));
      buf_len = sizeof(fhdr);
      snapto_packet(&fd, &packet_counter, pkt_buf, &buf_len);
      free(pkt_buf);

      //read_one_packet(fp);

      // while(packet_counter < 6){
      //   read_one_packet(fp, &packet_counter);
      // }
      buf = malloc(BUFFERLEN);
      while (read_one_packet(&fd, &packet_counter, &read_buf, buf) == 0){
        //sleep(1);
        ;
      }
      free(buf);
      // printf("counter: %u\n", byte_counter);
      // synthesis_pcap_header(fp, &fhdr);
      // fflush(stdout);
      // read_one_packet(fp);
      return 0;
    }

  pkt_buf = NULL;
  close(fd);

}




