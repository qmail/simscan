/*
 * $Id: simscanmk.c,v 1.5 2009/12/13 04:39:38 xen0phage Exp $
 * Copyright (C) 2004-2005 Inter7 Internet Technologies, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <fcntl.h>
#include <resolv.h>
#include <errno.h>
#include <pthread.h>
#include <ctype.h>
#include "config.h"

#include "cdb/cdb_make.h"
#include "cdb/cdb.h"
#include "cdb/buffer.h"

static struct cdb_make c;


#define MAX_KEY 40
#define MAX_DATA 40
#define MAX_LINE 4000
#define MAX_HOST_SIZE 200
#define MAX_IPS 200
#define MAX_HOSTS 200

#define BUILD_CLAM 1
#define BUILD_SPAM 2

void lowerit(char *input);
int make_cdb();
void usage();
void get_options(int argc,char **argv);
char ClearFile[200];
char CdbFile[200];
char CdbTmpFile[200];

#define TOKENS ":\n\t\r #"
#ifdef ENABLE_RECEIVED
int buildversions=0;
char CdbVersFile[200];
int make_version_cdb();
#endif

int main( int argc, char **argv)
{
  get_options(argc,argv);
#ifdef ENABLE_RECEIVED
  if (buildversions){
    int xcode = make_version_cdb();
    if (xcode != 0) exit(xcode);
  } else {
#endif
  int xcode = make_cdb();
  if (xcode != 0) exit(xcode);
#ifdef ENABLE_RECEIVED
  }
#endif
  exit(0);
}

void lowerit(char *input)
{
  while(*input!=0) {
    if ( isupper((u_char)*input) ) {
      *input = (u_char)tolower((u_char)*input);
    }
    ++input;
  }
}

#ifdef ENABLE_RECEIVED

int add_cdb_key (struct cdb_make *cdb, char *key, char *data){
  uint32 h;
  char *tmpptr;
  if (cdb_make_addbegin(cdb,strlen(key),strlen(data)) == -1) {
    printf("error on cdb_make_addbegin)\n");
    return(-1);
  } 
  h = CDB_HASHSTART;
  
  for(tmpptr=key;*tmpptr!=0;++tmpptr) {
    if (buffer_PUTC(&cdb->b,*tmpptr) == -1) {
      printf("error in buffer_PUTC\n");
      return(-1);
    }
    h = cdb_hashadd(h,*tmpptr);
  }

  for(tmpptr=data;*tmpptr!=0;++tmpptr) {
    if (buffer_PUTC(&cdb->b,*tmpptr) == -1) {
      printf("error in buffer_PUTC\n");
      return(-1);
    }
  }
  if (cdb_make_addend(cdb,strlen(key),strlen(data),h) == -1) {
    printf("error in cdb_make_addend\n");
    return(-1);
  }
  return(0);
}

int make_version_cdb() {
  int fdout;
  char key[MAX_KEY];
  char data[MAX_DATA];
  pid_t pid;
  int pin[2],rmstat,r,f;
  char input[MAX_LINE];
  char dbpath[MAX_LINE];
  char *pos;
#if ENABLE_SPAM==1 || ENABLE_TROPHIE==1
  int fnd_vsvers;
#endif
#if ENABLE_TROPHIE==1
  int fnd_patvers;
#endif

  if ( (fdout = open(CdbTmpFile, O_CREAT | O_TRUNC | O_WRONLY)) < 0) {
    printf("error on open tmp file\n");
    return(-1);
  }
  
  if (cdb_make_start(&c,fdout) == -1) {
    printf("error on cdb_make_start\n");
    return(-1);
  } 

  /* now add a check for every enabled scanner, and add the scanner to the cdb */
#ifdef ENABLE_ATTACH
  memset(data,'\0',MAX_DATA);
  strncpy(key,RCVD_ATTACH_KEY,MAX_KEY);
  strncpy(data,VERSION,MAX_DATA);
  add_cdb_key(&c,key,data);
#endif
#ifdef ENABLE_REGEX
  memset(data,'\0',MAX_DATA);
  strncpy(key,RCVD_REGEX_KEY,MAX_KEY);
  strncpy(data,VERSION,MAX_DATA);
  add_cdb_key(&c,key,data);
#endif
#ifdef ENABLE_TROPHIE
  memset(data,'\0',MAX_DATA);
  data[0]='\0';
  fnd_vsvers=0;
  fnd_patvers=0;
  strncpy(key,RCVD_TROPHIE_KEY,MAX_KEY);
  if (pipe(pin)){
    printf("error opening pipe for trophie\n");
  }
  pid=vfork();
  if (pid==0){
      /* in the child */
      close(pin[0]);
      dup2(pin[1],2); /* stderr goes to the pipe */
      execl(TROPHIEBINARY,TROPHIEBINARY,"-v",NULL);
      printf("error running trophie\n");
      _exit(-1); /* we should never get here! */
  } else if (pid){
    /* in the parent */
    close(pin[1]);
    while((r=read(pin[0],input,MAX_LINE))){
      /* we are looking for those two lines:
          Initializing    : VSAPI version 6.150-1001
          Initializing    : Pattern version 218 (pattern number 51417)
        and we want 6.150-1001/218/51417 in the string at the end */

      input[r]='\0';
      if ( (pos=strstr(input,"version ")) && (!fnd_vsvers || !fnd_patvers)){
        if (!fnd_vsvers && !fnd_patvers){
          /* this line is the vsapi version */
          strncpy(data,pos+8,strlen(pos)-9);
          strcat(data,"/");
          fnd_vsvers=1;
        } else if (!fnd_patvers){
          /* this line is the pattern version */
          for(f=0;*(pos+8+f)!=' ' && *(pos+8+f)!='\0';f++);
          strncpy(data+strlen(data),pos+8,f);
          if ( (pos=strstr(input,"number ")) ) {
            strcat(data,"/");
            for(f=0;*(pos+7+f)!=')' && *(pos+7+f)!='\0';f++);
            strncpy(data+strlen(data),pos+7,f);
          }
          fnd_patvers=1;
        }
      }
    }
    waitpid(pid,&rmstat,0);
    add_cdb_key(&c,key,data);
  } else {
    printf("error forking for trophie\n");
  }
  close(pin[0]); close(pin[1]);
#endif
#ifdef ENABLE_SPAM
  memset(data,'\0',MAX_DATA);
  fnd_vsvers=0;
  strncpy(key,RCVD_SPAM_KEY,MAX_KEY);
  if (pipe(pin)){
    printf("error opening pipe for spamassassin\n");
  }
  pid=vfork();
  if (pid==0){
      /* in the child */
      close(pin[0]);
      dup2(pin[1],1); /* stdout goes to the pipe */
      execl(SPAMASSASSINPATH,SPAMASSASSINPATH,"-V",NULL);
      printf("error running spamassassin\n");
      _exit(-1); /* we should never get here! */
  } else if (pid){
    /* in the parent */
    close(pin[1]);
    while((r=read(pin[0],input,MAX_LINE))){
      /* we are looking for this line:
          SpamAssassin version 2.63
          and have 2.63 as version
        */
      input[r]='\0';
      if ( (pos=strstr(input,"version ")) && !fnd_vsvers ){
        /* this line is the sa version */
        for(f=0;*(pos+8+f)!='\n' && *(pos+8+f)!='\0';f++);
        strncpy(data,pos+8,f);
        fnd_vsvers=1;
      }
    }
    waitpid(pid,&rmstat,0);
    add_cdb_key(&c,key,data);
  } else {
    printf("error forking for trophie\n");
  }
  close(pin[0]); close(pin[1]);
#endif
#ifdef ENABLE_CLAMAV
  memset(data,'\0',MAX_DATA);
  strncpy(key,RCVD_CLAM_KEY,MAX_KEY);
  if (pipe(pin)){
    printf("error opening pipe for sigtool\n");
  }
  pid=vfork();
  if (pid==0){
      /* in the child */
      close(pin[0]);
      dup2(pin[1],1); /* stdout goes to the pipe */
      execl(CLAMDSCAN,CLAMDSCAN,"--stdout","-V",NULL);
      printf("error running clamdscan\n");
      _exit(-1); /* we should never get here! */
  } else if (pid){
    /* in the parent */
    close(pin[1]);
    while((r=read(pin[0],input,MAX_LINE))){
      /* we are looking for this line:
         Version: 27
        */
      input[r]='\0';
      if ( (pos=strstr(input,"ClamAV "))){
        /* this line is the db version */
        for(f=0;*(pos+7+f)!='/' && *(pos+7+f)!='\0';f++);
        strncat(data,pos+7,f);
        strcat(data,"/");
      }
    }
    waitpid(pid,&rmstat,0);
    close(pin[0]); close(pin[1]);
  }
  strncpy(dbpath,CLAMAVDBPATH,MAX_LINE);
  strncat(dbpath,"/main.inc/main.info",(MAX_LINE-sizeof(CLAMAVDBPATH)-1));
  if(access(dbpath,F_OK)) {
    strncpy(dbpath,CLAMAVDBPATH,MAX_LINE);
    strncat(dbpath,"/main.cvd",(MAX_LINE-sizeof(CLAMAVDBPATH)-1));
  }
  if(access(dbpath,F_OK)) {
    strncpy(dbpath,CLAMAVDBPATH,MAX_LINE);
    strncat(dbpath,"/main.cld",(MAX_LINE-sizeof(CLAMAVDBPATH)-1));
  }
  strcat(data,"m:");
  if (pipe(pin)){
    printf("error opening pipe for sigtool\n");
  }
  pid=vfork();
  if (pid==0){
      /* in the child */
      close(pin[0]);
      dup2(pin[1],1); /* stdout goes to the pipe */
      execl(SIGTOOLPATH,SIGTOOLPATH,"--stdout","-i",dbpath,NULL);
      printf("error running sigtool\n");
      _exit(-1); /* we should never get here! */
  } else if (pid){
    /* in the parent */
    close(pin[1]);
    while((r=read(pin[0],input,MAX_LINE))){
      /* we are looking for this line:
         Version: 27
        */
      input[r]='\0';
      if ( (pos=strstr(input,"Version: "))){
        /* this line is the db version */
        for(f=0;*(pos+9+f)!='\n' && *(pos+9+f)!='\0';f++);
        strncat(data,pos+9,f);
      }
    }
    waitpid(pid,&rmstat,0);
    close(pin[0]); close(pin[1]);
    strncpy(dbpath,CLAMAVDBPATH,MAX_LINE);
    strncat(dbpath,"/daily.inc/daily.info",(MAX_LINE-sizeof(CLAMAVDBPATH)-1));
    if(access(dbpath,F_OK)) {
      strncpy(dbpath,CLAMAVDBPATH,MAX_LINE);
      strncat(dbpath,"/daily.cvd",(MAX_LINE-sizeof(CLAMAVDBPATH)-1));
    }
    if(access(dbpath,F_OK)) {
      strncpy(dbpath,CLAMAVDBPATH,MAX_LINE);
      strncat(dbpath,"/daily.cld",(MAX_LINE-sizeof(CLAMAVDBPATH)-1));
    }
    if (pipe(pin)){
     printf("error opening pipe for sigtool\n");
    }
    pid=vfork();
    if (pid==0){
      /* in the child */
      close(pin[0]);
      dup2(pin[1],1); /* stdout goes to the pipe */
      execl(SIGTOOLPATH,SIGTOOLPATH,"--stdout","-i",dbpath,NULL);
      printf("error running sigtool\n");
      _exit(-1); /* we should never get here! */
    } else if (pid){
      /* in the parent */
      close(pin[1]);
      while((r=read(pin[0],input,MAX_LINE))){
        /* we are looking for this line:
           Version: 27
          */
        input[r]='\0';
        if ( (pos=strstr(input,"Version: "))){
          /* this line is the db version */
          for(f=0;*(pos+9+f)!='\n' && *(pos+9+f)!='\0';f++);
          strcat(data,"/d:");
          strncat(data,pos+9,f);
        }
      }
      waitpid(pid,&rmstat,0);
      add_cdb_key(&c,key,data);
    }
  } else {
    printf("error forking for trophie\n");
  }
  close(pin[0]); close(pin[1]);
#endif
  if (cdb_make_finish(&c) == -1) {
    printf("error in cdb_make_finish\n"); 
    return(-1);
  }

  close(fdout);

  if (rename(CdbTmpFile, CdbVersFile)==-1) {
    printf("error: could not rename %s to %s\n", CdbTmpFile, CdbFile);
    return(-1);
  }
  chmod(CdbVersFile, 0644);
  printf("simscan versions cdb file built. %s\n", CdbVersFile);
  return(0);
}
#endif

int make_cdb()
{
 FILE *fs;
 int fdout;
 char *key;
 char *data;
 char *tmpptr;
 static char input[MAX_LINE];
 uint32 h;

  sleep(0); /* some NFS timing crazyness on solaris jk 20061108 */

  if ( (fs = fopen(ClearFile,"r")) == NULL) {
    printf("Not building simcontrol.cdb file. No %s/simcontrol text file\n",
      CONTROLDIR);
    return(-1);
  }
 
  if ( (fdout = open(CdbTmpFile, O_CREAT | O_TRUNC | O_WRONLY)) < 0) {
     printf("error on open tmp file\n");
    return(-1);
  }

  if (cdb_make_start(&c,fdout) == -1) {
    printf("error on cdb_make_start\n");
    return(-1);
  } 

  while(fgets(input,sizeof(input), fs)!=NULL) { 

    if ( input[0] == ':' ) {
      key = "";
      data = strtok(&input[1],"\r\n");
    } else {
      key = strtok(input,TOKENS);
      if ( key == NULL ) continue;
      data = strtok(NULL,"\r\n");
      // Lowercase all characters
      lowerit(key);
      lowerit(data);
    }

    if ( data == NULL ) data="";

    /*snprintf(key,sizeof(key),"%s", data);*/

    if (cdb_make_addbegin(&c,strlen(key),strlen(data)) == -1) {
      printf("error on cdb_make_addbegin)\n");
      return(-1);
    } 
    h = CDB_HASHSTART;
    
    for(tmpptr=key;*tmpptr!=0;++tmpptr) {
      if (buffer_PUTC(&c.b,*tmpptr) == -1) {
        printf("error in buffer_PUTC\n");
        return(-1);
      }
      h = cdb_hashadd(h,*tmpptr);
    }

    for(tmpptr=data;*tmpptr!=0;++tmpptr) {
      if (buffer_PUTC(&c.b,*tmpptr) == -1) {
        printf("error in buffer_PUTC\n");
        return(-1);
      }
    }
    if (cdb_make_addend(&c,strlen(key),strlen(data),h) == -1) {
      printf("error in cdb_make_addend\n");
      return(-1);
    }
  }
  if (cdb_make_finish(&c) == -1) {
    printf("error in cdb_make_finish\n"); 
    return(-1);
  }

  /*fprintf(fsout"\n");*/
  fclose(fs);
  close(fdout);

  if (rename(CdbTmpFile, CdbFile)==-1) {
    printf("error: could not rename %s to %s\n", CdbTmpFile, CdbFile);
    return(-1);
  }
  chmod(CdbFile, 0644);
  printf("simscan cdb file built. %s/simcontrol.cdb\n", CONTROLDIR);
  return(0);
}

void get_options(int argc,char **argv)
{
 int c;
 int errflag;
 extern char *optarg;
 extern int optind;

  snprintf(ClearFile, sizeof(ClearFile), "%s/simcontrol", CONTROLDIR);
  snprintf(CdbFile, sizeof(CdbFile), "%s/simcontrol.cdb", CONTROLDIR);

  snprintf(CdbTmpFile, sizeof(CdbTmpFile), "%s/ss.cdb.tmp.%d", 
    CONTROLDIR, getpid());

  errflag = 0;
  while( !errflag && (c=getopt(argc,argv,"g")) != -1 ) {
    switch(c) {
#ifdef ENABLE_RECEIVED
      case 'g':
        snprintf(CdbVersFile, sizeof(CdbFile), 
          "%s/simversions.cdb", CONTROLDIR);
        buildversions=1;
        break;
#endif
      default:
        errflag = 1;
        break;
    }
  }
  if ( errflag > 0 ) usage();
}

void usage()
{
#ifdef ENABLE_RECEIVED
  printf("usage: simscanmk [-g]\n");
  printf("       no params: builds %s/simcontrol.cdb from %s/simcontrol\n", 
    CONTROLDIR, CONTROLDIR);
  printf("       -g: builds %s/simversions.cdb from scanners\n", CONTROLDIR);
#else
  printf("usage: no options\n");
  printf("builds %s/simcontrol.cdb from %s/simcontrol\n", 
    CONTROLDIR, CONTROLDIR);
#endif
  exit(1);
}
