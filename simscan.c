/*
 * $Id: simscan.c,v 1.5 2007/10/30 18:12:43 xen0phage Exp $
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
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <time.h>
#include "config.h"
#include "cdb/cdb.h"
#ifdef ENABLE_REGEX
#include <pcre.h>
#endif
/* qmail-queue error codes */
#define EXIT_0     0  /* Success */
#define EXIT_11   11  /* address too long */
#define EXIT_454  54  /* unable to read message or envelope */
#define EXIT_400  71  /* temporary refusal to accept */
#define EXIT_500  31  /* permenent refusal to accept message SMTP: 5XX code */
#define EXIT_MSG  82  /* exit with custom error message */ 
#define EXIT_54   54  /* Unable to read the message or envelope. */
#define EXIT_91   91  /* Envelope format error. */



/*
       51   Out of memory.
       52   Timeout.
       53   Write error; e.g., disk full.
       54   Unable to read the message or envelope.
       55   Unable to read a configuration file.  (Not used by qmail-queue.)
       56   Problem making a network connection from this host.  (Not used  by
            qmail-queue.)
       61   Problem with the qmail home directory.
       62   Problem with the queue directory.
       63   Problem with queue/pid.
       64   Problem with queue/mess.
       65   Problem with queue/intd.
       66   Problem with queue/todo.
       71   Mail server temporarily refuses to send the message to any recipi-
            ents.  (Not used by qmail-queue.)
       72   Connection to mail server timed out.  (Not used by qmail-queue.)
       73   Connection to mail server rejected.  (Not used by qmail-queue.)
       74   Connection to mail server  succeeded,  but  communication  failed.
       81   Internal bug; e.g., segmentation fault.
       91   Envelope format error.
*/

#if HAVE_STRSEP!=1
char *strsep (char **pp, char *delim);
#endif

#ifdef QUARANTINEDIR 
void quarantine_msg(char *message_name);
#endif

#define MAX_DSPAM_ARGS 20
char *dspam_args[MAX_DSPAM_ARGS];

#define MAX_SPAMC_ARGS 20
char *spamc_args[MAX_SPAMC_ARGS];

/* --stdout is required for reading virus names */
char *viri_args[] = { "clamdscan", "--stdout", NULL };

/* Global work buffers */
#define BUFFER_SIZE 2048
char buffer[BUFFER_SIZE];
char message_name[BUFFER_SIZE];
char workdir[BUFFER_SIZE];
char unique_ext[BUFFER_SIZE];

void format_dir(char *workdir);
void exit_clean(int error_code);
int fd_move(int to,int from);
int fd_copy(int to,int from);
int remove_files(char *dir); 
int str_rstr(register char *h,register char *n);
char *replace(char *string, char *oldpiece, char *newpiece);
int DebugFlag = 0;

/* To/From address processing globals */
#define MAX_RCPT_TO 255
#define MAX_EMAIL 500
char addr_name[BUFFER_SIZE];
char *addr_buff;
int  MaxRcptTo;
char MailFrom[MAX_EMAIL];
char Subject[BUFFER_SIZE];
char RcptTo[MAX_RCPT_TO][MAX_EMAIL];

int  PerDomainHits = 0;
float PDHits;

int  cdb_seek(int fd, char *key, unsigned int len, uint32 *dlen);

char *qmail_queue = QMAILQUEUE;

void lowerit(char *input);

/* Per Domain globals */
#ifdef ENABLE_PER_DOMAIN
#define MAXDOMAINS 100
#define MAXDOMLEN 256
#define PER_DOMAIN_TOKENS " =\t\n\r,\"'"
#define MAIL_EXT_TOKENS "-"

int  PerDomainClam;
int  PerDomainSpam;
int  PerDomainTrophie;
int  PerDomainSpamPassthru;
int  MaxDomains;
char Domains[MAXDOMAINS][MAXDOMLEN];

void set_per_domain();
void init_per_domain();
void per_domain_lookup( char *key );
void per_domain_email_lookup (char *email);
#endif

/* Customer Smtp reject message globals */
#ifdef ENABLE_CUSTOM_SMTP_REJECT
char RejectMsg[500];
#endif

/* Generic virus scanner globals */
#ifdef VIRUSSCANNER
char VirusName[BUFFER_SIZE];
int FoundVirus=0;
#endif

/* attachment and virusscanner need ripmime */
#if (VIRUSSCANNER==1 || ENABLE_ATTACH==1) && DO_RIPMIME==1
int run_ripmime();
#endif

/* Trophie virus scanner globals */ 
#ifdef ENABLE_TROPHIE
int check_trophie();
#endif

/* ClamAntiVirus globals */
#ifdef ENABLE_CLAMAV
int InClamHeaders;
int check_clam();
int is_clam(char *clambuf);
#endif

/* Attachment scanning globals */
#ifdef ENABLE_ATTACH
#define ATTACH_TOKENS " :\t\n\r"
#define MAX_ATTACH 100
#define MAX_ATTACH_LINE 100
char AttachName[256];
char bk_attachments[MAX_ATTACH][MAX_ATTACH_LINE];
int MaxAttach=0;
int check_attach();
int init_attach();
#endif

float SpamProbability=0.0;
float DSpamConf=0.0;

/* DSPAM scanning globals */
#if defined(ENABLE_DSPAM)
int InHeaders;
int  IsSpam;
char spam_message_name[BUFFER_SIZE];
int check_dspam();
int is_dspam(char *spambuf);
#endif

float SpamHits;
float ReqHits;

/* Spam scanning globals */
#ifdef ENABLE_SPAM
char spamuser[BUFFER_SIZE];
int InHeaders;
int  IsSpam;
char spam_message_name[BUFFER_SIZE];
int check_spam();
int is_spam(char *spambuf);
#endif

struct timeval start,stop;
double utime;
#define SECS(tv) (tv.tv_sec + tv.tv_usec / 1000000.0)

/* write a received line */
#ifdef ENABLE_RECEIVED
char runned_scanners[MAX_EMAIL]="";
void add_run_scanner(char *key);
struct tm *tm;
static char monthname[12][4] = {
 "Jan","Feb","Mar","Apr","May","Jun"
,"Jul","Aug","Sep","Oct","Nov","Dec"};
#endif

#ifdef ENABLE_REGEX
#define MAX_REGEX 100
#define MAX_REGEX_LINE 500
int numRegex=0;
char regexs[MAX_REGEX][MAX_REGEX_LINE];
pcre *comp_regexs[MAX_REGEX];
int check_regex();
void init_regex(char *);
#endif

void log_message( char *state, char *subject, int spam );

int main(int argc, char **argv)
{
#ifdef HAS_ULIMIT_NPROC
 struct rlimit limits;
#endif
 static int fd;
 int ret;
 int fd_per;
 size_t tmpread;
 char *tmpstr;
 int pim[2];
 int qstat;
 int pid;
 int i = 0;
 int gotrcpt = 0;
 int gotfrom = 0;

  /* print out version information if requested */
  if ( argc > 1 && strcmp(argv[1],"-v" )==0 ) {
    printf("simscan version: %s\n", VERSION);
    exit(0);
  }

#ifdef HAS_ULIMIT_NPROC
  /* Set ulimits to prevent hangs if it forks too many processes */
  getrlimit(RLIMIT_NPROC, &limits);
  limits.rlim_cur = 1024;
  setrlimit(RLIMIT_NPROC, &limits);
#endif

  /* get the starttime of the process */
  gettimeofday(&start,(struct timezone *) 0);

  /* Set the debug flag if environment variable set */ 
  if ( (tmpstr=getenv("SIMSCAN_DEBUG"))!=NULL ) {
    DebugFlag = atoi(tmpstr);
  }
  
#ifdef ENABLE_ATTACH
  init_attach();
#endif

#ifdef ENABLE_PER_DOMAIN
  init_per_domain();
#endif

  /* format the new directory name */
  format_dir(workdir);

  if ( DebugFlag > 0 ) {
    fprintf(stderr, "simscan:[%d]: starting: work dir: %s\n", getppid(), workdir);
  }

  /* create the working directory, allow group access too */
  umask(027);
  if ( mkdir(workdir, 0750) == -1 ) {
    if ( DebugFlag > 0 ) {
       fprintf(stderr, "simscan:[%d]: error making work dir, exit 400, errno: %d\n",
               getppid(), errno);
    }
    _exit(EXIT_400);
  }

  /* change to the new working directory */
  if ( chdir(workdir) != 0 ) {
    if ( DebugFlag > 0 ) {
      fprintf(stderr, "simscan:[%d]: error changing directory to workdir errno: %d\n",
              getppid(), errno);
    }
    exit_clean(EXIT_400);
  }

  /* open a msg file to hold the email */
  snprintf(message_name, sizeof(message_name), "msg.%s", unique_ext);
  if ( (fd=open(message_name, O_WRONLY|O_CREAT|O_TRUNC,0644)) ==- 1) {
    if ( DebugFlag > 0 ) {
       fprintf(stderr, "simscan:[%d]: error opening msg file %s errnostr: %d\n", 
               getppid(), message_name, errno);
    }
    exit_clean(EXIT_400);
  }

  /* read the email into the new file */
  while( (ret = read(0, buffer, sizeof(buffer))) > 0 ) {
    if ( write(fd, buffer,ret) == -1 ) {
      if ( DebugFlag > 0 ) {
        fprintf(stderr, "simscan:[%d]: error writing msg error: %d\n", getppid(), errno);
      }
      /* on a write error close the file so we can remove the directory */
      close(fd);
      exit_clean(EXIT_400);
    }
  } 

  /* close the file */
  if ( close(fd) == -1 ) {
    if ( DebugFlag > 0 ) {
      fprintf(stderr, "simscan:[%d]: error closing email file errno: %d\n", getppid(), errno);
    }
    exit_clean(EXIT_400);
  }

  /* if we had a read error, exit with deferral message */
  if ( ret < 0 ) exit_clean(EXIT_400);

  /* open a msg file to hold the email addrs */
  snprintf(addr_name, sizeof(addr_name), "addr.%s", unique_ext);

  /* open the addr_name file */
  if ( (fd_per=open(addr_name, O_WRONLY|O_CREAT|O_TRUNC,0644)) ==- 1) {
    if ( DebugFlag > 0 ) {
      fprintf(stderr, "simscan:[%d]: error opening addr name: %s\n", getppid(), addr_name);
    }
    exit_clean(EXIT_400);
  }

  /* read/write in the email addresses */
  addr_buff = calloc(sizeof(char),MAX_EMAIL);
  if ( addr_buff == NULL ) exit_clean(EXIT_400);

  MaxRcptTo = 0;
  memset(RcptTo,0,sizeof(RcptTo));
  memset(MailFrom,0,sizeof(MailFrom));
  errno = 0;

  while( (tmpread=read(1,addr_buff+i,1))>0 ) {
     write(fd_per,addr_buff+i, 1);

     if (addr_buff[i++]!=0 && i<MAX_EMAIL)
        continue;

     /* one line received */
     i=0;
     if (addr_buff[0] == '\0') {
        // \0\0 is end of envelop list
        if (!gotrcpt) {
           // end of list without Recipient? Hm.. seems error
           free (addr_buff);
           close (fd_per);
           exit_clean(EXIT_91);
        }
        break;
     }
     if (addr_buff[0] == 'F') {
        if (gotfrom) {
           // only one MAIL FROM can be
           free (addr_buff);
           close (fd_per);
           exit_clean(EXIT_91);
        }
        strncpy(MailFrom, &addr_buff[1], sizeof(MailFrom)-1);
        gotfrom = 1;
        if ( DebugFlag > 3 )
          fprintf(stderr, "simscan:[%d]: F envelope is %s\n", getppid(), MailFrom);
     }
     if (addr_buff[0] == 'T') {
        if (MaxRcptTo<MAX_RCPT_TO) {
           strncpy(RcptTo[MaxRcptTo], &addr_buff[1], MAX_EMAIL-1);
           gotrcpt = 1;
           MaxRcptTo ++;
           if ( DebugFlag > 3 )
              fprintf(stderr, "simscan:[%d]: T%d envelope is %s\n", getppid(), MaxRcptTo, RcptTo[MaxRcptTo-1]);
        }
     }
   }

  free (addr_buff);

  if (tmpread <= 0 && errno != 0) {
     // error or unexpected EOF
     close (fd_per);
     exit_clean(EXIT_54);
  }


  if ( MailFrom[0] == 0 && RcptTo[0][0] == 0 ) {
    if ( DebugFlag > 0 ) {
      fprintf(stderr, "simscan:[%d]: no envelope information, deferred exit\n", getppid());
    }
    exit_clean(EXIT_454);
  }

  /* close the addr file */
  if ( close(fd_per) == -1 ) {
    exit_clean(EXIT_400);
  }

#if defined(ENABLE_DSPAM)
  if (getenv("RELAYCLIENT")==0) {
    for (i =0; i<MaxRcptTo; ++i){
      if ( strncmp("spam@", RcptTo[i], 5) == 0 || strncmp("nospam@", RcptTo[i], 7) == 0 ) {
#ifdef ENABLE_CUSTOM_SMTP_REJECT
        snprintf(RejectMsg,sizeof(RejectMsg), 
         "DYou are not authorized to send email to this address");
        write(4,RejectMsg, strlen(RejectMsg));
        exit_clean(EXIT_MSG);
#else
        exit_clean(EXIT_500); 
#endif
      }
    }
  }
#endif


  /* get the mail from value 
  memset(MailFrom,0,sizeof(MailFrom));
  strncpy(MailFrom, &addr_buff[1], sizeof(MailFrom)-1);
  */

#ifdef ENABLE_PER_DOMAIN
  /* setup the per domain values for checking virus or spam */
  set_per_domain();
#endif

#ifdef ENABLE_REGEX
  /* check for regexs to block */
  if ( check_regex() == 2 ) {
    log_message("REGEX", VirusName, 0);

#ifdef ENABLE_CUSTOM_SMTP_REJECT
    snprintf(RejectMsg,sizeof(RejectMsg), 
     "DYour email was rejected because it matches a filter (%s)",
       VirusName );
    write(4,RejectMsg, strlen(RejectMsg));
    exit_clean(EXIT_MSG);
#else
    exit_clean(EXIT_500); 
#endif
  }
#endif

#if defined(ENABLE_DSPAM)
/* The following code is copied from the Spamassassin check below, with the proper adjustments */

  /* re-open the file read only */
  if ( (fd = open(message_name, O_RDONLY)) == -1 ) {
    if ( DebugFlag > 0 ) {
      fprintf(stderr, "simscan:[%d]: spam can not open file: %s\n", getppid(), message_name);
    }
    exit_clean(EXIT_400);
  }

  /* set the standard input to be the new file */
  if ( fd_move(0,fd)  == -1 ) {
    if ( DebugFlag > 0 ) {
      fprintf(stderr, "simscan:[%d]: spam could not fd_move\n", getppid());
    }
    exit_clean(EXIT_400);
  }

  /* optionally check for spam with DSPAM */
  snprintf(spam_message_name, sizeof(spam_message_name), "spamc.msg.%s", unique_ext);
  IsSpam = 0;
  ret = check_dspam();
  switch ( ret ) {
    /* spamassassin not enabled for this domain */
    case 2:
      /* re-open the message file file read only */
      /* do nothing, message_name gets openend in any case*/
      break;

    /* spam detected, refuse message */
    case 1:
      if ( DebugFlag > 0 ) {
        fprintf(stderr, "simscan:[%d]: DSPAM reported message as being SPAM\n", getppid());
      }
      close(fd);

#ifdef QUARANTINEDIR
      quarantine_msg(spam_message_name);
      /* put message in quarantine */
#endif

#ifdef ENABLE_DROPMSG
      if ( DebugFlag > 0 ) {
        fprintf(stderr, "simscan:[%d]: droping the message\n", getppid());
      }
      exit_clean(EXIT_0);
      /* Drop the message, returning success to sender. */
#else
 #ifdef ENABLE_CUSTOM_SMTP_REJECT
      snprintf(RejectMsg,sizeof(RejectMsg), "DYour email is considered spam (%.4f probability)", SpamProbability );
      write(4,RejectMsg, strlen(RejectMsg));
      exit_clean(EXIT_MSG);
 #else
      exit_clean(EXIT_500);
 #endif
#endif
      break;

      /* dspam processed message and no spam detected */
    case 0:
        if ( DebugFlag > 0 ) {
                fprintf(stderr, "simscan:[%d]: DSPAM reported message as NOT being SPAM\n", getppid());
        }
      /* open the spam file read only */
      strncpy(message_name,spam_message_name,BUFFER_SIZE);
      break;
      /* errors , return temporary error */
    default:
      if ( DebugFlag > 0 ) {
        fprintf(stderr, "simscan:[%d]: check_dspam had an error ret: %d\n", getppid(), ret);
      }
      close(fd);
      exit_clean(EXIT_400);
  }

#endif



#if (VIRUSSCANNER==1 || ENABLE_ATTACH==1) && DO_RIPMIME==1
  /* break the email msg into mime parts */
  if ( run_ripmime() != 0 ) {
    if ( DebugFlag > 0 ) {
      fprintf(stderr, "simscan:[%d]: ripmime error\n", getppid());
    }
    exit_clean(EXIT_400);
  }
#endif

#ifdef ENABLE_ATTACH
  /* check for attachments to block */
  if ( check_attach() > 0 ) {
    log_message("ATTACH", AttachName, 0);

#ifdef ENABLE_CUSTOM_SMTP_REJECT
    snprintf(RejectMsg,sizeof(RejectMsg), 
     "DYour email was rejected because it contains a bad attachment: %s",
       AttachName );
    write(4,RejectMsg, strlen(RejectMsg));
    exit_clean(EXIT_MSG);
#else
    exit_clean(EXIT_500); 
#endif
  }
#endif


#ifdef ENABLE_CLAMAV
  /* Run ClamAntiVirus, exit on errors */ 
  ret = check_clam();
  switch ( ret ) {
    case -2: 
      if ( DebugFlag > 0 ) { fprintf(stderr, "simscan:[%d]: clamdscan disabled\n", getppid()); }
      break;
    case -1: 
      if ( DebugFlag > 0 ) {
        fprintf(stderr, "simscan:[%d]: fatal error executing clamdscan\n", getppid());
      }
      exit_clean(EXIT_400);
      break;
    case 1:
      FoundVirus=1;
      if ( DebugFlag > 0 ) {
        fprintf(stderr, "simscan:[%d]: clamdscan detected a virus\n", getppid());
      }
      break;
    case 2:
      if ( DebugFlag > 0 ) {
        fprintf(stderr, "simscan:[%d]: fatal error executing clamdscan\n", getppid());
      }
      exit_clean(EXIT_400);
      break;
    default: 
      if ( DebugFlag > 0 ) {
        fprintf(stderr, "simscan:[%d]: normal clamdscan return code: %d\n", getppid(), ret);
      }
      break;
  }
#endif

#ifdef ENABLE_TROPHIE
  ret = check_trophie();
  switch(ret) {
    case 0:
      if ( DebugFlag > 0 ) {
       fprintf(stderr, "simscan:[%d]: trophie found no virus\n", getppid());
      }
      break;
    case 1:
      if ( DebugFlag > 0 ) {
       fprintf(stderr, "simscan:[%d]: trophie found virus\n", getppid());
      }
      FoundVirus=1;
      break;
    case -1:
      /* disabled */
      if ( DebugFlag > 0 ) { fprintf(stderr, "simscan:[%d]: trophie disabled\n", getppid()); }
      break;
    default:
      if ( DebugFlag > 0 ) {
       fprintf(stderr, "simscan:[%d]: some temp. error occured with trophie\n", getppid());
      }
      exit_clean(EXIT_400);
  }
#endif

#ifdef VIRUSSCANNER
  /* check for viri, return error if found or a temporary problem */
  if ( FoundVirus == 1 ) {

#ifdef ENABLE_DROPMSG
    log_message("VIRUS DROPPED", VirusName, 0);
    /* Drop the message, returning success to sender. */
    exit_clean(EXIT_0);
#else
    log_message("VIRUS", VirusName, 0);

 #ifdef ENABLE_CUSTOM_SMTP_REJECT
    snprintf(RejectMsg,sizeof(RejectMsg), 
     "DYour email was rejected because it contains the %s virus",
       VirusName );
    write(4,RejectMsg, strlen(RejectMsg));
    exit_clean(EXIT_MSG);
 #else
    exit_clean(EXIT_500); 
 #endif
#endif
  }
#endif

#ifdef ENABLE_SPAM
  /* re-open the file read only */
  if ( (fd = open(message_name, O_RDONLY)) == -1 ) {
    if ( DebugFlag > 0 ) {
      fprintf(stderr, "simscan:[%d]: spam can not open file: %s\n", getppid(), message_name);
    }
    exit_clean(EXIT_400);
  }

  /* set the standard input to be the new file */
  if ( fd_move(0,fd)  == -1 ) {
    if ( DebugFlag > 0 ) {
      fprintf(stderr, "simscan:[%d]: spam could not fd_move\n", getppid());
    }
    exit_clean(EXIT_400);
  }

  /* optionally check for spam with spamassassin */ 
  snprintf(spam_message_name, sizeof(spam_message_name), "spamc.msg.%s", unique_ext);
  ret = check_spam();
  switch ( ret ) {
    /* spamassassin not enabled for this domain */
    case 2:
      /* re-open the message file file read only */
      /* do nothing, message_name gets openend in any case*/
      break;

    /* spam detected, refuse message */
    case 1:
      if ( DebugFlag > 0 ) {
        fprintf(stderr, "simscan:[%d]: check_spam detected spam refuse message\n", getppid());
      }
      close(fd);

#ifdef QUARANTINEDIR
      quarantine_msg(message_name);
      /* put message in quarantine */
#endif
	      
#ifdef ENABLE_DROPMSG
      if ( DebugFlag > 0 ) {
        fprintf(stderr, "simscan:[%d]: droping the message\n", getppid());
      }
      exit_clean(EXIT_0);
      /* Drop the message, returning success to sender. */
#else			
 #ifdef ENABLE_CUSTOM_SMTP_REJECT
      snprintf(RejectMsg,sizeof(RejectMsg), 
       "DYour email is considered spam (%.2f spam-hits)", SpamHits );
      write(4,RejectMsg, strlen(RejectMsg));
      exit_clean(EXIT_MSG);
 #else
      exit_clean(EXIT_500); 
 #endif
#endif
      break;

      /* spamassassin processed message and no spam detected */
    case 0:
      /* open the spam file read only */
      strncpy(message_name,spam_message_name,BUFFER_SIZE);
      break;
      /* errors , return temporary error */
    default:
      if ( DebugFlag > 0 ) {
        fprintf(stderr, "simscan:[%d]: check_spam had an error ret: %d\n", getppid(), ret);
      }
      close(fd);
      exit_clean(EXIT_400); 
  }
#endif

  /* re-open the file read only */
  if ( (fd = open(message_name, O_RDONLY)) == -1 ) {
    if ( DebugFlag > 0 ) {
      fprintf(stderr, "simscan:[%d]: could not re-open file: %s\n", getppid(), message_name);
    }
    exit_clean(EXIT_400);
  }

  /* re-open the address read only */
  if ( (fd_per = open(addr_name, O_RDONLY)) == -1 ) {
    if ( DebugFlag > 0 ) {
      fprintf(stderr, "simscan:[%d]: could not re-open address: %s\n", getppid(), addr_name);
    }
    exit_clean(EXIT_400);
  }

  /* set the standard input to be the new file */
  if ( fd_move(1,fd_per)  == -1 ) {
    if ( DebugFlag > 0 ) {
      fprintf(stderr, "simscan:[%d]: could not fd_move\n", getppid());
    }
    exit_clean(EXIT_400);
  }

  if ( DebugFlag > 0 ) fprintf(stderr, "simscan:[%d]: done, execing qmail-queue\n", getppid());

  if ( pipe(pim) != 0 ) return(-1);

  /* fork qmail-queue */
  switch(pid = vfork()) {
    case -1:
      if ( DebugFlag > 0 ) {
        fprintf(stderr, "simscan:[%d]: error forking qmail-queue\n", getppid());
      }
      close(pim[0]);
      close(pim[1]);
      exit_clean(EXIT_400);
    case 0:
      close(pim[1]);
      dup2(pim[0],0);
      execl(qmail_queue, qmail_queue, (char *)NULL);
      _exit(111);
  }
  close(pim[0]);

  #ifdef ENABLE_RECEIVED
  gettimeofday(&stop,(struct timezone *) 0);
  utime=SECS(stop)-SECS(start);
  tm = gmtime(&start.tv_sec);

  snprintf(buffer,sizeof(buffer), "Received: (simscan %s ppid %d pid %d t %.4fs)\n"
           " (scanners: %s); %02d %s %04d %02d:%02d:%02d -0000\n",
           VERSION, getppid(), getpid(), utime, runned_scanners[0] ? runned_scanners : "none",
           tm->tm_mday,monthname[tm->tm_mon],tm->tm_year,tm->tm_hour,tm->tm_min,tm->tm_sec);

  if ( write(pim[1], buffer,strlen(buffer)) == -1 ) {
    if ( DebugFlag > 0 ) {
      fprintf(stderr, "simscan:[%d]: error writing received line\n", getppid());
    }
    exit_clean(EXIT_400);
  }
  #endif

  /* write the message to qmail-queue */
  while( (ret = read(fd, buffer, sizeof(buffer))) > 0 ) {
    if ( write(pim[1], buffer,ret) == -1 ) {
      if ( DebugFlag > 0 ) {
        fprintf(stderr, 
          "simscan:[%d]: error writing msg to qmail-queue error: %d\n", getppid(), errno);
      }
      exit_clean(EXIT_400);
    }
  } 
  close(pim[1]);
  close(fd);

  /* wait for qmail-queue to finish */
  if (waitpid(pid,&qstat, 0) == -1) { 
    if ( DebugFlag > 0 ) {
      fprintf(stderr, "simscan:[%d]: error forking qmail-queue (back in simscan)\n", getppid());
    }
    exit_clean(EXIT_400);
  }

  /* hand the email to the qmail-queue */
  if ( DebugFlag > 0 ) {
    fprintf(stderr, "simscan:[%d]: qmail-queue exited %d\n", getppid(), WEXITSTATUS(qstat));
  }

  /* remove the working files */
  if ( remove_files(workdir) == -1 ) {
    exit_clean(EXIT_400);
  }
  
  /* pass qmail-queue's exit status on */
  _exit(WEXITSTATUS(qstat));

  /* suppress warning messages */
  return(0);
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

/* 
 * move a file descriptor 
 */
int fd_move(int to,int from)
{
  if (to == from) return 0;
  if (fd_copy(to,from) == -1) return -1;
  close(from);
  return 0;
}

/* 
 * copy a file descriptor 
 */
int fd_copy(int to,int from)
{
  if (to == from) return 0;
  if (fcntl(from,F_GETFL,0) == -1) return -1;
  close(to);
  if (fcntl(from,F_DUPFD,to) == -1) return -1;
  return 0;
}
#ifdef ENABLE_RECEIVED
void add_run_scanner(char *key){
  int ret;
  int fd;
  uint32 dlen;
  unsigned int keylen;
  char tmpbuf[256];
  char *data;
  
  if ( DebugFlag > 1 ) fprintf(stderr, "simscan:[%d]: cdb looking up version %s\n", getppid(), key);

  snprintf(tmpbuf,sizeof(tmpbuf), "%s/simversions.cdb", CONTROLDIR);
  if ( (fd = open(tmpbuf, O_RDONLY)) == -1 ) {
    return;
  }
  keylen = strlen(key);
  ret = cdb_seek(fd,key,keylen,&dlen);
  if ( ret <= 0 ) {
    close(fd);
    return;
  }
  data = calloc(sizeof(char),dlen+1);
  if ( data == NULL ) exit_clean(EXIT_400);

  ret = read(fd,data,dlen);
  close(fd);
  snprintf(runned_scanners+strlen(runned_scanners),MAX_EMAIL-strlen(runned_scanners)," %s: %s",key,data);
  if ( DebugFlag > 2 ) fprintf(stderr, "simscan:[%d]: runned_scanners is %s\n", getppid(), runned_scanners);
  if ( DebugFlag > 2 ) fprintf(stderr, "simscan:[%d]: found %s\n", getppid(), data);
}
#endif

#if (VIRUSSCANNER || ENABLE_ATTACH) && DO_RIPMIME==1
/*
 * break the email into mime parts for scanning 
 */
int run_ripmime()
{
 int pid;
 int rmstat;

  /* fork ripmime */
  switch(pid = vfork()) {
    case -1:
      return(-1);
    case 0:
     close(1);
     close(2);
     execl(RIPMIME, "ripmime", "--disable-qmail-bounce", 
           "-i", message_name, "-d", NULL );
     _exit(-1);
  }

  /* wait for ripmime to finish */
  if (waitpid(pid,&rmstat, 0) == -1) {
     return(-1);
  }

  /* check if the child died on a signal */
  if ( WIFSIGNALED(rmstat) ) return(-1);

  /* if it exited okay, return the status */ 
  if ( WIFEXITED(rmstat) ) {
    return(WEXITSTATUS(rmstat));
  }

  /* should not reach here */
  return(-1);
}
#endif


/* 
 * scan for viri
 */
#ifdef ENABLE_CLAMAV
int check_clam()
{
 int pid;
 int rmstat;
 int pim[2];
 int file_count;

#ifdef ENABLE_PER_DOMAIN
  if ( PerDomainClam == 0 ) return(-2);
#endif

  if ( DebugFlag > 0 ) {
    fprintf(stderr, "simscan:[%d]: calling clamdscan\n", getppid());
  }

  if ( pipe(pim) != 0 ) return(-1);

  /* fork clamdscan */
  switch(pid = vfork()) {
    case -1:
      close(pim[0]);
      close(pim[1]);
      return(-1);
    case 0:
      close(pim[0]);
      dup2(pim[1],1);
      close(pim[1]);
      execve(CLAMDSCAN, viri_args, 0);
      _exit(-1);
  }
  close(pim[1]);
  dup2(pim[0],0);
  close(pim[0]);

  InClamHeaders = 1;
  memset(buffer,0,sizeof(buffer));
  while((file_count=read(0,buffer,BUFFER_SIZE))>0) {
    if ( InClamHeaders == 1 ) {
      is_clam(buffer);
    }
    memset(buffer,0,sizeof(buffer));
  }

  /* wait for clamdscan to finish */
  if (waitpid(pid,&rmstat, 0) == -1) { 
    return(-1);
  }

  /* check if the child died on a signal */
  if ( WIFSIGNALED(rmstat) ) return(-1);

#ifdef ENABLE_RECEIVED
  add_run_scanner(RCVD_CLAM_KEY);
#endif
  /* if it exited okay, return the status */ 
  if ( WIFEXITED(rmstat) ) {
    return(WEXITSTATUS(rmstat));
  }

  /* should not reach here */
  return(-1);
}

int is_clam(char *clambuf)
{
 int i,j,k;
 int found;
 char *tmpstr;
 char *virus_name;

    for(i=0,j=0;clambuf[i]!=0;++i) {
       /* found a line */
       if (clambuf[i]=='\n' || clambuf[i]=='\r' ) {
         /* check for blank line, end of headers */
         for(k=j,found=0;k<i;++k) {
           switch(clambuf[k]) {
             /* skip blank spaces and new lines */
             case ' ':
             case '\n':
             case '\t':
             case '\r':
               break;

             /* found a non blank, so we are still
              * in the headers
              */
             default:
               /* set the found non blank char flag */
               found = 1;
               break;
           }
         }
         if ( found == 0 ) {
           InClamHeaders=0;
           return(0);
         }

         if ( (tmpstr=strstr(&clambuf[j], "FOUND")) != NULL ) {
           while(*tmpstr!=':' && tmpstr>clambuf) --tmpstr; ++tmpstr;
           virus_name = strtok(tmpstr, " ");
           memset(VirusName,0,sizeof(VirusName));
           strncpy(VirusName, virus_name, sizeof(VirusName)-1);
           return(1);
         }
         if (clambuf[i+1]!=0) j=i+1;
       }
     }
     return(0);
}
#endif

/*
 * optionally check for spam
 *
 * Returns: 2 if email should not be spam checked
 *          1 if it is spam
 *          0 if not spam
           <0 on errors
 */
#if defined(ENABLE_DSPAM)
int check_dspam()
{
 int pid;
 int rmstat;
 int pim[2];
 int spam_fd;
 char *tmpbuf;
FILE *spamfs;
 int i;
 int got_data;

#ifdef ENABLE_PER_DOMAIN
  if ( PerDomainSpam == 0 ) return(2);
#endif

#ifndef ENABLE_SPAM_AUTH_USER
  /* don't scan email from authenticated senders */
  if (getenv("RELAYCLIENT")) {
    log_message("RELAYCLIENT", "-", 0);
    return 2;
  }
#endif

  if ( (spam_fd=open(spam_message_name, O_RDWR|O_CREAT|O_TRUNC,0644)) ==- 1) {
    if ( DebugFlag > 0 ) {
      fprintf(stderr, "simscan:[%d]: check_spam could not open spam file: %s\n",
              getppid(), spam_message_name);
    }
    return(-1);
  }

  if ( DebugFlag > 0 ) {
    fprintf(stderr, "simscan:[%d]: calling dspam\n", getppid());
  }

  tmpbuf = malloc(strlen(DSPAM_ARGS)+1);
  strcpy(tmpbuf, DSPAM_ARGS);

  /* setup the dspam args 
  dspam_args[0] = "dspam";
  dspam_args[1] = "--stdout";
  tmpstr = strtok(tmpbuf," ");

  for(i=1;i<MAX_DSPAM_ARGS-1&&tmpstr!=NULL;++i,tmpstr=strtok(NULL," ")) {
    dspam_args[i] = tmpstr;
  }
  */

  i = 0;
  dspam_args[i++] = "dspamc";
  dspam_args[i++] = "--stdout";
  dspam_args[i++] = "--client";
  dspam_args[i++] = "--feature=chained,noise";
  dspam_args[i++] = "--deliver=innocent,spam";
  dspam_args[i++] = "--debug";

#ifdef ENABLE_DSPAM_USER
  if ( MaxRcptTo==1 ) {
    dspam_args[i++] = "--user";
    //dspam_args[i++] = "vpopmail";
    dspam_args[i++] = RcptTo[0];
  } else {
    dspam_args[i++] = "--user";
    dspam_args[i++] = "vpopmail";
  }
#else
  dspam_args[i++] = "--user";
  dspam_args[i++] = "vpopmail";
#endif

  dspam_args[i++] = NULL;

  if ( DebugFlag > 0 ) {
    fprintf(stderr, "simscan:[%d]: calling %s ", getppid(), DSPAM);
    i=0;
    while(dspam_args[i] != NULL){
      fprintf(stderr, " %s", dspam_args[i]);
      ++i;
    }
    fprintf(stderr, "\n");
  }
  if ( pipe(pim) == 0 ) {
    /* fork dspam */
    switch(pid = vfork()) {
      case -1:
        close(pim[0]);
        close(pim[1]);
	close(spam_fd);
        return(-1);
      case 0:
        close(pim[0]);
        dup2(pim[1],1);
        close(pim[1]);
        i = execve(DSPAM, dspam_args, 0);
        if ( DebugFlag > 0 ) {
	        fprintf(stderr, "simscan:[%d]: execve returned %d/%d\n", getppid(), i, errno);
        }
        _exit(-1);
    }
    close(pim[1]);
    dup2(pim[0],0);
    close(pim[0]);
  } else {
	close(spam_fd);
    return(0);
  }

  InHeaders=1;
  SpamProbability = 0;
  memset(buffer,0,sizeof(buffer));

  spamfs = fdopen(0,"r");
  IsSpam = 0;
  got_data = 0;
  while(fgets(buffer,sizeof(buffer)-1,spamfs) != NULL ) {
    if ( InHeaders == 1 ) {
      is_dspam(buffer);
    }
    write(spam_fd, buffer,strlen(buffer));
    memset(buffer,0,sizeof(buffer));
    got_data = 1;
  }

  close(spam_fd);

  /* wait for dspam to finish */
  if (waitpid(pid,&rmstat, 0) == -1) {
    return(-1);
  }

  /* check if the child died on a signal */
  if ( WIFSIGNALED(rmstat) ) return(-1);

  if ( got_data == 0 ) return(-1);

#ifdef ENABLE_SPAM_PASSTHRU
 #ifdef ENABLE_PER_DOMAIN
    if ( PerDomainSpamPassthru == 1) {
      if ( IsSpam == 1 ) {
        if (DebugFlag > 0) {
          fprintf(stderr,
            "simscan:[%d]: delivering spam because spam-passthru is defined in this domain\n", getppid());
        }
        log_message("PASSTHRU", Subject,1);
      } else {
        log_message("CLEAN", Subject,1);
      }
      return(0);
    } else {
      if ( IsSpam == 1 ) {
#ifdef ENABLE_DROPMSG
        log_message("SPAM DROPPED", Subject, 1);
#else
        log_message("SPAM REJECT", Subject,1);
#endif
        return(1);
      } else {
        log_message("CLEAN", Subject,1);
      }
    }
 #else
    if ( IsSpam == 1 ) {
      log_message("PASSTHRU", Subject,1);
    } else {
      log_message("CLEAN", Subject,1);
    }
    return(0);
 #endif
#else
  if ( IsSpam == 1 ) {
#ifdef ENABLE_DROPMSG
    log_message("SPAM DROPPED", Subject, 1);
#else
    log_message("SPAM REJECT", Subject,1);
#endif
    return(1);
  } else {
    log_message("CLEAN", Subject,1);
  }
#endif

  return(0);

}
#endif


/* 
 * optionally check for spam 
 *
 * Returns: 2 if email should not be spam checked 
 *          1 if it is spam
 *          0 if not spam
           <0 on errors
 */
#ifdef ENABLE_SPAM
int check_spam()
{
 int pid;
 int rmstat;
 int pim[2];
 int spam_fd;
 char *tmpstr;
 char *tmpbuf;
 int i;
 FILE *spamfs;

#ifdef ENABLE_PER_DOMAIN
  if ( PerDomainSpam == 0 ) return(2);
#endif

#ifndef ENABLE_SPAM_AUTH_USER
  /* don't scan email from authenticated senders */
  if (getenv("RELAYCLIENT")) {
    log_message("RELAYCLIENT", "-", 0);
    return 2;
  }
#endif
  
  if ( (spam_fd=open(spam_message_name, O_RDWR|O_CREAT|O_TRUNC,0644)) ==- 1) {
    if ( DebugFlag > 0 ) {
      fprintf(stderr, "simscan:[%d]: check_spam could not open spam file: %s\n",
              getppid(), spam_message_name);
    }
    return(-1);
  }

  if ( DebugFlag > 0 ) {
    fprintf(stderr, "simscan:[%d]: calling spamc\n", getppid());
  }

  tmpbuf = malloc(strlen(SPAMC_ARGS)+1);
  strcpy(tmpbuf, SPAMC_ARGS);

  /* setup the spamc args */
  spamc_args[0] = "spamc";
  tmpstr = strtok(tmpbuf," "); 

  for(i=1;i<MAX_SPAMC_ARGS-1&&tmpstr!=NULL;++i,tmpstr=strtok(NULL," ")) {
    spamc_args[i] = tmpstr;
  }

  if ( MaxRcptTo==1 && i<MAX_SPAMC_ARGS-2 && strlen(spamuser) > 0){
    spamc_args[i++] = "-u";
    spamc_args[i++] = spamuser;
#ifdef ENABLE_SPAMC_USER
  } else if ( MaxRcptTo==1 && i<MAX_SPAMC_ARGS-2 && strlen(spamuser) == 0) {
    spamc_args[i++] = "-u";
    spamc_args[i++] = RcptTo[0];
#endif
  }
  spamc_args[i] = NULL;

  if ( DebugFlag > 0 ) {
    fprintf(stderr, "simscan:[%d]: calling %s ", getppid(), SPAMC);
    i=0;
    while(spamc_args[i] != NULL){
      fprintf(stderr, " %s", spamc_args[i]);
      ++i;
    }
    fprintf(stderr, "\n");
  }
  if ( pipe(pim) == 0 ) {
    /* fork spamc */
    switch(pid = vfork()) {
      case -1:
        close(pim[0]);
        close(pim[1]);
        close(spam_fd);
        return(-1);
      case 0:
        close(pim[0]);
        dup2(pim[1],1);
        close(pim[1]);
        execve(SPAMC, spamc_args, 0);
        _exit(-1);
    }
    close(pim[1]);
    dup2(pim[0],0);
    close(pim[0]);
  } else {
    close(spam_fd);
    return(0);
  }
 
  InHeaders = 1;
  SpamHits = 0.0;
  ReqHits = 0.0;
  IsSpam = 0;
  memset(buffer,0,sizeof(buffer));
  spamfs = fdopen(0,"r");
  while(fgets(buffer,sizeof(buffer)-1,spamfs) != NULL ) {
    if ( InHeaders == 1 ) {
      is_spam(buffer);
    }
    write(spam_fd, buffer,strlen(buffer));
    memset(buffer,0,sizeof(buffer));
  }
  close(spam_fd);
  fclose(spamfs);

  /* wait for spamc to finish */
  if (waitpid(pid,&rmstat, 0) == -1) { 
    return(-1);
  }

  /* check if the child died on a signal */
  if ( WIFSIGNALED(rmstat) ) return(-1);

#ifdef ENABLE_RECEIVED
  add_run_scanner(RCVD_SPAM_KEY);
#endif

#ifdef SPAM_HITS
  if ( PerDomainHits==1 && ( SpamHits >= PDHits ) ) {
#ifdef ENABLE_DROPMSG
    log_message("SPAM DROPPED", Subject, 1);
#else
    log_message("SPAM REJECT", Subject,1);
#endif
    return(1);
  } else if ( PerDomainHits==0 && ( SpamHits >= SPAM_HITS ) ) {
#ifdef ENABLE_DROPMSG
    log_message("SPAM DROPPED", Subject, 1);
#else
    log_message("SPAM REJECT", Subject,1);
#endif
    return(1);
  }

  if (SpamHits >= SPAM_HITS) {
#ifdef ENABLE_DROPMSG
    log_message("SPAM DROPPED", Subject, 1);
#else
    log_message("SPAM REJECT", Subject,1);
#endif
  } else {
    log_message("CLEAN", Subject,1);
  }
#else

#ifdef ENABLE_SPAM_PASSTHRU
 #ifdef ENABLE_PER_DOMAIN
    if ( PerDomainSpamPassthru == 1) {
      if (( IsSpam == 1 ) && (DebugFlag > 0)){	    
        fprintf(stderr, 
          "simscan:[%d]: delivering spam because spam-passthru is defined in this domain\n", getppid());
      }	
      log_message("PASSTHRU", Subject,1);
      return(0);
    } else {
      if ( IsSpam == 1 ) {	    
#ifdef ENABLE_DROPMSG
        log_message("SPAM DROPPED", Subject, 1);
#else
        log_message("SPAM REJECT", Subject,1);
#endif
        return(1);
      } else {
        log_message("CLEAN", Subject,1);
      }
    }
 #else
    if ( IsSpam == 1 ) {	    
      log_message("PASSTHRU", Subject,1);
    } else {
      log_message("CLEAN", Subject,1);
    }
    return(0);
 #endif
#else
  if ( IsSpam == 1 ) {
#ifdef ENABLE_DROPMSG
    log_message("SPAM DROPPED", Subject, 1);
#else
    log_message("SPAM REJECT", Subject,1);
#endif
    return(1);
  } else {
    log_message("CLEAN", Subject,1);
  }
#endif

#endif
  return(0);
  
}
#endif


/*
 * format the directory name 
 * use time in seconds . micro seconds . process id
 */
void format_dir(char *workdir)
{
 struct timeval mytime;

  gettimeofday(&mytime,(struct timezone *) 0);
  snprintf(unique_ext, sizeof(unique_ext),"%ld.%ld.%ld", 
    mytime.tv_sec, mytime.tv_usec, (long int)getpid());

  snprintf(workdir,BUFFER_SIZE, "%s/%s", WORKDIR, unique_ext); 

}

/* 
 * From vpopmail source 
 * recursively remove a directory and all it's files
 */
int remove_files(char *dir)
{
 DIR *mydir;
 struct dirent *mydirent;
 struct stat statbuf;
 
  /* check the directory stat */
  if (lstat(dir, &statbuf) == 0) {

    /* if dir is not a directory unlink it */
    if ( !( S_ISDIR(statbuf.st_mode) ) ) {
      if ( unlink(dir) == 0 ) {
        /* return success we deleted the file */
        return(0);
      } else {
        /* error, return error to calling function,
         * we couldn't unlink the file
         */
        return(-1);
      }
    }

  } else {
    /* error, return error to calling function,
     * we couldn't lstat the file
     */
    return(-1);
  }

  /* go to the directory, and check for error */
  if (chdir(dir) == -1) {
    /* error, return error to calling function */
    return(-1);
  }

  /* open the directory and check for an error */
  if ( (mydir = opendir(".")) == NULL ) {
    /* error, return error */
    return(-1);
  }

  while((mydirent=readdir(mydir))!=NULL){

    /* skip the current directory and the parent directory entries */
    if ( strcmp(mydirent->d_name,".") !=0 &&
         strcmp(mydirent->d_name,"..")!=0 ) {

      /* stat the file to check it's type, I/O expensive */
      stat( mydirent->d_name, &statbuf);

      /* Is the entry a directory? */
      if ( S_ISDIR(statbuf.st_mode) ) {
        /* delete the sub tree, -1 means an error */
        if ( remove_files ( mydirent->d_name) == -1 ) {

          /* on error, close the directory stream */
          closedir(mydir);

          /* and return error */
          return(-1);
        }

      /* the entry is not a directory, unlink it to delete */
      } else {

        /* unlink the file and check for error */
        if (unlink(mydirent->d_name) == -1) {
          return(-1);
        }
      }
    }
  }

  /* close the directory stream, we don't need it anymore */
  closedir(mydir);
  /* go back to the parent directory and check for error */
  if (chdir("..") == -1) {
    return(-1);
  }

  /* delete the directory, I/O expensive */
  rmdir(dir);

  /* return success */
  return(0);
}

#ifdef QUARANTINEDIR 
void quarantine_msg(char *message_name)
{
 int fd_destino;
 int fd_origem;
 int ret;
 char quarantinefile[1024];

  strncpy(quarantinefile, QUARANTINEDIR, sizeof(quarantinefile)-1);
  strncat(quarantinefile, "/", sizeof(quarantinefile)-1);
  strncat(quarantinefile, message_name, sizeof(quarantinefile)-1);
  
  fprintf(stderr, "simscan:[%d]: Putting the message in quarantine: %s\n", 
          getppid(), quarantinefile);
  
  if ((fd_destino=open(quarantinefile, O_WRONLY|O_CREAT|O_TRUNC, 0644)) == -1) {
    if ( DebugFlag > 0 ) {
      fprintf(stderr, 
              "simscan:[%d]: error opening quarantine file %s errnostr: %d\n", 
              getppid(), message_name, errno);
    }
    return;
  }
  
  fd_origem = open(message_name, O_RDONLY);
  while ((ret = read(fd_origem, buffer, sizeof(buffer))) > 0) {
    if (write(fd_destino, buffer, ret) == -1) {
      if (DebugFlag > 0) {
        fprintf(stderr, "simscan:[%d]: error writing msg error: %d\n", getppid(), errno);
      }
      close(fd_origem);
      close(fd_destino);
      return;
    }
  }
  
  if (close(fd_origem) == -1) {
    if ( DebugFlag > 0 ) {
      fprintf(stderr, "simscan:[%d]: error closing original mail file errno: %d\n", 
              getppid(), errno);
    }
    return;
  }
  
  if ( close(fd_destino) == -1 ) {
    if ( DebugFlag > 0 ) {
      fprintf(stderr, "simscan:[%d]: error closing quarantine file errno: %d\n", 
              getppid(), errno);
    }
    return;
  } else {
    fprintf(stderr, "simscan:[%d]: Message recorded in quarantine successful\n", getppid());
  }
  return;
}
#endif


/* 
 * clean up and exit 
 */
void exit_clean( int error_code )
{
  remove_files(workdir);
  if ( DebugFlag > 0 ) {
    fprintf(stderr, "simscan:[%d]: exit error code: %d\n", getppid(), error_code); 
  }
  _exit(error_code);
}

#ifdef ENABLE_ATTACH

#ifndef ENABLE_PER_DOMAIN
/* init_attach - reads the attachment list from control/ssattach
 *     this version is for attachment only scanning, if you enable
 *     per_domain_scanning, attachment-parameters get read that way
 */
int init_attach()
{
 FILE *fs;
 char tmpbuf[256];
 char *tmpstr;

  MaxAttach = 0;
  memset(bk_attachments,'\0',sizeof(bk_attachments));
  snprintf(tmpbuf,sizeof(tmpbuf),"%s/ssattach", CONTROLDIR);
  if ( (fs = fopen(tmpbuf,"r") )==NULL ) return(0);

  while ( (fgets(tmpbuf,sizeof(tmpbuf),fs) != NULL) && MaxAttach<MAX_ATTACH ) {
    tmpstr = strtok(tmpbuf,ATTACH_TOKENS);
    if ( tmpstr == NULL ) continue;
    strncpy(&bk_attachments[MaxAttach][0], tmpstr, MAX_ATTACH_LINE-1);
    lowerit(&bk_attachments[MaxAttach][0]);
    ++MaxAttach;
  }
  return(0);
}
#endif

#ifdef ENABLE_PER_DOMAIN
int init_attach() {
  return(0);
}

/* add_attach - adds attachment names to the attachment scanning array
 *       list - colon separated list of attachments
 */
void add_attach (char *list) 
{
 char *found;
  
  MaxAttach = 0;
  if ( DebugFlag > 3 ) fprintf(stderr, "simscan:[%d]: add_attach called with %s\n", getppid(), list);  
  while( ( found = strsep(&list,":") ) != NULL) {
    strncpy(bk_attachments[MaxAttach], found, strlen(found));
    if ( DebugFlag > 1 ) {
      fprintf(stderr, "simscan:[%d]: %s is attachment number %d\n", getppid(), 
      bk_attachments[MaxAttach], MaxAttach);  
    }
    ++MaxAttach;
  }
}
#endif

/* 
 * check for attachements 
 */
int check_attach()
{
 DIR *mydir;
 struct dirent *mydirent;
 int i;

  if (MaxAttach <=0 ) { return(-1); }
  memset(AttachName,0,sizeof(AttachName));

  mydir = opendir(".");
  if ( mydir==NULL) return(0);

  while((mydirent=readdir(mydir))!=NULL) {
    /* skip . and .. */
    if (  mydirent->d_name[0] == '.' && 
         (mydirent->d_name[1] == '.' || mydirent->d_name[1] == 0) ) { 
      continue;
    }

    for(i=0;i<MaxAttach;++i) {
      if ( DebugFlag > 2 ) fprintf(stderr, "simscan:[%d]: checking attachment %s against %s\n", getppid(), mydirent->d_name, bk_attachments[i] );  
      lowerit(mydirent->d_name); 
      if ( str_rstr(mydirent->d_name,bk_attachments[i]) == 0 ) {
        strncpy(AttachName, mydirent->d_name, sizeof(AttachName)-1); 
        closedir(mydir);
        return(1);
      }
    }
  }
  closedir(mydir);
#ifdef ENABLE_RECEIVED
  add_run_scanner(RCVD_ATTACH_KEY);
#endif
  return(0);
}
#endif

/* 
 * check for a string match starting at the end of the string 
 */
int str_rstr(register char *h,register char *n)
{
 register char *sh;
 register char *sn;

  for(sh=h;*h!=0;++h); --h;
  for(sn=n;*n!=0;++n); --n;

  for(;h>=sh && n>=sn;--h,--n) {
    if ( *h!=*n ) {
      return(-1);
    }
  }
  return(0);
}

#ifdef ENABLE_PER_DOMAIN
void init_per_domain()
{
  PerDomainClam = 0;
  PerDomainSpam = 0;
  PerDomainTrophie = 0;
  PerDomainSpamPassthru = 0;
  per_domain_lookup("");
}

void per_domain_lookup( char *key )
{
 int ret;
 int fd;
 uint32 dlen;
 unsigned int keylen;
 char tmpbuf[256];
 char *data;
 char *parm;
 char *val = NULL;
  
  // switch the domain to lowercase
  lowerit(key);

  if ( DebugFlag > 1 ) fprintf(stderr, "simscan:[%d]: cdb looking up %s\n", getppid(), key);

  snprintf(tmpbuf,sizeof(tmpbuf), "%s/simcontrol.cdb", CONTROLDIR);
  if ( (fd = open(tmpbuf, O_RDONLY)) == -1 ) {
    return;
  }
  keylen = strlen(key);
  ret = cdb_seek(fd,key,keylen,&dlen);
  if ( ret <= 0 ) {
    close(fd);
    return;
  }
  data = calloc(sizeof(char),dlen+1);
  if ( data == NULL ) exit_clean(EXIT_400);

  ret = read(fd,data,dlen);
  close(fd);
  
  if ( DebugFlag > 1 ) fprintf(stderr, "simscan:[%d]: cdb for %s found %s\n", getppid(), key, data);

  parm = strsep(&data, PER_DOMAIN_TOKENS);
  if ( parm != NULL ) val = strsep(&data, PER_DOMAIN_TOKENS);
  while ( parm != NULL && val != NULL) {
    if ( DebugFlag > 1 ) fprintf(stderr, "simscan:[%d]: pelookup %s = %s\n", getppid(), parm, val);
    if ( strcasecmp(parm,"clam") == 0 ) {
      if ( strcasecmp(val, "yes") == 0 ) {
        PerDomainClam = 1; 
      } else if ( strcasecmp(val, "no") == 0 ) {
        PerDomainClam = 0; 
      }
    } else if ( strcasecmp(parm,"spam") == 0 ) {
      if ( strcasecmp(val, "yes") == 0 ) {
        PerDomainSpam = 1; 
      } else if ( strcasecmp(val, "no") == 0 ) {
        PerDomainSpam = 0; 
      }
    } else if ( strcasecmp(parm,"qmailqueue") == 0 ) {
      qmail_queue = strdup(val);
      if ( DebugFlag > 1 ) fprintf(stderr, "simscan:[%d]: qmailqueue = %s\n", getppid(), val);

#ifdef ENABLE_SPAM
    } else if ( strcasecmp(parm,"spamuser") == 0 ) {
      strncpy(spamuser,val,BUFFER_SIZE);
      if ( DebugFlag > 1 ) fprintf(stderr, "simscan:[%d]: spamuser = %s\n", getppid(), spamuser);
#endif

    } else if ( strcasecmp(parm,"trophie") == 0 ) {
      if ( strcasecmp(val, "yes") == 0 ) {
        PerDomainTrophie = 1; 
      } else if ( strcasecmp(val, "no") == 0 ) {
        PerDomainTrophie = 0; 
      }
      if ( DebugFlag > 1 ) fprintf(stderr, "simscan:[%d]: trophie = %s/%d\n", getppid(), val, PerDomainTrophie);
#ifdef ENABLE_REGEX
    } else if ( strcasecmp(parm,"regex") == 0 ) {
      if ( DebugFlag > 1 ) fprintf(stderr, "simscan:[%d]: regex flag %s = %s\n", getppid(), parm, val);
      init_regex(val);
#endif
#ifdef ENABLE_ATTACH
    } else if ( strcasecmp(parm,"attach") == 0 ) {
      if ( DebugFlag > 1 ) fprintf(stderr, "simscan:[%d]: attachment flag %s = %s\n", getppid(), parm, val);
      add_attach(val);
#endif
#ifdef SPAM_HITS
    } else if ( strcasecmp(parm,"spam_hits") == 0 ) {
      PerDomainHits = 1;
      PDHits = atof(val);
      if ( DebugFlag > 1 ) fprintf(stderr, "simscan:[%d]: Per Domain Hits set to : %f\n", getppid(), PDHits);
#endif
#ifdef ENABLE_SPAM_PASSTHRU
    } else if ( strcasecmp(parm,"spam_passthru") == 0) {
      if ( strcasecmp(val, "yes") == 0 ) {
        PerDomainSpamPassthru = 1;
      } else if ( strcasecmp(val, "no") == 0 ) {
        PerDomainSpamPassthru = 0;
      }
      if ( DebugFlag > 1 ) fprintf(stderr, "simscan:[%d]: spampassthru = %s/%d\n", getppid(), val, PerDomainSpamPassthru);
#endif   
    } else {
      if ( DebugFlag > 1 ) fprintf(stderr, "simscan:[%d]: unimplemented flag %s = %s\n", getppid(), parm, val);
    }
    parm = strsep(&data, PER_DOMAIN_TOKENS);
    if ( parm != NULL ) val = strsep(&data, PER_DOMAIN_TOKENS);
  }
}

void set_per_domain()
{
  int i;

  /* lookup the sender */
  per_domain_email_lookup(MailFrom);

  /* lookup all reciepients */
  for (i =0; i<MaxRcptTo; ++i){
    per_domain_email_lookup(RcptTo[i]);
  }
}

/* per_domain_email_lookup - looks up *email in the cdb database
 */
void per_domain_email_lookup (char *email) {
  char domain[MAX_EMAIL];
  char local[MAX_EMAIL];
  char localtmp[MAX_EMAIL];
  char toScan[MAX_RCPT_TO][MAX_EMAIL];
  char *tmpstr;
  char *l_ptr;
  char *lpart;
  int i,keyIndex=0;

  *localtmp='\0';
  if ( DebugFlag > 1 ) fprintf(stderr, "simscan:[%d]: pelookup: called with %s\n", getppid(), email);

  /* first we lookup the domain */
  
  for(tmpstr = email; tmpstr!=NULL && *tmpstr!='@' && keyIndex < MAX_EMAIL; ++tmpstr ){++keyIndex;}
  if (*tmpstr != '@') {
    if ( DebugFlag > 1 ) fprintf(stderr, "simscan:[%d]: WARN: no domain part found! %s\n", getppid(), email);
    *domain='\0';
  } else {
    keyIndex++;
    strncpy(domain,email+keyIndex,sizeof(domain)-keyIndex-1); 
    if ( DebugFlag > 1 ) fprintf(stderr, "simscan:[%d]: pelookup: domain is %s\n", getppid(), domain);
    per_domain_lookup( domain ); 
  }
 
  strncpy(local,email, sizeof(local)); 
  for(l_ptr=local; l_ptr!=NULL && *l_ptr!='@' && *l_ptr!='\0'; ++l_ptr );
  *l_ptr='\0';
  if ( DebugFlag > 1 ) fprintf(stderr, "simscan:[%d]: pelookup: local part is %s\n", getppid(), local);

  /* then we check if the local part is an extended address (bla-ext)
   * we have to fill an array, as per_domain_lookup uses strtok again
   * and it kills our strtok call */
  l_ptr = local;
  keyIndex=0;
  while( (lpart = strsep(&l_ptr,MAIL_EXT_TOKENS) )!= NULL && keyIndex < MAX_RCPT_TO) {
    if ( DebugFlag > 2 ) fprintf(stderr, "simscan:[%d]: lpart: local part is *%s*\n", getppid(), localtmp);
    strncat(localtmp,lpart,MAX_EMAIL-strlen(localtmp)-strlen(lpart)-1);
    sprintf(toScan[keyIndex], "%s@%s", localtmp,domain);
    strncat(localtmp,"-",MAX_EMAIL-strlen(localtmp)-2);
    ++keyIndex;
    /*strncpy(localtmp+strlen(localtmp),lpart,MAX_EMAIL-strlen(localtmp)); 
    snprintf(toScan[keyIndex], MAX_EMAIL, "%s@%s",localtmp,domain);
    strncpy(localtmp+strlen(localtmp),"-",MAX_EMAIL-strlen(localtmp)-1);
    ++keyIndex;*/
  }
  
  /* we check for every email address*/
  for (i = 0; i < keyIndex; ++i){
    per_domain_lookup( toScan[i] ); 
  }
}

#endif

#if defined(ENABLE_DSPAM)
/* Check for a spam message
 * This is done by checking for a matching line
 * in the email headers for X-DSPAM-Result: which
 * we put in each spam email
 *
 * Return 1 if spam
 * Return 0 if not spam
 * Return -1 on error
 */
int is_dspam(char *spambuf)
{
 int l;

  if ( spambuf[0] == '\n' || spambuf[1] == '\n' ) {
    InHeaders = 0;
    return(0);
  }

  if (strstr(spambuf, "X-DSPAM-Result:")) {
    if ( strstr(spambuf, "X-DSPAM-Result: Spam")) {
      IsSpam=1;
    }
  } else if ( strncmp(spambuf, "X-DSPAM-Probability:", 19 ) == 0 ) {
    SpamProbability = atof(&spambuf[20]);
  } else if ( strncmp(spambuf, "X-DSPAM-Confidence:", 19 ) == 0 ) {
    DSpamConf = atof(&spambuf[19]);
  } else if ( strncmp(spambuf, "Subject:", 8 ) == 0 ) {
    strncpy(Subject, &spambuf[9], sizeof(Subject)-1);

    /* replace : char with _ and null terminate on
     * newline or carrage return
     */
    for(l=0;Subject[l]!=0 && l<sizeof(Subject);++l) {
      if ( Subject[l] == ':' ) Subject[l] = '_';
      if ( Subject[l] == '\r' || Subject[l] == '\n' ) {
        Subject[l] = 0;
        break;
      }
    }
  } 

  return(0);
}

#endif


#ifdef ENABLE_SPAM
/* Check for a spam message
 * This is done by checking for a matching line
 * in the email headers for X-Spam-Level: which
 * we put in each spam email
 *
 * Return 1 if spam
 * Return 0 if not spam
 * Return -1 on error
 */
int is_spam(char *spambuf)
{
 int l;
 char *tmpstr;
 char hits[10];

  if ( spambuf[0] == '\n' || spambuf[1] == '\n' ) {
    InHeaders = 0;
    return(0);
  }

  if ( strncmp(spambuf, "X-Spam-Flag: YES", 16 ) == 0 ) {
    IsSpam = 1;

  /* still in the headers get Subject */ 
  } else if ( strncmp(spambuf, "Subject:", 8 ) == 0 ) {
    
    strncpy(Subject, &spambuf[9], sizeof(Subject)-1);

    /* replace : char with _ and null terminate on
     * newline or carrage return
     */
    for(l=0;Subject[l]!=0 && l<sizeof(Subject);++l) {
      if ( Subject[l] == ':' ) Subject[l] = '_';
      if ( Subject[l] == '\r' || Subject[l] == '\n' ) {
        Subject[l] = 0;
        break;
      }
    }

  /* still in the headers check for spam header */
  } else if ( strncmp(spambuf, "X-Spam-Status:", 14 ) == 0 ) {
    tmpstr = strstr(spambuf, "hits=");

    /* spamassassin 3 uses score= as default
     * so check for that
     */
    if ( tmpstr == NULL ) {
       tmpstr = strstr(spambuf, "score=");
       if ( tmpstr == NULL ) {
         if ( DebugFlag > 1 ) {
           fprintf(stderr,
           "simscan:[%d]: neither hits= or score= in X-Spam-Status header\n", getppid());
         }
         return(0);
       }
       tmpstr+=6;
    } else {
       tmpstr+=5;
    }
    if ( tmpstr == NULL ) {
       if ( DebugFlag > 1 ) {
         fprintf(stderr,
           "simscan:[%d]: neither hits= or score= in X-Spam-Status header\n", getppid());
       }
    }
    memset(hits,0,sizeof(hits));
    for(l=0;l<9 && *tmpstr!=' '; ++l, ++tmpstr) {
      hits[l] = *tmpstr;
    }
    SpamHits = atof(hits);

    if ( (tmpstr = strstr(spambuf, "required=")) != NULL ) {
      tmpstr+=9;
      memset(hits,0,sizeof(hits));
      for(l=0;l<9 && *tmpstr!=' '; ++l, ++tmpstr) {
        hits[l] = *tmpstr;
      }
      ReqHits = atof(hits);
    }

  }
  return(0);
}

#endif

#ifdef ENABLE_REGEX
/*  check_regex - returns 0 if no match
 *                returns 1 if there was an error matching
 *                returns 2 if a regex matched and fills the number
 *                          VirusName;
 *                uses regex[][] array
 */
int check_regex () {
  int retvalue=0;
  int i,rc;
  char line[MAX_REGEX_LINE];
  const char *error;
  int erroffset;
  FILE *regex_fd;
  int match=0;

  for (i=0;i<numRegex;i++){
      if ( DebugFlag > 1 ) { fprintf(stderr, "simscan:[%d]: compiling regex %d (%s)\n", getppid(), i,regexs[i]);  }
      comp_regexs[i]=pcre_compile(regexs[i], 0, &error, &erroffset, NULL);    
      if (comp_regexs[i] == NULL){
        if ( DebugFlag > 0 ) { fprintf(stderr, "simscan:[%d]: error compiling regex %d (%s): %s\n", getppid(), i,regexs[i],error);  }
      }
  }
  
  if ( DebugFlag > 1 ) { fprintf(stderr, "simscan:[%d]: regex opening message file %s\n", getppid(), message_name);  }
  if ( (regex_fd=fopen(message_name, "r")) == NULL ) {
    if ( DebugFlag > 1 ) { fprintf(stderr, "simscan:[%d]: regex error opening message file %s\n", getppid(), message_name);  }
    retvalue=1;
  } else {
    if ( DebugFlag > 1 ) { fprintf(stderr, "simscan:[%d]: regex reading message\n", getppid());  }
    while(!feof(regex_fd) && !match){
      /* read line and match it */
      fgets(line, MAX_REGEX_LINE, regex_fd);
      if (line != NULL){
        for (i=0;i<numRegex && !match;i++){
          if (comp_regexs[i] != NULL){
            rc=pcre_exec(comp_regexs[i], NULL, line, strlen(line), 0, 0, NULL,0);
            if (rc >= 0){
              if ( DebugFlag > 0 ) { fprintf(stderr, "simscan:[%d]: regex match %d (%s) matches %s\n", getppid(), i, regexs[i],line);  };
              match=1;
              retvalue=2;
              snprintf(VirusName,BUFFER_SIZE,"#%ld",i);
            } else if (rc < -1){
              /* -1 means no match, but all other errors are ``strange'' */
              if ( DebugFlag > 0 ) { fprintf(stderr, "simscan:[%d]: regex %d (%s) error %d\n", getppid(), i, regexs[i],rc);  };
            }
          }
        }
      }
    }
  }
  
  if ( DebugFlag > 0 ) { fprintf(stderr, "simscan:[%d]: regex freeing memory\n", getppid());  };
  for (i=0;i<numRegex;i++){
    pcre_free(comp_regexs[i]);
  }

#ifdef ENABLE_RECEIVED
  add_run_scanner(RCVD_REGEX_KEY);
#endif

  return retvalue;
}

void init_regex (char *list) {
  int len=0;
  char *found;
  if ( DebugFlag > 3 ) fprintf(stderr, "simscan:[%d]: init_regex called with %s\n", getppid(), list);  
  while( ( found = strsep(&list,":") ) != NULL) {
      strncpy(regexs[numRegex], found, strlen(found));
      if ( DebugFlag > 1 ) fprintf(stderr, "simscan:[%d]: regex %d is %s\n", getppid(), numRegex,regexs[numRegex]);  
      ++numRegex;
  }
}
#endif

#ifdef ENABLE_TROPHIE
/* check_trophie - scans using trophie scanner
 *       returns - 0 - no virus, no error
 *                 1 - virus found, name is in virusName (global)
 *                 2 - could not open socket
 *                 3 - error writing to socket
 *                 4 - error reading from socket
 *                 5 - error scanning
 */

int check_trophie() {
  int sock;
  int bread;
  int retvalue=0;
  struct sockaddr_un server;
  char command[BUFFER_SIZE];

#ifdef ENABLE_PER_DOMAIN
  if ( PerDomainTrophie == 0 ) return(-1);
#endif
      
  if ( DebugFlag > 1 ) {
    fprintf(stderr, "simscan:[%d]: trophie starting!\n", getppid());  
  }

  /* Create socket */
  sock = socket(AF_UNIX, SOCK_STREAM, 0);
  if (sock < 0) {
		retvalue=2;
  }
	
  server.sun_family=AF_UNIX;

  strncpy(server.sun_path, TROPHIESOCKET, sizeof(server.sun_path)-1);

  if (retvalue == 0 && connect(sock, (struct sockaddr *) &server, 
    sizeof(struct sockaddr_un)) < 0) {
    retvalue=2;
  }
  
  strncpy(command,workdir,sizeof(workdir)); 
  strncat(command, "\n", sizeof(command)-1);

  if ( DebugFlag > 1 ) {
    fprintf(stderr, "simscan:[%d]: sending command [%s]\n", getppid(),command);  
  }

  if (retvalue == 0 && write(sock, command, strlen(command)) < 0 ) {
    retvalue=3;
  }
	
  memset(buffer, 0, sizeof(buffer));
  if (retvalue == 0 && (bread = read(sock, buffer, sizeof(buffer))) > 0) {
    if (strchr(buffer, '\n'))
      *strchr(buffer, '\n') = '\0';

    if (buffer[0] == '1') {
      strncpy(VirusName,buffer+2,sizeof(VirusName)); 
      if ( DebugFlag > 0 ) {
        fprintf(stderr, "simscan:[%d]: trophie, virus found [%s]\n", getppid(),VirusName);  
      }
      retvalue=1;
    } else if (!strncmp(buffer, "-1", 2)) {
      if ( DebugFlag > 0 ) fprintf(stderr, "simscan:[%d]: trophie, error scanning file!\n", getppid()); 
      retvalue=5;
    } else if (!strncmp(buffer, "-2", 2)) {
      if ( DebugFlag > 0 ) fprintf(stderr, "simscan:[%d]: trophie, error scanning file!\n", getppid()); 
      retvalue=5;
    } else {
      if ( DebugFlag > 1 ) {
        fprintf(stderr, "simscan:[%d]: trophie, file clean\n", getppid());
      }
      retvalue=0;
    }
  } else if (retvalue == 0) {
    if ( DebugFlag > 0 ) {
      fprintf(stderr, "simscan:[%d]: trophie, error reading from socket\n", getppid());
    }
    retvalue=4;
  }
  
  close(sock);
  if ( DebugFlag > 1 ) {
    fprintf(stderr, "simscan:[%d]: trophie ending, retvalue = %d\n", getppid(), retvalue);
  }

#ifdef ENABLE_RECEIVED
  add_run_scanner(RCVD_TROPHIE_KEY);
#endif
  return retvalue;
}

/* end of trophie ifdef */
#endif


#if HAVE_STRSEP!=1
char *strsep (char **pp, char *delim) 
{
 char *p, *q;

  if (!(p = *pp)) return 0;
  if ((q = strpbrk (p, delim))) {
      *pp = q + 1;
      *q = '\0';
  } else {
    *pp = 0;
  }
  return p;
}
#endif

/* Given a string, replaces all instances of "oldpiece" with "newpiece".
 *
 * Modified this routine to eliminate recursion and to avoid infinite
 * expansion of string when newpiece contains oldpiece. --Byron
*/

char *replace(char *string, char *oldpiece, char *newpiece)
{
   int str_index, newstr_index, oldpiece_index, end,
      new_len, old_len, cpy_len;
   char *c;
   static char newstring[BUFFER_SIZE];

   if ((c = (char *) strstr(string, oldpiece)) == NULL)
      return string;

   new_len = strlen(newpiece);
   old_len = strlen(oldpiece);
   end = strlen(string) - old_len;
   oldpiece_index = c - string;

   newstr_index = 0;
   str_index = 0;
   while(str_index <= end && c != NULL)
   {
      /* Copy characters from the left of matched pattern occurence */
      cpy_len = oldpiece_index-str_index;
      strncpy(newstring+newstr_index, string+str_index, cpy_len);
      newstr_index += cpy_len;
      str_index += cpy_len;

      /* Copy replacement characters instead of matched pattern */
      strcpy(newstring+newstr_index, newpiece);
      newstr_index += new_len;
      str_index += old_len;

      /* Check for another pattern match */
      if((c = (char *) strstr(string+str_index, oldpiece)) != NULL)
         oldpiece_index = c - string;
   }
   /* Copy remaining characters from the right of last matched pattern */
   strcpy(newstring+newstr_index, string+str_index);

   return newstring;
} 

void log_message( char *state, char *subject, int spam )
{
 int i;
#ifdef ENABLE_SPAM
 float reqhits;
#endif

  gettimeofday(&stop,(struct timezone *) 0);
  utime=SECS(stop)-SECS(start);

  if ( spam == 1 ) {
#ifdef ENABLE_SPAM
    if ( PerDomainHits == 1 ) reqhits = PDHits;
    else reqhits = ReqHits;
    fprintf(stderr, "simscan:[%d]:%s (%.2f/%.2f):%3.4fs:%s:%s:%s:%s",
      getppid(), state, SpamHits,reqhits, utime, subject,
      getenv("TCPREMOTEIP"), MailFrom, RcptTo[0]);
#else
    fprintf(stderr, "simscan:[%d]:%s (%.4f/%.4f):%3.4fs:%s:%s:%s:%s",
      getppid(), state, SpamProbability,DSpamConf, utime, subject,
      getenv("TCPREMOTEIP"), MailFrom, RcptTo[0]);
#endif
  } else {
    fprintf(stderr, "simscan:[%d]:%s:%3.4fs:%s:%s:%s:%s",
      getppid(),state,utime,subject,getenv("TCPREMOTEIP"),MailFrom,RcptTo[0]);
  }

  for(i=1;i<MaxRcptTo;++i) {
    fprintf(stderr, ",%s", RcptTo[i]);
  }
  fprintf(stderr, "\n");
}
