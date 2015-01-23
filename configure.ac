dnl Process this file with autoconf to produce a configure script.

AC_INIT([simscan], [1.4.1.3])
AC_CONFIG_SRCDIR([simscan.c])
AM_INIT_AUTOMAKE
AM_CONFIG_HEADER(config.h)
AC_CANONICAL_HOST
AC_CHECK_FUNCS([strsep])

dnl Checks for programs.
AC_PROG_CC

if test "$GCC"="yes"
then
         CXXFLAGS="$CXXFLAGS -Wall"
         CFLAGS="$CFLAGS -Wall"
fi

#----------------------------------------------------------------------
AC_ARG_ENABLE(user, [  --enable-user=<user> Change the user for simscan.  Default: simscan.],
	ENABLE_USER="$enableval",
	[
		ENABLE_USER="simscan"
	])
	
AC_MSG_CHECKING(whether the $ENABLE_USER user exists)
AC_TRY_RUN( [
  #include <pwd.h>

  int main() {
    struct passwd *pw;
        if (( pw=getpwnam("$ENABLE_USER")) != 0 ) return 0; 
        else return 1;
	return -1;
  }
  ],
    AC_MSG_RESULT(yes),
    AC_MSG_RESULT(no)
    AC_MSG_ERROR(could not find the $ENABLE_USER user.  Please add the $ENABLE_USER user and try again.),
    AC_MSG_RESULT(no)
    AC_MSG_ERROR(could not find the $ENABLE_USER user.  Please add the $ENABLE_USER user and try again.)
)

AC_SUBST(ENABLE_USER)


#----------------------------------------------------------------------
VIRUSSCANNER=0
DO_RIPMIME=0

AC_ARG_ENABLE(clamav, [  --enable-clamav=y|n   Turn on clamav scanning. default yes.],
    ENABLE_CLAMAV="$enableval",
    [
      ENABLE_CLAMAV=yes
    ] )

case $ENABLE_CLAMAV in
1*|y*|Y*)
        ENABLE_CLAMAV=1
        AC_DEFINE([ENABLE_CLAMAV], [], [enable clamav scanning])

        #----------------------------------------------------------------------
      
        AC_MSG_CHECKING(whether we can locate the clamdscan program)
        clamdscan=""
        for f in /usr/local/bin/clamdscan /usr/bin/clamdscan 
        do
            if test -f $f
            then
                clamdscan=$f
                break
            fi
        done
        
        AC_ARG_ENABLE(clamdscan,
            [  --enable-clamdscan=PATH   Full path to clamdscan program.],
            clamdscan="$enableval",
            [
                if test "$clamdscan" = ""
                then
                    AC_MSG_RESULT(no)
                    AC_MSG_ERROR([Unable to find your clamdscan program, specify --enable-clamdscan.])
                fi
            ]
        )
        AC_MSG_RESULT(yes)
        AC_DEFINE_UNQUOTED(CLAMDSCAN,"$clamdscan","clamdscan program")
	VIRUSSCANNER=1
        ;;
*)
        ENABLE_CLAMAV=0
        ;;
esac

#----------------------------------------------------------------------

AC_ARG_ENABLE(custom-smtp-reject, [  --enable-custom-smtp-reject=y|n   Return smtp reject message with virus name.],
    ENABLE_CUSTOM_SMTP_REJECT="$enableval",
    [
      ENABLE_CUSTOM_SMTP_REJECT=no
    ] )
case $ENABLE_CUSTOM_SMTP_REJECT in
1*|y*|Y*)
        ENABLE_CUSTOM_SMTP_REJECT=1
        AC_DEFINE([ENABLE_CUSTOM_SMTP_REJECT], [], [enable custom smtp reject message with virus name])
        ;;
*)
        ENABLE_CUSTOM_SMTP_REJECT=0
        ;;
esac

#----------------------------------------------------------------------

AC_ARG_ENABLE(per-domain, [  --enable-per-domain=y|n   Turn on per domain based checking.],
    ENABLE_PER_DOMAIN="$enableval",
    [
      ENABLE_PER_DOMAIN=no
    ] )
case $ENABLE_PER_DOMAIN in
1*|y*|Y*)
        ENABLE_PER_DOMAIN=1
        AC_DEFINE([ENABLE_PER_DOMAIN], [], [enable per domain checking])
        ;;
*)
        ENABLE_PER_DOMAIN=0
        ;;
esac

#----------------------------------------------------------------------

AC_ARG_ENABLE(attach, [  --enable-attach=y|n   Turn on attachment scanning. default no.],
    ENABLE_ATTACH="$enableval",
    [
      ENABLE_ATTACH=no
    ] )
case $ENABLE_ATTACH in
1*|y*|Y*)
        ENABLE_ATTACH=1
        DO_RIPMIME=1
        AC_DEFINE_UNQUOTED([ENABLE_ATTACH], $ENABLE_ATTACH, [enable attachment scanning])
        ;;
*)
        ENABLE_ATTACH=0
        ;;
esac


#----------------------------------------------------------------------

AC_ARG_ENABLE(dropmsg, [  --enable-dropmsg=y|n   Drop message in case of virus/spam found. Don't return error to sender.],
    ENABLE_DROPMSG="$enableval",
    [
      ENABLE_DROPMSG=no
    ] )
case $ENABLE_DROPMSG in
1*|y*|Y*)
	ENABLE_DROPMSG=1
	AC_DEFINE([ENABLE_DROPMSG], [], [enable drop message])
        ;;
*)
        ENABLE_DROPMSG=0
        ;;
esac

#----------------------------------------------------------------------

AC_ARG_ENABLE(dspam, [  --enable-dspam=y|n   Turn on dspam scanning. default no.],
    ENABLE_DSPAM="$enableval",
    [
      ENABLE_DSPAM=no
    ] )
case $ENABLE_DSPAM in
1*|y*|Y*)
        ENABLE_DSPAM=1
        AC_DEFINE_UNQUOTED([ENABLE_DSPAM], $ENABLE_DSPAM, [enable dspam scanning])
        ;;
*)
        ENABLE_DSPAM=0
        ;;
esac

case $ENABLE_DSPAM in
  1*|y*|Y*)

    AC_ARG_ENABLE(spam-passthru, [  --enable-spam-passthru=y|n   Pass spam email thru or reject (default disable, reject).],
        ENABLE_SPAM_PASSTHRU="$enableval",
        [
          ENABLE_SPAM_PASSTHRU=no
        ] )
    case $ENABLE_SPAM_PASSTHRU in
    1*|y*|Y*)
            ENABLE_SPAM_PASSTHRU=1
            AC_DEFINE([ENABLE_SPAM_PASSTHRU], [], [pass spam through to user])
            ;;
    *)
            ENABLE_SPAM_PASSTHRU=0
            ;;
    esac
        ;;
esac

#----------------------------------------------------------------------

case $ENABLE_DSPAM in
1*|y*|Y*)

    AC_MSG_CHECKING(whether we can locate the dspam program)
    dspam=""
    for f in /usr/bin/dspam /usr/local/bin/dspam
    do
        if test -f $f
        then
            dspam=$f
            break
        fi
    done

    AC_ARG_ENABLE(dspam-user, [  --enable-dspam-user=y|n   Set user option to spamc.],
        ENABLE_DSPAM_USER="$enableval",
        [
          ENABLE_DSPAM_USER=no
        ] )
    case $ENABLE_DSPAM_USER in
    1*|y*|Y*)
            ENABLE_DSPAM_USER=1
            AC_DEFINE([ENABLE_DSPAM_USER], [], [dspam --user user@domain option.])
            ;;
    *)
            ENABLE_DSPAM_USER=0
            ;;
    esac

    AC_ARG_ENABLE(dspam-path,
        [  --enable-dspam-path=PATH   Full path to spamc program.],
        dspam="$enableval",
        [
        if test "$dspam" = ""
        then
            AC_MSG_RESULT(no)
            AC_MSG_ERROR([Unable to find your dspam program, specify --enable-dspam-path.])
        fi
        ]
    )
    AC_MSG_RESULT(yes)
    AC_DEFINE_UNQUOTED(DSPAM,"$dspam","dspam program")

    AC_ARG_ENABLE(dspam-args, [  --enable-dspam-args="args" Override the default dspam arguments.],
        ENABLE_DSPAM_ARGS="$enableval",
        [
                ENABLE_DSPAM_ARGS=""
        ])
    AC_DEFINE_UNQUOTED(DSPAM_ARGS,"$ENABLE_DSPAM_ARGS","dspam arguments")
  ;;

esac

#----------------------------------------------------------------------

AC_ARG_ENABLE(spam, [  --enable-spam=y|n   Turn on spam scanning. default no.],
    ENABLE_SPAM="$enableval",
    [
      ENABLE_SPAM=no
    ] )
case $ENABLE_SPAM in
1*|y*|Y*)
        ENABLE_SPAM=1
        AC_DEFINE_UNQUOTED([ENABLE_SPAM], $ENABLE_SPAM, [enable spam scanning])
        ;;
*)
        ENABLE_SPAM=0
        ;;
esac

case $ENABLE_SPAM in
  1*|y*|Y*)

    AC_ARG_ENABLE(spam-passthru, [  --enable-spam-passthru=y|n   Pass spam email thru or reject (default disable, reject).],
        ENABLE_SPAM_PASSTHRU="$enableval",
        [
          ENABLE_SPAM_PASSTHRU=no
        ] )
    case $ENABLE_SPAM_PASSTHRU in
    1*|y*|Y*)
            ENABLE_SPAM_PASSTHRU=1
            AC_DEFINE([ENABLE_SPAM_PASSTHRU], [], [pass spam through to user])
            ;;
    *)
            ENABLE_SPAM_PASSTHRU=0
            ;;
    esac

    AC_ARG_ENABLE(spamc-user, [  --enable-spamc-user=y|n   Set user option to spamc.],
        ENABLE_SPAMC_USER="$enableval",
        [
          ENABLE_SPAMC_USER=no
        ] )
    case $ENABLE_SPAMC_USER in
    1*|y*|Y*)
            ENABLE_SPAMC_USER=1
            AC_DEFINE([ENABLE_SPAMC_USER], [], [spamc -u user@domain option.])
            ;;
    *)
            ENABLE_SPAMC_USER=0
            ;;
    esac

    AC_ARG_ENABLE(spam-auth-user, [  --enable-spam-auth-user=y|n   Turn on spam scanning for authenticated users (default no).],
        ENABLE_SPAM_AUTH_USER="$enableval",
        [
          ENABLE_SPAM_AUTH_USER=no
        ] )
    case $ENABLE_SPAM_AUTH_USER in
    1*|y*|Y*)
            ENABLE_SPAM_AUTH_USER=1
            AC_DEFINE([ENABLE_SPAM_AUTH_USER], [], [scan authenticated users for spam.])
            ;;
    *)
            ENABLE_SPAM_USER=0
            ;;
    esac

    spamhits=""
    AC_ARG_ENABLE(spam-hits, [  --enable-spam-hits=number   Reject spam above this hit level. default 10.0],
    ENABLE_SPAM_HITS="$enableval",
    [
      ENABLE_SPAM_HITS="no"
    ] )

    if test $ENABLE_SPAM_HITS = "yes"
    then
      ENABLE_SPAM_HITS="10.0"
    fi

    case $ENABLE_SPAM_HITS in
      0*|n*|N*)
        ;;
      *)
        AC_DEFINE_UNQUOTED(SPAM_HITS,$ENABLE_SPAM_HITS,"spam hits")
        spamhits=$ENABLE_SPAM_HITS
        ;;
    esac

    AC_MSG_CHECKING(whether we can locate the spamc program)
    spamc=""
    for f in /usr/bin/spamc /usr/local/bin/spamc
    do
        if test -f $f
        then
            spamc=$f
            break
        fi
    done
    AC_ARG_ENABLE(spamc,
        [  --enable-spamc=PATH   Full path to spamc program.],
        spamc="$enableval",
        [
        if test "$spamc" = ""
        then
            AC_MSG_RESULT(no)
            AC_MSG_ERROR([Unable to find your spamc program, specify --enable-spamc.])
        fi
        ]
    )
    AC_MSG_RESULT(yes)
    AC_DEFINE_UNQUOTED(SPAMC,"$spamc","spamc program")

    AC_ARG_ENABLE(spamc-args, [  --enable-spamc-args="args" Override the default spamc arguments.],
	ENABLE_SPAMC_ARGS="$enableval",
	[
		ENABLE_SPAMC_ARGS=""
	])
    AC_DEFINE_UNQUOTED(SPAMC_ARGS,"$ENABLE_SPAMC_ARGS","spamc arguments")
  ;;
esac

#----------------------------------------------------------------------

AC_MSG_CHECKING(whether we can locate the qmail directory)
qmaildir=""
for f in /var/qmail
do
    if test -d $f
    then
        qmaildir=$f
    fi
done

AC_ARG_ENABLE(qmaildir,
    [  --enable-qmaildir=DIR      Base qmail directory [/var/qmail].],
    qmaildir="$enableval",
    [
        if test "$qmaildir" = ""
        then
            AC_MSG_RESULT(no)
            AC_MSG_ERROR([Unable to find your qmaildir directory, specify --enable-qmaildir.])
        fi
    ]
)
AC_DEFINE_UNQUOTED(QMAILDIR,"$qmaildir","qmail directory")
AC_SUBST(qmaildir)
AC_MSG_RESULT(yes)

#----------------------------------------------------------------------


AC_MSG_CHECKING(setting the work directory)

workdir="$qmaildir/simscan"
AC_ARG_ENABLE(workdir,
    [  --enable-workdir=DIR      Directory to unpack emails [/var/qmail/simscan].],
    workdir="$enableval",
    [
        if test "$workdir" = ""
        then
            AC_MSG_RESULT(no)
            AC_MSG_ERROR([Unable to find your workdir directory, specify --enable-workdir.])
        fi
    ]
)
AC_DEFINE_UNQUOTED(WORKDIR,"$workdir","working directory")
AC_SUBST(workdir)
AC_MSG_RESULT(done)

#----------------------------------------------------------------------


AC_MSG_CHECKING(setting the control directory)

controldir="$qmaildir/control"
AC_ARG_ENABLE(controldir,
    [  --enable-controldir=DIR      Directory to place control files [/var/qmail/control].],
    controldir="$enableval",
    [
        if test "$controldir" = ""
        then
            AC_MSG_RESULT(no)
            AC_MSG_ERROR([Unable to find your controldir directory, specify --enable-controldir.])
        fi
    ]
)
AC_DEFINE_UNQUOTED(CONTROLDIR,"$controldir","working directory")
AC_SUBST(controldir)
AC_MSG_RESULT(done)

#----------------------------------------------------------------------

AC_ARG_ENABLE(quarantinedir, 
   [  --enable-quarantinedir=DIR   Directory to keep spam and/or infected emails [/var/qmail/quarantine].],
   ENABLE_QUARANTINE="$enableval",
   [
      ENABLE_QUARANTINE=no
   ])

  case $ENABLE_QUARANTINE in
    0*|n*|N*)
     ;;
    *)
     AC_MSG_CHECKING(setting the quarantine directory)
     quarantinedir="$qmaildir/quarantine"
     if test "$quarantinedir" = ""
     then
       AC_MSG_RESULT(no)
       AC_MSG_ERROR([Unable to find your quarantinedir directory, specify --enable-quarantinedir.])
     fi
     AC_DEFINE_UNQUOTED(QUARANTINEDIR,"$quarantinedir","quarantine directory")
     AC_SUBST(quarantinedir)
     AC_MSG_RESULT(done)
     ;;
  esac
  
#----------------------------------------------------------------------


AC_MSG_CHECKING(whether we can locate the qmail-queue program)
qmailqueue=""
for f in "$qmaildir"/bin/qmail-queue /usr/sbin/qmail-queue
do
    if test -f $f
    then
        qmailqueue=$f
        break
    fi
done

AC_ARG_ENABLE(qmail-queue,
    [  --enable-qmail-queue=PATH   Full path to qmail-queue program.],
    qmailqueue="$enableval",
    [
        if test "$qmailqueue" = ""
        then
            AC_MSG_RESULT(no)
            AC_MSG_ERROR([Unable to find your qmail-queue file, specify --enable-qmail-queue.])
        fi
    ]
)
AC_MSG_RESULT(yes)
AC_DEFINE_UNQUOTED(QMAILQUEUE,"$qmailqueue","qmail-queue program")

#----------------------------------------------------------------------

ENABLE_TROPHIE=0
AC_ARG_ENABLE(trophie-socket,
    [  --enable-trophie-socket=PATH   Full path to the trophie socket.],
    [
       AC_MSG_CHECKING(whether if the trophie-socket path is set)
       trophiesocket="$enableval"
       # check for path to trophie
      AC_ARG_ENABLE(trophie-path,
        [  --enable-trophie-path=PATH   Full path to the trophie binary.],
        [
          trophiebinary="$enableval"
          AC_MSG_RESULT(yes)
          ENABLE_TROPHIE=1
          AC_DEFINE_UNQUOTED(TROPHIESOCKET,"$trophiesocket","path to trophie socket")
          AC_DEFINE_UNQUOTED(TROPHIEBINARY,"$trophiebinary","path to trophie binary")
          AC_DEFINE_UNQUOTED([ENABLE_TROPHIE], $ENABLE_TROPHIE, [enable trophie scanning])
          DO_RIPMIME=1
          VIRUSSCANNER=1
        ], [
          AC_MSG_RESULT(no)
          AC_MSG_ERROR([Unable to find your trophie binary, specify --enable-trophie-path.])
        ]
      )
    ]
)

#----------------------------------------------------------------------
AC_ARG_ENABLE(ripmime, 
   [  --enable-ripmime=PATH   Full path to ripmime program.],
   ENABLE_RIPMIME="$enableval",
   [
      ENABLE_RIPMIME=no
   ])

  case $ENABLE_RIPMIME in
    0*|n*|N*)
     ;;
    *)
     DO_RIPMIME=1
     ;;
  esac
  

if test $DO_RIPMIME -eq 1 
then
   AC_MSG_CHECKING(whether we can locate the ripmime program)
   ripmime=""
   for f in "$ENABLE_RIPMIME" /usr/local/bin/ripmime /usr/bin/ripmime 
   do
      if test -f $f
      then
         ripmime=$f
         break
      fi
   done

   if test "$ripmime" = ""
   then
     AC_MSG_RESULT(no)
     AC_MSG_ERROR([Unable to find your ripmime program, specify --enable-ripmime.])
   else
     AC_MSG_RESULT(yes)
   fi

   AC_DEFINE_UNQUOTED(RIPMIME,"$ripmime","ripmime program")
fi

AC_DEFINE_UNQUOTED(DO_RIPMIME, $DO_RIPMIME, [run ripmime program])

#----------------------------------------------------------------------
AC_DEFINE_UNQUOTED(VIRUSSCANNER, $VIRUSSCANNER, [one or more virusscanners are active])

#----------------------------------------------------------------------

AC_ARG_ENABLE(received, [  --enable-received=y|n   Add a Received: line to the message, showing the runned scanners and some stats],
    ENABLE_RECEIVED="$enableval",
    [
      ENABLE_RECEIVED=no
    ] )
  case $ENABLE_RECEIVED in
    1*|y*|Y*)

#------------------------------------------------------------
      if test $ENABLE_SPAM -eq 1; then
        SA_PATH=""
        AC_MSG_CHECKING(whether we can locate the spamassassin-path)
        AC_ARG_ENABLE(spamassassin-path, [  --enable-spamassassin-path=PATH  Path to the spamassassin binary],
        [
          SA_PATH="$enableval"
        ])

        spamass=""
        for f in $SA_PATH /usr/bin/spamassassin /usr/local/bin/spamassassin
        do
          if test -f $f
          then
            spamass=$f
            break;
          fi
        done
  
        if test "$spamass" = ""
        then
            AC_MSG_RESULT(no)
            AC_MSG_ERROR([Unable to find your spamassassin binary, specify --enable-spamassassin-path.])
        else
            AC_MSG_RESULT(yes)
            AC_DEFINE_UNQUOTED([SPAMASSASSINPATH], "$spamass", [Path to the spamassassin binary])
        fi
      fi
#------------------------------------------------------------
      if test $ENABLE_CLAMAV -eq 1; then
        CLAMAV_DB=""
        AC_MSG_CHECKING(whether we can locate the clamav db path)
        AC_ARG_ENABLE(clamavdb-path, [  --enable-clamavdb-path=PATH  Directory where the clamav master.cvd and daily.cvd files are saved],
        [
          CLAMAV_DB="$enableval"
        ])
        clamavdb=""
        if test "$CLAMAV_DB" = ""
        then
          for f in "$CLAMAV_DB" /usr/local/share/clamav /var/lib/clamav
          do
            if test -f "$f/daily.cvd"
            then
              clamavdb=$f
              break
            elif test -f "$f/daily.inc/daily.info"
            then
              clamavdb=$f
              break
            fi
          done
        else
          # don't test path when set on compile-time
          clamavdb="$CLAMAV_DB"
        fi

        if test "$clamavdb" = ""
        then
          AC_MSG_RESULT(no)
          AC_MSG_ERROR([Unable to find your clamav databases, specify --enable-clamavdb-path.])
        else
          AC_MSG_RESULT(yes)
          AC_DEFINE_UNQUOTED([CLAMAVDBPATH], "$clamavdb", [Path to the clamav databases binary])
        fi
#---------------
        SIGTOOL_PATH=""
        AC_MSG_CHECKING(whether we can locate the sigtool binary)
        AC_ARG_ENABLE(sigtool-path, [  --enable-sigtool-path=PATH  Path to the sigtool binary],
        [
          SIGTOOL_PATH="$enableval"
        ])

        sigtoolp=""
        for f in $SIGTOOL_PATH /usr/local/bin/sigtool /usr/bin/sigtool
        do
          if test -f $f
          then
            sigtoolp=$f
            break
          fi
        done

        if test "$sigtoolp" = ""
        then
          AC_MSG_RESULT(no)
          AC_MSG_ERROR([Unable to find your sigtool binary, specify --enable-sigtool-path.])
        else
          AC_MSG_RESULT(yes)
          AC_DEFINE_UNQUOTED([SIGTOOLPATH], "$sigtoolp", [Path to the sigtool binary.])
        fi

#------------------------------------------------------------
      fi
      ENABLE_RECEIVED=1
      AC_DEFINE_UNQUOTED([ENABLE_RECEIVED], $ENABLE_RECEIVED, [enable received header])
      AC_DEFINE([RCVD_REGEX_KEY], "regex", [key for regex scanner])
      AC_DEFINE([RCVD_ATTACH_KEY], "attach", [key for attachment scanner])
      AC_DEFINE([RCVD_SPAM_KEY], "spam", [key for spamassassin])
      AC_DEFINE([RCVD_CLAM_KEY], "clamav", [key for clamav])
      AC_DEFINE([RCVD_TROPHIE_KEY], "trophie", [key for clamav])
      AC_DEFINE([RCVD_DSPAM_KEY], "dspam", [key for dspam])
     ;;
    *)
      ENABLE_RECEIVED=0
     ;;
  esac

AC_ARG_WITH(pcre-include, [  --with-pcre-include=path   path to the pcre includes directory],
    [
      CFLAGS="-I$withval"
    ],
    [])

AC_ARG_WITH(pcre-lib, [  --with-pcre-lib=path   path to the pcre library directory],
    [
      CFLAGS="-L$withval"
    ],
    [])


AC_ARG_ENABLE(regex, [  --enable-regex=y|n   enables regex scanner],
    ENABLE_REGEX="$enableval",
    [
      ENABLE_REGEX=no
    ] )
  case $ENABLE_REGEX in
    1*|y*|Y*)
      # check for library
      AC_CHECK_HEADER(pcre.h, [
        AC_CHECK_LIB(pcre,pcre_compile,[
          AC_MSG_CHECKING(enable the regex scanner)
          AC_MSG_RESULT(yes)
          ENABLE_REGEX=1;
          AC_DEFINE_UNQUOTED([ENABLE_REGEX], $ENABLE_REGEX, [enable regex scanner])
          LIBS="$LIBS -lpcre"
        ], [
          ENABLE_REGEX=0;
          AC_MSG_ERROR([Unable to find the pcre library. Specify --with-pcre-lib=/path/to/libdir])
        ],)

      ],[
        ENABLE_REGEX=0;
        AC_MSG_ERROR([Unable to find the pcre header file. Specify --with-pcre-include=/path/to/include dir])
      ],)
      ;;
    *)
      ENABLE_REGEX=0;
      AC_MSG_CHECKING(enable the regex scanner)
      AC_MSG_RESULT(no)
      ;;
  esac
    

#----------------------------------------------------------------------
AC_MSG_CHECKING(whether system has nproc ulimit)
case "$host" in
  *-*-solaris*)
    AC_MSG_RESULT(no)
    ;;
  *)
    AC_DEFINE_UNQUOTED(HAS_ULIMIT_NPROC,1,"system supports nproc ulimit")
    AC_MSG_RESULT(yes)
    ;;
esac

#----------------------------------------------------------------------


AC_OUTPUT(Makefile)

echo ""
echo "            Current settings"
echo "---------------------------------------"
echo " user                  = $ENABLE_USER"
echo " qmail directory       = $qmaildir"
echo " work directory        = $workdir"
echo " control directory     = $controldir"
echo " qmail queue program   = $qmailqueue"

case $ENABLE_CLAMAV in
  1*|y*|Y*)
  echo " clamdscan program     = $clamdscan"
  echo " clamav scan           = ON"
    ;;
  *)
  echo " clamav scan           = OFF"
    ;;
esac

case $ENABLE_TROPHIE in
  1*|y*|Y*)
  echo " trophie socket        = $trophiesocket"
  echo " trophie binary        = $trophiebinary"
  echo " trophie scanning      = ON"
    ;;
  *)
  echo " trophie scanning      = OFF"
    ;;
esac

case $ENABLE_ATTACH in
  1*|y*|Y*)
    echo " attachement scan      = ON"
    ;;
  *)
    echo " attachement scan      = OFF"
    ;;
esac

if test $DO_RIPMIME -eq 1 
then
  echo " ripmime program       = $ripmime"
else
  echo " ripmime program       = OFF" 
fi

case $ENABLE_CUSTOM_SMTP_REJECT in
  1*|y*|Y*)
    echo " custom smtp reject    = ON"
    ;;
  *)
    echo " custom smtp reject    = OFF"
    ;;
esac

case $ENABLE_DROPMSG in
  1*|y*|Y*)
  echo " drop message          = ON"
    ;;
  *)
  echo " drop message          = OFF"
    ;;
esac

case $ENABLE_REGEX in
  1*|y*|Y*)
  echo " regex scanner         = ON"

    ;;
  *)
  echo " regex scanner         = OFF"
    ;;
esac

case $ENABLE_QUARANTINE in
  0*|n*|N*)
    echo " quarantine processing = OFF"
    ;;
  *)
    echo " quarantine processing = ON"
    echo " quarantine directory  = $quarantinedir"
    ;;
esac
  

case $ENABLE_PER_DOMAIN in
  1*|y*|Y*)
    echo " domain based checking = ON"
    ;;
  *)
    echo " domain based checking = OFF"
    ;;
esac

case $ENABLE_RECEIVED in
  1*|y*|Y*)
    echo " add received header   = ON"
    ;;
  *)
    echo " add received header   = OFF"
    ;;
esac

case $ENABLE_SPAM in
  1*|y*|Y*)
    echo " spam scanning         = ON"
    echo " spamc program         = $spamc"
    echo " spamc arguments       = $ENABLE_SPAMC_ARGS"

  case $ENABLE_SPAMC_USER in
    0*|n*|N*)
      echo " spamc user            = OFF"
      ;;
    *)
      echo " spamc user            = ON"
      ;;
  esac

  case $ENABLE_SPAM_AUTH_USER in
    0*|n*|N*)
      echo "authenticated users scanned = OFF"
      ;;
    *)
      echo "authenticated users scanned = ON"
      ;;
  esac

  case $ENABLE_SPAM_PASSTHRU in
    0*|n*|N*)
      echo " spam passthru         = OFF"
      ;;
    *)
      echo " spam passthru         = ON"
      ;;
  esac

  case $ENABLE_SPAM_HITS in
    0*|n*|N*)
      ;;
    *)
      echo " spam hits             = $spamhits"
      ;;
  esac
    ;;

  *)
    echo " spam scanning         = OFF"
    ;;
esac

case $ENABLE_DSPAM in
  1*|y*|Y*)
    echo " dspam scanning        = ON"
    echo " dspam program         = $dspam"
    echo " dspam arguments       = $ENABLE_DSPAM_ARGS"
  case $ENABLE_SPAM_PASSTHRU in
    0*|n*|N*)
      echo " spam passthru         = OFF"
      ;;
    *)
      echo " spam passthru         = ON"
      ;;
  esac
  case $ENABLE_DSPAM_USER in
    0*|n*|N*)
      echo " dspam user            = OFF"
      ;;
    *)
      echo " dspam user            = ON"
      ;;
  esac

    ;;

  *)
    echo " dspam scanning        = OFF"
    ;;
esac

echo ""
