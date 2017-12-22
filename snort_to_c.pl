#!/usr/bin/perl

# jwlampe (jwlampe@nessus.org || dmitry.chan@gmail.com) ... .modified C code written by syzop
# OK, so for unknown protocols, you sniff a packet and want to fuzz or nudge
# different replies from the server...
# so grab a SNORT dump of the first packet and run
# ./snort_to_c.pl <snort dump file> [tcp,udp] > source.c
# then compile source.c and let it go to work for a few days...


$infile = shift || YewSage();
$proto = shift || YewSage();
if (lc($proto) eq "udp") {$method = "SOCK_DGRAM";}
elsif (lc($proto) eq "tcp") {$method = "SOCK_STREAM";}
else {YewSage();}

print "\#include <stdio.h>";
print qq!
\#include <stdlib.h>
\#include <unistd.h>
\#include <netdb.h>
\#include <sys/types.h>
\#include <sys/socket.h>
\#include <netinet/in.h>
\#include <arpa/inet.h>
\#include <ctype.h>
\#include <string.h>
\#include <sys/signal.h>
\#include <arpa/nameser.h>
\#include <sys/time.h>
\#include <time.h>
\#include <errno.h>

\#define TIMEOUT 3

\#define TCP_NODELAY 0

char buf[8192];
char buf2[8192];

int counter, diffcounter;

const char motherfuzzer[] =
!;


# open the SNORT file and read in the first packet of unknown protocol

open(IN,"$infile");
while (<IN>) {
    if ($_ =~ /\=\+\=\+\=\+/) {$packcount++;}
    next if ($packcount >= 2);
    next if ($_ =~ /.*\:[0-9].*\-\> [0-9].*/);
    next unless ($_ =~ /^[0-9A-F]/);
    $flag=0;
    chop($_);
    @rray = split(/\s+/,$_);
    print "\"";  
    foreach $i (0..15) {
        if ( (length($rray[$i]) == 2) && ($rray[$i] =~ /[0-9a-fA-F][0-9a-fA-F]/) ) {
                print "\\x$rray[$i]";
                $flag++;
        }
    }
    print "\"\n" if ($flag > 0);
}
print "\;\n";

print qq!
\#define FUZZLEN (sizeof(motherfuzzer))

int offsetz[FUZZLEN] = {};


void mangle(char *buf, int len) {
	int phi, omega, moffset, divisor;
	divisor = ((FUZZLEN / 8) % 15) + 1;
	phi = rand() % divisor + 1; 

	for (omega=0; omega < phi; omega++)
	{
		moffset = rand() % len;
		buf[moffset] = rand() % 256;
	}
}




void diffit() {
	int i;
	diffcounter++;	
	time_t mytime;
	mytime = time(NULL);

        printf("DIFF %s\\n",asctime(localtime(&mytime)) );
        for (i=0; i < FUZZLEN; i++)
        {
                if (buf[i] \!= motherfuzzer[i])
		{
                        printf("Offset \%d: 0x\%x -> 0x\%x\\n", i, motherfuzzer[i] \& 0x000000FF, buf[i] \& 0x000000FF);
			offsetz[i]++;
		}
        }
        printf("*****\\n");
}


void handle_offsetz()
{
	int zeta;
	FILE *fp;
	double bling;
	fp = fopen("REZULTS.txt", "w");

	if (diffcounter == 0)
		return ;
	bling = diffcounter;
	for (zeta=0; zeta<=FUZZLEN; zeta++)
	{
		printf("OFFSET: %d\\t%d\\t(%f)\\n", zeta, offsetz[zeta], offsetz[zeta] / bling);
		fprintf(fp, "OFFSET: %d\\t%d\\t(%f)\\n", zeta, offsetz[zeta], offsetz[zeta] / bling);
	}
	return;
}


void handle_offset()
{
	handle_offsetz();
	exit(0);
}


int main(int argc, char *argv[]) 
{
	struct sockaddr_in addr;
	int s, port = 0, len, totalcounter, mu, last, seeder, x, giantrunt;
	char *host = NULL;
	int seed;
	struct timeval tv;
  	signal(SIGTERM, handle_offset);
  	signal(SIGINT, handle_offset);
  	signal(SIGQUIT, handle_offset);
  	signal(SIGHUP, handle_offset);
  	signal(SIGALRM, handle_offset);

	seed = time(NULL);
    	srand(seed);

	printf("Generic Protocol fuzzer [jwl in the hizzzzzouse]\\n\\n");

        if (argc < 3) 
	{
                fprintf(stderr, "Use: \%s [ip] [port]\\n", argv[0]);
                exit(1);
        }
	

	host = argv\[1\];
	port = atoi(argv\[2\]);
	if ((port < 1) || (port > 65535)) 
	{
		fprintf(stderr, "Port out of range (%d)\\n", port);
		exit(1);
	}

	for (s=0; s<=FUZZLEN; s++)
	{
		offsetz[s] = 0;
	}

        memset(&tv, 0, sizeof(tv));
        tv.tv_sec = TIMEOUT;
        tv.tv_usec = 0;


	memset(&addr, 0, sizeof(addr));


	signal(SIGPIPE, SIG_IGN); /* Ignore SIGPIPE */
        counter = 0;
        fprintf(stdout, "Fuzzing...\\n");
        while(1) 
	{
	    giantrunt = 0;
            counter++;
	    if ((s = socket(AF_INET, $method, 0)) < 0) 
	    {
		fprintf(stderr, "Socket error: %s\\n", strerror(errno));
		exit(EXIT_FAILURE);
	    }
            setsockopt(s,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv));        //recv timeout
	    setsockopt(s,IPPROTO_TCP,TCP_NODELAY,&x,sizeof(x));         //disable nagles alg.

	    addr.sin_family = AF_INET;
	    addr.sin_port = htons(port);
	    addr.sin_addr.s_addr = inet_addr(host);
	    if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) 
	    {
                sleep(1);
                if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) 
		{
		    fprintf(stdout, "Unable to connect: %s\\n", strerror(errno));
	            diffit();
		    handle_offsetz();
                    exit(0);
                }
	    }

            memcpy(buf, motherfuzzer, FUZZLEN);

	    mangle(buf, FUZZLEN);         /* puts 1-17 random bytes into buf */
            if ((counter % 9) == 8)
	    {
                    write(s,buf, rand() % FUZZLEN);		// every 9th packet, send a RUNT
		    giantrunt = 1;
	    }
            else
	    {
                write(s, buf, FUZZLEN);
	    }
	    if ((counter % 7) == 1)
 	    {
	    	write(s,buf, rand() % FUZZLEN);   		// every 7th packet, send a GIANT
		giantrunt = 1;
	    }
            memset (&buf2, 0, sizeof(buf2));
            mu=recv(s,buf2,sizeof(buf2),0);

	    if (giantrunt == 0)
	    {
            	if ( (mu \!= last) && (counter > 1) ) 
	    	{
                    fprintf(stdout, "return buffer from scanned host just changed Counter=%d\\n", counter);
                    fprintf(stdout, "expected \%d return bytes...received \%d bytes\\n", last, mu);
                    diffit();
            	}
            	last = mu;
	    }

            totalcounter = 0;
	    close(s);
	    if ((counter % 10) == 9)
	    	sleep(1);				//yo, remove this if you want to silly DoS
        }
	
	exit(EXIT_SUCCESS);
}

!;




sub YewSage 
{
    print "\nUsage: ./snort_to_c.pl <snort dump file> <protocol>\n";
    print "Example, ./snort_to_c.pl dump.txt tcp > mysource.c \n";
    print "\nThen, run gcc -omysource mysource.c\n\n"; 
    exit(0);
}


