
//includes
#include <stdio.h>
#include <time.h>
#include <ctype.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include "pcre.h"


//access log file to be scanned
#define logfile "/var/www/olivermcpheely.com/logs/access.log"

//DEFINING SQL INJECTION ATTACK PATTERS. Numbers proceeded by a % are URL ecnoded characters, that can be found here: http://www.w3schools.com/tags/ref_urlencode.asp
//SQLI Union Regex
#define attack1 "(((\%27)|(')|(\%20))*([Uu]{1}[Nn]{1}[Ii]{1}[Oo]{1}[Nn]{1}))+"

//SQLI Stacked Queries Regex -
#define attack2 "((\%27)|(\%20))*((;)|(\%3B))+((\%27)|(\%20))*"

//SQLI Comment Regex
#define attack3 "((\%27)|(\%20))*((#)|(\%23)|(\%2D\%2D)|(--)|(\%2F\%2A)|(\\/\\*))+((\%27)|(\%20))*"

//SQLI Equals Operator - used for OR 1=1 etc.
#define attack4 "((\%20)|(\%27)|('))+([^\n])*((=)|(%3D))+[a-zA-z0-9]*"

//SQLI Order By keyword Regex - used for column counting
#define attack5 "((\%27)|(\%20))*([Oo][Rr][Dd][Ee][Rr])+((\%27)|(\%20))+([Bb][Yy])+"

//SQL WAITFOR keyword Regex - used for time-based blind injection
#define attack6 "((\%27)|(\%20))*([Ww][Aa][Ii][Tt][Ff][Oo][Rr])+((\%27)|(\%20))+"

//SQL ASCII keyword regex - used for boolean and time-based blind injection
#define attack7 "((\%27)|(\%20))*([Aa][Ss][Cc][Ii]{2})+((\%27)|(\%20))*"

//define HTML header keywords for searching access logs
#define get "GET"
#define post "POST"
//define number of elements in the PCRE vector (must be a multiple of 3: http://www.pcre.org/original/doc/html/pcre_exec.html)
#define OVECSIZE 30


//function to block ip address
void block_iptables(char *log_line) {
	/* declare pointers to required files */
	FILE *iptables;
	FILE *SQLIlog;
	
	/*declare character arrays to store the console command and ipaddress in. */
	char console[1000];
	char *ipaddress = malloc(100);
	int x;

	/* initialize ipaddress */
	for (x = 0; x <= 100 ; x++) {
		if (!isspace(log_line[x])) {
			ipaddress[x] = log_line[x];
		}
	}
	/* create the iptables command and store in array 'console'. */
	sprintf(console, "/sbin/iptables -A INPUT -s %s -j DROP", ipaddress);

	/* store offending log line in a text file for easy access.*/
	SQLIlog = fopen("SQLILOG.txt", "a");
	fprintf(SQLIlog, "SQL Injection Attempt: = %s", log_line);
	fclose(SQLIlog);

	/* execute console command on the file */
	iptables = (FILE*)popen(console, "r");
	
	/* close file and release ipaddress from memory */
	pclose(iptables);
	free(ipaddress);

}

char *matchscanner(char *line, char *regex, int attack_vector) {
	/* pointer to the compiled regular expression */
	pcre *comp_regex;
	/* pointer to error message (http://www.pcre.org/original/doc/html/pcre_compile.html) */
	const char *errptr;
 	/* offset in pattern where error was found (http://www.pcre.org/original/doc/html/pcre_compile.html) */
	int erroffset;
	/* dynamic array of integers for the results offset*/
	int ovector[OVECSIZE];
	/* catches a match in the regex */
	int match;
	
	/* compile the regex */
	comp_regex = pcre_compile(regex, 0, &errptr, &erroffset, NULL);
	
	/* execute regex */
	match = pcre_exec(comp_regex, NULL, line, strlen(line), 0, 0, ovector, OVECSIZE);

	
	/* upon successful match, prints string based on integer passed by scanner and invokes block_iptables() */
	if (match > 0)
		switch (attack_vector) {
		case 0:
			printf("An SQL Injection Union attempt has been detected.\n");
			block_iptables(line);
			break;
		case 1:
			printf("An SQL Injection Stacked Query attempt has been detected.\n");
			block_iptables(line);
			break;
		case 2:
			printf("An SQL Injection Comment attempt has been detected.\n");
			block_iptables(line);
			break;
		case 3:
			printf("An SQL Injection Equals Operator attempt has been detected.\n");
			block_iptables(line);
			break;
		case 4:
			printf("An SQL Injection ORDERBY attempt has been detected.\n");
			block_iptables(line);
			break;
		case 5:
			printf("An SQL Injection WAITFOR Keyword attempt has been detected.\n");
			block_iptables(line);
			break;
		case 6:
			printf("An SQL Injection ASCII Keyword attempt has been detected.\n");
			block_iptables(line);
			break;
		default:
			break;
		}

	return 0;
}

char *scanner(char *line) {
	
	/*used to time scanner() */
	//clock_t start_t, end_t;
	//double totaltime;

	/* pointers to attack vectors */
	char *unionRegex = attack1;
	char *stackedqueryRegex = attack2;
	char *commentRegex = attack3;
	char *equalsRegex = attack4;
	char *orderbyRegex = attack5;
	char *waitforRegex = attack6;
	char *asciiRegex = attack7;

	/* used to time scanner() function */
	//start_t = clock();

	/* invoke matchscanner, passing parameters. */
	matchscanner(line, unionRegex, 0);
	matchscanner(line, stackedqueryRegex, 1);
	matchscanner(line, commentRegex, 2);
	matchscanner(line, equalsRegex, 3);
	matchscanner(line, orderbyRegex, 4);
	matchscanner(line, waitforRegex, 5);
	matchscanner(line, asciiRegex, 6);
	//end_t = clock();
	//totaltime = (double)(end_t - start_t) / CLOCKS_PER_SEC;
	//printf("Time taken to perform scanner(): %fseconds\n", totaltime);

}

	int main(void) {
		/* used for fgets() */
		char line[LINE_MAX];
		/* pointer to access file*/
		FILE *file;
		/* indicates the position within the file */
		fpos_t position;

		/* bottom_line used to test bottom log line only  */
		//int bottom_line = 1;

		/* indicates script has started */
		printf("SQL Injection Firewall Has Started.\n");

		/* infinite loop to ensure script is constantly running*/
		while (1) {
			/* open up file */
			file = fopen(logfile, "r");
			
			/* set position within file */
			fsetpos(file, &position);
			
			if (file != NULL) {
				
				//int bottom_line = 0;
				while (fgets(line, LINE_MAX, file) != NULL) {

					/* used for testing. reads only the bottom log line */
					//bottom_line = 1;
					//	if (got_line) {
					
					/* looks for keywords GET or POST */
					if (strstr(line, get) || strstr(line, post)) {
						/* find the position of the occurence */
						fgetpos(file, &position);
						/* invoke scanner on the line */
						scanner(line);
					}
				}
				fclose(file);
			} else
				/* file is empty */			
				fprintf(stderr, "Log File Empty!\n");
		}
		return 0;
	}
