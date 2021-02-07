#include <stdlib.h>

#ifdef _WIN32

#include <windows.h>
#include <ws2tcpip.h>

#define strtok_r strtok_r_win
char *strtok_r_win (char *, const char *, char **);

#else

#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#endif

#define ZFREE(p)	\
	if (p) {	\
		free(p);	\
		(p) = NULL;	\
	}

char *timestamp ();
int sckerror (char *caption, struct sockaddr *sa, int salen);
unsigned long get_timer ();
int cmpsockhost (struct sockaddr *s1, struct sockaddr *s2);
int cmpsockaddr (struct sockaddr *s1, struct sockaddr *s2);
