#include <stdio.h>
#include <time.h>
#include <sys/time.h>
#include <string.h>
#include <errno.h>

#include "utilities.h"

char *timestamp ()
{
	int i;
	struct timeval now;
	struct tm *ptm;
	static char timestr[32];

	gettimeofday (&now, NULL);
	ptm = gmtime (&now.tv_sec);
	i = snprintf (timestr, sizeof(timestr),
		"%04d-%02d-%02d %02d:%02d:%02d.%03ld",
		ptm->tm_year+1900, ptm->tm_mon+1, ptm->tm_mday,
		ptm->tm_hour, ptm->tm_min, ptm->tm_sec, (long)now.tv_usec/1000);

	if (i < 0) return ("#error#");

	return (timestr);
}

int sckerror (char *caption, struct sockaddr *sa, int salen)
{
	char MsgText[256];

	fprintf (stderr, caption);
#ifndef _WIN32
	if (sa) {
		char host[256];
		getnameinfo (sa, salen, host, sizeof(host), 0, 0, NI_NUMERICHOST);
		fprintf (stderr, " [%s]", host);
	}
#endif

#ifdef _WIN32
	int MsgId = WSAGetLastError ();
	FormatMessage (FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS |
		FORMAT_MESSAGE_ARGUMENT_ARRAY,
		0, MsgId, 0, MsgText, sizeof(MsgText), 0);
#else
	strcpy (MsgText, strerror(errno));
#endif
	fprintf (stderr, ": %s\n", MsgText);

	return (0);
}

/* Elapsed time clock - in milliseconds */
unsigned long get_timer ()
{
#if defined(_WIN64)
	return (GetTickCount64());
#elif defined (_WIN32)
	return (GetTickCount());
#else
	struct timespec ts;

	clock_gettime (CLOCK_MONOTONIC, &ts);

	return (ts.tv_sec * 1000 + ts.tv_nsec / 1e6);
#endif
}

#ifdef _WIN32
char *strtok_r_win (char *newstring, const char *delims, char **context)
{
	char *ptr;

	ptr = (newstring ? newstring : *context);
	if (!ptr) return (NULL);

	ptr += strspn (ptr, delims);

	*context = strpbrk (ptr, delims);
	if (*context) *(*context)++ = 0;

	return (*ptr ? ptr : NULL);
}
#endif

int cmpsockhost (struct sockaddr *s1, struct sockaddr *s2)
{
	if (s1->sa_family < s2->sa_family) return (-1);
	if (s1->sa_family > s2->sa_family) return (+1);

	if (s1->sa_family == AF_INET) {
		if (ntohl(((struct sockaddr_in *)s1)->sin_addr.s_addr) <
			ntohl(((struct sockaddr_in *)s2)->sin_addr.s_addr))
			return (-1);
		if (ntohl(((struct sockaddr_in *)s1)->sin_addr.s_addr) >
			ntohl(((struct sockaddr_in *)s2)->sin_addr.s_addr))
			return (+1);
	}

	if (s1->sa_family == AF_INET6) {
		int i;

		for (i=0; i<sizeof(struct in6_addr); i++) {
			if (((struct sockaddr_in6 *)s1)->sin6_addr.s6_addr[i] <
				((struct sockaddr_in6 *)s2)->sin6_addr.s6_addr[i])
				return (-1);
			if (((struct sockaddr_in6 *)s1)->sin6_addr.s6_addr[i] >
				((struct sockaddr_in6 *)s2)->sin6_addr.s6_addr[i])
				return (+1);
		}
	}

	return (0);
}

int cmpsockaddr (struct sockaddr *s1, struct sockaddr *s2)
{
	int r;

	r = cmpsockhost (s1, s2);
	if (r) return (r);

	if (s1->sa_family == AF_INET) {
		if (htons(((struct sockaddr_in *)s1)->sin_port) <
			(htons(((struct sockaddr_in *)s2)->sin_port)))
			return (-1);
		if (htons(((struct sockaddr_in *)s1)->sin_port) >
			(htons(((struct sockaddr_in *)s2)->sin_port)))
			return (+1);
	}

	if (s1->sa_family == AF_INET6) {
		if (htons(((struct sockaddr_in6 *)s1)->sin6_port) <
			(htons(((struct sockaddr_in6 *)s2)->sin6_port)))
			return (-1);
		if (htons(((struct sockaddr_in6 *)s1)->sin6_port) >
			(htons(((struct sockaddr_in6 *)s2)->sin6_port)))
			return (+1);
	}

	return (0);
}
