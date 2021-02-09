#define MAJOR_VERSION 1
#define MINOR_VERSION 0
#define RELEASE "-2"

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <assert.h>

#ifdef _WIN32

#include <windows.h>
#include <ws2tcpip.h>

#else

#include <sys/select.h>
#include <sys/wait.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#endif

#include "utilities.h"
#include "msgbuf.h"

#define CHECK_MALLOC(m) assert ((m) != 0)

#define MAX_NAME_LEN 255
#define BUFLEN 2000

#define FLAGS_RESPONSE			0x8000
#define FLAGS_AUTHORATIVE_ANSWER	0x0400
#define FLAGS_TRUNCATED			0x0200
#define FLAGS_RECURSION_DESIRED		0x0100
#define FLAGS_RECURSION_AVAIL		0x0080
#define FLAGS_Z				0x0040
#define FLAGS_AUTHENTICATED_DATA	0x0020
#define FLAGS_CHECKING_DISABLED		0x0010
#define GET_REPLY_CODE(f) ((f) & 0x000f)
#define GET_OPCODE(f) (((f) >> 11) & 0x0f)
#define SET_REPLY_CODE(f, r) (f) = (((f) & 0xfff0) | ((r) & 0x000f))
#define SET_OPCODE(f, o) (f) = (((f) & 0x87ff) | (((o) & 0x0f) << 11))

#define REPLY_NOERROR		0
#define REPLY_FORMERR		1
#define REPLY_SERVFAIL		2
#define REPLY_NXDOMAIN		3
#define REPLY_NOTIMP		4
#define REPLY_REFUSED		5

/*
 * DNSNAMEREF: We need to reference the offset of a name when writing
 * out this record, but the offset is not set yet - however we need to
 * know where to find it later. idx is an index into that name where
 * only part of that domain name is being referenced.
 */
typedef struct dnsNR_t {
	char *text;
	uint16_t *ref;
	uint16_t idx;
} DNSNAMEREF;

typedef struct dnsQ_t {
	struct dnsQ_t *link;
	uint16_t	type;
	uint16_t	class;
	char		*name;
	uint16_t	offset;
} DNSQUESTION;

typedef struct dnsRR_t {
	struct dnsRR_t	*link;
	DNSNAMEREF	nameref;
	uint16_t	type;
	uint16_t	class;
	uint32_t	ttl;
	MSGBUF *	addr;
	uint16_t	offset;
} DNSRESOURCE;

typedef struct dnsquery_t {
	uint16_t	tranid;
	uint16_t	flags;
	uint16_t	num_questions;
	uint16_t	num_answers;
	uint16_t	num_authority;
	uint16_t	num_additional;
	DNSQUESTION *questions;
	DNSRESOURCE *answers;
	DNSRESOURCE *authority;
	DNSRESOURCE *additional;
} DNSQUERY;

struct job_t {
	struct job_t		*link;
	DNSQUERY		*query;
	unsigned long		start;
	/* Network info about how / where to reply */
	int			skt;
	struct sockaddr		*sa;
	socklen_t		sa_len;
	/* State info about active shell script */
	DNSQUESTION		*question;
	pid_t			pid;
	int			pipe;
	char			buffer[256];
	size_t			bpos;
	/* Values we carry through to next question / resource */
	uint16_t		*ref;
	uint32_t		ttl;
};

#define NO_JOBS 10
struct job_t *free_jobs = NULL;
struct job_t *active_jobs = NULL;

enum free_query_mode {
	FREE_ALL,
	FREE_QUESTIONS,
	FREE_ANSWERS,
	FREE_AUTHORITY,
	FREE_ADDITIONAL
};

struct {
	sig_atomic_t	signal;
	unsigned long overrun;
	unsigned long badquery;
	unsigned long duplicate;
	unsigned long syserr;
	unsigned long nomatch;
	unsigned long success;
} counters;

static void mainloop ();
static void process_request (int);
static DNSQUERY *parse_query (char *, size_t);
static pid_t ask_next_question (struct job_t *);
static void process_reply (struct job_t *);
static void parse_results_ip (struct job_t *);
static void job_done (struct job_t *);
static void send_response (struct job_t *);

#define MAX_SOCKETS 3
int skts[MAX_SOCKETS];

int sys_ttl = 0;		/* System-wide default time-to-live */
char *sys_script = "dns-gw.sh";
size_t max_send = 512;

sig_atomic_t good;		/* Run state */

static void sig_child(int signum)
{
	struct job_t *job;
	int status;

	for (job = active_jobs; job; job = job->link)
		if (job->pid && waitpid (job->pid, &status, WNOHANG | WUNTRACED)) {
			job->pid = 0;
			if (status) {
				SET_REPLY_CODE (job->query->flags, REPLY_SERVFAIL);
				counters.syserr++;
			}
		}
}

static void sig_counters(int signum)
{
	counters.signal++;
}

static int _putnametext (MSGBUF *m, char *nametext)
{
	size_t olen;
	unsigned char len = 0;
	char buffer[MAX_NAME_LEN + 1], *label, *ctx;

	if (!nametext || !*nametext) return (0);
	if (strlen (nametext) >= MAX_NAME_LEN) return (-1);

	/* String passed to strtok_r() needs to be writable - so take a copy */
	strncpy (buffer, nametext, MAX_NAME_LEN + 1);

	label = strtok_r (buffer, ".", &ctx);
	while (label) {
		olen = strlen(label);
		if (olen > 255) return (-1);

		len = olen;
		if (MBput (m, &len, 1) < 0) return (-1);

		if (MBput (m, label, len) < 0) return (-1);

		label = strtok_r (NULL, ".", &ctx);
	}

	return (0);
}

static int putname (MSGBUF *m, char *name)
{
	unsigned char len = 0;

	if (_putnametext (m, name)) return (-1);
	if (MBput (m, &len, 1) < 0) return (-1);
	return (0);
}

static int putnameref (MSGBUF *m, DNSNAMEREF *nameref)
{
	if (_putnametext (m, nameref->text)) return (-1);
	if (nameref->ref) {
		uint16_t offset = (*nameref->ref + nameref->idx);
		if (MBput_uint16n (m, 0xc000 | offset)) return (-1);
	} else {
		unsigned char len = 0;
		if (MBput (m, &len, 1) < 0) return (-1);
	}
	return (0);
}

static char *getname (MSGBUF *m)
{
	char buffer[MAX_NAME_LEN + 1], *ptr;
	unsigned char len;
	uint16_t offset, save = 0;

	ptr = buffer;
	if (MBget (m, &len, 1) < 0) return (NULL);

	while (len) {
		switch (len & 0xc0) {
			case 0x00:
				if (MBget (m, ptr, len) < 0) return (NULL);
				ptr += len;
				*ptr++ = '.';
				break;

			case 0x80:
			case 0x40:
				return (NULL);

			case 0xc0:		/* Follow offset */
				/* Step back 1 and re-get as 16bit offset */
				MBseek (m, -1, SEEK_CUR);
				if (MBget_uint16n (m, &offset) < 0) return (NULL);
				if (!save) save = MBtell(m);
				if (MBseek (m, offset & 0x3ff, SEEK_SET)) return (NULL);
				break;
		}
		if (MBget (m, &len, 1) < 0) return (NULL);
	}

	if (save)
		MBseek (m, save, SEEK_SET);

	if (ptr>buffer) ptr--;
	*ptr = 0;

	ptr = strdup (buffer);
	return (ptr);
}

static void free_query (DNSQUERY *query, enum free_query_mode mode)
{
	if (!query) return;

	if (mode == FREE_ALL || mode == FREE_QUESTIONS) {
		DNSQUESTION *next;
		while (query->questions) {
			next = query->questions->link;
			ZFREE (query->questions->name);
			free (query->questions);
			query->questions = next;
		}
		query->num_questions = 0;
	}

	if (mode == FREE_ALL || mode == FREE_ANSWERS) {
		DNSRESOURCE *next;
		while (query->answers) {
			next = query->answers->link;
			ZFREE (query->answers->nameref.text);
			if (query->answers->addr)
				MBfree (query->answers->addr);
			free (query->answers);
			query->answers = next;
		}
		query->num_answers = 0;
	}

	if (mode == FREE_ALL || mode == FREE_AUTHORITY) {
		DNSRESOURCE *next;
		while (query->authority) {
			next = query->authority->link;
			ZFREE (query->authority->nameref.text);
			if (query->authority->addr)
				MBfree (query->authority->addr);
			free (query->authority);
			query->authority = next;
		}
		query->num_authority = 0;
	}

	if (mode == FREE_ALL || mode == FREE_ADDITIONAL) {
		DNSRESOURCE *next;
		while (query->additional) {
			next = query->additional->link;
			ZFREE (query->additional->nameref.text);
			if (query->additional->addr)
				MBfree (query->additional->addr);
			free (query->additional);
			query->additional = next;
		}
		query->num_additional = 0;
	}

	if (mode == FREE_ALL) free (query);
}

static int replycode (char *str)
{
	long val;
	char *ptr;

	if (!(strcasecmp(str, "noerror"))) return REPLY_NOERROR;
	if (!(strcasecmp(str, "formerr"))) return REPLY_FORMERR;
	if (!(strcasecmp(str, "servfail"))) return REPLY_SERVFAIL;
	if (!(strcasecmp(str, "nxdomain"))) return REPLY_NXDOMAIN;
	if (!(strcasecmp(str, "notimp"))) return REPLY_NOTIMP;
	if (!(strcasecmp(str, "refused"))) return REPLY_REFUSED;

	/* Otherwise try it as a decimal number */
	errno = 0;
	val = strtol (str, &ptr, 10);
	return ((errno || *ptr || val<0 || val>0x0f) ? -1 : val);
}

static const char *replyname (int code)
{
	switch (code) {
		case REPLY_NOERROR: return ("NOERROR");
		case REPLY_FORMERR: return ("FORMERR");
		case REPLY_SERVFAIL: return ("SERVFAIL");
		case REPLY_NXDOMAIN: return ("NXDOMAIN");
		case REPLY_NOTIMP: return ("NOTIMP");
		case REPLY_REFUSED: return ("REFUSED");
		default: return ("(unknown)");
	}
}

static const char *flagnames(uint16_t flags)
{
	static char result[30];
	char *ptr = result;

	if (flags & FLAGS_RESPONSE) ptr = stpcpy (ptr, "qr ");
	if (flags & FLAGS_AUTHORATIVE_ANSWER) ptr = stpcpy (ptr, "aa ");
	if (flags & FLAGS_TRUNCATED) ptr = stpcpy (ptr, "tc ");
	if (flags & FLAGS_RECURSION_DESIRED) ptr = stpcpy (ptr, "rd ");
	if (flags & FLAGS_RECURSION_AVAIL) ptr = stpcpy (ptr, "ra ");
	if (flags & FLAGS_Z) ptr = stpcpy (ptr, "zz ");
	if (flags & FLAGS_AUTHENTICATED_DATA) ptr = stpcpy (ptr, "ad ");
	if (flags & FLAGS_CHECKING_DISABLED) ptr = stpcpy (ptr, "cd ");

	/* Remove trailing space */
	if (ptr > result) *(--ptr) = 0;

	return (result);
}

static const char *classname(uint16_t class)
{
	static char result[16];

	switch (class) {
		case 1: return ("IN");
		case 3: return ("CHAOS");
		default:
			snprintf (result, sizeof(result), "class=%d", class);
			return (result);
	}
}

static const char *typename(uint16_t type)
{
	static char result[16];

	switch (type) {
		case 1: return("A");
		case 2: return("NS");
		case 3: return("MD");
		case 4: return("MF");
		case 5: return("CNAME");
		case 6: return("SOA");
		case 7: return("MB");
		case 8: return("MG");
		case 9: return("MR");
		case 10: return("NULL");
		case 11: return("WKS");
		case 12: return("PTR");
		case 13: return("HINFO");
		case 14: return("MINFO");
		case 15: return("MX");
		case 16: return("TXT");
		case 17: return("RP");
		case 18: return("AFSDB");
		case 19: return("X25");
		case 20: return("ISDN");
		case 21: return("RT");
		case 22: return("NSAP");
		case 23: return("NSAP_PTR");
		case 24: return("SIG");
		case 25: return("KEY");
		case 26: return("PX");
		case 27: return("GPOS");
		case 28: return("AAAA");
		case 29: return("LOC");
		case 30: return("NXT");
		case 31: return("EID");
		case 32: return("NIMLOC");
		case 33: return("SRV");
		case 34: return("ATMA");
		case 35: return("NAPTR");
		case 36: return("KX");
		case 37: return("CERT");
		case 38: return("A6");
		case 39: return("DNAME");
		case 40: return("SINK");
		case 41: return("OPT");
		case 42: return("APL");
		case 43: return("DS");
		case 44: return("SSHFP");
		case 45: return("IPSECKEY");
		case 46: return("RRSIG");
		case 47: return("NSEC");
		case 48: return("DNSKEY");
		case 49: return("DHCID");
		default:
			snprintf (result, sizeof(result), "type=%d", type);
			return (result);
	}
}

int main (int argc, char *argv[])
{
	int i, n;
	int flags;
	struct addrinfo ai_hints, *ai_results, *ai;
	char host[NI_MAXHOST], port[NI_MAXSERV];

	printf ("DNS GateWay v%d.%d (dns-gw-%d.%d%s)\n",
		MAJOR_VERSION, MINOR_VERSION,
		MAJOR_VERSION, MINOR_VERSION, RELEASE);

	if (argc<=1) {
		printf ("Usage: %s <port> [<script>]\n", argv[0]);
		exit (EXIT_FAILURE);
	}

#ifdef _WIN32
	WSADATA wsadata;
	i = WSAStartup (2, &wsadata);
	if (i) {
		sckerror ("WSAStartup failed", 0, 0);
		exit (EXIT_FAILURE);
	}
#endif

	memset (&counters, 0, sizeof(counters));

	memset (&ai_hints, 0, sizeof(ai_hints));
	ai_hints.ai_socktype = SOCK_DGRAM;
	ai_hints.ai_flags = (AI_PASSIVE);
	i = getaddrinfo (NULL, argv[1], &ai_hints, &ai_results);
	if (i<0) {
		fprintf (stderr, "getaddrinfo: %s\n", gai_strerror(i));
		exit (EXIT_FAILURE);
	}

	ai = ai_results;
	good = 0;

	for (n=0; n<MAX_SOCKETS; n++) {
		if (!ai) {
			skts[n] = -1;		/* unused socket */
			continue;
		}

		skts[n] = socket (ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (skts[n]<0) {
			sckerror ("socket", (struct sockaddr *)ai->ai_addr, ai->ai_addrlen);
			exit (EXIT_FAILURE);
		}

		/* Don't share this socket with child processes - set FD_CLOEXEC */
		flags = fcntl (skts[n], F_GETFD, 0);
		if (flags == -1) {
			perror ("F_GETFD on socket");
		} else {
			flags = fcntl (skts[n], F_SETFD, flags | FD_CLOEXEC);
			if (flags == -1) perror ("F_SETFD on socket");
		}

#ifndef _WIN32
		if (ai->ai_family == AF_INET6) {
			i = 1;
			setsockopt (skts[n], IPPROTO_IPV6, IPV6_V6ONLY, &i, sizeof(i));
		}
#endif

		i = bind (skts[n], (struct sockaddr *)ai->ai_addr, ai->ai_addrlen);
		if (i<0) {
			sckerror ("bind", ai->ai_addr, sizeof(struct sockaddr));
			close (skts[n]);
			skts[n] = -1;
		} else {
			i = getnameinfo ((struct sockaddr *)ai->ai_addr, ai->ai_addrlen,
				host, sizeof(host), port, sizeof(port),
				NI_NUMERICHOST | NI_NUMERICSERV);
			printf ("#%d bound to [%s]:%s\n", skts[n], host, port);
			good++;
		}

		ai = ai->ai_next;
	}

	freeaddrinfo (ai_results);

	if (argc > 2) sys_script = argv[2];

	/* Create free list for jobs */
	free_jobs = malloc (sizeof(struct job_t) * NO_JOBS);
	CHECK_MALLOC (free_jobs);
	for (i=1; i<NO_JOBS; i++)
		free_jobs[i-1].link = &free_jobs[i];

	signal (SIGUSR1, sig_counters);
	signal (SIGCHLD, sig_child);

	while (good) mainloop ();

#ifdef _WIN32
	WSACleanup ();
#endif
}

static void mainloop ()
{
	int n;
	int nfds=0;
	fd_set fds;
	struct timeval tv, *ptv = NULL;
	unsigned long now;
	struct job_t *job;
	pid_t pid;

	FD_ZERO (&fds);
	for (n = 0; n < MAX_SOCKETS; n++)
		if (skts[n] >= 0) {
			FD_SET (skts[n], &fds);
			if (skts[n] > nfds) nfds = skts[n];
		}
	for (job = active_jobs; job; job = job->link)
		if (job->pipe >= 0) {
			FD_SET (job->pipe, &fds);
			if (job->pipe > nfds) nfds = job->pipe;
		}

	if (active_jobs) {
		tv.tv_sec = 1; tv.tv_usec = 0;
		ptv = &tv;	/* Enable timeout */
	}

	nfds = select (nfds+1, &fds, NULL, NULL, ptv);

	if (nfds>0) {
		for (n=0; n<MAX_SOCKETS; n++) {
			if (skts[n] >= 0 && FD_ISSET (skts[n], &fds))
				process_request (skts[n]);
		}
		for (job = active_jobs; job; job = job->link)
			if (job->pipe >= 0 && FD_ISSET (job->pipe, &fds))
				process_reply (job);
	}

	/* Sort out any un-cooperative scripts!! */
	now = get_timer();
	for (job = active_jobs; job; job = job->link) {

		/* job->pid could be changed by signal handler! */
		pid = job->pid;

		if (pid) {
			if ((now - job->start) >= 5000) {
				if (kill (-pid, SIGKILL)) perror ("SIGKILL");
			} else if ((now - job->start) >= 3000) {
				if (kill (-pid, SIGTERM)) perror("SIGTERM");
			}
		}
	}

	if (counters.signal) {
		printf ("Counters: overrun=%lu, badquery=%lu, duplicate=%lu, "
			"syserr=%lu, nomatch=%lu, success=%lu\n",
			counters.overrun, counters.badquery, counters.duplicate,
			counters.syserr, counters.nomatch, counters.success);
		fflush (stdout);
		counters.signal = 0;
	}
}

static void process_request(int skt)
{
	struct job_t *job;
	int bytes;
	char buffer[BUFLEN];
	socklen_t len;
	char host[NI_MAXHOST], port[NI_MAXSERV];
	struct sockaddr_storage ss;
	DNSQUERY *query;

	len = sizeof(ss);
	bytes = recvfrom (skt, buffer, BUFLEN, 0,
		(struct sockaddr *)&ss, &len);
	if (bytes<0) {
		sckerror ("recv", (struct sockaddr *)&ss, len);
		return;
	}
	getnameinfo ((struct sockaddr *)&ss, len,
		host, sizeof(host), port, sizeof(port),
		NI_NUMERICHOST | NI_NUMERICSERV);
	printf ("%s UTC recv %d bytes from %s:%s\n",
		timestamp(), bytes, host, port);

	if (!free_jobs) {
		counters.overrun++;
		return;
	}

	query = parse_query(buffer, bytes);
	if (!query) {
		counters.syserr++;
		return;
	}

	if (!GET_REPLY_CODE (query->flags)) {
		/* Check for duplicate requests by tranid and source */
		for (job = active_jobs; job; job = job->link)
			if (query->tranid == job->query->tranid
					&& !cmpsockaddr(job->sa, (struct sockaddr *)&ss)) {
				free_query (query, FREE_ALL);
				counters.duplicate++;
				return;
			}
	}

	/* Allocate a free job entry */
	job = free_jobs;
	free_jobs = free_jobs->link;
	memset (job, 0, sizeof(struct job_t));

	job->skt = skt;
	job->sa = malloc(len);
	CHECK_MALLOC (job->sa);
	memcpy (job->sa, &ss, len);
	job->sa_len = len;
	job->query = query;
	job->start = get_timer();
	job->question = job->query->questions;
	job->ref = &job->question->offset;
	job->pipe = -1;
	job->ttl = sys_ttl;

	/* Add to active list */
	job->link = active_jobs;
	active_jobs = job;

	/* Get rid of any existing resource records */
	free_query (query, FREE_ANSWERS);
	free_query (query, FREE_AUTHORITY);
	free_query (query, FREE_ADDITIONAL);

	/* Clear unsupported flags */
	query->flags &= ~(FLAGS_AUTHENTICATED_DATA | FLAGS_RECURSION_AVAIL);

	if (GET_OPCODE(query->flags) != 0) {
		SET_REPLY_CODE (query->flags, REPLY_NOTIMP);
		counters.badquery++;
	}

	if (!ask_next_question (job))
		job_done(job);
}

DNSRESOURCE *parse_resource (MSGBUF *m)
{
	DNSRESOURCE *r;
	uint16_t addrlen;

	r = malloc(sizeof(DNSRESOURCE));
	CHECK_MALLOC (r);

	memset (r, 0, sizeof(DNSRESOURCE));

	if ((r->nameref.text = getname (m)) == NULL) goto abort;
	if (MBget_uint16n (m, &r->type)) goto abort;
	if (MBget_uint16n (m, &r->class)) goto abort;
	if (MBget_uint32n (m, &r->ttl)) goto abort;
	if (MBget_uint16n (m, &addrlen)) goto abort;

	r->offset = MBtell(m);
	if (!(r->addr = MBcreate(addrlen))) goto abort;
	if (MBcopy (r->addr, m, addrlen) < 0) goto abort;

	return (r);

abort:
	free (r);
	return (NULL);
}

static DNSQUERY *parse_query (char *buffer, size_t bytes)
{
	int n;
	DNSQUERY *query = NULL;
	MSGBUF *m = NULL;
	DNSRESOURCE **pnext, *r;

	query = malloc (sizeof(DNSQUERY));
	CHECK_MALLOC (query);
	memset (query, 0, sizeof(DNSQUERY));

	/* Create a msgbuf and attach buffer so we can parse it */
	m = MBcreate (0);
	MBattach (m, buffer, bytes);

	if (MBget_uint16n (m, &query->tranid)) goto abort;
	if (MBget_uint16n (m, &query->flags)) goto abort;
	if (MBget_uint16n (m, &query->num_questions)) goto abort;
	if (MBget_uint16n (m, &query->num_answers)) goto abort;
	if (MBget_uint16n (m, &query->num_authority)) goto abort;
	if (MBget_uint16n (m, &query->num_additional)) goto abort;

	/* Decode Questions */
	for (n=0; n<query->num_questions; n++) {
		DNSQUESTION *q;

		q = malloc(sizeof(DNSQUESTION));
		CHECK_MALLOC (q);

		q->offset = MBtell(m);
		if ((q->name = getname (m)) == NULL) goto abort;
		if (MBget_uint16n (m, &q->type)) goto abort;
		if (MBget_uint16n (m, &q->class)) goto abort;

		/* Add to overal query */
		q->link = query->questions;
		query->questions = q;
	}

	pnext = &query->answers;
	for (n=0; n<query->num_answers; n++) {
		r = parse_resource (m);
		if (!r) goto abort;

		/* Append to list */
		r->link = *pnext;
		*pnext = r;
		pnext = &(r->link);
	}

	pnext = &query->authority;
	for (n=0; n<query->num_authority; n++) {
		r = parse_resource (m);
		if (!r) goto abort;

		/* Append to list */
		r->link = *pnext;
		*pnext = r;
		pnext = &(r->link);
	}

	pnext = &query->additional;
	for (n=0; n<query->num_additional; n++) {
		r = parse_resource (m);
		if (!r) goto abort;

		/* Append to list */
		r->link = *pnext;
		*pnext = r;
		pnext = &(r->link);
	}

	n = MBlen (m) - MBtell (m);
	if (n > 0)
		fprintf (stderr, "Warning: %d bytes remaining after query parsed\n", n);

	/* We don't expect / want responses or reply codes */
	if ((query->flags & FLAGS_RESPONSE)
		|| GET_REPLY_CODE (query->flags))
		SET_REPLY_CODE (query->flags, REPLY_FORMERR);

	MBfree (m);

	return (query);

abort:
	fprintf (stderr, "parse_query: aborted\n");
	if (m) MBfree (m);

	SET_REPLY_CODE (query->flags, REPLY_FORMERR);

	return (query);
}

static void process_reply (struct job_t *job)
{
	ssize_t r;
	char c;

	while ((r = read (job->pipe, &c, 1)) > 0) {
		if (job->bpos < sizeof(job->buffer) - 1)
			job->buffer[job->bpos++] = c;
		if (c == '\n' || c == 0) {
			job->buffer[job->bpos] = 0;
			parse_results_ip (job);
			job->bpos = 0;
		}
	}

	if (r < 0) return;

	close (job->pipe);
	job->pipe = -1;

	/* Move on to next question for this query */
	job->question = job->question->link;
	if (!ask_next_question (job))
		job_done (job);
}

static void job_done (struct job_t *job)
{
	struct job_t **pjob;

	/* Finalise ultimate response */
	if (GET_REPLY_CODE(job->query->flags)) {
		free_query (job->query, FREE_ANSWERS);
		free_query (job->query, FREE_AUTHORITY);
		free_query (job->query, FREE_ADDITIONAL);
	} else if (job->query->num_answers > 0) {
		counters.success++;
	}

	/* Send response - if we have something to report */
	if (job->query->num_answers > 0
			|| GET_REPLY_CODE(job->query->flags)) {

		job->query->flags |= (FLAGS_RESPONSE);
		send_response (job);
	}

	/* Remove job from active list */
	for (pjob = &active_jobs; *pjob; pjob = &(*pjob)->link)
		if (job == *pjob) {
			*pjob = job->link;
			break;
		}

	/* Release attached memory buffers */
	free_query (job->query, FREE_ALL);
	ZFREE (job->sa);

	/* Return job entry to free list */
	memset (job, 0, sizeof(struct job_t));
	job->link = free_jobs;
	free_jobs = job;

}

static int put_resource (MSGBUF *m, DNSRESOURCE *r)
{
	if (putnameref (m, &r->nameref)) return (-1);
	if (MBput_uint16n (m, r->type)) return (-1);
	if (MBput_uint16n (m, r->class)) return (-1);
	if (MBput_uint32n (m, r->ttl)) return (-1);
	if (MBput_uint16n (m, MBlen(r->addr))) return (-1);
	r->offset = MBlen(m);		/* Mark offset of addr */
	MBseek (r->addr, 0, SEEK_SET);	/* Output whole of data */
	if (MBcopy (m, r->addr, MBlen(r->addr)) < 0) return (-1);

	return (0);
}

static void send_response (struct job_t *job)
{
	int bytes;
	size_t valid_bytes = 0;	/* Checkpoint at complete records */
	MSGBUF *m;
	DNSQUESTION *question;
	DNSRESOURCE *resource;

	m = MBcreate (max_send);
	if (!m) return;

	/* DNS Header */
	if (MBput_uint16n (m, job->query->tranid)) goto send_now;
	if (MBput_uint16n (m, job->query->flags)) goto send_now;
	if (MBput_uint16n (m, job->query->num_questions)) goto send_now;
	if (MBput_uint16n (m, job->query->num_answers)) goto send_now;
	if (MBput_uint16n (m, job->query->num_authority)) goto send_now;
	if (MBput_uint16n (m, job->query->num_additional)) goto send_now;
	valid_bytes = MBlen (m);

	for (question = job->query->questions; question; question = question->link) {
		question->offset = MBlen(m);
		if (putname (m, question->name)) goto send_now;
		if (MBput_uint16n (m, question->type)) goto send_now;
		if (MBput_uint16n (m, question->class)) goto send_now;
		valid_bytes = MBlen (m);
	}

	for (resource = job->query->answers; resource; resource = resource->link) {
		if (put_resource (m, resource)) goto send_now;
		valid_bytes = MBlen (m);
	}

	for (resource = job->query->authority; resource; resource = resource->link) {
		if (put_resource (m, resource)) goto send_now;
		valid_bytes = MBlen (m);
	}

	for (resource = job->query->additional; resource; resource = resource->link) {
		if (put_resource (m, resource)) goto send_now;
		valid_bytes = MBlen (m);
	}

send_now:
	bytes = sendto (job->skt, MBdata(m), valid_bytes, 0, job->sa, job->sa_len);

	if (bytes < 0) {
		perror ("sento");
	} else {
		printf ("ID %hu: reply %s %s (%'lu ms): "
			"%d ans, %d auth, %d add (%d bytes)\n",
			job->query->tranid, replyname(GET_REPLY_CODE(job->query->flags)),
			flagnames (job->query->flags), get_timer() - job->start,
			job->query->num_answers, job->query->num_authority,
			job->query->num_additional, bytes);
	}

	MBfree (m);
}

static pid_t ask_next_question (struct job_t *job)
{
	struct stat st;
	char *ptr;
	pid_t pid;
	int fd[2];
	int flags;
	size_t size;

	if (GET_REPLY_CODE (job->query->flags)	/* Already failed */
		|| !job->question)		/* No more questions */
		return (0);

	size = strlen(sys_script) + strlen(job->question->name) + 5;
	char path[size];

	if (job->question->class != 1) {		/* IN */
		SET_REPLY_CODE (job->query->flags, REPLY_NOTIMP);
		counters.nomatch++;
		return (0);
	}

	switch (job->question->type) {
		case 1:		/* A */
		case 5:		/* CNAME */
		case 12:	/* PTR */
		case 28:	/* AAAA */
			break;
		default:
			SET_REPLY_CODE (job->query->flags, REPLY_NOTIMP);
			counters.nomatch++;
			return (0);
		}

	if (*sys_script == '/')
		strcpy (path, sys_script);	/* Absolute path */
	else
		snprintf (path, size, "./%s", sys_script);	/* Current directory */

	if (stat (path, &st)) {
		fprintf (stderr, "ID %hu: script file %s: ",
			job->query->tranid, path);
		perror ("");
		SET_REPLY_CODE (job->query->flags, REPLY_SERVFAIL);
		counters.syserr++;
		return (0);
	}

	if (S_ISDIR (st.st_mode)) {
		ptr = job->question->name;

		/*
		 * Find the filename which matches the most of the
		 * question name in the scripts directory specified.
		 */
		while (*ptr) {
			if (*sys_script == '/')
				snprintf (path, size, "%s/%s", sys_script, ptr);
			else
				snprintf (path, size, "./%s/%s", sys_script, ptr);
			if (!stat (path, &st)) break;

			while (*ptr && *ptr != '.') ptr++;
			if (*ptr) ptr++;
		}

		if (!*ptr) {
			fprintf (stderr, "ID %hu: nothing in '%s' for %s/%s/%s\n",
				job->query->tranid, sys_script, job->question->name,
				classname(job->question->class), typename(job->question->type));
//			Ignore - sending reply only invites re-tries
//			SET_REPLY_CODE (job->query->flags, REPLY_SERVFAIL);
			counters.nomatch++;
			return (0);
		}

		/* Have specific script for this domain */
		job->query->flags |= FLAGS_AUTHORATIVE_ANSWER;
	}

	if (!S_ISREG (st.st_mode)) {
		fprintf (stderr, "ID %hu: %s is not a script file\n",
			job->query->tranid, path);
		SET_REPLY_CODE (job->query->flags, REPLY_SERVFAIL);
		counters.syserr++;
		return (0);
	}

	if (pipe (fd)) {
		perror ("pipe");
		SET_REPLY_CODE (job->query->flags, REPLY_SERVFAIL);
		counters.syserr++;
		return (0);
	}

	pid = fork ();
	if (pid < 0) {
		perror ("fork() failed");
		SET_REPLY_CODE (job->query->flags, REPLY_SERVFAIL);
		counters.syserr++;
		return (0);
	}

	/* fork() - branch to new process */
	if (pid == 0) {
		close (fd[0]);	/* Close read end */
		dup2 (fd[1], STDOUT_FILENO);

		/* Create a separate session for this process */
		setsid();

		execl (path, path, job->question->name,
			classname(job->question->class),
			typename(job->question->type), NULL);

		/* If exec() returns it has failed - abort sub-process */
		fprintf (stderr, "ID %hu: script file %s: ",
			job->query->tranid, path);
		perror ("");
		_exit (EXIT_FAILURE);
	}

	/* fork() - continue in existing process */

	close (fd[1]);	/* Close write end */

	/* Don't share this pipe with child processes - set FD_CLOEXEC */
	flags = fcntl (fd[0], F_GETFD, 0);
	if (flags == -1) {
		perror ("F_GETFD on pipe");
	} else {
		flags = fcntl (fd[0], F_SETFD, flags | FD_CLOEXEC);
		if (flags == -1) perror ("F_SETFD on pipe");
	}

	/* Set the pipe for non-blocking I/O - set O_NONBLOCK */
	flags = fcntl (fd[0], F_GETFL, 0);
	if (flags == -1) {
		perror ("F_GETFL on pipe");
	} else {
		flags = fcntl (fd[0], F_SETFL, flags | O_NONBLOCK);
		if (flags == -1) perror ("F_SETFL on pipe");
	}

	job->pipe = fd[0];
	job->pid = pid;

	printf ("ID %hu: @%d #%d %s %s %s %s\n",
		job->query->tranid, job->pid, job->pipe,
		path, job->question->name,
		classname(job->question->class),
		typename(job->question->type));

	return (pid);
}

static void parse_results_ip (struct job_t *job)
{
	const char *delims = " \t\n\r";
	char *token, *ctx;
	struct in_addr ipv4_addr;
	struct in6_addr ipv6_addr;
	DNSRESOURCE *answer = NULL, **pnext;

	token = strtok_r (job->buffer, delims, &ctx);
	if (!token) return;

	if (token[0] == '$') {
		long val;

		if (!strcasecmp("$ttl", token)) {
			token = strtok_r (NULL, delims, &ctx);
			if (!token) return;
			val = atol (token);
			if (val >= 0) job->ttl = val;
			return;
		}
		if (!strcasecmp("$return", token)) {
			token = strtok_r (NULL, delims, &ctx);
			if (token) {
				val = replycode (token);
				if (val > 0) {
					SET_REPLY_CODE (job->query->flags, val);
					free_query (job->query, FREE_ANSWERS);
				} else if (val < 0)
					fprintf (stderr, "Invalid return code <%s>\n", token);
			}
			return;
		}
		if (!strcasecmp("$cname", token)) {
			token = strtok_r (NULL, delims, &ctx);
			if (!token) return;
			answer = malloc (sizeof(DNSRESOURCE));
			CHECK_MALLOC (answer);
			answer->nameref.text = 0;
			answer->nameref.ref = job->ref;
			answer->nameref.idx = 0;
			answer->class = job->question->class;
			answer->type = 5;	/* CNAME */
			answer->ttl = job->ttl;
			answer->addr = MBcreate(0);
			if (putname(answer->addr, token)) {
				MBfree (answer->addr);
				ZFREE (answer);
				return;
			}
			job->ref = &answer->offset;
		}
	} else {

		switch (job->question->type) {
			case 1:	/* A - IPv4 address */
				if (!inet_pton (AF_INET, token, &ipv4_addr))
					break;
				answer = malloc (sizeof(DNSRESOURCE));
				CHECK_MALLOC (answer);
				answer->nameref.text = 0;
				answer->nameref.ref = job->ref;
				answer->nameref.idx = 0;
				answer->class = job->question->class;
				answer->type = job->question->type;
				answer->ttl = job->ttl;
				answer->addr = MBcreate(0);
				MBput (answer->addr, &ipv4_addr, sizeof(ipv4_addr));
				break;

			case 28:	/* AAAA - IPv6 address */
				if (!inet_pton (AF_INET6, token, &ipv6_addr))
					break;
				answer = malloc (sizeof(DNSRESOURCE));
				CHECK_MALLOC (answer);
				answer->nameref.text = 0;
				answer->nameref.ref = job->ref;
				answer->nameref.idx = 0;
				answer->class = job->question->class;
				answer->type = job->question->type;
				answer->ttl = job->ttl;
				answer->addr = MBcreate(0);
				MBput (answer->addr, &ipv6_addr, sizeof(ipv6_addr));
				break;

			case 5:		/* CNAME */
			case 12:	/* PTR */
				answer = malloc (sizeof(DNSRESOURCE));
				CHECK_MALLOC (answer);
				answer->nameref.text = 0;
				answer->nameref.ref = job->ref;
				answer->nameref.idx = 0;
				answer->class = job->question->class;
				answer->type = job->question->type;
				answer->ttl = job->ttl;
				answer->addr = MBcreate(0);
				if (putname(answer->addr, token)) {
					MBfree (answer->addr);
					ZFREE (answer);
				}
				break;

			default:
				fprintf (stderr, "Can't handle response for %s\n",
					typename(job->question->type));
		}
	}

	if (answer) {
		/* Find end of list of answers - as pointer to link field */
		for (pnext = &job->query->answers; *pnext; pnext = &(*pnext)->link);

		/* Add new answer to end of list */
		answer->link = NULL;
		*pnext = answer;
		pnext = &(answer->link);

		job->query->num_answers++;
	}
}
