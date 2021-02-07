#define _DEFAULT_SOURCE 1

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#include "msgbuf.h"

/* Runtime Endianess tests (requires stdint.h) */
static const char _endian_magic_constant[] = "1234";
#define ENDIAN_MAGIC (*(uint32_t *)_endian_magic_constant)
#define LITTLE_ENDIAN_MAGIC		0x34333231
#define BIG_ENDIAN_MAGIC   		0x31323334

#define MAX_SIZE 32768
#define BLK_SIZE	64
#define SIZE2BLKS(s) (size_t)((s + BLK_SIZE - 1) / BLK_SIZE)

/* Private (internal) functions */

static int _mbresize (MSGBUF *pmb, size_t size)
{
	void *newdata = NULL;

	if (pmb->flags & MBF_EXTERNAL_BUFFER) {
		errno = EPERM;
		return (-1);
	}
	if (size < 0 || size > MAX_SIZE) {
		errno = EINVAL;
		return (-1);
	}

	if (size < pmb->len) size = pmb->len;

	if (SIZE2BLKS(pmb->size) == SIZE2BLKS(size)) {
		pmb->size = size;
		return (0);
	}

	if (!size) {
		if (pmb->data) free (pmb->data);
		pmb->data = NULL;
		pmb->size = pmb->len = pmb->pos = 0;
		return (0);
	}

	newdata = realloc (pmb->data, SIZE2BLKS(size) * BLK_SIZE);
	if (!newdata) return (-1);

	pmb->size = size;
	pmb->data = newdata;

	return (0);
}

static int _mbput (MSGBUF *pmb, void *data, size_t len)
{
	if (pmb->flags & MBF_DYNAMIC_RESIZE) {
		if (_mbresize (pmb, pmb->size + len))
			return (-1);
	} else {
		if (pmb->len + len > pmb->size) {
			errno = ENOMEM;
			return (-1);
		}
	}

	memcpy (pmb->data + pmb->len, data, len);

	pmb->len += len;
	return (0);
}

static int _mbputn (MSGBUF *pmb, void *data, size_t len)
{
	int i;
	char *src, *dst;

	if (pmb->flags & MBF_DYNAMIC_RESIZE) {
		if (_mbresize (pmb, pmb->size + len))
			return (-1);
	} else {
		if (pmb->len + len > pmb->size) {
			errno = ENOMEM;
			return (-1);
		}
	}

	src = (char *)data;
	dst = (char *)pmb->data + pmb->len;

	switch (ENDIAN_MAGIC) {
		case BIG_ENDIAN_MAGIC:
			/* No endianess conversion needed */
			memcpy (dst, src, len);
			break;
		case LITTLE_ENDIAN_MAGIC:
			/* Reverse byte order */
			for (i=0; i<len; i++) {
				dst[i] = src[len-i-1];
			}
			break;
		default:
			fprintf (stderr,
				"ERROR: Unable to determine Endianess (Magic=%04x)\n", ENDIAN_MAGIC);
			return (-1);
	}

	pmb->len += len;
	return (0);
}

static ssize_t _mbget (MSGBUF *pmb, void *data, size_t len)
{
	if (len > pmb->len - pmb->pos) {
		errno = EPERM;
		return (-1);
	}

	memcpy (data, pmb->data + pmb->pos, len);

	pmb->pos += len;
	return (len);
}

static size_t _mbgetn (MSGBUF *pmb, void *data, size_t len)
{
	int i;
	char *src, *dst;

	if (len > pmb->len - pmb->pos) {
		errno = EPERM;
		return (-1);
	}

	src = (char *)pmb->data + pmb->pos;
	dst = (char *)data;

	switch (ENDIAN_MAGIC) {
		case BIG_ENDIAN_MAGIC:
			/* No endianess conversion needed */
			memcpy (dst, src, len);
			break;
		case LITTLE_ENDIAN_MAGIC:
			/* Reverse byte order */
			for (i=0; i<len; i++) {
				dst[i] = src[len-i-1];
			}
			break;
		default:
			fprintf (stderr,
				"ERROR: Unable to determine Endianess: (Magic=%04x)\n", ENDIAN_MAGIC);
			return (-1);
	}

	pmb->pos += len;
	return (len);
}


/* Public functions */

MSGBUF *MBcreate (size_t size)
{
	MSGBUF *pmb;

	pmb = malloc (sizeof(MSGBUF));
	if (!pmb) return (NULL);

	pmb->size = pmb->len = pmb->pos = 0;
	pmb->data = NULL;

	if (size>0) {
		pmb->flags = 0;
		if (_mbresize (pmb, size)) {
			free (pmb);
			return (NULL);
		}
	} else {
		pmb->flags = MBF_DYNAMIC_RESIZE;
	}

	return (pmb);
}

void MBattach (MSGBUF *pmb, void * data, size_t len)
{
	if (!(pmb->flags & MBF_EXTERNAL_BUFFER) && pmb->data)
		free (pmb->data);

	pmb->data = data;
	pmb->size = len;
	pmb->len = len;
	pmb->pos = 0;
	pmb->flags = MBF_EXTERNAL_BUFFER;
}

void MBfree (MSGBUF *pmb)
{
	if (pmb->data && !(pmb->flags & MBF_EXTERNAL_BUFFER))
		free (pmb->data);

	free (pmb);
}

int MBseek (MSGBUF *pmb, long offset, int origin)
{

	switch (origin) {

		case SEEK_SET:
			if (offset < 0 || offset > pmb->len)
				return (-1);
			pmb->pos = offset;
			return (0);

		case SEEK_CUR:
			if ((pmb->pos + offset) < 0 || (pmb->pos + offset) > pmb->len)
				return (-1);
			pmb->pos += offset;
			return (0);

		case SEEK_END:
			if ((pmb->len + offset) < 0 || offset > 0)
				return (-1);
			pmb->len += offset;
			return (0);

		default:
			return (-1);
	}
}

ssize_t MBcopy (MSGBUF *dst_mb, MSGBUF *src_mb, size_t len)
{
	if (!len) return (0);

	if (len > src_mb->len - src_mb->pos)
			return (-1);

	if (dst_mb->flags & MBF_DYNAMIC_RESIZE) {
		if (_mbresize (dst_mb, dst_mb->size + len))
			return (-1);
	} else {
		if (dst_mb->len + len > dst_mb->size) {
			errno = ENOMEM;
			return (-1);
		}
	}

	memcpy (dst_mb->data + dst_mb->len, src_mb->data + src_mb->pos, len);

	src_mb->pos += len;
	dst_mb->len += len;

	return (len);
}

int MBput (MSGBUF *pmb, void *data, size_t len)
{
	return (_mbput(pmb, data, len));
}

int MBput_int16 (MSGBUF *pmb, int16_t value)
{
	return (_mbput(pmb, &value, sizeof(value)));
}

int MBput_int32 (MSGBUF *pmb, int32_t value)
{
	return (_mbput(pmb, &value, sizeof(value)));
}

int MBput_int64 (MSGBUF *pmb, int64_t value)
{
	return (_mbput(pmb, &value, sizeof(value)));
}

int MBput_uint16 (MSGBUF *pmb, uint16_t value)
{
	return (_mbput(pmb, &value, sizeof(value)));
}

int MBput_uint32 (MSGBUF *pmb, uint32_t value)
{
	return (_mbput(pmb, &value, sizeof(value)));
}

int MBput_uint64 (MSGBUF *pmb, uint64_t value)
{
	return (_mbput(pmb, &value, sizeof(value)));
}

int MBput_int16n (MSGBUF *pmb, int16_t value)
{
	return (_mbputn(pmb, &value, sizeof(value)));
}

int MBput_int32n (MSGBUF *pmb, int32_t value)
{
	return (_mbputn(pmb, &value, sizeof(value)));
}

int MBput_int64n (MSGBUF *pmb, int64_t value)
{
	return (_mbputn(pmb, &value, sizeof(value)));
}

int MBput_uint16n (MSGBUF *pmb, uint16_t value)
{
	return (_mbputn(pmb, &value, sizeof(value)));
}

int MBput_uint32n (MSGBUF *pmb, uint32_t value)
{
	return (_mbputn(pmb, &value, sizeof(value)));
}

int MBput_uint64n (MSGBUF *pmb, uint64_t value)
{
	return (_mbputn(pmb, &value, sizeof(value)));
}

ssize_t MBget (MSGBUF *pmb, void *data, size_t len)
{
	if (len > pmb->len - pmb->pos)
		len = pmb->len - pmb->pos;
	if (!len) return (0);

	return (_mbget(pmb, data, len));
}

int MBget_int16 (MSGBUF *pmb, int16_t *pvalue)
{
	return (_mbget(pmb, pvalue, sizeof(*pvalue))<0 ? -1 : 0);
}

int MBget_int32 (MSGBUF *pmb, int32_t *pvalue)
{
	return (_mbget(pmb, pvalue, sizeof(*pvalue))<0 ? -1 : 0);
}

int MBget_int64 (MSGBUF *pmb, int64_t *pvalue)
{
	return (_mbget(pmb, pvalue, sizeof(*pvalue))<0 ? -1 : 0);
}

int MBget_uint16 (MSGBUF *pmb, uint16_t *pvalue)
{
	return (_mbget(pmb, pvalue, sizeof(*pvalue))<0 ? -1 : 0);
}

int MBget_uint32 (MSGBUF *pmb, uint32_t *pvalue)
{
	return (_mbget(pmb, pvalue, sizeof(*pvalue))<0 ? -1 : 0);
}

int MBget_uint64 (MSGBUF *pmb, uint64_t *pvalue)
{
	return (_mbget(pmb, pvalue, sizeof(*pvalue))<0 ? -1 : 0);
}

int MBget_int16n (MSGBUF *pmb, int16_t *pvalue)
{
	return (_mbgetn(pmb, pvalue, sizeof(*pvalue))<0 ? -1 : 0);
}

int MBget_int32n (MSGBUF *pmb, int32_t *pvalue)
{
	return (_mbgetn(pmb, pvalue, sizeof(*pvalue))<0 ? -1 : 0);
}

int MBget_int64n (MSGBUF *pmb, int64_t *pvalue)
{
	return (_mbgetn(pmb, pvalue, sizeof(*pvalue))<0 ? -1 : 0);
}

int MBget_uint16n (MSGBUF *pmb, uint16_t *pvalue)
{
	return (_mbgetn(pmb, pvalue, sizeof(*pvalue))<0 ? -1 : 0);
}

int MBget_uint32n (MSGBUF *pmb, uint32_t *pvalue)
{
	return (_mbgetn(pmb, pvalue, sizeof(*pvalue))<0 ? -1 : 0);
}

int MBget_uint64n (MSGBUF *pmb, uint64_t *pvalue)
{
	return (_mbgetn(pmb, pvalue, sizeof(*pvalue))<0 ? -1 : 0);
}

void MBdump (MSGBUF *pmb, char *caption)
{
	int i;
	char print[20], *pp=print;

	if (!caption) caption = "MBdump";

	printf ("%s: Size=%ld, Len=%ld, Pos=%ld\n",
		caption, (long)pmb->size, (long)pmb->len, (long)pmb->pos);

	for (i=0; i<pmb->len; i++) {
		int c = *((char *)pmb->data + i);

		if (i%16 == 0) {
			printf (" %04X  ", i);
		} else {
			if (i%4 == 0) {
				printf (" ");
				*pp++ = ' ';
			}
		}

		printf ("%02x ", c & 0xff);
		*pp++ = (isprint(c) ? c : '.');

		if ((i+1)%16 == 0) {
			*pp = 0;		/* Termination */
			printf ("*%s*\n", print);
			pp = print;	/* Reset */
		}
	}

	/* Finish partial line */
	for ( ; i<((pmb->len/16+1)*16); i++) {
		if (i%4 == 0) {
			printf (" ");
			*pp++ = ' ';
		}
		fputs ("-- ", stdout);
		*pp++ = ' ';
	}
	*pp = 0;
	printf ("*%s*\n", print);
}
