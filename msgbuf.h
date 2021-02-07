#ifndef _MSGBUF_H
#define _MSGBUF_H

#include <stdint.h>

typedef struct msgbuf_t {
	int flags;
	size_t size, len, pos;
	void *data;
} MSGBUF;

#define MBF_DYNAMIC_RESIZE		0x0001
#define MBF_EXTERNAL_BUFFER		0x0002

#define MBdata(pmb) ((pmb)->data)
#define MBlen(pmb) ((pmb)->len)
#define MBtell(pmb) ((pmb)->pos)
#define MBspace(pmb) ((pmb)->size - (pmb)->len)

MSGBUF *MBcreate (size_t);
void MBattach (MSGBUF *, void *, size_t);
void MBfree (MSGBUF *);
int MBseek (MSGBUF *, long, int);
ssize_t MBcopy (MSGBUF *, MSGBUF *, size_t);

int MBput (MSGBUF*, void *, size_t);

int MBput_int16 (MSGBUF *, int16_t);
int MBput_int32 (MSGBUF *, int32_t);
int MBput_int64 (MSGBUF *, int64_t);

int MBput_uint16 (MSGBUF *, uint16_t);
int MBput_uint32 (MSGBUF *, uint32_t);
int MBput_uint64 (MSGBUF *, uint64_t);

int MBput_int16n (MSGBUF *, int16_t);
int MBput_int32n (MSGBUF *, int32_t);
int MBput_int64n (MSGBUF *, int64_t);

int MBput_uint16n (MSGBUF *, uint16_t);
int MBput_uint32n (MSGBUF *, uint32_t);
int MBput_uint64n (MSGBUF *, uint64_t);

ssize_t MBget (MSGBUF *, void *, size_t);

int MBget_int16 (MSGBUF *, int16_t *);
int MBget_int32 (MSGBUF *, int32_t *);
int MBget_int64 (MSGBUF *, int64_t *);

int MBget_uint16 (MSGBUF *, uint16_t *);
int MBget_uint32 (MSGBUF *, uint32_t *);
int MBget_uint64 (MSGBUF *, uint64_t *);

int MBget_int16n (MSGBUF *, int16_t *);
int MBget_int32n (MSGBUF *, int32_t *);
int MBget_int64n (MSGBUF *, int64_t *);

int MBget_uint16n (MSGBUF *, uint16_t *);
int MBget_uint32n (MSGBUF *, uint32_t *);
int MBget_uint64n (MSGBUF *, uint64_t *);

void MBdump (MSGBUF *, char *);

#endif
