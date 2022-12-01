/*-
 * Copyright (c) 2013 Juniper Networks, Inc.
 * Copyright (c) 2022 Klara Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "opt_tarfs.h"
#include "opt_gzio.h"
#include "opt_zstdio.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/counter.h>
#include <sys/buf.h>
#include <sys/malloc.h>
#include <sys/mount.h>
#include <sys/rmlock.h>
#include <sys/sysctl.h>
#include <sys/uio.h>
#include <sys/vnode.h>

#include <xz.h>

#ifdef GZIO
#include <contrib/zlib/zlib.h>
#endif

#ifdef ZSTDIO
#define ZSTD_STATIC_LINKING_ONLY
#include <contrib/zstd/lib/zstd.h>
#endif

#include <fs/tarfs/tarfs.h>
#include <fs/tarfs/tarfs_dbg.h>

#ifdef TARFS_DEBUG
SYSCTL_NODE(_vfs_tarfs, OID_AUTO, zio, CTLFLAG_RD, 0,
    "Tar filesystem decompression layer");
COUNTER_U64_DEFINE_EARLY(tarfs_zio_inflated);
SYSCTL_COUNTER_U64(_vfs_tarfs_zio, OID_AUTO, inflated, CTLFLAG_RD,
    &tarfs_zio_inflated, "Amount of compressed data inflated.");
COUNTER_U64_DEFINE_EARLY(tarfs_zio_consumed);
SYSCTL_COUNTER_U64(_vfs_tarfs_zio, OID_AUTO, consumed, CTLFLAG_RD,
    &tarfs_zio_consumed, "Amount of compressed data consumed.");

static int
tarfs_sysctl_handle_zio_reset(SYSCTL_HANDLER_ARGS)
{
	unsigned int tmp;
	int error;

	tmp = 0;
	if ((error = SYSCTL_OUT(req, &tmp, sizeof(tmp))) != 0)
		return (error);
	if (req->newptr != NULL) {
		if ((error = SYSCTL_IN(req, &tmp, sizeof(tmp))) != 0)
			return (error);
		counter_u64_zero(tarfs_zio_inflated);
		counter_u64_zero(tarfs_zio_consumed);
	}
	return 0;
}

SYSCTL_PROC(_vfs_tarfs_zio, OID_AUTO, reset,
    CTLTYPE_INT | CTLFLAG_MPSAFE | CTLFLAG_RW,
    NULL, 0, tarfs_sysctl_handle_zio_reset, "IU",
    "Reset compression counters.");
#endif

MALLOC_DEFINE(M_TARFSZSTATE, "tarfs zstate", "tarfs decompression state");
MALLOC_DEFINE(M_TARFSZBUF, "tarfs zbuf", "tarfs decompression buffers");

#define XZ_MAGIC		(uint8_t[]){ 0xfd, 0x37, 0x7a, 0x58, 0x5a }
#define ZLIB_MAGIC		(uint8_t[]){ 0x1f, 0x8b, 0x08 }
#define ZSTD_MAGIC		(uint8_t[]){ 0x28, 0xb5, 0x2f, 0xfd }

/* XXX review use of curthread / uio_td / td_cred */

static int
tarfs_read_raw(struct tarfs_mount *tmp, struct uio *uiop)
{
	struct vnode *vp = tmp->vp;
#ifdef TARFS_DEBUG
	off_t off = uiop->uio_offset;
	size_t len = uiop->uio_resid;
#endif
	int error;

	error = VOP_READ(vp, uiop, IO_DIRECT, uiop->uio_td->td_ucred);
	TARFS_DPF(IO, "%s(%zu, %zu) = %d (resid %zu)\n", __func__,
	    off, len, error, uiop->uio_resid);
	return error;
}

static ssize_t
tarfs_read_direct(struct tarfs_mount *tmp, void *buf, size_t off, size_t len)
{
	struct uio auio;
	struct iovec aiov;
	ssize_t res;
	int error;

	if (len == 0) {
		TARFS_DPF(IO, "%s(%zu, %zu) null\n", __func__,
		    off, len);
		return 0;
	}
	aiov.iov_base = buf;
	aiov.iov_len = len;
	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	auio.uio_offset = off;
	auio.uio_segflg = UIO_SYSSPACE;
	auio.uio_rw = UIO_READ;
	auio.uio_resid = len;
	auio.uio_td = curthread;
	error = tarfs_read_raw(tmp, &auio);
	if (error != 0) {
		TARFS_DPF(IO, "%s(%zu, %zu) error %d\n", __func__,
		    off, len, error);
		return -error;
	}
	res = len - auio.uio_resid;
	if (res == 0 && len != 0) {
		TARFS_DPF(IO, "%s(%zu, %zu) eof\n", __func__,
		    off, len);
	} else {
		TARFS_DPF(IO, "%s(%zu, %zu) read %zu | %*D\n", __func__,
		    off, len, res,
		    (int)(res > 8 ? 8 : res), (u_char *)buf, " ");
	}
	return res;
}

struct tarfs_xz {
	struct xz_dec *s;
	struct xz_buf b;
};

static int
tarfs_read_xz(struct tarfs_mount *tmp, struct uio *uiop)
{
	struct tarfs_xz *xz = tmp->xz;
	struct tarfs_zbuf *zibuf = tmp->zibuf;
	struct tarfs_zbuf *zobuf = tmp->zobuf;
	u_char *cbuf;
	size_t clen;
	ssize_t res;
#ifdef TARFS_DEBUG
	off_t off = uiop->uio_offset;
	size_t len = uiop->uio_resid;
#endif
	int error;

	rms_wlock(&tmp->zio_lock);
	if (uiop->uio_offset < zobuf->off) {
		/* rewind */
		TARFS_DPF(XZ, "%s: rewinding\n", __func__);
		if (zibuf->off > 0) {
			zibuf->off = 0;
			zibuf->len = 0;
		}
		xz->b.in_size = zibuf->len;
		xz->b.in_pos = 0;
		zobuf->off = 0;
		zobuf->len = 0;
		xz->b.out_size = sizeof(zobuf->buf);
		xz->b.out_pos = 0;
		xz_dec_reset(xz->s);
	}
	error = 0;
	for (;;) {
		if (uiop->uio_offset >= zobuf->off &&
		    uiop->uio_offset < zobuf->off + zobuf->len) {
			cbuf = zobuf->buf + (uiop->uio_offset - zobuf->off);
			clen = zobuf->len - (uiop->uio_offset - zobuf->off);
			if (clen > uiop->uio_resid) {
				clen = uiop->uio_resid;
			}
			error = uiomove(cbuf, clen, uiop);
			if (error != 0) {
				break;
			}
		}
		if (uiop->uio_resid == 0) {
			/* done */
			break;
		}
		if (xz->b.in_pos < xz->b.in_size) {
			/* unconsumed data remains in input buffer, move it up */
			TARFS_DPF(XZ, "%s: keep %zu\n", __func__,
			    xz->b.in_size - xz->b.in_pos);
			memmove(zibuf->buf, zibuf->buf + xz->b.in_pos,
			    xz->b.in_size - xz->b.in_pos);
		}
		zibuf->off += xz->b.in_pos;
		zibuf->len -= xz->b.in_pos;
		TARFS_DPF(XZ, "%s: zibuf off %08zx len %08zx\n", __func__,
		    zibuf->off, zibuf->len);
		/* backfill input buffer */
		res = tarfs_read_direct(tmp, zibuf->buf + zibuf->len,
		    zibuf->off + zibuf->len,
		    sizeof(zibuf->buf) - zibuf->len);
		if (res < 0) {
			error = -res;
			break;
		}
		zibuf->len += res;
		xz->b.in_pos = 0;
		xz->b.in_size = zibuf->len;
		if (xz->b.in_size == 0) {
			/* EOF */
			TARFS_DPF(XZ, "%s: eof\n", __func__);
			break;
		}
		/* empty output buffer */
		zobuf->off += zobuf->len;
		zobuf->len = 0;
		xz->b.out_pos = 0;
		xz->b.out_size = sizeof(zobuf->buf);
		TARFS_DPF(XZ, "%s: zobuf off %08zx len %08zx\n", __func__,
		    zobuf->off, zobuf->len);
		/* decompress as much as possible */
		error = xz_dec_run(xz->s, &xz->b);
		if (error == XZ_STREAM_END) {
			TARFS_DPF(XZ, "%s: end of stream after %zu\n", __func__,
			    zibuf->off + xz->b.in_pos);
		} else if (error != XZ_OK) {
			TARFS_DPF(XZ, "%s: inflate failed after %zu: %d\n", __func__,
			    zibuf->off + xz->b.in_pos, error);
			error = EIO;
			break;
		}
		zobuf->len = xz->b.out_pos;
		TARFS_DPF(XZ, "%s: inflated %zu\n", __func__, zobuf->len);
#ifdef TARFS_DEBUG
		counter_u64_add(tarfs_zio_inflated, zobuf->len);
#endif
	}
	TARFS_DPF(IO, "%s(%zu, %zu) = %d (resid %zu)\n", __func__,
	    off, len, error, uiop->uio_resid);
#ifdef TARFS_DEBUG
	counter_u64_add(tarfs_zio_consumed, len - uiop->uio_resid);
#endif
	rms_wunlock(&tmp->zio_lock);
	return error;
}

#ifdef GZIO
static int
tarfs_read_zlib(struct tarfs_mount *tmp, struct uio *uiop)
{
	struct z_stream_s *zlib = tmp->zlib;
	struct tarfs_zbuf *zibuf = tmp->zibuf;
	struct tarfs_zbuf *zobuf = tmp->zobuf;
	u_char *cbuf;
	size_t clen;
	ssize_t res;
#ifdef TARFS_DEBUG
	off_t off = uiop->uio_offset;
	size_t len = uiop->uio_resid;
#endif
	int error;

	rms_wlock(&tmp->zio_lock);
	if (uiop->uio_offset < zobuf->off) {
		/* rewind */
		TARFS_DPF(ZLIB, "%s: rewinding\n", __func__);
		if (zibuf->off > 0) {
			zibuf->off = 0;
			zibuf->len = 0;
		}
		zlib->next_in = zibuf->buf;
		zlib->avail_in = zibuf->len;
		zobuf->off = 0;
		zobuf->len = 0;
		zlib->next_out = zobuf->buf;
		inflateReset(zlib);
	}
	error = 0;
	for (;;) {
		if (uiop->uio_offset >= zobuf->off &&
		    uiop->uio_offset < zobuf->off + zobuf->len) {
			cbuf = zobuf->buf + (uiop->uio_offset - zobuf->off);
			clen = zobuf->len - (uiop->uio_offset - zobuf->off);
			if (clen > uiop->uio_resid) {
				clen = uiop->uio_resid;
			}
			error = uiomove(cbuf, clen, uiop);
			if (error != 0) {
				break;
			}
		}
		if (uiop->uio_resid == 0) {
			/* done */
			break;
		}
		if (zlib->avail_in > 0) {
			/* unconsumed data remains in input buffer, move it up */
			TARFS_DPF(ZLIB, "%s: keep %u\n", __func__,
			    zlib->avail_in);
			memmove(zibuf->buf, zlib->next_in, zlib->avail_in);
		}
		zibuf->off += zlib->next_in - zibuf->buf;
		zibuf->len = zlib->avail_in;
		TARFS_DPF(ZLIB, "%s: zibuf off %08zx len %08zx\n", __func__,
		    zibuf->off, zibuf->len);
		/* backfill input buffer */
		res = tarfs_read_direct(tmp, zibuf->buf + zibuf->len,
		    zibuf->off + zibuf->len,
		    sizeof(zibuf->buf) - zibuf->len);
		if (res < 0) {
			error = -res;
			TARFS_DPF(ZLIB, "%s: read failed: %d\n", __func__,
			    error);
			break;
		}
		zibuf->len += res;
		zlib->next_in = zibuf->buf;
		zlib->avail_in = zibuf->len;
		if (zlib->avail_in == 0) {
			/* EOF */
			TARFS_DPF(ZLIB, "%s: eof\n", __func__);
			break;
		}
		/* empty output buffer */
		zobuf->off += zobuf->len;
		zobuf->len = 0;
		zlib->next_out = zobuf->buf;
		zlib->avail_out = sizeof(zobuf->buf);
		TARFS_DPF(ZLIB, "%s: zobuf off %08zx len %08zx\n", __func__,
		    zobuf->off, zobuf->len);
		/* decompress as much as possible */
		error = inflate(zlib, Z_SYNC_FLUSH);
		if (error == Z_STREAM_END) {
			TARFS_DPF(ZLIB, "%s: end of stream after %zu\n", __func__,
			    zibuf->off + zlib->next_in - zibuf->buf);
		} else if (error != Z_OK) {
			TARFS_DPF(ZLIB, "%s: inflate failed after %zu: %d\n", __func__,
			    zibuf->off + zlib->next_in - zibuf->buf, error);
			error = EIO;
			break;
		}
		zobuf->len = zlib->next_out - zobuf->buf;
		TARFS_DPF(ZLIB, "%s: inflated %zu\n", __func__, zobuf->len);
#ifdef TARFS_DEBUG
		counter_u64_add(tarfs_zio_inflated, zobuf->len);
#endif
	}
	TARFS_DPF(IO, "%s(%zu, %zu) = %d (resid %zu)\n", __func__,
	    off, len, error, uiop->uio_resid);
#ifdef TARFS_DEBUG
	counter_u64_add(tarfs_zio_consumed, len - uiop->uio_resid);
#endif
	rms_wunlock(&tmp->zio_lock);
	return error;
}
#endif

#ifdef ZSTDIO
struct tarfs_zstd {
	ZSTD_DStream *zds;
	ZSTD_inBuffer zib;
	ZSTD_outBuffer zob;
};

static int
tarfs_read_zstd(struct tarfs_mount *tmp, struct uio *uiop)
{
	struct tarfs_zstd *zstd = tmp->zstd;
	struct tarfs_zbuf *zibuf = tmp->zibuf;
	struct tarfs_zbuf *zobuf = tmp->zobuf;
	u_char *cbuf;
	size_t clen, zerror;
	ssize_t res;
#ifdef TARFS_DEBUG
	off_t off = uiop->uio_offset;
	size_t len = uiop->uio_resid;
#endif
	unsigned int i;
	int error;

	rms_wlock(&tmp->zio_lock);
	if (uiop->uio_offset < zobuf->off ||
	    (tmp->curidx < tmp->nidx - 1 && uiop->uio_offset >= tmp->idx[tmp->curidx + 1].o)) {
		// XXX maybe do a binary search instead
		for (i = 0; i < tmp->nidx - 1; i++)
			if (tmp->idx[i + 1].o > uiop->uio_offset)
				break;
		// XXX should try to reuse zibuf if possible
		TARFS_DPF(ZSTD, "%s: skipping to index %u = i %zu o %zu\n", __func__,
		    i, tmp->idx[i].i, tmp->idx[i].o);
		tmp->curidx = i;
		zibuf->off = tmp->idx[i].i;
		zibuf->len = 0;
		zobuf->off = tmp->idx[i].o;
		zobuf->len = 0;
		ZSTD_resetDStream(zstd->zds);
		MPASS(zibuf->off <= uiop->uio_offset);
		zstd->zib.size = zibuf->len;
		zstd->zib.pos = 0;
		zstd->zob.size = sizeof(zobuf->buf);
		zstd->zob.pos = 0;
	}
	error = 0;
	for (;;) {
		if (uiop->uio_offset >= zobuf->off &&
		    uiop->uio_offset < zobuf->off + zobuf->len) {
			cbuf = zobuf->buf + (uiop->uio_offset - zobuf->off);
			clen = zobuf->len - (uiop->uio_offset - zobuf->off);
			if (clen > uiop->uio_resid) {
				clen = uiop->uio_resid;
			}
			error = uiomove(cbuf, clen, uiop);
			if (error != 0) {
				break;
			}
		}
		if (uiop->uio_resid == 0) {
			/* done */
			break;
		}
		if (zstd->zib.pos < zstd->zib.size) {
			/* unconsumed data remains in input buffer, move it up */
			TARFS_DPF(ZSTD, "%s: keep %zu\n", __func__,
			    zstd->zib.size - zstd->zib.pos);
			memmove(zibuf->buf, zibuf->buf + zstd->zib.pos,
			    zstd->zib.size - zstd->zib.pos);
		}
		zibuf->off += zstd->zib.pos;
		zibuf->len -= zstd->zib.pos;
		TARFS_DPF(ZSTD, "%s: zibuf off %08zx len %08zx\n", __func__,
		    zibuf->off, zibuf->len);
		/* backfill input buffer */
		res = tarfs_read_direct(tmp, zibuf->buf + zibuf->len,
		    zibuf->off + zibuf->len,
		    sizeof(zibuf->buf) - zibuf->len);
		if (res < 0) {
			error = -res;
			break;
		}
		zibuf->len += res;
		zstd->zib.pos = 0;
		zstd->zib.size = zibuf->len;
		if (zstd->zib.size == 0) {
			/* EOF */
			TARFS_DPF(ZSTD, "%s: eof\n", __func__);
			break;
		}
		/* empty output buffer */
		zobuf->off += zobuf->len;
		zobuf->len = 0;
		zstd->zob.pos = 0;
		zstd->zob.size = sizeof(zobuf->buf);
		TARFS_DPF(ZSTD, "%s: zobuf off %08zx len %08zx\n", __func__,
		    zobuf->off, zobuf->len);
		/* decompress as much as possible */
		zerror = ZSTD_decompressStream(zstd->zds, &zstd->zob, &zstd->zib);
		if (zerror == 0 && zstd->zob.pos == 0) {
			TARFS_DPF(ZSTD, "%s: end of stream after i %zu o %zu\n", __func__,
			    zibuf->off + zstd->zib.pos,
			    zobuf->off + zstd->zob.pos);
		} else if (zerror == 0) {
			TARFS_DPF(ZSTD, "%s: end of frame after i %zu o %zu\n", __func__,
			    zibuf->off + zstd->zib.pos,
			    zobuf->off + zstd->zob.pos);
			/* update index */
			if (++tmp->curidx >= tmp->nidx) {
				if (++tmp->nidx > tmp->szidx) {
					tmp->szidx *= 2;
					tmp->idx = realloc(tmp->idx,
					    tmp->szidx * sizeof(*tmp->idx),
					    M_TARFSZSTATE, M_ZERO | M_WAITOK);
				}
				tmp->idx[tmp->curidx].i = zibuf->off + zstd->zib.pos;
				tmp->idx[tmp->curidx].o = zobuf->off + zstd->zob.pos;
				TARFS_DPF(XZ, "%s: index %u = i %zu o %zu\n", __func__,
				    tmp->curidx, tmp->idx[tmp->curidx].i, tmp->idx[tmp->curidx].o);
                       }
                       MPASS(tmp->idx[tmp->curidx].i == zibuf->off + zstd->zib.pos);
                       MPASS(tmp->idx[tmp->curidx].o == zobuf->off + zstd->zob.pos);
		} else if (ZSTD_isError(zerror)) {
			TARFS_DPF(ZSTD, "%s: inflate failed after i %zu o %zu: %s\n", __func__,
			    zibuf->off + zstd->zib.pos,
			    zobuf->off + zstd->zob.pos,
			    ZSTD_getErrorName(zerror));
			error = EIO;
			break;
		}
		zobuf->len = zstd->zob.pos;
		TARFS_DPF(ZSTD, "%s: inflated %zu\n", __func__, zobuf->len);
#ifdef TARFS_DEBUG
		counter_u64_add(tarfs_zio_inflated, zobuf->len);
#endif
	}
	TARFS_DPF(IO, "%s(%zu, %zu) = %d (resid %zu)\n", __func__,
	    off, len, error, uiop->uio_resid);
#ifdef TARFS_DEBUG
	counter_u64_add(tarfs_zio_consumed, len - uiop->uio_resid);
#endif
	rms_wunlock(&tmp->zio_lock);
	return error;
}
#endif

int
tarfs_read_cooked(struct tarfs_mount *tmp, struct uio *uiop)
{
#ifdef TARFS_DEBUG
	off_t off = uiop->uio_offset;
	size_t len = uiop->uio_resid;
#endif
	int ret;

	if (tmp->xz != NULL) {
		return tarfs_read_xz(tmp, uiop);
	}
#ifdef GZIO
	if (tmp->zlib != NULL) {
		return tarfs_read_zlib(tmp, uiop);
	}
#endif
#ifdef ZSTDIO
	if (tmp->zstd != NULL) {
		return tarfs_read_zstd(tmp, uiop);
	}
#endif
	ret = tarfs_read_raw(tmp, uiop);
	TARFS_DPF(IO, "%s(%zu, %zu) = %d (resid %zu)\n", __func__,
	    off, len, ret, uiop->uio_resid);
	return ret;
}

ssize_t
tarfs_read_buf(struct tarfs_mount *tmp, void *buf, size_t off, size_t len)
{
	struct uio auio;
	struct iovec aiov;
	ssize_t res;
	int error;

	if (len == 0) {
		TARFS_DPF(IO, "%s(%zu, %zu) null\n", __func__,
		    off, len);
		return 0;
	}
	aiov.iov_base = buf;
	aiov.iov_len = len;
	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	auio.uio_offset = off;
	auio.uio_segflg = UIO_SYSSPACE;
	auio.uio_rw = UIO_READ;
	auio.uio_resid = len;
	auio.uio_td = curthread;
	error = tarfs_read_cooked(tmp, &auio);
	if (error != 0) {
		TARFS_DPF(IO, "%s(%zu, %zu) error %d\n", __func__,
		    off, len, error);
		return -error;
	}
	res = len - auio.uio_resid;
	if (res == 0 && len != 0) {
		TARFS_DPF(IO, "%s(%zu, %zu) eof\n", __func__,
		    off, len);
	} else {
		TARFS_DPF(IO, "%s(%zu, %zu) read %zu | %*D\n", __func__,
		    off, len, res,
		    (int)(res > 8 ? 8 : res), (u_char *)buf, " ");
	}
	return res;
}

#if defined(GZIO) || defined(ZSTDIO)
static void *
tarfs_zstate_nalloc(void *opaque, unsigned int items, unsigned int size)
{

	(void)opaque;
	return malloc(size * items, M_TARFSZSTATE, M_WAITOK);
}
#endif

#ifdef ZSTDIO
static void *
tarfs_zstate_alloc(void *opaque, size_t size)
{

	(void)opaque;
	return malloc(size, M_TARFSZSTATE, M_WAITOK);
}
#endif

#if defined(GZIO) || defined(ZSTDIO)
static void
tarfs_zstate_free(void *opaque, void *address)
{

	(void)opaque;
	free(address, M_TARFSZSTATE);
}
#endif

#ifdef ZSTDIO
static ZSTD_customMem tarfs_zstd_mem = {
	tarfs_zstate_alloc,
	tarfs_zstate_free,
	NULL,
};
#endif

int
tarfs_io_init(struct tarfs_mount *tmp)
{
	u_char block[TARFS_BLOCKSIZE];
	ssize_t res;
	int error;

	rms_init(&tmp->zio_lock, "tarfs decompression lock");
	memset(block, 0, sizeof(block));
	res = tarfs_read_buf(tmp, block, 0, sizeof(block));
	if (res < 0) {
		return -res;
	}
	if (memcmp(block, XZ_MAGIC, sizeof(XZ_MAGIC)) == 0) {
		tmp->zibuf = malloc(sizeof(*tmp->zibuf),
		    M_TARFSZBUF, M_WAITOK);
		tmp->zibuf->off = 0;
		memcpy(tmp->zibuf->buf, block, res);
		tmp->zibuf->len = res;
		TARFS_DPF(ALLOC, "%s: allocated input buffer\n", __func__);
		tmp->zobuf = malloc(sizeof(*tmp->zobuf),
		    M_TARFSZBUF, M_WAITOK);
		tmp->zobuf->off = tmp->zobuf->len = 0;
		TARFS_DPF(ALLOC, "%s: allocated output buffer\n", __func__);
		tmp->xz = malloc(sizeof(*tmp->xz), M_TARFSZSTATE, M_WAITOK);
		tmp->xz->s = xz_dec_init(XZ_DYNALLOC, 1<<24); /* 16 MB */
		tmp->xz->b.in = tmp->zibuf->buf;
		tmp->xz->b.in_pos = 0;
		tmp->xz->b.in_size = tmp->zibuf->len;
		tmp->xz->b.out = tmp->zobuf->buf;
		tmp->xz->b.out_pos = 0;
		tmp->xz->b.out_size = sizeof(tmp->zobuf->buf);
		// fail fast if there's something wrong with the file
		error = xz_dec_run(tmp->xz->s, &tmp->xz->b);
		if (error != XZ_OK) {
			TARFS_DPF(XZ, "%s: xz error %d", __func__,
			    error);
			return EFTYPE;
		}
		tmp->zobuf->len = tmp->xz->b.out_pos;
		TARFS_DPF(XZ, "%s: preloaded %zu bytes\n", __func__,
		    tmp->zobuf->len);
		return 0;
	}
	if (memcmp(block, ZLIB_MAGIC, sizeof(ZLIB_MAGIC)) == 0) {
#ifdef GZIO
		tmp->zibuf = malloc(sizeof(*tmp->zibuf),
		    M_TARFSZBUF, M_WAITOK);
		tmp->zibuf->off = 0;
		memcpy(tmp->zibuf->buf, block, res);
		tmp->zibuf->len = res;
		TARFS_DPF(ALLOC, "%s: allocated input buffer\n", __func__);
		tmp->zobuf = malloc(sizeof(*tmp->zobuf),
		    M_TARFSZBUF, M_WAITOK);
		tmp->zobuf->off = tmp->zobuf->len = 0;
		TARFS_DPF(ALLOC, "%s: allocated output buffer\n", __func__);
		tmp->zlib = malloc(sizeof(*tmp->zlib),
		    M_TARFSZSTATE, M_ZERO | M_WAITOK);
		tmp->zlib->zalloc = tarfs_zstate_nalloc;
		tmp->zlib->zfree = tarfs_zstate_free;
		tmp->zlib->opaque = tmp;
		tmp->zlib->next_in = tmp->zibuf->buf;
		tmp->zlib->avail_in = 0;
		tmp->zlib->next_out = tmp->zobuf->buf;
		tmp->zlib->avail_out = sizeof(tmp->zobuf->buf);
		if (inflateInit2(tmp->zlib, 0x2f) != Z_OK) {
			return EFTYPE;
		}
		return 0;
#else
		printf("zlib compression not supported\n");
		return EOPNOTSUPP;
#endif
	}
	if (memcmp(block, ZSTD_MAGIC, sizeof(ZSTD_MAGIC)) == 0) {
#ifdef ZSTDIO
		tmp->zibuf = malloc(sizeof(*tmp->zibuf),
		    M_TARFSZBUF, M_WAITOK);
		tmp->zibuf->off = 0;
		memcpy(tmp->zibuf->buf, block, res);
		tmp->zibuf->len = res;
		TARFS_DPF(ALLOC, "%s: allocated input buffer\n", __func__);
		tmp->zobuf = malloc(sizeof(*tmp->zobuf),
		    M_TARFSZBUF, M_WAITOK);
		tmp->zobuf->off = tmp->zobuf->len = 0;
		TARFS_DPF(ALLOC, "%s: allocated output buffer\n", __func__);
		tmp->zstd = malloc(sizeof(*tmp->zstd), M_TARFSZSTATE, M_WAITOK);
		tmp->zstd->zds = ZSTD_createDStream_advanced(tarfs_zstd_mem);
		tmp->zstd->zib.src = tmp->zibuf->buf;
		tmp->zstd->zib.size = tmp->zibuf->len;
		tmp->zstd->zib.pos = 0;
		tmp->zstd->zob.dst = tmp->zobuf->buf;
		tmp->zstd->zob.size = sizeof(tmp->zobuf->buf);
		tmp->zstd->zob.pos = 0;
		(void)ZSTD_initDStream(tmp->zstd->zds);
		/*
		 * Initialize the index.  We don't get an explicit
		 * location for the first frame, but resetting to the
		 * beginning of the file works.
		 */
		tmp->szidx = 128;
		tmp->idx = malloc(tmp->szidx * sizeof(*tmp->idx), M_TARFSZSTATE,
		    M_ZERO | M_WAITOK);
		tmp->curidx = 0;
		tmp->nidx = 1;
		return 0;
#else
		printf("zstd compression not supported\n");
		return EOPNOTSUPP;
#endif
	}
	return 0;
}

void
tarfs_io_fini(struct tarfs_mount *tmp)
{

	rms_destroy(&tmp->zio_lock);
	if (tmp->xz != NULL) {
		TARFS_DPF(ALLOC, "%s: freeing xz state\n", __func__);
		xz_dec_end(tmp->xz->s);
		free(tmp->xz, M_TARFSZSTATE);
	}
#ifdef GZIO
	if (tmp->zlib != NULL) {
		TARFS_DPF(ALLOC, "%s: freeing zlib state\n", __func__);
		inflateEnd(tmp->zlib);
		free(tmp->zlib, M_TARFSZSTATE);
	}
#endif
#ifdef ZSTDIO
	if (tmp->zstd != NULL) {
		TARFS_DPF(ALLOC, "%s: freeing zstd state\n", __func__);
		ZSTD_freeDStream(tmp->zstd->zds);
		free(tmp->zstd, M_TARFSZSTATE);
	}
#endif
	if (tmp->zibuf != NULL) {
		TARFS_DPF(ALLOC, "%s: freeing input buffer\n", __func__);
		free(tmp->zibuf, M_TARFSZBUF);
	}
	if (tmp->zobuf != NULL) {
		TARFS_DPF(ALLOC, "%s: freeing output buffer\n", __func__);
		free(tmp->zobuf, M_TARFSZBUF);
	}
	if (tmp->idx != NULL) {
		TARFS_DPF(ALLOC, "%s: freeing index\n", __func__);
		free(tmp->idx, M_TARFSZSTATE);
	}
}
