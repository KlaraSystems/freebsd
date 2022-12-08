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
#include "opt_zstdio.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/counter.h>
#include <sys/bio.h>
#include <sys/buf.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mount.h>
#include <sys/sysctl.h>
#include <sys/uio.h>
#include <sys/vnode.h>

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

#ifdef ZSTDIO
struct tarfs_zstd {
	ZSTD_DStream *zds;
};
#endif

/* XXX review use of curthread / uio_td / td_cred */

/*
 * Reads from the tar file according to the provided uio.  If the archive
 * is compressed and raw is false, reads the decompressed stream;
 * otherwise, reads directly from the original file.  Returns 0 on success
 * and a positive errno value on failure.
 */
int
tarfs_io_read(struct tarfs_mount *tmp, bool raw, struct uio *uiop)
{
#ifdef TARFS_DEBUG
	off_t off = uiop->uio_offset;
	size_t len = uiop->uio_resid;
#endif
	int error;

	if (raw || tmp->znode == NULL) {
		error = VOP_READ(tmp->vp, uiop, IO_DIRECT,
		    uiop->uio_td->td_ucred);
	} else {
		error = vn_lock(tmp->znode, LK_EXCLUSIVE);
		if (error == 0) {
			error = VOP_READ(tmp->znode, uiop, IO_DIRECT,
			    uiop->uio_td->td_ucred);
			VOP_UNLOCK(tmp->znode);
		}
	}
	TARFS_DPF(IO, "%s(%zu, %zu) = %d (resid %zu)\n", __func__,
	    off, len, error, uiop->uio_resid);
	return error;
}

/*
 * Reads from the tar file into the provided buffer.  If the archive is
 * compressed and raw is false, reads the decompressed stream; otherwise,
 * reads directly from the original file.  Returns the number of bytes
 * read on success, 0 on EOF, and a negative errno value on failure.
 */
ssize_t
tarfs_io_read_buf(struct tarfs_mount *tmp, bool raw,
    void *buf, size_t off, size_t len)
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
	error = tarfs_io_read(tmp, raw, &auio);
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

#ifdef ZSTDIO
static void *
tarfs_zstate_alloc(void *opaque, size_t size)
{

	(void)opaque;
	return malloc(size, M_TARFSZSTATE, M_WAITOK);
}
#endif

#ifdef ZSTDIO
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

/*
 * Updates the decompression frame index, recording the current input and
 * output offsets in a new index entry, and growing the index if
 * necessary.
 */
static void
tarfs_zio_update_index(struct tarfs_zio *zio, off_t i, off_t o)
{

	if (++zio->curidx >= zio->nidx) {
		if (++zio->nidx > zio->szidx) {
			zio->szidx *= 2;
			zio->idx = realloc(zio->idx,
			    zio->szidx * sizeof(*zio->idx),
			    M_TARFSZSTATE, M_ZERO | M_WAITOK);
			TARFS_DPF(ALLOC, "%s: resized zio index\n", __func__);
		}
		zio->idx[zio->curidx].i = i;
		zio->idx[zio->curidx].o = o;
		TARFS_DPF(ZIDX, "%s: index %u = i %zu o %zu\n", __func__,
		    zio->curidx, zio->idx[zio->curidx].i, zio->idx[zio->curidx].o);
	}
	MPASS(zio->idx[zio->curidx].i == i);
	MPASS(zio->idx[zio->curidx].o == o);
}

/*
 * VOP_ACCESS for zio node.
 */
static int
tarfs_zaccess(struct vop_access_args *ap)
{
	struct vnode *vp = ap->a_vp;
	struct tarfs_zio *zio = vp->v_data;
	struct tarfs_mount *tmp = zio->tmp;
	accmode_t accmode = ap->a_accmode;
	int error = EPERM;

	if (accmode == VREAD)
		error = VOP_ACCESS(tmp->vp, accmode, ap->a_cred, ap->a_td);
	TARFS_DPF(ZIO, "%s(%d) = %d\n", __func__, accmode, error);
	return error;
}

/*
 * VOP_GETATTR for zio node.
 */
static int
tarfs_zgetattr(struct vop_getattr_args *ap)
{
	struct vattr va;
	struct vnode *vp = ap->a_vp;
	struct tarfs_zio *zio = vp->v_data;
	struct tarfs_mount *tmp = zio->tmp;
	struct vattr *vap = ap->a_vap;
	int error = 0;

	VATTR_NULL(vap);
	error = VOP_GETATTR(tmp->vp, &va, ap->a_cred);
	if (error == 0) {
		vap->va_type = VREG;
		vap->va_mode = va.va_mode;
		vap->va_nlink = 1;
		vap->va_gid = va.va_gid;
		vap->va_uid = va.va_uid;
		vap->va_fsid = vp->v_mount->mnt_stat.f_fsid.val[0];
		vap->va_fileid = TARFS_ZIOINO;
		vap->va_size = zio->idx[zio->nidx - 1].o;
		vap->va_blocksize = vp->v_mount->mnt_stat.f_iosize;
		vap->va_atime = va.va_atime;
		vap->va_ctime = va.va_ctime;
		vap->va_mtime = va.va_mtime;
		vap->va_birthtime = tmp->root->birthtime;
		vap->va_bytes = va.va_bytes;
	}
	TARFS_DPF(ZIO, "%s() = %d\n", __func__, error);
	return error;
}

/*
 * VOP_READ for zio node.
 */
static int
tarfs_zread(struct vop_read_args *ap)
{
	struct vnode *vp = ap->a_vp;
	struct tarfs_zio *zio = vp->v_data;
	struct tarfs_mount *tmp = zio->tmp;
	struct uio *uiop = ap->a_uio;
	struct buf *bp;
	off_t off = uiop->uio_offset;
	size_t len = uiop->uio_resid;
	int error;

	TARFS_DPF(ZIO, "%s: bread(%zu, %zu)\n", __func__,
	    off / tmp->iosize,
	    (off + len + tmp->iosize - 1) / tmp->iosize - off / tmp->iosize);
	error = bread(vp, off / tmp->iosize,
	    (off + len + tmp->iosize - 1) / tmp->iosize - off / tmp->iosize,
	    uiop->uio_td->td_ucred, &bp);
	if (error == 0) {
		if (off % tmp->iosize + len > bp->b_bufsize)
			len = bp->b_bufsize - off % tmp->iosize;
		error = uiomove(bp->b_data + off % tmp->iosize, len, uiop);
		brelse(bp);
	}
	TARFS_DPF(ZIO, "%s(%zu, %zu) = %d (resid %zu)\n", __func__,
	    off, len, error, uiop->uio_resid);
	return error;
}

/*
 * VOP_RECLAIM for zio node.
 */
static int
tarfs_zreclaim(struct vop_reclaim_args *ap)
{
	struct vnode *vp = ap->a_vp;

	TARFS_DPF(ZIO, "%s(%p)\n", __func__, vp);
	vp->v_data = NULL;
	vnode_destroy_vobject(vp);
	cache_purge(vp);
	return 0;
}

#ifdef ZSTDIO
/*
 * VOP_STRATEGY for zio node, zstd edition.
 */
static int
tarfs_zstrategy_zstd(struct tarfs_zio *zio, struct buf *bp)
{
#ifndef TARFS_ZIO_BREAD
	char buf[PAGE_SIZE];
	struct uio auio;
	struct iovec aiov;
#endif
	struct tarfs_mount *tmp = zio->tmp;
	struct tarfs_zstd *zstd = zio->zstd;
	struct vattr va;
	ZSTD_inBuffer zib;
	ZSTD_outBuffer zob;
#ifdef TARFS_ZIO_BREAD
	struct buf *ubp = NULL;
	size_t ubsize;
	off_t upos;
	size_t ulen;
#endif
	off_t ipos, opos;
	size_t ilen, olen;
	size_t zerror;
	off_t off = bp->b_blkno * tmp->iosize;
	size_t len = bp->b_bufsize;
	int error;
	bool reset = false;

	TARFS_DPF(ZIO, "%s: bufsize %zu bcount %zu resid %zu\n", __func__,
	    (size_t)bp->b_bufsize, (size_t)bp->b_bcount, (size_t)bp->b_resid);

	/* check size */
#ifdef TARFS_ZIO_BREAD
	ubsize = tmp->vp->v_mount->mnt_stat.f_iosize;
#endif
	error = VOP_GETATTR(tmp->vp, &va, bp->b_rcred);
	if (error != 0) {
		goto fail;
	}
	/* do we have to rewind? */
	if (off < zio->opos) {
		while (zio->curidx > 0 && off < zio->idx[zio->curidx].o)
			zio->curidx--;
		reset = true;
	}
	/* advance to the nearest index entry */
	if (off > zio->opos) {
		// XXX maybe do a binary search instead
		while (zio->curidx < zio->nidx - 1 &&
		    off >= zio->idx[zio->curidx + 1].o) {
			zio->curidx++;
			reset = true;
		}
	}
	/* reset the decompression stream if needed */
	if (reset) {
		zio->ipos = zio->idx[zio->curidx].i;
		zio->opos = zio->idx[zio->curidx].o;
		ZSTD_resetDStream(zstd->zds);
		TARFS_DPF(ZIDX, "%s: skipping to index %u = i %zu o %zu\n", __func__,
		    zio->curidx, zio->ipos, zio->opos);
	} else {
		TARFS_DPF(ZIDX, "%s: continuing at i %zu o %zu\n", __func__,
		    zio->ipos, zio->opos);
	}
	if (zio->ipos >= va.va_size) {
		error = EIO;
		goto fail;
	}
	MPASS(zio->opos <= off);
	zib.src = NULL;
	zib.size = 0;
	zib.pos = 0;
	zob.dst = bp->b_data;
	zob.size = bp->b_bufsize;
	zob.pos = 0;
	bp->b_resid = len;
	error = 0;
	while (bp->b_resid > 0) {
		if (zib.pos == zib.size) {
			/* request data from the underlying file */
#ifdef TARFS_ZIO_BREAD
			if (ubp != NULL) {
				brelse(ubp);
				ubp = NULL;
			}
			upos = zio->ipos / ubsize;
			ulen = max(PAGE_SIZE / ubsize, 1);
			TARFS_DPF(ZIO, "%s: bread(%zu, %zu)\n", __func__,
			    (size_t)upos, ulen);
			error = bread(tmp->vp, upos, ulen, bp->b_rcred, &ubp);
			if (error != 0)
				goto fail;
			TARFS_DPF(ZIO, "%s: req %zu+%zu got %zu+%zu\n", __func__,
			    upos * ubsize, ulen * ubsize,
			    ubp->b_lblkno * ubsize, ubp->b_bufsize);
			zib.src = ubp->b_data;
			zib.size = ubp->b_bufsize;
			zib.pos = zio->ipos - (ubp->b_lblkno * ubsize);
#else
			aiov.iov_base = buf;
			aiov.iov_len = sizeof(buf);
			auio.uio_iov = &aiov;
			auio.uio_iovcnt = 1;
			auio.uio_offset = zio->ipos;
			auio.uio_segflg = UIO_SYSSPACE;
			auio.uio_rw = UIO_READ;
			auio.uio_resid = sizeof(buf);
			auio.uio_td = curthread;
			error = VOP_READ(tmp->vp, &auio, IO_DIRECT, bp->b_rcred);
			if (error != 0)
				goto fail;
			TARFS_DPF(ZIO, "%s: req %zu+%zu got %zu+%zu\n", __func__,
			    zio->ipos, sizeof(buf),
			    zio->ipos, sizeof(buf) - auio.uio_resid);
			zib.src = buf;
			zib.size = sizeof(buf) - auio.uio_resid;
			zib.pos = 0;
#endif
		}
		MPASS(zib.pos <= zib.size);
		if (zib.pos == zib.size) {
			TARFS_DPF(ZIO, "%s: end of file after i %zu o %zu\n", __func__,
			    zio->ipos, zio->opos);
			goto fail;
		}
		if (zio->opos < off) {
			/* to be discarded */
			zob.size = min(off - zio->opos, bp->b_bufsize);
			zob.pos = 0;
		} else {
			zob.size = bp->b_bufsize;
			zob.pos = zio->opos - off;
			if (zob.size > zob.pos + bp->b_resid)
				zob.size = zob.pos + bp->b_resid;
		}
		ipos = zib.pos;
		opos = zob.pos;
		/* decompress as much as possible */
//		TARFS_DPF(ZIO, "%s: zib %zu / %zu zob %zu / %zu\n", __func__,
//		    zib.pos, zib.size, zob.pos, zob.size);
		zerror = ZSTD_decompressStream(zstd->zds, &zob, &zib);
		zio->ipos += ilen = zib.pos - ipos;
		zio->opos += olen = zob.pos - opos;
//		TARFS_DPF(ZIO, "%s: inflate %zu -> %zu (%zu) %s\n", __func__,
//		    ilen, olen, zerror, ZSTD_getErrorName(zerror));
		if (zio->opos > off)
			bp->b_resid -= olen;
		if (ZSTD_isError(zerror)) {
			TARFS_DPF(ZIO, "%s: inflate failed after i %zu o %zu: %s\n", __func__,
			    zio->ipos, zio->opos, ZSTD_getErrorName(zerror));
			error = EIO;
			goto fail;
		}
		if (zerror == 0 && olen == 0) {
			TARFS_DPF(ZIO, "%s: end of stream after i %zu o %zu\n", __func__,
			    zio->ipos, zio->opos);
			break;
		}
		if (zerror == 0) {
			TARFS_DPF(ZIO, "%s: end of frame after i %zu o %zu\n", __func__,
			    zio->ipos, zio->opos);
			tarfs_zio_update_index(zio, zio->ipos, zio->opos);
		}
		TARFS_DPF(ZIO, "%s: inflated %zu\n", __func__, olen);
#ifdef TARFS_DEBUG
		counter_u64_add(tarfs_zio_inflated, olen);
#endif
	}
fail:
#ifdef TARFS_ZIO_BREAD
	if (ubp != NULL)
		brelse(ubp);
#endif
	TARFS_DPF(ZIO, "%s(%zu, %zu) = %d (resid %zu)\n", __func__,
	    off, len, error, bp->b_resid);
#ifdef TARFS_DEBUG
	counter_u64_add(tarfs_zio_consumed, len - bp->b_resid);
#endif
	bp->b_flags |= B_DONE;
	bp->b_error = error;
	if (error != 0) {
		bp->b_ioflags |= BIO_ERROR;
		zio->curidx = 0;
		zio->ipos = zio->idx[0].i;
		zio->opos = zio->idx[0].o;
		ZSTD_resetDStream(zstd->zds);
	}
	return 0;
}
#endif

/*
 * VOP_STRATEGY for zio node.
 */
static int
tarfs_zstrategy(struct vop_strategy_args *ap)
{
	struct vnode *vp = ap->a_vp;
	struct buf *bp = ap->a_bp;
	struct tarfs_zio *zio = vp->v_data;

#ifdef ZSTDIO
	if (zio->zstd != NULL) {
		return tarfs_zstrategy_zstd(zio, bp);
	}
#endif
	bp->b_flags |= B_DONE;
	bp->b_ioflags |= BIO_ERROR;
	bp->b_error = EFTYPE;
	return 0;
}

static struct vop_vector tarfs_znodeops = {
	.vop_default =		&default_vnodeops,

	.vop_access =		tarfs_zaccess,
	.vop_getattr =		tarfs_zgetattr,
	.vop_read =		tarfs_zread,
	.vop_reclaim =		tarfs_zreclaim,
	.vop_strategy =		tarfs_zstrategy,
};

/*
 * Initializes the decompression layer.
 */
static struct tarfs_zio *
tarfs_zio_init(struct tarfs_mount *tmp, off_t i, off_t o)
{
	struct tarfs_zio *zio;
	struct vnode *zvp;

	zio = malloc(sizeof(*zio), M_TARFSZSTATE, M_ZERO | M_WAITOK);
	TARFS_DPF(ALLOC, "%s: allocated zio\n", __func__);
	zio->tmp = tmp;
	zio->szidx = 128;
	zio->idx = malloc(zio->szidx * sizeof(*zio->idx), M_TARFSZSTATE,
	    M_ZERO | M_WAITOK);
	zio->curidx = 0;
	zio->nidx = 1;
	zio->idx[zio->curidx].i = zio->ipos = i;
	zio->idx[zio->curidx].o = zio->opos = o;
	tmp->zio = zio;
	TARFS_DPF(ALLOC, "%s: allocated zio index\n", __func__);
	getnewvnode("tarfs", tmp->vfs, &tarfs_znodeops, &zvp);
	zvp->v_data = zio;
	zvp->v_type = VREG;
	zvp->v_mount = tmp->vfs;
	tmp->znode = zvp;
	TARFS_DPF(ZIO, "%s: created zio node\n", __func__);
	return zio;
}

/*
 * Initializes the I/O layer, including decompression if the signature of
 * a supported compression format is detected.  Returns 0 on success and a
 * positive errno value on failure.
 */
int
tarfs_io_init(struct tarfs_mount *tmp)
{
	u_char block[tmp->iosize];
	struct tarfs_zio *zio = NULL;
	ssize_t res;
	int error;

	memset(block, 0, sizeof(block));
	res = tarfs_io_read_buf(tmp, true, block, 0, sizeof(block));
	if (res < 0) {
		return -res;
	}
	if (memcmp(block, XZ_MAGIC, sizeof(XZ_MAGIC)) == 0) {
		printf("xz compression not supported\n");
		error = EOPNOTSUPP;
		goto bad;
	} else if (memcmp(block, ZLIB_MAGIC, sizeof(ZLIB_MAGIC)) == 0) {
		printf("zlib compression not supported\n");
		error = EOPNOTSUPP;
		goto bad;
	} else if (memcmp(block, ZSTD_MAGIC, sizeof(ZSTD_MAGIC)) == 0) {
#ifdef ZSTDIO
		zio = tarfs_zio_init(tmp, 0, 0);
		zio->zstd = malloc(sizeof(*zio->zstd), M_TARFSZSTATE, M_WAITOK);
		zio->zstd->zds = ZSTD_createDStream_advanced(tarfs_zstd_mem);
		(void)ZSTD_initDStream(zio->zstd->zds);
#else
		printf("zstd compression not supported\n");
		error = EOPNOTSUPP;
		goto bad;
#endif
	}
	return 0;
bad:
	return error;
}

/*
 * Tears down the decompression layer.
 */
static void
tarfs_zio_fini(struct tarfs_mount *tmp)
{
	struct tarfs_zio *zio = tmp->zio;

	if (tmp->znode != NULL) {
		vgone(tmp->znode);
		vunref(tmp->znode);
		tmp->znode = NULL;
	}
#ifdef ZSTDIO
	if (zio->zstd != NULL) {
		TARFS_DPF(ALLOC, "%s: freeing zstd state\n", __func__);
		ZSTD_freeDStream(zio->zstd->zds);
		free(zio->zstd, M_TARFSZSTATE);
	}
#endif
	if (zio->idx != NULL) {
		TARFS_DPF(ALLOC, "%s: freeing index\n", __func__);
		free(zio->idx, M_TARFSZSTATE);
	}
	TARFS_DPF(ALLOC, "%s: freeing zio\n", __func__);
	free(zio, M_TARFSZSTATE);
	tmp->zio = NULL;
}

/*
 * Tears down the I/O layer, including the decompression layer if
 * applicable.
 */
void
tarfs_io_fini(struct tarfs_mount *tmp)
{

	if (tmp->zio != NULL) {
		tarfs_zio_fini(tmp);
	}
}
