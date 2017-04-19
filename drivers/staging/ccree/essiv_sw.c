/*
 * Copyright (C) 2003 Jana Saout <jana@saout.de>
 * Copyright (C) 2004 Clemens Fruhwirth <clemens@endorphin.org>
 * Copyright (C) 2006-2015 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2013 Milan Broz <gmazyland@gmail.com>
 *
 * This file is released under the GPL.
 */

#include <linux/completion.h>
#include <linux/err.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/key.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/mempool.h>
#include <linux/slab.h>
#include <linux/crypto.h>
#include <linux/workqueue.h>
#include <linux/kthread.h>
#include <linux/backing-dev.h>
#include <linux/atomic.h>
#include <linux/scatterlist.h>
#include <linux/rbtree.h>
#include <linux/ctype.h>
#include <asm/page.h>
#include <asm/unaligned.h>
#include <crypto/hash.h>
#include <crypto/md5.h>
#include <crypto/algapi.h>
#include <crypto/skcipher.h>
#include <keys/user-type.h>
#include <linux/device-mapper.h>
#include <crypto/internal/skcipher.h>
#include <linux/backing-dev.h>
#include <linux/log2.h>
#include <crypto/geniv.h>

#define DM_MSG_PREFIX		"crypt"
#define MAX_SG_LIST		(BIO_MAX_PAGES * 8)
#define MIN_IOS			64
#define LMK_SEED_SIZE		64 /* hash + 0 */
#define TCW_WHITENING_SIZE	16

struct geniv_ctx;
struct geniv_req_ctx;

/* Sub request for each of the skcipher_request's for a segment */
struct geniv_subreq {
	struct scatterlist src;
	struct scatterlist dst;
	struct geniv_req_ctx *rctx;
	struct skcipher_request req CRYPTO_MINALIGN_ATTR;
};

struct geniv_req_ctx {
	struct geniv_subreq *subreq;
	int is_write;
	sector_t iv_sector;
	unsigned int nents;
	struct completion restart;
	atomic_t req_pending;
	struct skcipher_request *req;
};

struct crypt_iv_operations {
	int (*ctr)(struct geniv_ctx *ctx);
	void (*dtr)(struct geniv_ctx *ctx);
	int (*init)(struct geniv_ctx *ctx);
	int (*wipe)(struct geniv_ctx *ctx);
	int (*generator)(struct geniv_ctx *ctx,
			 struct geniv_req_ctx *rctx,
			 struct geniv_subreq *subreq, u8 *iv);
	int (*post)(struct geniv_ctx *ctx,
		    struct geniv_req_ctx *rctx,
		    struct geniv_subreq *subreq, u8 *iv);
};

struct geniv_essiv_private {
	struct crypto_ahash *hash_tfm;
	u8 *salt;
};

struct geniv_benbi_private {
	int shift;
};

struct geniv_lmk_private {
	struct crypto_shash *hash_tfm;
	u8 *seed;
};

struct geniv_tcw_private {
	struct crypto_shash *crc32_tfm;
	u8 *iv_seed;
	u8 *whitening;
};

struct geniv_ctx {
	unsigned int tfms_count;
	struct crypto_skcipher *child;
	struct crypto_skcipher **tfms;
	char *ivmode;
	unsigned int iv_size;
	unsigned int iv_start;
	char *algname;
	char *ivopts;
	char *cipher;
	char *ciphermode;
	const struct crypt_iv_operations *iv_gen_ops;
	union {
		struct geniv_essiv_private essiv;
		struct geniv_benbi_private benbi;
		struct geniv_lmk_private lmk;
		struct geniv_tcw_private tcw;
	} iv_gen_private;
	void *iv_private;
	struct crypto_skcipher *tfm;
	mempool_t *subreq_pool;
	unsigned int key_size;
	unsigned int key_extra_size;
	unsigned int key_parts;      /* independent parts in key buffer */
	enum setkey_op keyop;
	char *msg;
	u8 *key;
};

static struct crypto_skcipher *any_tfm(struct geniv_ctx *ctx)
{
	return ctx->tfms[0];
}

static inline
struct geniv_req_ctx *geniv_req_ctx(struct skcipher_request *req)
{
	struct crypto_skcipher *tfm = crypto_skcipher_reqtfm(req);
	unsigned long align = crypto_skcipher_alignmask(tfm);

	return (void *) PTR_ALIGN((u8 *) skcipher_request_ctx(req), align + 1);
}

static u8 *iv_of_subreq(struct geniv_ctx *ctx, struct geniv_subreq *subreq)
{
	struct crypto_skcipher *tfm = crypto_skcipher_reqtfm(subreq->rctx->req);
	return (u8*) ALIGN((unsigned long) ((char *) subreq + ctx->iv_start),
			   crypto_skcipher_alignmask(tfm) + 1);
}

/*
 * Different IV generation algorithms:
 *
 * essiv: "encrypted sector|salt initial vector", the sector number is
 *        encrypted with the bulk cipher using a salt as key. The salt
 *        should be derived from the bulk cipher's key via hashing.
 *
 * plumb: unimplemented, see:
 * http://article.gmane.org/gmane.linux.kernel.device-mapper.dm-crypt/454
 */

/* Initialise ESSIV - compute salt but no local memory allocations */
static int crypt_iv_essiv_init(struct geniv_ctx *ctx)
{
	struct geniv_essiv_private *essiv = &ctx->iv_gen_private.essiv;
	struct scatterlist sg;
	struct crypto_cipher *essiv_tfm;
	int err;
	AHASH_REQUEST_ON_STACK(req, essiv->hash_tfm);

	sg_init_one(&sg, ctx->key, ctx->key_size);
	ahash_request_set_tfm(req, essiv->hash_tfm);
	ahash_request_set_callback(req, CRYPTO_TFM_REQ_MAY_SLEEP, NULL, NULL);
	ahash_request_set_crypt(req, &sg, essiv->salt, ctx->key_size);

	err = crypto_ahash_digest(req);
	ahash_request_zero(req);
	if (err)
		return err;

	essiv_tfm = ctx->iv_private;

	err = crypto_cipher_setkey(essiv_tfm, essiv->salt,
			    crypto_ahash_digestsize(essiv->hash_tfm));
	if (err)
		return err;

	return 0;
}

/* Wipe salt and reset key derived from volume key */
static int crypt_iv_essiv_wipe(struct geniv_ctx *ctx)
{
	struct geniv_essiv_private *essiv = &ctx->iv_gen_private.essiv;
	unsigned int salt_size = crypto_ahash_digestsize(essiv->hash_tfm);
	struct crypto_cipher *essiv_tfm;
	int r, err = 0;

	memset(essiv->salt, 0, salt_size);

	essiv_tfm = ctx->iv_private;
	r = crypto_cipher_setkey(essiv_tfm, essiv->salt, salt_size);
	if (r)
		err = r;

	return err;
}

/* Set up per cpu cipher state */
static struct crypto_cipher *setup_essiv_cpu(struct geniv_ctx *ctx,
					     u8 *salt, unsigned int saltsize)
{
	struct crypto_cipher *essiv_tfm;
	int err;

	/* Setup the essiv_tfm with the given salt */
	essiv_tfm = crypto_alloc_cipher(ctx->cipher, 0, CRYPTO_ALG_ASYNC);

	if (IS_ERR(essiv_tfm)) {
		DMERR("Error allocating crypto tfm for ESSIV\n");
		return essiv_tfm;
	}

	if (crypto_cipher_blocksize(essiv_tfm) !=
	    crypto_skcipher_ivsize(any_tfm(ctx))) {
		DMERR("Block size of ESSIV cipher does not match IV size of block cipher\n");
		crypto_free_cipher(essiv_tfm);
		return ERR_PTR(-EINVAL);
	}

	err = crypto_cipher_setkey(essiv_tfm, salt, saltsize);
	if (err) {
		DMERR("Failed to set key for ESSIV cipher\n");
		crypto_free_cipher(essiv_tfm);
		return ERR_PTR(err);
	}
	return essiv_tfm;
}

static void crypt_iv_essiv_dtr(struct geniv_ctx *ctx)
{
	struct crypto_cipher *essiv_tfm;
	struct geniv_essiv_private *essiv = &ctx->iv_gen_private.essiv;

	crypto_free_ahash(essiv->hash_tfm);
	essiv->hash_tfm = NULL;

	kzfree(essiv->salt);
	essiv->salt = NULL;

	essiv_tfm = ctx->iv_private;

	if (essiv_tfm)
		crypto_free_cipher(essiv_tfm);

	ctx->iv_private = NULL;
}

static int crypt_iv_essiv_ctr(struct geniv_ctx *ctx)
{
	struct crypto_cipher *essiv_tfm = NULL;
	struct crypto_ahash *hash_tfm = NULL;
	u8 *salt = NULL;
	int err;

	if (!ctx->ivopts) {
		DMERR("Digest algorithm missing for ESSIV mode\n");
		return -EINVAL;
	}

	/* Allocate hash algorithm */
	hash_tfm = crypto_alloc_ahash(ctx->ivopts, 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(hash_tfm)) {
		err = PTR_ERR(hash_tfm);
		DMERR("Error initializing ESSIV hash. err=%d\n", err);
		goto bad;
	}

	salt = kzalloc(crypto_ahash_digestsize(hash_tfm), GFP_KERNEL);
	if (!salt) {
		err = -ENOMEM;
		goto bad;
	}

	ctx->iv_gen_private.essiv.salt = salt;
	ctx->iv_gen_private.essiv.hash_tfm = hash_tfm;

	essiv_tfm = setup_essiv_cpu(ctx, salt,
				crypto_ahash_digestsize(hash_tfm));
	if (IS_ERR(essiv_tfm)) {
		crypt_iv_essiv_dtr(ctx);
		return PTR_ERR(essiv_tfm);
	}
	ctx->iv_private = essiv_tfm;

	return 0;

bad:
	if (hash_tfm && !IS_ERR(hash_tfm))
		crypto_free_ahash(hash_tfm);
	kfree(salt);
	return err;
}

static int crypt_iv_essiv_gen(struct geniv_ctx *ctx,
			      struct geniv_req_ctx *rctx,
			      struct geniv_subreq *subreq, u8 *iv)
{
	struct crypto_cipher *essiv_tfm = ctx->iv_private;

	memset(iv, 0, ctx->iv_size);
	*(__le64 *)iv = cpu_to_le64(rctx->iv_sector);
	crypto_cipher_encrypt_one(essiv_tfm, iv, iv);

	return 0;
}

static const struct crypt_iv_operations crypt_iv_essiv_ops = {
	.ctr       = crypt_iv_essiv_ctr,
	.dtr       = crypt_iv_essiv_dtr,
	.init      = crypt_iv_essiv_init,
	.wipe      = crypt_iv_essiv_wipe,
	.generator = crypt_iv_essiv_gen
};

static int geniv_setkey_set(struct geniv_ctx *ctx)
{
	int ret = 0;

	if (ctx->iv_gen_ops && ctx->iv_gen_ops->init)
		ret = ctx->iv_gen_ops->init(ctx);
	return ret;
}

static int geniv_setkey_wipe(struct geniv_ctx *ctx)
{
	int ret = 0;

	if (ctx->iv_gen_ops && ctx->iv_gen_ops->wipe) {
		ret = ctx->iv_gen_ops->wipe(ctx);
		if (ret)
			return ret;
	}
	return ret;
}

static int geniv_init_iv(struct geniv_ctx *ctx)
{
	int ret = -EINVAL;

	DMDEBUG("IV Generation algorithm : %s\n", ctx->ivmode);

	if (ctx->ivmode == NULL)
		ctx->iv_gen_ops = NULL;
	else if (strcmp(ctx->ivmode, "essiv") == 0)
		ctx->iv_gen_ops = &crypt_iv_essiv_ops;
	else {
		ret = -EINVAL;
		DMERR("Invalid IV mode %s\n", ctx->ivmode);
		goto end;
	}

	/* Allocate IV */
	if (ctx->iv_gen_ops && ctx->iv_gen_ops->ctr) {
		ret = ctx->iv_gen_ops->ctr(ctx);
		if (ret < 0) {
			DMERR("Error creating IV for %s\n", ctx->ivmode);
			goto end;
		}
	}

	/* Initialize IV (set keys for ESSIV etc) */
	if (ctx->iv_gen_ops && ctx->iv_gen_ops->init) {
		ret = ctx->iv_gen_ops->init(ctx);
		if (ret < 0)
			DMERR("Error creating IV for %s\n", ctx->ivmode);
	}
	ret = 0;
end:
	return ret;
}

static void geniv_free_tfms(struct geniv_ctx *ctx)
{
	unsigned int i;

	if (!ctx->tfms)
		return;

	for (i = 0; i < ctx->tfms_count; i++)
		if (ctx->tfms[i] && !IS_ERR(ctx->tfms[i])) {
			crypto_free_skcipher(ctx->tfms[i]);
			ctx->tfms[i] = NULL;
		}

	kfree(ctx->tfms);
	ctx->tfms = NULL;
}

/* Allocate memory for the underlying cipher algorithm. Ex: cbc(aes)
 */

static int geniv_alloc_tfms(struct crypto_skcipher *parent,
			    struct geniv_ctx *ctx)
{
	unsigned int i, reqsize, align;
	int err = 0;

	ctx->tfms = kcalloc(ctx->tfms_count, sizeof(struct crypto_skcipher *),
			   GFP_KERNEL);
	if (!ctx->tfms) {
		err = -ENOMEM;
		goto end;
	}

	/* First instance is already allocated in geniv_init_tfm */
	ctx->tfms[0] = ctx->child;
	for (i = 1; i < ctx->tfms_count; i++) {
		ctx->tfms[i] = crypto_alloc_skcipher(ctx->ciphermode, 0, 0);
		if (IS_ERR(ctx->tfms[i])) {
			err = PTR_ERR(ctx->tfms[i]);
			geniv_free_tfms(ctx);
			goto end;
		}

		/* Setup the current cipher's request structure */
		align = crypto_skcipher_alignmask(parent);
		align &= ~(crypto_tfm_ctx_alignment() - 1);
		reqsize = align + sizeof(struct geniv_req_ctx) +
			  crypto_skcipher_reqsize(ctx->tfms[i]);
		crypto_skcipher_set_reqsize(parent, reqsize);
	}

end:
	return err;
}

/* Initialize the cipher's context with the key, ivmode and other parameters.
 * Also allocate IV generation template ciphers and initialize them.
 */

static int geniv_setkey_init(struct crypto_skcipher *parent,
			     struct geniv_key_info *info)
{
	struct geniv_ctx *ctx = crypto_skcipher_ctx(parent);
	int ret = -ENOMEM;

	ctx->tfms_count = info->tfms_count;
	ctx->key = info->key;
	ctx->key_size = info->key_size;
	ctx->key_parts = info->key_parts;
	ctx->ivopts = info->ivopts;

	ret = geniv_alloc_tfms(parent, ctx);
	if (ret)
		goto end;

	ret = geniv_init_iv(ctx);

end:
	return ret;
}

static int geniv_setkey_tfms(struct crypto_skcipher *parent,
			     struct geniv_ctx *ctx,
			     struct geniv_key_info *info)
{
	unsigned int subkey_size;
	int ret = 0, i;

	/* Ignore extra keys (which are used for IV etc) */
	subkey_size = (ctx->key_size - ctx->key_extra_size)
		      >> ilog2(ctx->tfms_count);

	for (i = 0; i < ctx->tfms_count; i++) {
		struct crypto_skcipher *child = ctx->tfms[i];
		char *subkey = ctx->key + (subkey_size) * i;

		crypto_skcipher_clear_flags(child, CRYPTO_TFM_REQ_MASK);
		crypto_skcipher_set_flags(child,
					  crypto_skcipher_get_flags(parent) &
					  CRYPTO_TFM_REQ_MASK);
		ret = crypto_skcipher_setkey(child, subkey, subkey_size);
		if (ret) {
			DMERR("Error setting key for tfms[%d]\n", i);
			break;
		}
		crypto_skcipher_set_flags(parent,
					  crypto_skcipher_get_flags(child) &
					  CRYPTO_TFM_RES_MASK);
	}

	return ret;
}

static int geniv_setkey(struct crypto_skcipher *parent,
			const u8 *key, unsigned int keylen)
{
	int err = 0;
	struct geniv_ctx *ctx = crypto_skcipher_ctx(parent);
	struct geniv_key_info *info = (struct geniv_key_info *) key;

	DMDEBUG("SETKEY Operation : %d\n", info->keyop);

	switch (info->keyop) {
	case SETKEY_OP_INIT:
		err = geniv_setkey_init(parent, info);
		break;
	case SETKEY_OP_SET:
		err = geniv_setkey_set(ctx);
		break;
	case SETKEY_OP_WIPE:
		err = geniv_setkey_wipe(ctx);
		break;
	}

	if (err)
		goto end;

	err = geniv_setkey_tfms(parent, ctx, info);

end:
	return err;
}

static void geniv_async_done(struct crypto_async_request *async_req, int error);

static int geniv_alloc_subreq(struct skcipher_request *req,
			      struct geniv_ctx *ctx,
			      struct geniv_req_ctx *rctx)
{
	int key_index, r = 0;
	struct skcipher_request *sreq;

	if (!rctx->subreq) {
		rctx->subreq = mempool_alloc(ctx->subreq_pool, GFP_NOIO);
		if (!rctx->subreq)
			r = -ENOMEM;
	}

	sreq = &rctx->subreq->req;
	rctx->subreq->rctx = rctx;

	key_index = rctx->iv_sector & (ctx->tfms_count - 1);

	skcipher_request_set_tfm(sreq, ctx->tfms[key_index]);
	skcipher_request_set_callback(sreq, req->base.flags,
				      geniv_async_done, rctx->subreq);
	return r;
}

/* Asynchronous IO completion callback for each sector in a segment. When all
 * pending i/o are completed the parent cipher's async function is called.
 */

static void geniv_async_done(struct crypto_async_request *async_req, int error)
{
	struct geniv_subreq *subreq =
		(struct geniv_subreq *) async_req->data;
	struct geniv_req_ctx *rctx = subreq->rctx;
	struct skcipher_request *req = rctx->req;
	struct crypto_skcipher *tfm = crypto_skcipher_reqtfm(req);
	struct geniv_ctx *ctx = crypto_skcipher_ctx(tfm);
	u8 *iv;

	/*
	 * A request from crypto driver backlog is going to be processed now,
	 * finish the completion and continue in crypt_convert().
	 * (Callback will be called for the second time for this request.)
	 */

	if (error == -EINPROGRESS) {
		complete(&rctx->restart);
		return;
	}

	iv = iv_of_subreq(ctx, subreq);
	if (!error && ctx->iv_gen_ops && ctx->iv_gen_ops->post)
		error = ctx->iv_gen_ops->post(ctx, rctx, subreq, iv);

	mempool_free(subreq, ctx->subreq_pool);

	/* req_pending needs to be checked before req->base.complete is called
	 * as we need 'req_pending' to be equal to 1 to ensure all subrequests
	 * are processed.
	 */
	if (!atomic_dec_and_test(&rctx->req_pending)) {
		/* Call the parent cipher's completion function */
		skcipher_request_complete(req, error);
	}
}

static unsigned int geniv_get_sectors(struct scatterlist *sg1,
				      struct scatterlist *sg2,
				      unsigned int segments)
{
	unsigned int i, n1, n2, nents;

	n1 = n2 = 0;
	for (i = 0; i < segments ; i++) {
		n1 += sg1[i].length >> SECTOR_SHIFT;
		n1 += (sg1[i].length & ~SECTOR_MASK) ? 1 : 0;
	}

	for (i = 0; i < segments ; i++) {
		n2 += sg2[i].length >> SECTOR_SHIFT;
		n2 += (sg2[i].length & ~SECTOR_MASK) ? 1 : 0;
	}

	nents = n1 > n2 ? n1 : n2;
	return nents;
}

/* Iterate scatterlist of segments to retrieve the 512-byte sectors so that
 * unique IVs could be generated for each 512-byte sector. This split may not
 * be necessary e.g. when these ciphers are modelled in hardware, where it can
 * make use of the hardware's IV generation capabilities.
 */

static int geniv_iter_block(struct skcipher_request *req,
			    struct geniv_subreq *subreq,
			    struct geniv_req_ctx *rctx,
			    unsigned int *seg_no,
			    unsigned int *done)

{
	unsigned int srcoff, dstoff, len, rem;
	struct scatterlist *src1, *dst1, *src2, *dst2;

	if (unlikely(*seg_no >= rctx->nents))
		return 0; /* done */

	src1 = &req->src[*seg_no];
	dst1 = &req->dst[*seg_no];
	src2 = &subreq->src;
	dst2 = &subreq->dst;

	if (*done >= src1->length) {
		(*seg_no)++;

		if (*seg_no >= rctx->nents)
			return 0; /* done */

		src1 = &req->src[*seg_no];
		dst1 = &req->dst[*seg_no];
		*done = 0;
	}

	srcoff = src1->offset + *done;
	dstoff = dst1->offset + *done;
	rem = src1->length - *done;

	len = rem > SECTOR_SIZE ? SECTOR_SIZE : rem;

	DMDEBUG("segment:(%d/%u), srcoff:%d, dstoff:%d, done:%d, rem:%d\n",
		*seg_no + 1, rctx->nents, srcoff, dstoff, *done, rem);

	sg_init_table(src2, 1);
	sg_set_page(src2, sg_page(src1), len, srcoff);
	sg_init_table(dst2, 1);
	sg_set_page(dst2, sg_page(dst1), len, dstoff);

	*done += len;

	return len; /* bytes returned */
}

/* Common encryt/decrypt function for geniv template cipher. Before the crypto
 * operation, it splits the memory segments (in the scatterlist) into 512 byte
 * sectors. The initialization vector(IV) used is based on a unique sector
 * number which is generated here.
 */
static int geniv_crypt(struct skcipher_request *req, int encrypt)
{
	struct crypto_skcipher *tfm = crypto_skcipher_reqtfm(req);
	struct geniv_ctx *ctx = crypto_skcipher_ctx(tfm);
	struct geniv_req_ctx *rctx = geniv_req_ctx(req);
	struct geniv_req_info *rinfo = (struct geniv_req_info *) req->iv;
	int i, bytes, cryptlen, ret = 0;
	unsigned int sectors, segno = 0, done = 0;
	char *str __maybe_unused = encrypt ? "encrypt" : "decrypt";
	u8 *iv;

	/* Instance of 'struct geniv_req_info' is stored in IV ptr */
	rctx->is_write = encrypt;
	rctx->iv_sector = rinfo->iv_sector;
	rctx->nents = rinfo->nents;
	rctx->req = req;
	rctx->subreq = NULL;
	cryptlen = req->cryptlen;

	DMDEBUG("geniv:%s: starting sector=%d, #segments=%u\n", str,
		(unsigned int) rctx->iv_sector, rctx->nents);

	sectors = geniv_get_sectors(req->src, req->dst, rctx->nents);

	init_completion(&rctx->restart);
	atomic_set(&rctx->req_pending, 1);

	for (i = 0; i < sectors; i++) {
		struct geniv_subreq *subreq;

		ret = geniv_alloc_subreq(req, ctx, rctx);
		if (ret)
			goto end;

		subreq = rctx->subreq;
		subreq->rctx = rctx;
		iv = iv_of_subreq(ctx, subreq);

		atomic_inc(&rctx->req_pending);
		bytes = geniv_iter_block(req, subreq, rctx, &segno, &done);

		if (bytes == 0)
			break;

		cryptlen -= bytes;

		if (ctx->iv_gen_ops)
			ret = ctx->iv_gen_ops->generator(ctx, rctx, subreq, iv);

		if (ret < 0) {
			DMERR("Error in generating IV ret: %d\n", ret);
			goto end;
		}

		skcipher_request_set_crypt(&subreq->req, &subreq->src,
					   &subreq->dst, bytes, iv);

		if (encrypt)
			ret = crypto_skcipher_encrypt(&subreq->req);

		else
			ret = crypto_skcipher_decrypt(&subreq->req);

		if (!ret && ctx->iv_gen_ops && ctx->iv_gen_ops->post)
			ret = ctx->iv_gen_ops->post(ctx, rctx, subreq, iv);

		switch (ret) {
		/*
		 * The request was queued by a crypto driver
		 * but the driver request queue is full, let's wait.
		 */
		case -EBUSY:
			wait_for_completion(&rctx->restart);
			reinit_completion(&rctx->restart);
			/* fall through */
		/*
		 * The request is queued and processed asynchronously,
		 * completion function geniv_async_done() is called.
		 */
		case -EINPROGRESS:
			/* Marking this NULL lets the creation of a new sub-
			 * request when 'geniv_alloc_subreq' is called.
			 */
			rctx->subreq = NULL;
			rctx->iv_sector++;
			cond_resched();
			break;
		/*
		 * The request was already processed (synchronously).
		 */
		case 0:
			atomic_dec(&rctx->req_pending);
			rctx->iv_sector++;
			cond_resched();
			continue;

		/* There was an error while processing the request. */
		default:
			atomic_dec(&rctx->req_pending);
			return ret;
		}

		if (ret)
			break;
	}

	if (rctx->subreq && atomic_read(&rctx->req_pending) == 1) {
		DMDEBUG("geniv:%s: Freeing sub request\n", str);
		mempool_free(rctx->subreq, ctx->subreq_pool);
	}

end:
	return ret;
}

static int geniv_encrypt(struct skcipher_request *req)
{
	return geniv_crypt(req, 1);
}

static int geniv_decrypt(struct skcipher_request *req)
{
	return geniv_crypt(req, 0);
}

static int geniv_init_tfm(struct crypto_skcipher *tfm)
{
	struct geniv_ctx *ctx = crypto_skcipher_ctx(tfm);
	unsigned int reqsize, align;
	size_t iv_size_padding;
	char *algname, *chainmode;
	int psize, ret = 0;

	algname = (char *) crypto_tfm_alg_name(crypto_skcipher_tfm(tfm));
	ctx->ciphermode = kmalloc(CRYPTO_MAX_ALG_NAME, GFP_KERNEL);
	if (!ctx->ciphermode) {
		ret = -ENOMEM;
		goto out;
	}

	ctx->algname = kmalloc(CRYPTO_MAX_ALG_NAME, GFP_KERNEL);
	if (!ctx->algname) {
		ret = -ENOMEM;
		goto free_ciphermode;
	}

	strlcpy(ctx->algname, algname, CRYPTO_MAX_ALG_NAME);
	algname = ctx->algname;

	/* Parse the algorithm name 'ivmode(chainmode(cipher))' */
	ctx->ivmode	= strsep(&algname, "(");
	chainmode	= strsep(&algname, "(");
	ctx->cipher	= strsep(&algname, ")");

	snprintf(ctx->ciphermode, CRYPTO_MAX_ALG_NAME, "%s(%s)",
		 chainmode, ctx->cipher);

	DMDEBUG("ciphermode=%s, ivmode=%s\n", ctx->ciphermode, ctx->ivmode);

	/*
	 * Usually the underlying cipher instances are spawned here, but since
	 * the value of tfms_count (which is equal to the key_count) is not
	 * known yet, create only one instance and delay the creation of the
	 * rest of the instances of the underlying cipher 'cbc(aes)' until
	 * the setkey operation is invoked.
	 * The first instance created i.e. ctx->child will later be assigned as
	 * the 1st element in the array ctx->tfms. Creation of atleast one
	 * instance of the cipher is necessary to be created here to uncover
	 * any errors earlier than during the setkey operation later where the
	 * remaining instances are created.
	 */
	ctx->child = crypto_alloc_skcipher(ctx->ciphermode, 0, 0);
	if (IS_ERR(ctx->child)) {
		ret = PTR_ERR(ctx->child);
		DMERR("Failed to create skcipher %s. err %d\n",
		      ctx->ciphermode, ret);
		goto free_algname;
	}

	/* Setup the current cipher's request structure */
	align = crypto_skcipher_alignmask(tfm);
	align &= ~(crypto_tfm_ctx_alignment() - 1);
	reqsize = align + sizeof(struct geniv_req_ctx)
			+ crypto_skcipher_reqsize(ctx->child);
	crypto_skcipher_set_reqsize(tfm, reqsize);

	ctx->iv_start = sizeof(struct geniv_subreq);
	ctx->iv_start += crypto_skcipher_reqsize(tfm);

	ctx->iv_size = crypto_skcipher_ivsize(tfm);
	/* at least a 64 bit sector number should fit in our buffer */
	if (ctx->iv_size)
		ctx->iv_size = max(ctx->iv_size,
				  (unsigned int)(sizeof(u64) / sizeof(u8)));

	if (crypto_skcipher_alignmask(tfm) < CRYPTO_MINALIGN) {
		/* Allocate the padding exactly */
		iv_size_padding = -ctx->iv_start
				& crypto_skcipher_alignmask(tfm);
	} else {
		/*
		 * If the cipher requires greater alignment than kmalloc
		 * alignment, we don't know the exact position of the
		 * initialization vector. We must assume worst case.
		 */
		iv_size_padding = crypto_skcipher_alignmask(tfm);
	}

	/* create memory pool for sub-request structure */
	psize = ctx->iv_start + iv_size_padding + ctx->iv_size;

	ctx->subreq_pool = mempool_create_kmalloc_pool(MIN_IOS, psize);
	if (!ctx->subreq_pool) {
		ret = -ENOMEM;
		DMERR("Could not allocate crypt sub-request mempool\n");
		goto free_skcipher;
	}
out:
	return ret;

free_skcipher:
	crypto_free_skcipher(ctx->child);
free_algname:
	kfree(ctx->algname);
free_ciphermode:
	kfree(ctx->ciphermode);
	goto out;
}

static void geniv_exit_tfm(struct crypto_skcipher *tfm)
{
	struct geniv_ctx *ctx = crypto_skcipher_ctx(tfm);

	if (ctx->iv_gen_ops && ctx->iv_gen_ops->dtr)
		ctx->iv_gen_ops->dtr(ctx);

	mempool_destroy(ctx->subreq_pool);
	geniv_free_tfms(ctx);
	kfree(ctx->ciphermode);
	kfree(ctx->algname);
}

static void geniv_free(struct skcipher_instance *inst)
{
	struct crypto_skcipher_spawn *spawn = skcipher_instance_ctx(inst);

	crypto_drop_skcipher(spawn);
	kfree(inst);
}

static int geniv_create(struct crypto_template *tmpl,
			struct rtattr **tb, char *algname)
{
	struct crypto_attr_type *algt;
	struct skcipher_instance *inst;
	struct skcipher_alg *alg;
	struct crypto_skcipher_spawn *spawn;
	const char *cipher_name;
	int err;

	algt = crypto_get_attr_type(tb);

	if (IS_ERR(algt))
		return PTR_ERR(algt);

	if ((algt->type ^ CRYPTO_ALG_TYPE_SKCIPHER) & algt->mask)
		return -EINVAL;

	cipher_name = crypto_attr_alg_name(tb[1]);

	if (IS_ERR(cipher_name))
		return PTR_ERR(cipher_name);

	inst = kzalloc(sizeof(*inst) + sizeof(*spawn), GFP_KERNEL);
	if (!inst)
		return -ENOMEM;

	spawn = skcipher_instance_ctx(inst);

	crypto_set_skcipher_spawn(spawn, skcipher_crypto_instance(inst));
	err = crypto_grab_skcipher(spawn, cipher_name, 0,
				    crypto_requires_sync(algt->type,
							 algt->mask));

	if (err)
		goto err_free_inst;

	alg = crypto_spawn_skcipher_alg(spawn);

	err = -EINVAL;

	/* Only support blocks of size which is of a power of 2 */
	if (!is_power_of_2(alg->base.cra_blocksize))
		goto err_drop_spawn;

	/* algname: essiv, base.cra_name: cbc(aes) */
	err = -ENAMETOOLONG;
	if (snprintf(inst->alg.base.cra_name, CRYPTO_MAX_ALG_NAME, "%s(%s)",
		     algname, alg->base.cra_name) >= CRYPTO_MAX_ALG_NAME)
		goto err_drop_spawn;
	if (snprintf(inst->alg.base.cra_driver_name, CRYPTO_MAX_ALG_NAME,
		     "%s(%s)", algname, alg->base.cra_driver_name) >=
	    CRYPTO_MAX_ALG_NAME)
		goto err_drop_spawn;

	inst->alg.base.cra_flags = CRYPTO_ALG_TYPE_BLKCIPHER;
	inst->alg.base.cra_priority = alg->base.cra_priority;
	inst->alg.base.cra_blocksize = alg->base.cra_blocksize;
	inst->alg.base.cra_alignmask = alg->base.cra_alignmask;
	inst->alg.base.cra_flags = alg->base.cra_flags & CRYPTO_ALG_ASYNC;
	inst->alg.ivsize = alg->base.cra_blocksize;
	inst->alg.chunksize = crypto_skcipher_alg_chunksize(alg);
	inst->alg.min_keysize = crypto_skcipher_alg_min_keysize(alg);
	inst->alg.max_keysize = crypto_skcipher_alg_max_keysize(alg);

	inst->alg.setkey = geniv_setkey;
	inst->alg.encrypt = geniv_encrypt;
	inst->alg.decrypt = geniv_decrypt;

	inst->alg.base.cra_ctxsize = sizeof(struct geniv_ctx);

	inst->alg.init = geniv_init_tfm;
	inst->alg.exit = geniv_exit_tfm;

	inst->free = geniv_free;

	err = skcipher_register_instance(tmpl, inst);
	if (err)
		goto err_drop_spawn;

out:
	return err;

err_drop_spawn:
	crypto_drop_skcipher(spawn);
err_free_inst:
	kfree(inst);
	goto out;
}

static int crypto_essiv_create(struct crypto_template *tmpl,
			       struct rtattr **tb)
{
	return geniv_create(tmpl, tb, "essiv");
}

static struct crypto_template crypto_essiv_tmpl = {
	.name   = "essiv",
	.create = crypto_essiv_create,
	.module = THIS_MODULE,
};

static int __init essiv_init(void)
{
	return crypto_register_template(&crypto_essiv_tmpl);
}

static void __exit essiv_exit(void)
{
	crypto_unregister_template(&crypto_essiv_tmpl);
}

module_init(essiv_init);
module_exit(essiv_exit);

MODULE_AUTHOR("Binoy Jayan <binoy.jayan@linaro.org>");
MODULE_DESCRIPTION(DM_NAME " essiv implementation for cryptocell 712");
MODULE_LICENSE("GPL");
