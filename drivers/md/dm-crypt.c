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
	struct skcipher_request req CRYPTO_MINALIGN_ATTR;
	struct scatterlist src;
	struct scatterlist dst;
	int n;
	struct geniv_req_ctx *rctx;
};

struct geniv_req_ctx {
	struct geniv_subreq *subreq;
	bool is_write;
	sector_t iv_sector;
	unsigned int nents;
	u8 *iv;
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
			 struct geniv_subreq *subreq);
	int (*post)(struct geniv_ctx *ctx,
		    struct geniv_req_ctx *rctx,
		    struct geniv_subreq *subreq);
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

/*
 * Different IV generation algorithms:
 *
 * plain: the initial vector is the 32-bit little-endian version of the sector
 *        number, padded with zeros if necessary.
 *
 * plain64: the initial vector is the 64-bit little-endian version of the sector
 *        number, padded with zeros if necessary.
 *
 * essiv: "encrypted sector|salt initial vector", the sector number is
 *        encrypted with the bulk cipher using a salt as key. The salt
 *        should be derived from the bulk cipher's key via hashing.
 *
 * benbi: the 64-bit "big-endian 'narrow block'-count", starting at 1
 *        (needed for LRW-32-AES and possible other narrow block modes)
 *
 * null: the initial vector is always zero.  Provides compatibility with
 *       obsolete loop_fish2 devices.  Do not use for new devices.
 *
 * lmk:  Compatible implementation of the block chaining mode used
 *       by the Loop-AES block device encryption system
 *       designed by Jari Ruusu. See http://loop-aes.sourceforge.net/
 *       It operates on full 512 byte sectors and uses CBC
 *       with an IV derived from the sector number, the data and
 *       optionally extra IV seed.
 *       This means that after decryption the first block
 *       of sector must be tweaked according to decrypted data.
 *       Loop-AES can use three encryption schemes:
 *         version 1: is plain aes-cbc mode
 *         version 2: uses 64 multikey scheme with lmk IV generator
 *         version 3: the same as version 2 with additional IV seed
 *                   (it uses 65 keys, last key is used as IV seed)
 *
 * tcw:  Compatible implementation of the block chaining mode used
 *       by the TrueCrypt device encryption system (prior to version 4.1).
 *       For more info see: https://gitlab.com/cryptsetup/cryptsetup/wikis/TrueCryptOnDiskFormat
 *       It operates on full 512 byte sectors and uses CBC
 *       with an IV derived from initial key and the sector number.
 *       In addition, whitening value is applied on every sector, whitening
 *       is calculated from initial key, sector number and mixed using CRC32.
 *       Note that this encryption scheme is vulnerable to watermarking attacks
 *       and should be used for old compatible containers access only.
 *
 * plumb: unimplemented, see:
 * http://article.gmane.org/gmane.linux.kernel.device-mapper.dm-crypt/454
 */

static int crypt_iv_plain_gen(struct geniv_ctx *ctx,
			      struct geniv_req_ctx *rctx,
			      struct geniv_subreq *subreq)
{
	u8 *iv = rctx->iv;

	memset(iv, 0, ctx->iv_size);
	*(__le32 *)iv = cpu_to_le32(rctx->iv_sector & 0xffffffff);

	return 0;
}

static int crypt_iv_plain64_gen(struct geniv_ctx *ctx,
				struct geniv_req_ctx *rctx,
				struct geniv_subreq *subreq)
{
	u8 *iv = rctx->iv;

	memset(iv, 0, ctx->iv_size);
	*(__le64 *)iv = cpu_to_le64(rctx->iv_sector);

	return 0;
}

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
			      struct geniv_subreq *subreq)
{
	u8 *iv = rctx->iv;
	struct crypto_cipher *essiv_tfm = ctx->iv_private;

	memset(iv, 0, ctx->iv_size);
	*(__le64 *)iv = cpu_to_le64(rctx->iv_sector);
	crypto_cipher_encrypt_one(essiv_tfm, iv, iv);

	return 0;
}

static int crypt_iv_benbi_ctr(struct geniv_ctx *ctx)
{
	unsigned int bs = crypto_skcipher_blocksize(any_tfm(ctx));
	int log = ilog2(bs);

	/* we need to calculate how far we must shift the sector count
	 * to get the cipher block count, we use this shift in _gen
	 */

	if (1 << log != bs) {
		DMERR("cypher blocksize is not a power of 2\n");
		return -EINVAL;
	}

	if (log > 9) {
		DMERR("cypher blocksize is > 512\n");
		return -EINVAL;
	}

	ctx->iv_gen_private.benbi.shift = 9 - log;

	return 0;
}

static int crypt_iv_benbi_gen(struct geniv_ctx *ctx,
			      struct geniv_req_ctx *rctx,
			      struct geniv_subreq *subreq)
{
	u8 *iv = rctx->iv;
	__be64 val;

	memset(iv, 0, ctx->iv_size - sizeof(u64)); /* rest is cleared below */

	val = cpu_to_be64(((u64) rctx->iv_sector <<
			  ctx->iv_gen_private.benbi.shift) + 1);
	put_unaligned(val, (__be64 *)(iv + ctx->iv_size - sizeof(u64)));

	return 0;
}

static int crypt_iv_null_gen(struct geniv_ctx *ctx,
			     struct geniv_req_ctx *rctx,
			     struct geniv_subreq *subreq)
{
	u8 *iv = rctx->iv;

	memset(iv, 0, ctx->iv_size);
	return 0;
}

static void crypt_iv_lmk_dtr(struct geniv_ctx *ctx)
{
	struct geniv_lmk_private *lmk = &ctx->iv_gen_private.lmk;

	if (lmk->hash_tfm && !IS_ERR(lmk->hash_tfm))
		crypto_free_shash(lmk->hash_tfm);
	lmk->hash_tfm = NULL;

	kzfree(lmk->seed);
	lmk->seed = NULL;
}

static int crypt_iv_lmk_ctr(struct geniv_ctx *ctx)
{
	struct geniv_lmk_private *lmk = &ctx->iv_gen_private.lmk;

	lmk->hash_tfm = crypto_alloc_shash("md5", 0, 0);
	if (IS_ERR(lmk->hash_tfm)) {
		DMERR("Error initializing LMK hash; err=%ld\n",
		      PTR_ERR(lmk->hash_tfm));
		return PTR_ERR(lmk->hash_tfm);
	}

	/* No seed in LMK version 2 */
	if (ctx->key_parts == ctx->tfms_count) {
		lmk->seed = NULL;
		return 0;
	}

	lmk->seed = kzalloc(LMK_SEED_SIZE, GFP_KERNEL);
	if (!lmk->seed) {
		crypt_iv_lmk_dtr(ctx);
		DMERR("Error kmallocing seed storage in LMK\n");
		return -ENOMEM;
	}

	return 0;
}

static int crypt_iv_lmk_init(struct geniv_ctx *ctx)
{
	struct geniv_lmk_private *lmk = &ctx->iv_gen_private.lmk;
	int subkey_size = ctx->key_size / ctx->key_parts;

	/* LMK seed is on the position of LMK_KEYS + 1 key */
	if (lmk->seed)
		memcpy(lmk->seed, ctx->key + (ctx->tfms_count * subkey_size),
		       crypto_shash_digestsize(lmk->hash_tfm));

	return 0;
}

static int crypt_iv_lmk_wipe(struct geniv_ctx *ctx)
{
	struct geniv_lmk_private *lmk = &ctx->iv_gen_private.lmk;

	if (lmk->seed)
		memset(lmk->seed, 0, LMK_SEED_SIZE);

	return 0;
}

static int crypt_iv_lmk_one(struct geniv_ctx *ctx, u8 *iv,
			    struct geniv_req_ctx *rctx, u8 *data)
{
	struct geniv_lmk_private *lmk = &ctx->iv_gen_private.lmk;
	struct md5_state md5state;
	__le32 buf[4];
	int i, r;
	SHASH_DESC_ON_STACK(desc, lmk->hash_tfm);

	desc->tfm = lmk->hash_tfm;
	desc->flags = CRYPTO_TFM_REQ_MAY_SLEEP;

	r = crypto_shash_init(desc);
	if (r)
		return r;

	if (lmk->seed) {
		r = crypto_shash_update(desc, lmk->seed, LMK_SEED_SIZE);
		if (r)
			return r;
	}

	/* Sector is always 512B, block size 16, add data of blocks 1-31 */
	r = crypto_shash_update(desc, data + 16, 16 * 31);
	if (r)
		return r;

	/* Sector is cropped to 56 bits here */
	buf[0] = cpu_to_le32(rctx->iv_sector & 0xFFFFFFFF);
	buf[1] = cpu_to_le32((((u64)rctx->iv_sector >> 32) & 0x00FFFFFF)
			     | 0x80000000);
	buf[2] = cpu_to_le32(4024);
	buf[3] = 0;
	r = crypto_shash_update(desc, (u8 *)buf, sizeof(buf));
	if (r)
		return r;

	/* No MD5 padding here */
	r = crypto_shash_export(desc, &md5state);
	if (r)
		return r;

	for (i = 0; i < MD5_HASH_WORDS; i++)
		__cpu_to_le32s(&md5state.hash[i]);
	memcpy(iv, &md5state.hash, ctx->iv_size);

	return 0;
}

static int crypt_iv_lmk_gen(struct geniv_ctx *ctx,
			    struct geniv_req_ctx *rctx,
			    struct geniv_subreq *subreq)
{
	u8 *src;
	u8 *iv = rctx->iv;
	int r = 0;

	if (rctx->is_write) {
		src = kmap_atomic(sg_page(&subreq->src));
		r = crypt_iv_lmk_one(ctx, iv, rctx, src + subreq->src.offset);
		kunmap_atomic(src);
	} else
		memset(iv, 0, ctx->iv_size);

	return r;
}

static int crypt_iv_lmk_post(struct geniv_ctx *ctx,
			     struct geniv_req_ctx *rctx,
			     struct geniv_subreq *subreq)
{
	u8 *dst;
	u8 *iv = rctx->iv;
	int r;

	if (rctx->is_write)
		return 0;

	dst = kmap_atomic(sg_page(&subreq->dst));
	r = crypt_iv_lmk_one(ctx, iv, rctx, dst + subreq->dst.offset);

	/* Tweak the first block of plaintext sector */
	if (!r)
		crypto_xor(dst + subreq->dst.offset, iv, ctx->iv_size);

	kunmap_atomic(dst);
	return r;
}

static void crypt_iv_tcw_dtr(struct geniv_ctx *ctx)
{
	struct geniv_tcw_private *tcw = &ctx->iv_gen_private.tcw;

	kzfree(tcw->iv_seed);
	tcw->iv_seed = NULL;
	kzfree(tcw->whitening);
	tcw->whitening = NULL;

	if (tcw->crc32_tfm && !IS_ERR(tcw->crc32_tfm))
		crypto_free_shash(tcw->crc32_tfm);
	tcw->crc32_tfm = NULL;
}

static int crypt_iv_tcw_ctr(struct geniv_ctx *ctx)
{
	struct geniv_tcw_private *tcw = &ctx->iv_gen_private.tcw;

	if (ctx->key_size <= (ctx->iv_size + TCW_WHITENING_SIZE)) {
		DMERR("Wrong key size (%d) for TCW. Choose a value > %d bytes\n",
			ctx->key_size,
			ctx->iv_size + TCW_WHITENING_SIZE);
		return -EINVAL;
	}

	tcw->crc32_tfm = crypto_alloc_shash("crc32", 0, 0);
	if (IS_ERR(tcw->crc32_tfm)) {
		DMERR("Error initializing CRC32 in TCW; err=%ld\n",
			PTR_ERR(tcw->crc32_tfm));
		return PTR_ERR(tcw->crc32_tfm);
	}

	tcw->iv_seed = kzalloc(ctx->iv_size, GFP_KERNEL);
	tcw->whitening = kzalloc(TCW_WHITENING_SIZE, GFP_KERNEL);
	if (!tcw->iv_seed || !tcw->whitening) {
		crypt_iv_tcw_dtr(ctx);
		DMERR("Error allocating seed storage in TCW\n");
		return -ENOMEM;
	}

	return 0;
}

static int crypt_iv_tcw_init(struct geniv_ctx *ctx)
{
	struct geniv_tcw_private *tcw = &ctx->iv_gen_private.tcw;
	int key_offset = ctx->key_size - ctx->iv_size - TCW_WHITENING_SIZE;

	memcpy(tcw->iv_seed, &ctx->key[key_offset], ctx->iv_size);
	memcpy(tcw->whitening, &ctx->key[key_offset + ctx->iv_size],
	       TCW_WHITENING_SIZE);

	return 0;
}

static int crypt_iv_tcw_wipe(struct geniv_ctx *ctx)
{
	struct geniv_tcw_private *tcw = &ctx->iv_gen_private.tcw;

	memset(tcw->iv_seed, 0, ctx->iv_size);
	memset(tcw->whitening, 0, TCW_WHITENING_SIZE);

	return 0;
}

static int crypt_iv_tcw_whitening(struct geniv_ctx *ctx,
				  struct geniv_req_ctx *rctx, u8 *data)
{
	struct geniv_tcw_private *tcw = &ctx->iv_gen_private.tcw;
	__le64 sector = cpu_to_le64(rctx->iv_sector);
	u8 buf[TCW_WHITENING_SIZE];
	int i, r;
	SHASH_DESC_ON_STACK(desc, tcw->crc32_tfm);

	/* xor whitening with sector number */
	memcpy(buf, tcw->whitening, TCW_WHITENING_SIZE);
	crypto_xor(buf, (u8 *)&sector, 8);
	crypto_xor(&buf[8], (u8 *)&sector, 8);

	/* calculate crc32 for every 32bit part and xor it */
	desc->tfm = tcw->crc32_tfm;
	desc->flags = CRYPTO_TFM_REQ_MAY_SLEEP;
	for (i = 0; i < 4; i++) {
		r = crypto_shash_init(desc);
		if (r)
			goto out;
		r = crypto_shash_update(desc, &buf[i * 4], 4);
		if (r)
			goto out;
		r = crypto_shash_final(desc, &buf[i * 4]);
		if (r)
			goto out;
	}
	crypto_xor(&buf[0], &buf[12], 4);
	crypto_xor(&buf[4], &buf[8], 4);

	/* apply whitening (8 bytes) to whole sector */
	for (i = 0; i < (SECTOR_SIZE / 8); i++)
		crypto_xor(data + i * 8, buf, 8);
out:
	memzero_explicit(buf, sizeof(buf));
	return r;
}

static int crypt_iv_tcw_gen(struct geniv_ctx *ctx,
			    struct geniv_req_ctx *rctx,
			    struct geniv_subreq *subreq)
{
	u8 *iv = rctx->iv;
	struct geniv_tcw_private *tcw = &ctx->iv_gen_private.tcw;
	__le64 sector = cpu_to_le64(rctx->iv_sector);
	u8 *src;
	int r = 0;

	/* Remove whitening from ciphertext */
	if (!rctx->is_write) {
		src = kmap_atomic(sg_page(&subreq->src));
		r = crypt_iv_tcw_whitening(ctx, rctx,
					   src + subreq->src.offset);
		kunmap_atomic(src);
	}

	/* Calculate IV */
	memcpy(iv, tcw->iv_seed, ctx->iv_size);
	crypto_xor(iv, (u8 *)&sector, 8);
	if (ctx->iv_size > 8)
		crypto_xor(&iv[8], (u8 *)&sector, ctx->iv_size - 8);

	return r;
}

static int crypt_iv_tcw_post(struct geniv_ctx *ctx,
			     struct geniv_req_ctx *rctx,
			     struct geniv_subreq *subreq)
{
	u8 *dst;
	int r;

	if (!rctx->is_write)
		return 0;

	/* Apply whitening on ciphertext */
	dst = kmap_atomic(sg_page(&subreq->dst));
	r = crypt_iv_tcw_whitening(ctx, rctx, dst + subreq->dst.offset);
	kunmap_atomic(dst);

	return r;
}

static const struct crypt_iv_operations crypt_iv_plain_ops = {
	.generator = crypt_iv_plain_gen
};

static const struct crypt_iv_operations crypt_iv_plain64_ops = {
	.generator = crypt_iv_plain64_gen
};

static const struct crypt_iv_operations crypt_iv_essiv_ops = {
	.ctr       = crypt_iv_essiv_ctr,
	.dtr       = crypt_iv_essiv_dtr,
	.init      = crypt_iv_essiv_init,
	.wipe      = crypt_iv_essiv_wipe,
	.generator = crypt_iv_essiv_gen
};

static const struct crypt_iv_operations crypt_iv_benbi_ops = {
	.ctr	   = crypt_iv_benbi_ctr,
	.generator = crypt_iv_benbi_gen
};

static const struct crypt_iv_operations crypt_iv_null_ops = {
	.generator = crypt_iv_null_gen
};

static const struct crypt_iv_operations crypt_iv_lmk_ops = {
	.ctr	   = crypt_iv_lmk_ctr,
	.dtr	   = crypt_iv_lmk_dtr,
	.init	   = crypt_iv_lmk_init,
	.wipe	   = crypt_iv_lmk_wipe,
	.generator = crypt_iv_lmk_gen,
	.post	   = crypt_iv_lmk_post
};

static const struct crypt_iv_operations crypt_iv_tcw_ops = {
	.ctr	   = crypt_iv_tcw_ctr,
	.dtr	   = crypt_iv_tcw_dtr,
	.init	   = crypt_iv_tcw_init,
	.wipe	   = crypt_iv_tcw_wipe,
	.generator = crypt_iv_tcw_gen,
	.post	   = crypt_iv_tcw_post
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
	else if (strcmp(ctx->ivmode, "plain") == 0)
		ctx->iv_gen_ops = &crypt_iv_plain_ops;
	else if (strcmp(ctx->ivmode, "plain64") == 0)
		ctx->iv_gen_ops = &crypt_iv_plain64_ops;
	else if (strcmp(ctx->ivmode, "essiv") == 0)
		ctx->iv_gen_ops = &crypt_iv_essiv_ops;
	else if (strcmp(ctx->ivmode, "benbi") == 0)
		ctx->iv_gen_ops = &crypt_iv_benbi_ops;
	else if (strcmp(ctx->ivmode, "null") == 0)
		ctx->iv_gen_ops = &crypt_iv_null_ops;
	else if (strcmp(ctx->ivmode, "lmk") == 0)
		ctx->iv_gen_ops = &crypt_iv_lmk_ops;
	else if (strcmp(ctx->ivmode, "tcw") == 0) {
		ctx->iv_gen_ops = &crypt_iv_tcw_ops;
		ctx->key_parts += 2; /* IV + whitening */
		ctx->key_extra_size = ctx->iv_size + TCW_WHITENING_SIZE;
	} else {
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

	ctx->iv_size = crypto_skcipher_ivsize(parent);
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

	/*
	 * A request from crypto driver backlog is going to be processed now,
	 * finish the completion and continue in crypt_convert().
	 * (Callback will be called for the second time for this request.)
	 */

	if (error == -EINPROGRESS) {
		complete(&rctx->restart);
		return;
	}

	if (!error && ctx->iv_gen_ops && ctx->iv_gen_ops->post)
		error = ctx->iv_gen_ops->post(ctx, rctx, subreq);

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
	for (i = 0; i < segments ; i++)
		n1 += sg1[i].length / SECTOR_SIZE;

	for (i = 0; i < segments ; i++)
		n2 += sg2[i].length / SECTOR_SIZE;

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

	sg_set_page(src2, sg_page(src1), len, srcoff);
	sg_set_page(dst2, sg_page(dst1), len, dstoff);

	*done += len;

	return len; /* bytes returned */
}

/* Common encryt/decrypt function for geniv template cipher. Before the crypto
 * operation, it splits the memory segments (in the scatterlist) into 512 byte
 * sectors. The initialization vector(IV) used is based on a unique sector
 * number which is generated here.
 */
static inline int geniv_crypt(struct skcipher_request *req, bool encrypt)
{
	struct crypto_skcipher *tfm = crypto_skcipher_reqtfm(req);
	struct geniv_ctx *ctx = crypto_skcipher_ctx(tfm);
	struct geniv_req_ctx *rctx = geniv_req_ctx(req);
	struct geniv_req_info *rinfo = (struct geniv_req_info *) req->iv;
	int i, bytes, cryptlen, ret = 0;
	unsigned int sectors, segno = 0, done = 0;
	char *str __maybe_unused = encrypt ? "encrypt" : "decrypt";

	/* Instance of 'struct geniv_req_info' is stored in IV ptr */
	rctx->is_write = rinfo->is_write;
	rctx->iv_sector = rinfo->iv_sector;
	rctx->nents = rinfo->nents;
	rctx->iv = rinfo->iv;
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

		atomic_inc(&rctx->req_pending);
		bytes = geniv_iter_block(req, subreq, rctx, &segno, &done);

		if (bytes == 0)
			break;

		cryptlen -= bytes;

		if (ctx->iv_gen_ops)
			ret = ctx->iv_gen_ops->generator(ctx, rctx, subreq);

		if (ret < 0) {
			DMERR("Error in generating IV ret: %d\n", ret);
			goto end;
		}

		skcipher_request_set_crypt(&subreq->req, &subreq->src,
					   &subreq->dst, bytes, rctx->iv);

		if (encrypt)
			ret = crypto_skcipher_encrypt(&subreq->req);

		else
			ret = crypto_skcipher_decrypt(&subreq->req);

		if (!ret && ctx->iv_gen_ops && ctx->iv_gen_ops->post)
			ret = ctx->iv_gen_ops->post(ctx, rctx, subreq);

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
	return geniv_crypt(req, true);
}

static int geniv_decrypt(struct skcipher_request *req)
{
	return geniv_crypt(req, false);
}

static int geniv_init_tfm(struct crypto_skcipher *tfm)
{
	struct geniv_ctx *ctx = crypto_skcipher_ctx(tfm);
	const int psize = sizeof(struct geniv_subreq);
	unsigned int reqsize, align;
	char *algname, *chainmode;
	int ret = 0;

	algname = (char *) crypto_tfm_alg_name(crypto_skcipher_tfm(tfm));
	ctx->ciphermode = kmalloc(CRYPTO_MAX_ALG_NAME, GFP_KERNEL);
	if (!ctx->ciphermode) {
		ret = -ENOMEM;
		goto end;
	}

	/* Parse algorithm name 'ivmode(chainmode(cipher))' */
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
		goto end;
	}

	/* Setup the current cipher's request structure */
	align = crypto_skcipher_alignmask(tfm);
	align &= ~(crypto_tfm_ctx_alignment() - 1);
	reqsize = align + sizeof(struct geniv_req_ctx)
			+ crypto_skcipher_reqsize(ctx->child);
	crypto_skcipher_set_reqsize(tfm, reqsize);

	/* create memory pool for sub-request structure */
	ctx->subreq_pool = mempool_create_kmalloc_pool(MIN_IOS, psize);
	if (!ctx->subreq_pool) {
		ret = -ENOMEM;
		DMERR("Could not allocate crypt sub-request mempool\n");
	}
end:
	return ret;
}

static void geniv_exit_tfm(struct crypto_skcipher *tfm)
{
	struct geniv_ctx *ctx = crypto_skcipher_ctx(tfm);

	if (ctx->iv_gen_ops && ctx->iv_gen_ops->dtr)
		ctx->iv_gen_ops->dtr(ctx);

	mempool_destroy(ctx->subreq_pool);
	geniv_free_tfms(ctx);
	kfree(ctx->ciphermode);
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

static int crypto_plain_create(struct crypto_template *tmpl,
			       struct rtattr **tb)
{
	return geniv_create(tmpl, tb, "plain");
}

static int crypto_plain64_create(struct crypto_template *tmpl,
				 struct rtattr **tb)
{
	return geniv_create(tmpl, tb, "plain64");
}

static int crypto_essiv_create(struct crypto_template *tmpl,
			       struct rtattr **tb)
{
	return geniv_create(tmpl, tb, "essiv");
}

static int crypto_benbi_create(struct crypto_template *tmpl,
			       struct rtattr **tb)
{
	return geniv_create(tmpl, tb, "benbi");
}

static int crypto_null_create(struct crypto_template *tmpl,
			      struct rtattr **tb)
{
	return geniv_create(tmpl, tb, "null");
}

static int crypto_lmk_create(struct crypto_template *tmpl,
			     struct rtattr **tb)
{
	return geniv_create(tmpl, tb, "lmk");
}

static int crypto_tcw_create(struct crypto_template *tmpl,
			     struct rtattr **tb)
{
	return geniv_create(tmpl, tb, "tcw");
}

static struct crypto_template crypto_plain_tmpl = {
	.name   = "plain",
	.create = crypto_plain_create,
	.module = THIS_MODULE,
};

static struct crypto_template crypto_plain64_tmpl = {
	.name   = "plain64",
	.create = crypto_plain64_create,
	.module = THIS_MODULE,
};

static struct crypto_template crypto_essiv_tmpl = {
	.name   = "essiv",
	.create = crypto_essiv_create,
	.module = THIS_MODULE,
};

static struct crypto_template crypto_benbi_tmpl = {
	.name   = "benbi",
	.create = crypto_benbi_create,
	.module = THIS_MODULE,
};

static struct crypto_template crypto_null_tmpl = {
	.name   = "null",
	.create = crypto_null_create,
	.module = THIS_MODULE,
};

static struct crypto_template crypto_lmk_tmpl = {
	.name   = "lmk",
	.create = crypto_lmk_create,
	.module = THIS_MODULE,
};

static struct crypto_template crypto_tcw_tmpl = {
	.name   = "tcw",
	.create = crypto_tcw_create,
	.module = THIS_MODULE,
};

static int __init geniv_register_algs(void)
{
	int err;

	err = crypto_register_template(&crypto_plain_tmpl);
	if (err)
		goto out;

	err = crypto_register_template(&crypto_plain64_tmpl);
	if (err)
		goto out_undo_plain;

	err = crypto_register_template(&crypto_essiv_tmpl);
	if (err)
		goto out_undo_plain64;

	err = crypto_register_template(&crypto_benbi_tmpl);
	if (err)
		goto out_undo_essiv;

	err = crypto_register_template(&crypto_null_tmpl);
	if (err)
		goto out_undo_benbi;

	err = crypto_register_template(&crypto_lmk_tmpl);
	if (err)
		goto out_undo_null;

	err = crypto_register_template(&crypto_tcw_tmpl);
	if (!err)
		goto out;

	crypto_unregister_template(&crypto_lmk_tmpl);
out_undo_null:
	crypto_unregister_template(&crypto_null_tmpl);
out_undo_benbi:
	crypto_unregister_template(&crypto_benbi_tmpl);
out_undo_essiv:
	crypto_unregister_template(&crypto_essiv_tmpl);
out_undo_plain64:
	crypto_unregister_template(&crypto_plain64_tmpl);
out_undo_plain:
	crypto_unregister_template(&crypto_plain_tmpl);
out:
	return err;
}

static void __exit geniv_deregister_algs(void)
{
	crypto_unregister_template(&crypto_plain_tmpl);
	crypto_unregister_template(&crypto_plain64_tmpl);
	crypto_unregister_template(&crypto_essiv_tmpl);
	crypto_unregister_template(&crypto_benbi_tmpl);
	crypto_unregister_template(&crypto_null_tmpl);
	crypto_unregister_template(&crypto_lmk_tmpl);
	crypto_unregister_template(&crypto_tcw_tmpl);
}

/* End of geniv template cipher algorithms */

/*
 * context holding the current state of a multi-part conversion
 */
struct convert_context {
	struct completion restart;
	struct bio *bio_in;
	struct bio *bio_out;
	struct bvec_iter iter_in;
	struct bvec_iter iter_out;
	sector_t cc_sector;
	atomic_t cc_pending;
	struct skcipher_request *req;
};

/*
 * per bio private data
 */
struct dm_crypt_io {
	struct crypt_config *cc;
	struct bio *base_bio;
	struct work_struct work;

	struct convert_context ctx;

	atomic_t io_pending;
	int error;
	sector_t sector;

	struct rb_node rb_node;
} CRYPTO_MINALIGN_ATTR;

struct dm_crypt_request {
	struct convert_context *ctx;
	struct scatterlist *sg_in;
	struct scatterlist *sg_out;
	sector_t iv_sector;
};

struct crypt_config;

/*
 * Crypt: maps a linear range of a block device
 * and encrypts / decrypts at the same time.
 */
enum flags { DM_CRYPT_SUSPENDED, DM_CRYPT_KEY_VALID,
	     DM_CRYPT_SAME_CPU, DM_CRYPT_NO_OFFLOAD };

/*
 * The fields in here must be read only after initialization.
 */
struct crypt_config {
	struct dm_dev *dev;
	sector_t start;

	/*
	 * pool for per bio private data, crypto requests and
	 * encryption requeusts/buffer pages
	 */
	mempool_t *req_pool;
	mempool_t *page_pool;
	struct bio_set *bs;
	struct mutex bio_alloc_lock;

	struct workqueue_struct *io_queue;
	struct workqueue_struct *crypt_queue;

	struct task_struct *write_thread;
	wait_queue_head_t write_thread_wait;
	struct rb_root write_tree;

	char *cipher;
	char *cipher_string;
	char *key_string;

	sector_t iv_offset;
	unsigned int iv_size;

	/* ESSIV: struct crypto_cipher *essiv_tfm */
	void *iv_private;
	struct crypto_skcipher *tfm;
	unsigned int tfms_count;

	/*
	 * Layout of each crypto request:
	 *
	 *   struct skcipher_request
	 *      context
	 *      padding
	 *   struct dm_crypt_request
	 *      padding
	 *   IV
	 *
	 * The padding is added so that dm_crypt_request and the IV are
	 * correctly aligned.
	 */
	unsigned int dmreq_start;

	unsigned int per_bio_data_size;

	unsigned long flags;
	unsigned int key_size;
	unsigned int key_parts;      /* independent parts in key buffer */
	unsigned int key_extra_size; /* additional keys length */
	u8 key[0];
};

static void clone_init(struct dm_crypt_io *, struct bio *);
static void kcryptd_queue_crypt(struct dm_crypt_io *io);
static u8 *iv_of_dmreq(struct crypt_config *cc, struct dm_crypt_request *dmreq);

static void crypt_convert_init(struct crypt_config *cc,
			       struct convert_context *ctx,
			       struct bio *bio_out, struct bio *bio_in,
			       sector_t sector)
{
	ctx->bio_in = bio_in;
	ctx->bio_out = bio_out;
	if (bio_in)
		ctx->iter_in = bio_in->bi_iter;
	if (bio_out)
		ctx->iter_out = bio_out->bi_iter;
	ctx->cc_sector = sector + cc->iv_offset;
	init_completion(&ctx->restart);
}

static struct dm_crypt_request *dmreq_of_req(struct crypt_config *cc,
					     struct skcipher_request *req)
{
	return (struct dm_crypt_request *)((char *)req + cc->dmreq_start);
}

static struct skcipher_request *req_of_dmreq(struct crypt_config *cc,
					       struct dm_crypt_request *dmreq)
{
	return (struct skcipher_request *)((char *)dmreq - cc->dmreq_start);
}

static u8 *iv_of_dmreq(struct crypt_config *cc,
		       struct dm_crypt_request *dmreq)
{
	return (u8 *)ALIGN((unsigned long)(dmreq + 1),
		crypto_skcipher_alignmask(cc->tfm) + 1);
}

static void kcryptd_async_done(struct crypto_async_request *async_req,
			       int error);

static void crypt_alloc_req(struct crypt_config *cc,
			    struct convert_context *ctx)
{
	if (!ctx->req)
		ctx->req = mempool_alloc(cc->req_pool, GFP_NOIO);

	skcipher_request_set_tfm(ctx->req, cc->tfm);

	/*
	 * Use REQ_MAY_BACKLOG so a cipher driver internally backlogs
	 * requests if driver request queue is full.
	 */
	skcipher_request_set_callback(ctx->req,
	    CRYPTO_TFM_REQ_MAY_BACKLOG | CRYPTO_TFM_REQ_MAY_SLEEP,
	    kcryptd_async_done, dmreq_of_req(cc, ctx->req));
}

static void crypt_free_req(struct crypt_config *cc,
			   struct skcipher_request *req, struct bio *base_bio)
{
	struct dm_crypt_io *io = dm_per_bio_data(base_bio, cc->per_bio_data_size);

	if ((struct skcipher_request *)(io + 1) != req)
		mempool_free(req, cc->req_pool);
}

/*
 * Encrypt / decrypt data from one bio to another one (can be the same one)
 */

static int crypt_convert_bio(struct crypt_config *cc,
			     struct convert_context *ctx)
{
	unsigned int cryptlen, n1, n2, nents, i = 0, bytes = 0;
	struct skcipher_request *req;
	struct dm_crypt_request *dmreq;
	struct geniv_req_info rinfo;
	struct bio_vec bv_in, bv_out;
	int r;
	u8 *iv;

	atomic_set(&ctx->cc_pending, 1);
	crypt_alloc_req(cc, ctx);

	req = ctx->req;
	dmreq = dmreq_of_req(cc, req);
	iv = iv_of_dmreq(cc, dmreq);

	n1 = bio_segments(ctx->bio_in);
	n2 = bio_segments(ctx->bio_in);
	nents = n1 > n2 ? n1 : n2;
	nents = nents > MAX_SG_LIST ? MAX_SG_LIST : nents;
	cryptlen = ctx->iter_in.bi_size;

	DMDEBUG("dm-crypt:%s: segments:[in=%u, out=%u] bi_size=%u\n",
		bio_data_dir(ctx->bio_in) == WRITE ? "write" : "read",
		n1, n2, cryptlen);

	dmreq->sg_in  = kcalloc(nents, sizeof(struct scatterlist), GFP_KERNEL);
	dmreq->sg_out = kcalloc(nents, sizeof(struct scatterlist), GFP_KERNEL);
	if (!dmreq->sg_in || !dmreq->sg_out) {
		DMERR("dm-crypt: Failed to allocate scatterlist\n");
		r = -ENOMEM;
		goto end;
	}
	dmreq->ctx = ctx;

	sg_init_table(dmreq->sg_in, nents);
	sg_init_table(dmreq->sg_out, nents);

	while (ctx->iter_in.bi_size && ctx->iter_out.bi_size && i < nents) {
		bv_in = bio_iter_iovec(ctx->bio_in, ctx->iter_in);
		bv_out = bio_iter_iovec(ctx->bio_out, ctx->iter_out);

		sg_set_page(&dmreq->sg_in[i], bv_in.bv_page, bv_in.bv_len,
			    bv_in.bv_offset);
		sg_set_page(&dmreq->sg_out[i], bv_out.bv_page, bv_out.bv_len,
			    bv_out.bv_offset);

		bio_advance_iter(ctx->bio_in, &ctx->iter_in, bv_in.bv_len);
		bio_advance_iter(ctx->bio_out, &ctx->iter_out, bv_out.bv_len);

		bytes += bv_in.bv_len;
		i++;
	}

	DMDEBUG("dm-crypt: Processed %u of %u bytes\n", bytes, cryptlen);

	rinfo.is_write = bio_data_dir(ctx->bio_in) == WRITE;
	rinfo.iv_sector = ctx->cc_sector;
	rinfo.nents = nents;
	rinfo.iv = iv;

	skcipher_request_set_crypt(req, dmreq->sg_in, dmreq->sg_out,
				   bytes, &rinfo);

	if (bio_data_dir(ctx->bio_in) == WRITE)
		r = crypto_skcipher_encrypt(req);
	else
		r = crypto_skcipher_decrypt(req);

	switch (r) {
	/* The request was queued so wait. */
	case -EBUSY:
		wait_for_completion(&ctx->restart);
		reinit_completion(&ctx->restart);
		/* fall through */
	/*
	 * The request is queued and processed asynchronously,
	 * completion function kcryptd_async_done() is called.
	 */
	case -EINPROGRESS:
		ctx->req = NULL;
		cond_resched();
		break;
	}
end:
	return r;
}


static void crypt_free_buffer_pages(struct crypt_config *cc, struct bio *clone);

/*
 * Generate a new unfragmented bio with the given size
 * This should never violate the device limitations (but only because
 * max_segment_size is being constrained to PAGE_SIZE).
 *
 * This function may be called concurrently. If we allocate from the mempool
 * concurrently, there is a possibility of deadlock. For example, if we have
 * mempool of 256 pages, two processes, each wanting 256, pages allocate from
 * the mempool concurrently, it may deadlock in a situation where both processes
 * have allocated 128 pages and the mempool is exhausted.
 *
 * In order to avoid this scenario we allocate the pages under a mutex.
 *
 * In order to not degrade performance with excessive locking, we try
 * non-blocking allocations without a mutex first but on failure we fallback
 * to blocking allocations with a mutex.
 */
static struct bio *crypt_alloc_buffer(struct dm_crypt_io *io, unsigned size)
{
	struct crypt_config *cc = io->cc;
	struct bio *clone;
	unsigned int nr_iovecs = (size + PAGE_SIZE - 1) >> PAGE_SHIFT;
	gfp_t gfp_mask = GFP_NOWAIT | __GFP_HIGHMEM;
	unsigned i, len, remaining_size;
	struct page *page;

retry:
	if (unlikely(gfp_mask & __GFP_DIRECT_RECLAIM))
		mutex_lock(&cc->bio_alloc_lock);

	clone = bio_alloc_bioset(GFP_NOIO, nr_iovecs, cc->bs);
	if (!clone)
		goto return_clone;

	clone_init(io, clone);

	remaining_size = size;

	for (i = 0; i < nr_iovecs; i++) {
		page = mempool_alloc(cc->page_pool, gfp_mask);
		if (!page) {
			crypt_free_buffer_pages(cc, clone);
			bio_put(clone);
			gfp_mask |= __GFP_DIRECT_RECLAIM;
			goto retry;
		}

		len = (remaining_size > PAGE_SIZE) ? PAGE_SIZE : remaining_size;

		bio_add_page(clone, page, len, 0);

		remaining_size -= len;
	}

return_clone:
	if (unlikely(gfp_mask & __GFP_DIRECT_RECLAIM))
		mutex_unlock(&cc->bio_alloc_lock);

	return clone;
}

static void crypt_free_buffer_pages(struct crypt_config *cc, struct bio *clone)
{
	unsigned int i;
	struct bio_vec *bv;

	bio_for_each_segment_all(bv, clone, i) {
		BUG_ON(!bv->bv_page);
		mempool_free(bv->bv_page, cc->page_pool);
		bv->bv_page = NULL;
	}
}

static void crypt_io_init(struct dm_crypt_io *io, struct crypt_config *cc,
			  struct bio *bio, sector_t sector)
{
	io->cc = cc;
	io->base_bio = bio;
	io->sector = sector;
	io->error = 0;
	io->ctx.req = NULL;
	atomic_set(&io->io_pending, 0);
}

static void crypt_inc_pending(struct dm_crypt_io *io)
{
	atomic_inc(&io->io_pending);
}

/*
 * One of the bios was finished. Check for completion of
 * the whole request and correctly clean up the buffer.
 */
static void crypt_dec_pending(struct dm_crypt_io *io)
{
	struct crypt_config *cc = io->cc;
	struct bio *base_bio = io->base_bio;
	struct dm_crypt_request *dmreq;
	int error = io->error;

	if (!atomic_dec_and_test(&io->io_pending))
		return;

	dmreq = dmreq_of_req(cc, io->ctx.req);
	DMDEBUG("dm-crypt: Freeing scatterlists [sync]\n");
	kfree(dmreq->sg_in);
	kfree(dmreq->sg_out);

	if (io->ctx.req)
		crypt_free_req(cc, io->ctx.req, base_bio);

	base_bio->bi_error = error;
	bio_endio(base_bio);
}

/*
 * kcryptd/kcryptd_io:
 *
 * Needed because it would be very unwise to do decryption in an
 * interrupt context.
 *
 * kcryptd performs the actual encryption or decryption.
 *
 * kcryptd_io performs the IO submission.
 *
 * They must be separated as otherwise the final stages could be
 * starved by new requests which can block in the first stages due
 * to memory allocation.
 *
 * The work is done per CPU global for all dm-crypt instances.
 * They should not depend on each other and do not block.
 */
static void crypt_endio(struct bio *clone)
{
	struct dm_crypt_io *io = clone->bi_private;
	struct crypt_config *cc = io->cc;
	unsigned rw = bio_data_dir(clone);
	int error;

	/*
	 * free the processed pages
	 */
	if (rw == WRITE)
		crypt_free_buffer_pages(cc, clone);

	error = clone->bi_error;
	bio_put(clone);

	if (rw == READ && !error) {
		kcryptd_queue_crypt(io);
		return;
	}

	if (unlikely(error))
		io->error = error;

	crypt_dec_pending(io);
}

static void clone_init(struct dm_crypt_io *io, struct bio *clone)
{
	struct crypt_config *cc = io->cc;

	clone->bi_private = io;
	clone->bi_end_io  = crypt_endio;
	clone->bi_bdev    = cc->dev->bdev;
	clone->bi_opf	  = io->base_bio->bi_opf;
}

static int kcryptd_io_read(struct dm_crypt_io *io, gfp_t gfp)
{
	struct crypt_config *cc = io->cc;
	struct bio *clone;

	/*
	 * We need the original biovec array in order to decrypt
	 * the whole bio data *afterwards* -- thanks to immutable
	 * biovecs we don't need to worry about the block layer
	 * modifying the biovec array; so leverage bio_clone_fast().
	 */
	clone = bio_clone_fast(io->base_bio, gfp, cc->bs);
	if (!clone)
		return 1;

	crypt_inc_pending(io);

	clone_init(io, clone);
	clone->bi_iter.bi_sector = cc->start + io->sector;

	generic_make_request(clone);
	return 0;
}

static void kcryptd_io_read_work(struct work_struct *work)
{
	struct dm_crypt_io *io = container_of(work, struct dm_crypt_io, work);

	crypt_inc_pending(io);
	if (kcryptd_io_read(io, GFP_NOIO))
		io->error = -ENOMEM;
	crypt_dec_pending(io);
}

static void kcryptd_queue_read(struct dm_crypt_io *io)
{
	struct crypt_config *cc = io->cc;

	INIT_WORK(&io->work, kcryptd_io_read_work);
	queue_work(cc->io_queue, &io->work);
}

static void kcryptd_io_write(struct dm_crypt_io *io)
{
	struct bio *clone = io->ctx.bio_out;

	generic_make_request(clone);
}

#define crypt_io_from_node(node) rb_entry((node), struct dm_crypt_io, rb_node)

static int dmcrypt_write(void *data)
{
	struct crypt_config *cc = data;
	struct dm_crypt_io *io;

	while (1) {
		struct rb_root write_tree;
		struct blk_plug plug;

		DECLARE_WAITQUEUE(wait, current);

		spin_lock_irq(&cc->write_thread_wait.lock);
continue_locked:

		if (!RB_EMPTY_ROOT(&cc->write_tree))
			goto pop_from_list;

		set_current_state(TASK_INTERRUPTIBLE);
		__add_wait_queue(&cc->write_thread_wait, &wait);

		spin_unlock_irq(&cc->write_thread_wait.lock);

		if (unlikely(kthread_should_stop())) {
			set_task_state(current, TASK_RUNNING);
			remove_wait_queue(&cc->write_thread_wait, &wait);
			break;
		}

		schedule();

		set_task_state(current, TASK_RUNNING);
		spin_lock_irq(&cc->write_thread_wait.lock);
		__remove_wait_queue(&cc->write_thread_wait, &wait);
		goto continue_locked;

pop_from_list:
		write_tree = cc->write_tree;
		cc->write_tree = RB_ROOT;
		spin_unlock_irq(&cc->write_thread_wait.lock);

		BUG_ON(rb_parent(write_tree.rb_node));

		/*
		 * Note: we cannot walk the tree here with rb_next because
		 * the structures may be freed when kcryptd_io_write is called.
		 */
		blk_start_plug(&plug);
		do {
			io = crypt_io_from_node(rb_first(&write_tree));
			rb_erase(&io->rb_node, &write_tree);
			kcryptd_io_write(io);
		} while (!RB_EMPTY_ROOT(&write_tree));
		blk_finish_plug(&plug);
	}
	return 0;
}

static void kcryptd_crypt_write_io_submit(struct dm_crypt_io *io, int async)
{
	struct bio *clone = io->ctx.bio_out;
	struct crypt_config *cc = io->cc;
	unsigned long flags;
	sector_t sector;
	struct rb_node **rbp, *parent;

	if (unlikely(io->error < 0)) {
		crypt_free_buffer_pages(cc, clone);
		bio_put(clone);
		crypt_dec_pending(io);
		return;
	}

	/* crypt_convert should have filled the clone bio */
	BUG_ON(io->ctx.iter_out.bi_size);

	clone->bi_iter.bi_sector = cc->start + io->sector;

	if (likely(!async) && test_bit(DM_CRYPT_NO_OFFLOAD, &cc->flags)) {
		generic_make_request(clone);
		return;
	}

	spin_lock_irqsave(&cc->write_thread_wait.lock, flags);
	rbp = &cc->write_tree.rb_node;
	parent = NULL;
	sector = io->sector;
	while (*rbp) {
		parent = *rbp;
		if (sector < crypt_io_from_node(parent)->sector)
			rbp = &(*rbp)->rb_left;
		else
			rbp = &(*rbp)->rb_right;
	}
	rb_link_node(&io->rb_node, parent, rbp);
	rb_insert_color(&io->rb_node, &cc->write_tree);

	wake_up_locked(&cc->write_thread_wait);
	spin_unlock_irqrestore(&cc->write_thread_wait.lock, flags);
}

static void kcryptd_crypt_write_convert(struct dm_crypt_io *io)
{
	struct crypt_config *cc = io->cc;
	struct bio *clone;
	int crypt_finished;
	sector_t sector = io->sector;
	int r;

	/*
	 * Prevent io from disappearing until this function completes.
	 */
	crypt_inc_pending(io);
	crypt_convert_init(cc, &io->ctx, NULL, io->base_bio, sector);

	clone = crypt_alloc_buffer(io, io->base_bio->bi_iter.bi_size);
	if (unlikely(!clone)) {
		io->error = -EIO;
		goto dec;
	}

	io->ctx.bio_out = clone;
	io->ctx.iter_out = clone->bi_iter;

	sector += bio_sectors(clone);

	crypt_inc_pending(io);
	r = crypt_convert_bio(cc, &io->ctx);
	if (r)
		io->error = -EIO;
	crypt_finished = atomic_dec_and_test(&io->ctx.cc_pending);

	/* Encryption was already finished, submit io now */
	if (crypt_finished) {
		kcryptd_crypt_write_io_submit(io, 0);
		io->sector = sector;
	}

dec:
	crypt_dec_pending(io);
}

static void kcryptd_crypt_read_done(struct dm_crypt_io *io)
{
	crypt_dec_pending(io);
}

static void kcryptd_crypt_read_convert(struct dm_crypt_io *io)
{
	struct crypt_config *cc = io->cc;
	int r = 0;

	crypt_inc_pending(io);

	crypt_convert_init(cc, &io->ctx, io->base_bio, io->base_bio,
			   io->sector);

	r = crypt_convert_bio(cc, &io->ctx);

	if (r < 0)
		io->error = -EIO;

	if (atomic_dec_and_test(&io->ctx.cc_pending))
		kcryptd_crypt_read_done(io);

	crypt_dec_pending(io);
}

static void kcryptd_async_done(struct crypto_async_request *async_req,
			       int error)
{
	struct dm_crypt_request *dmreq = async_req->data;
	struct convert_context *ctx = dmreq->ctx;
	struct dm_crypt_io *io = container_of(ctx, struct dm_crypt_io, ctx);
	struct crypt_config *cc = io->cc;

	/*
	 * A request from crypto driver backlog is going to be processed now,
	 * finish the completion and continue in crypt_convert().
	 * (Callback will be called for the second time for this request.)
	 */
	if (error == -EINPROGRESS) {
		complete(&ctx->restart);
		return;
	}

	if (error < 0)
		io->error = -EIO;

	DMDEBUG("dm-crypt: Freeing scatterlists and request struct [async]\n");
	kfree(dmreq->sg_in);
	kfree(dmreq->sg_out);

	crypt_free_req(cc, req_of_dmreq(cc, dmreq), io->base_bio);

	if (!atomic_dec_and_test(&ctx->cc_pending))
		return;

	if (bio_data_dir(io->base_bio) == READ)
		kcryptd_crypt_read_done(io);
	else
		kcryptd_crypt_write_io_submit(io, 1);
}

static void kcryptd_crypt(struct work_struct *work)
{
	struct dm_crypt_io *io = container_of(work, struct dm_crypt_io, work);

	if (bio_data_dir(io->base_bio) == READ)
		kcryptd_crypt_read_convert(io);
	else
		kcryptd_crypt_write_convert(io);
}

static void kcryptd_queue_crypt(struct dm_crypt_io *io)
{
	struct crypt_config *cc = io->cc;

	INIT_WORK(&io->work, kcryptd_crypt);
	queue_work(cc->crypt_queue, &io->work);
}

/*
 * Decode key from its hex representation
 */
static int crypt_decode_key(u8 *key, char *hex, unsigned int size)
{
	char buffer[3];
	unsigned int i;

	buffer[2] = '\0';

	for (i = 0; i < size; i++) {
		buffer[0] = *hex++;
		buffer[1] = *hex++;

		if (kstrtou8(buffer, 16, &key[i]))
			return -EINVAL;
	}

	if (*hex != '\0')
		return -EINVAL;

	return 0;
}

static void crypt_free_tfm(struct crypt_config *cc)
{
	if (!cc->tfm)
		return;

	if (cc->tfm && !IS_ERR(cc->tfm))
		crypto_free_skcipher(cc->tfm);

	cc->tfm = NULL;
}

static int crypt_alloc_tfm(struct crypt_config *cc, char *ciphermode)
{
	int err;

	cc->tfm = crypto_alloc_skcipher(ciphermode, 0, 0);
	if (IS_ERR(cc->tfm)) {
		err = PTR_ERR(cc->tfm);
		crypt_free_tfm(cc);
		return err;
	}

	return 0;
}

static inline int crypt_setkey(struct crypt_config *cc, enum setkey_op keyop,
			       char *ivopts)
{
	DECLARE_GENIV_KEY(kinfo, keyop, cc->tfms_count, cc->key, cc->key_size,
			  cc->key_parts, ivopts);

	return crypto_skcipher_setkey(cc->tfm, (u8 *) &kinfo, sizeof(kinfo));
}

#ifdef CONFIG_KEYS

static bool contains_whitespace(const char *str)
{
	while (*str)
		if (isspace(*str++))
			return true;
	return false;
}

static int crypt_set_keyring_key(struct crypt_config *cc,
				 const char *key_string,
				 enum setkey_op keyop, char *ivopts)
{
	char *new_key_string, *key_desc;
	int ret;
	struct key *key;
	const struct user_key_payload *ukp;

	/*
	 * Reject key_string with whitespace. dm core currently lacks code for
	 * proper whitespace escaping in arguments on DM_TABLE_STATUS path.
	 */
	if (contains_whitespace(key_string)) {
		DMERR("whitespace chars not allowed in key string");
		return -EINVAL;
	}

	/* look for next ':' separating key_type from key_description */
	key_desc = strpbrk(key_string, ":");
	if (!key_desc || key_desc == key_string || !strlen(key_desc + 1))
		return -EINVAL;

	if (strncmp(key_string, "logon:", key_desc - key_string + 1) &&
	    strncmp(key_string, "user:", key_desc - key_string + 1))
		return -EINVAL;

	new_key_string = kstrdup(key_string, GFP_KERNEL);
	if (!new_key_string)
		return -ENOMEM;

	key = request_key(key_string[0] == 'l' ? &key_type_logon : &key_type_user,
			  key_desc + 1, NULL);
	if (IS_ERR(key)) {
		kzfree(new_key_string);
		return PTR_ERR(key);
	}

	rcu_read_lock();

	ukp = user_key_payload(key);
	if (!ukp) {
		rcu_read_unlock();
		key_put(key);
		kzfree(new_key_string);
		return -EKEYREVOKED;
	}

	if (cc->key_size != ukp->datalen) {
		rcu_read_unlock();
		key_put(key);
		kzfree(new_key_string);
		return -EINVAL;
	}

	memcpy(cc->key, ukp->data, cc->key_size);

	rcu_read_unlock();
	key_put(key);

	/* clear the flag since following operations may invalidate previously valid key */
	clear_bit(DM_CRYPT_KEY_VALID, &cc->flags);

	ret = crypt_setkey(cc, keyop, ivopts);

	/* wipe the kernel key payload copy in each case */
	memset(cc->key, 0, cc->key_size * sizeof(u8));

	if (!ret) {
		set_bit(DM_CRYPT_KEY_VALID, &cc->flags);
		kzfree(cc->key_string);
		cc->key_string = new_key_string;
	} else
		kzfree(new_key_string);

	return ret;
}

static int get_key_size(char **key_string)
{
	char *colon, dummy;
	int ret;

	if (*key_string[0] != ':')
		return strlen(*key_string) >> 1;

	/* look for next ':' in key string */
	colon = strpbrk(*key_string + 1, ":");
	if (!colon)
		return -EINVAL;

	if (sscanf(*key_string + 1, "%u%c", &ret, &dummy) != 2 || dummy != ':')
		return -EINVAL;

	*key_string = colon;

	/* remaining key string should be :<logon|user>:<key_desc> */

	return ret;
}

#else

static int crypt_set_keyring_key(struct crypt_config *cc,
				 const char *key_string,
				 enum setkey_op keyop, char *ivopts)
{
	return -EINVAL;
}

static int get_key_size(char **key_string)
{
	return (*key_string[0] == ':') ? -EINVAL : strlen(*key_string) >> 1;
}

#endif

static int crypt_set_key(struct crypt_config *cc, enum setkey_op keyop,
			 char *key, char *ivopts)
{
	int r = -EINVAL;
	int key_string_len = strlen(key);

	/* Hyphen (which gives a key_size of zero) means there is no key. */
	if (!cc->key_size && strcmp(key, "-"))
		goto out;

	/* ':' means the key is in kernel keyring, short-circuit normal key processing */
	if (key[0] == ':') {
		r = crypt_set_keyring_key(cc, key + 1, keyop, ivopts);
		goto out;
	}

	/* clear the flag since following operations may invalidate previously valid key */
	clear_bit(DM_CRYPT_KEY_VALID, &cc->flags);

	/* wipe references to any kernel keyring key */
	kzfree(cc->key_string);
	cc->key_string = NULL;

	if (cc->key_size && crypt_decode_key(cc->key, key, cc->key_size) < 0)
		goto out;

	r = crypt_setkey(cc, keyop, ivopts);
	if (!r)
		set_bit(DM_CRYPT_KEY_VALID, &cc->flags);

out:
	/* Hex key string not needed after here, so wipe it. */
	memset(key, '0', key_string_len);

	return r;
}

static int crypt_init_key(struct dm_target *ti, char *key, char *ivopts)
{
	struct crypt_config *cc = ti->private;
	int ret;

	ret = crypt_set_key(cc, SETKEY_OP_INIT, key, ivopts);
	if (ret < 0)
		ti->error = "Error decoding and setting key";
	return ret;
}

static int crypt_wipe_key(struct crypt_config *cc)
{
	clear_bit(DM_CRYPT_KEY_VALID, &cc->flags);
	memset(&cc->key, 0, cc->key_size * sizeof(u8));
	kzfree(cc->key_string);
	cc->key_string = NULL;

	return crypt_setkey(cc, SETKEY_OP_WIPE, NULL);
}

static void crypt_dtr(struct dm_target *ti)
{
	struct crypt_config *cc = ti->private;

	ti->private = NULL;

	if (!cc)
		return;

	if (cc->write_thread)
		kthread_stop(cc->write_thread);

	if (cc->io_queue)
		destroy_workqueue(cc->io_queue);
	if (cc->crypt_queue)
		destroy_workqueue(cc->crypt_queue);

	crypt_free_tfm(cc);

	if (cc->bs)
		bioset_free(cc->bs);

	mempool_destroy(cc->page_pool);
	mempool_destroy(cc->req_pool);

	if (cc->dev)
		dm_put_device(ti, cc->dev);

	kzfree(cc->cipher);
	kzfree(cc->cipher_string);
	kzfree(cc->key_string);

	/* Must zero key material before freeing */
	kzfree(cc);
}

static int crypt_ctr_cipher(struct dm_target *ti,
			    char *cipher_in, char *key)
{
	struct crypt_config *cc = ti->private;
	char *tmp, *cipher, *chainmode, *ivmode, *ivopts, *keycount;
	char *cipher_api = NULL;
	int ret = -EINVAL;
	char dummy;

	/* Convert to crypto api definition? */
	if (strchr(cipher_in, '(')) {
		ti->error = "Bad cipher specification";
		return -EINVAL;
	}

	cc->cipher_string = kstrdup(cipher_in, GFP_KERNEL);
	if (!cc->cipher_string)
		goto bad_mem;

	/*
	 * Legacy dm-crypt cipher specification
	 * cipher[:keycount]-mode-iv:ivopts
	 */
	tmp = cipher_in;
	keycount = strsep(&tmp, "-");
	cipher = strsep(&keycount, ":");

	if (!keycount)
		cc->tfms_count = 1;
	else if (sscanf(keycount, "%u%c", &cc->tfms_count, &dummy) != 1 ||
		 !is_power_of_2(cc->tfms_count)) {
		ti->error = "Bad cipher key count specification";
		return -EINVAL;
	}
	cc->key_parts = cc->tfms_count;
	cc->key_extra_size = 0;

	cc->cipher = kstrdup(cipher, GFP_KERNEL);
	if (!cc->cipher)
		goto bad_mem;

	chainmode = strsep(&tmp, "-");
	ivopts = strsep(&tmp, "-");
	ivmode = strsep(&ivopts, ":");

	if (tmp)
		DMWARN("Ignoring unexpected additional cipher options");

	/*
	 * For compatibility with the original dm-crypt mapping format, if
	 * only the cipher name is supplied, use cbc-plain.
	 */
	if (!chainmode || (!strcmp(chainmode, "plain") && !ivmode)) {
		chainmode = "cbc";
		ivmode = "plain";
	}

	if (strcmp(chainmode, "ecb") && !ivmode) {
		ti->error = "IV mechanism required";
		return -EINVAL;
	}

	cipher_api = kmalloc(CRYPTO_MAX_ALG_NAME, GFP_KERNEL);
	if (!cipher_api)
		goto bad_mem;

create_cipher:
	/* For those ciphers which do not support IVs,
	 * use the 'null' template cipher
	 */

	if (!ivmode)
		ivmode = "null";

	ret = snprintf(cipher_api, CRYPTO_MAX_ALG_NAME, "%s(%s(%s))",
		       ivmode, chainmode, cipher);
	if (ret < 0) {
		kfree(cipher_api);
		goto bad_mem;
	}

	/* Allocate cipher */
	ret = crypt_alloc_tfm(cc, cipher_api);
	if (ret < 0) {
		ti->error = "Error allocating crypto tfm";
		goto bad;
	}

	/* Initialize IV */
	cc->iv_size = crypto_skcipher_ivsize(cc->tfm);
	if (cc->iv_size)
		/* at least a 64 bit sector number should fit in our buffer */
		cc->iv_size = max(cc->iv_size,
				  (unsigned int)(sizeof(u64) / sizeof(u8)));
	else if (ivmode) {
		DMWARN("Selected cipher does not support IVs");
		ivmode = NULL;
		goto create_cipher;
	}

	if (strcmp(ivmode, "lmk") == 0) {
		/*
		 * Version 2 and 3 is recognised according
		 * to length of provided multi-key string.
		 * If present (version 3), last key is used as IV seed.
		 * All keys (including IV seed) are always the same size.
		 */
		if (cc->key_size % cc->key_parts) {
			cc->key_parts++;
			cc->key_extra_size = cc->key_size / cc->key_parts;
		}
	} else if (strcmp(ivmode, "tcw") == 0) {
		cc->key_parts += 2; /* IV + whitening */
		cc->key_extra_size = cc->iv_size + TCW_WHITENING_SIZE;
	}

	/* Initialize and set key */
	ret = crypt_init_key(ti, key, ivopts);
	if (ret < 0)
		goto bad;

	ret = 0;
bad:
	kfree(cipher_api);
	return ret;

bad_mem:
	ti->error = "Cannot allocate cipher strings";
	return -ENOMEM;
}

/*
 * Construct an encryption mapping:
 * <cipher> [<key>|:<key_size>:<user|logon>:<key_description>] <iv_offset> <dev_path> <start>
 */
static int crypt_ctr(struct dm_target *ti, unsigned int argc, char **argv)
{
	struct crypt_config *cc;
	int key_size;
	unsigned int opt_params;
	unsigned long long tmpll;
	int ret;
	size_t iv_size_padding;
	struct dm_arg_set as;
	const char *opt_string;
	char dummy;

	static struct dm_arg _args[] = {
		{0, 3, "Invalid number of feature args"},
	};

	if (argc < 5) {
		ti->error = "Not enough arguments";
		return -EINVAL;
	}

	key_size = get_key_size(&argv[1]);
	if (key_size < 0) {
		ti->error = "Cannot parse key size";
		return -EINVAL;
	}

	cc = kzalloc(sizeof(*cc) + key_size * sizeof(u8), GFP_KERNEL);
	if (!cc) {
		ti->error = "Cannot allocate encryption context";
		return -ENOMEM;
	}
	cc->key_size = key_size;

	ti->private = cc;
	ret = crypt_ctr_cipher(ti, argv[0], argv[1]);
	if (ret < 0)
		goto bad;

	cc->dmreq_start = sizeof(struct skcipher_request);
	cc->dmreq_start += crypto_skcipher_reqsize(cc->tfm);
	cc->dmreq_start = ALIGN(cc->dmreq_start, __alignof__(struct dm_crypt_request));

	if (crypto_skcipher_alignmask(cc->tfm) < CRYPTO_MINALIGN) {
		/* Allocate the padding exactly */
		iv_size_padding = -(cc->dmreq_start + sizeof(struct dm_crypt_request))
				& crypto_skcipher_alignmask(cc->tfm);
	} else {
		/*
		 * If the cipher requires greater alignment than kmalloc
		 * alignment, we don't know the exact position of the
		 * initialization vector. We must assume worst case.
		 */
		iv_size_padding = crypto_skcipher_alignmask(cc->tfm);
	}

	ret = -ENOMEM;
	cc->req_pool = mempool_create_kmalloc_pool(MIN_IOS, cc->dmreq_start +
			sizeof(struct dm_crypt_request) + iv_size_padding + cc->iv_size);
	if (!cc->req_pool) {
		ti->error = "Cannot allocate crypt request mempool";
		goto bad;
	}

	cc->per_bio_data_size = ti->per_io_data_size =
		ALIGN(sizeof(struct dm_crypt_io) + cc->dmreq_start +
		      sizeof(struct dm_crypt_request) + iv_size_padding + cc->iv_size,
		      ARCH_KMALLOC_MINALIGN);

	cc->page_pool = mempool_create_page_pool(BIO_MAX_PAGES, 0);
	if (!cc->page_pool) {
		ti->error = "Cannot allocate page mempool";
		goto bad;
	}

	cc->bs = bioset_create(MIN_IOS, 0);
	if (!cc->bs) {
		ti->error = "Cannot allocate crypt bioset";
		goto bad;
	}

	mutex_init(&cc->bio_alloc_lock);

	ret = -EINVAL;
	if (sscanf(argv[2], "%llu%c", &tmpll, &dummy) != 1) {
		ti->error = "Invalid iv_offset sector";
		goto bad;
	}
	cc->iv_offset = tmpll;

	ret = dm_get_device(ti, argv[3], dm_table_get_mode(ti->table), &cc->dev);
	if (ret) {
		ti->error = "Device lookup failed";
		goto bad;
	}

	ret = -EINVAL;
	if (sscanf(argv[4], "%llu%c", &tmpll, &dummy) != 1) {
		ti->error = "Invalid device sector";
		goto bad;
	}
	cc->start = tmpll;

	argv += 5;
	argc -= 5;

	/* Optional parameters */
	if (argc) {
		as.argc = argc;
		as.argv = argv;

		ret = dm_read_arg_group(_args, &as, &opt_params, &ti->error);
		if (ret)
			goto bad;

		ret = -EINVAL;
		while (opt_params--) {
			opt_string = dm_shift_arg(&as);
			if (!opt_string) {
				ti->error = "Not enough feature arguments";
				goto bad;
			}

			if (!strcasecmp(opt_string, "allow_discards"))
				ti->num_discard_bios = 1;

			else if (!strcasecmp(opt_string, "same_cpu_crypt"))
				set_bit(DM_CRYPT_SAME_CPU, &cc->flags);

			else if (!strcasecmp(opt_string, "submit_from_crypt_cpus"))
				set_bit(DM_CRYPT_NO_OFFLOAD, &cc->flags);

			else {
				ti->error = "Invalid feature arguments";
				goto bad;
			}
		}
	}

	ret = -ENOMEM;
	cc->io_queue = alloc_workqueue("kcryptd_io", WQ_MEM_RECLAIM, 1);
	if (!cc->io_queue) {
		ti->error = "Couldn't create kcryptd io queue";
		goto bad;
	}

	if (test_bit(DM_CRYPT_SAME_CPU, &cc->flags))
		cc->crypt_queue = alloc_workqueue("kcryptd", WQ_CPU_INTENSIVE | WQ_MEM_RECLAIM, 1);
	else
		cc->crypt_queue = alloc_workqueue("kcryptd", WQ_CPU_INTENSIVE | WQ_MEM_RECLAIM | WQ_UNBOUND,
						  num_online_cpus());
	if (!cc->crypt_queue) {
		ti->error = "Couldn't create kcryptd queue";
		goto bad;
	}

	init_waitqueue_head(&cc->write_thread_wait);
	cc->write_tree = RB_ROOT;

	cc->write_thread = kthread_create(dmcrypt_write, cc, "dmcrypt_write");
	if (IS_ERR(cc->write_thread)) {
		ret = PTR_ERR(cc->write_thread);
		cc->write_thread = NULL;
		ti->error = "Couldn't spawn write thread";
		goto bad;
	}
	wake_up_process(cc->write_thread);

	ti->num_flush_bios = 1;
	ti->discard_zeroes_data_unsupported = true;

	return 0;

bad:
	crypt_dtr(ti);
	return ret;
}

static int crypt_map(struct dm_target *ti, struct bio *bio)
{
	struct dm_crypt_io *io;
	struct crypt_config *cc = ti->private;

	/*
	 * If bio is REQ_PREFLUSH or REQ_OP_DISCARD, just bypass crypt queues.
	 * - for REQ_PREFLUSH device-mapper core ensures that no IO is in-flight
	 * - for REQ_OP_DISCARD caller must use flush if IO ordering matters
	 */
	if (unlikely(bio->bi_opf & REQ_PREFLUSH ||
	    bio_op(bio) == REQ_OP_DISCARD)) {
		bio->bi_bdev = cc->dev->bdev;
		if (bio_sectors(bio))
			bio->bi_iter.bi_sector = cc->start +
				dm_target_offset(ti, bio->bi_iter.bi_sector);
		return DM_MAPIO_REMAPPED;
	}

	/*
	 * Check if bio is too large, split as needed.
	 */
	if (unlikely(bio->bi_iter.bi_size > (BIO_MAX_PAGES << PAGE_SHIFT)) &&
	    bio_data_dir(bio) == WRITE)
		dm_accept_partial_bio(bio, ((BIO_MAX_PAGES << PAGE_SHIFT) >> SECTOR_SHIFT));

	io = dm_per_bio_data(bio, cc->per_bio_data_size);
	crypt_io_init(io, cc, bio, dm_target_offset(ti, bio->bi_iter.bi_sector));
	io->ctx.req = (struct skcipher_request *)(io + 1);

	if (bio_data_dir(io->base_bio) == READ) {
		if (kcryptd_io_read(io, GFP_NOWAIT))
			kcryptd_queue_read(io);
	} else {
		kcryptd_queue_crypt(io);
	}

	return DM_MAPIO_SUBMITTED;
}

static void crypt_status(struct dm_target *ti, status_type_t type,
			 unsigned status_flags, char *result, unsigned maxlen)
{
	struct crypt_config *cc = ti->private;
	unsigned i, sz = 0;
	int num_feature_args = 0;

	switch (type) {
	case STATUSTYPE_INFO:
		result[0] = '\0';
		break;

	case STATUSTYPE_TABLE:
		DMEMIT("%s ", cc->cipher_string);

		if (cc->key_size > 0) {
			if (cc->key_string)
				DMEMIT(":%u:%s", cc->key_size, cc->key_string);
			else
				for (i = 0; i < cc->key_size; i++)
					DMEMIT("%02x", cc->key[i]);
		} else
			DMEMIT("-");

		DMEMIT(" %llu %s %llu", (unsigned long long)cc->iv_offset,
				cc->dev->name, (unsigned long long)cc->start);

		num_feature_args += !!ti->num_discard_bios;
		num_feature_args += test_bit(DM_CRYPT_SAME_CPU, &cc->flags);
		num_feature_args += test_bit(DM_CRYPT_NO_OFFLOAD, &cc->flags);
		if (num_feature_args) {
			DMEMIT(" %d", num_feature_args);
			if (ti->num_discard_bios)
				DMEMIT(" allow_discards");
			if (test_bit(DM_CRYPT_SAME_CPU, &cc->flags))
				DMEMIT(" same_cpu_crypt");
			if (test_bit(DM_CRYPT_NO_OFFLOAD, &cc->flags))
				DMEMIT(" submit_from_crypt_cpus");
		}

		break;
	}
}

static void crypt_postsuspend(struct dm_target *ti)
{
	struct crypt_config *cc = ti->private;

	set_bit(DM_CRYPT_SUSPENDED, &cc->flags);
}

static int crypt_preresume(struct dm_target *ti)
{
	struct crypt_config *cc = ti->private;

	if (!test_bit(DM_CRYPT_KEY_VALID, &cc->flags)) {
		DMERR("aborting resume - crypt key is not set.");
		return -EAGAIN;
	}

	return 0;
}

static void crypt_resume(struct dm_target *ti)
{
	struct crypt_config *cc = ti->private;

	clear_bit(DM_CRYPT_SUSPENDED, &cc->flags);
}

/* Message interface
 *	key set <key>
 *	key wipe
 */
static int crypt_message(struct dm_target *ti, unsigned argc, char **argv)
{
	struct crypt_config *cc = ti->private;
	int key_size;

	if (argc < 2)
		goto error;

	if (!strcasecmp(argv[0], "key")) {
		if (!test_bit(DM_CRYPT_SUSPENDED, &cc->flags)) {
			DMWARN("not suspended during key manipulation.");
			return -EINVAL;
		}
		if (argc == 3 && !strcasecmp(argv[1], "set")) {
			/* The key size may not be changed. */
			key_size = get_key_size(&argv[2]);
			if (key_size < 0 || cc->key_size != key_size) {
				memset(argv[2], '0', strlen(argv[2]));
				return -EINVAL;
			}

			return crypt_set_key(cc, SETKEY_OP_SET, argv[2], NULL);
		}
		if (argc == 2 && !strcasecmp(argv[1], "wipe")) {
			return crypt_wipe_key(cc);
		}
	}

error:
	DMWARN("unrecognised message received.");
	return -EINVAL;
}

static int crypt_iterate_devices(struct dm_target *ti,
				 iterate_devices_callout_fn fn, void *data)
{
	struct crypt_config *cc = ti->private;

	return fn(ti, cc->dev, cc->start, ti->len, data);
}

static void crypt_io_hints(struct dm_target *ti, struct queue_limits *limits)
{
	/*
	 * Unfortunate constraint that is required to avoid the potential
	 * for exceeding underlying device's max_segments limits -- due to
	 * crypt_alloc_buffer() possibly allocating pages for the encryption
	 * bio that are not as physically contiguous as the original bio.
	 */
	limits->max_segment_size = PAGE_SIZE;
}

static struct target_type crypt_target = {
	.name   = "crypt",
	.version = {1, 16, 0},
	.module = THIS_MODULE,
	.ctr    = crypt_ctr,
	.dtr    = crypt_dtr,
	.map    = crypt_map,
	.status = crypt_status,
	.postsuspend = crypt_postsuspend,
	.preresume = crypt_preresume,
	.resume = crypt_resume,
	.message = crypt_message,
	.iterate_devices = crypt_iterate_devices,
	.io_hints = crypt_io_hints,
};

static int __init dm_crypt_init(void)
{
	int r;

	geniv_register_algs();
	r = dm_register_target(&crypt_target);
	if (r < 0)
		DMERR("register failed %d", r);

	return r;
}

static void __exit dm_crypt_exit(void)
{
	dm_unregister_target(&crypt_target);
	geniv_deregister_algs();
}

module_init(dm_crypt_init);
module_exit(dm_crypt_exit);

MODULE_AUTHOR("Jana Saout <jana@saout.de>");
MODULE_DESCRIPTION(DM_NAME " target for transparent encryption / decryption");
MODULE_LICENSE("GPL");
