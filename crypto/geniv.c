/*
 * geniv: IV generation algorithms
 *
 * Copyright (c) 2016, Linaro Ltd.
 * Copyright (C) 2006-2015 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2013 Milan Broz <gmazyland@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 */

#include <crypto/algapi.h>
#include <crypto/internal/skcipher.h>
#include <linux/err.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/log2.h>
#include <linux/module.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/completion.h>
#include <linux/crypto.h>
#include <linux/workqueue.h>
#include <linux/backing-dev.h>
#include <linux/atomic.h>
#include <linux/rbtree.h>
#include <crypto/hash.h>
#include <crypto/md5.h>
#include <crypto/algapi.h>
#include <crypto/skcipher.h>
#include <asm/unaligned.h>
#include <crypto/geniv.h>

struct crypto_geniv_req_ctx {
	struct skcipher_request subreq CRYPTO_MINALIGN_ATTR;
};

static struct crypto_skcipher *any_tfm(struct geniv_ctx_data *cd)
{
	return cd->tfm;
}

static int crypt_iv_plain_gen(struct geniv_ctx_data *cd, u8 *iv,
			      struct dm_crypt_request *dmreq)
{
	memset(iv, 0, cd->iv_size);
	*(__le32 *)iv = cpu_to_le32(dmreq->iv_sector & 0xffffffff);

	return 0;
}

static int crypt_iv_plain64_gen(struct geniv_ctx_data *cd, u8 *iv,
				struct dm_crypt_request *dmreq)
{
	memset(iv, 0, cd->iv_size);
	*(__le64 *)iv = cpu_to_le64(dmreq->iv_sector);

	return 0;
}

/* Initialise ESSIV - compute salt but no local memory allocations */
static int crypt_iv_essiv_init(struct geniv_ctx_data *cd)
{
	struct geniv_essiv_private *essiv = &cd->iv_gen_private.essiv;
	struct scatterlist sg;
	struct crypto_cipher *essiv_tfm;
	int err;
	AHASH_REQUEST_ON_STACK(req, essiv->hash_tfm);

	sg_init_one(&sg, cd->key, cd->key_size);
	ahash_request_set_tfm(req, essiv->hash_tfm);
	ahash_request_set_callback(req, CRYPTO_TFM_REQ_MAY_SLEEP, NULL, NULL);
	ahash_request_set_crypt(req, &sg, essiv->salt, cd->key_size);

	err = crypto_ahash_digest(req);
	ahash_request_zero(req);
	if (err)
		return err;

	essiv_tfm = cd->iv_private;

	err = crypto_cipher_setkey(essiv_tfm, essiv->salt,
			    crypto_ahash_digestsize(essiv->hash_tfm));
	if (err)
		return err;

	return 0;
}

/* Wipe salt and reset key derived from volume key */
static int crypt_iv_essiv_wipe(struct geniv_ctx_data *cd)
{
	struct geniv_essiv_private *essiv = &cd->iv_gen_private.essiv;
	unsigned int salt_size = crypto_ahash_digestsize(essiv->hash_tfm);
	struct crypto_cipher *essiv_tfm;
	int r, err = 0;

	memset(essiv->salt, 0, salt_size);

	essiv_tfm = cd->iv_private;
	r = crypto_cipher_setkey(essiv_tfm, essiv->salt, salt_size);
	if (r)
		err = r;

	return err;
}

/* Set up per cpu cipher state */
static struct crypto_cipher *setup_essiv_cpu(struct geniv_ctx_data *cd,
					     u8 *salt, unsigned int saltsize)
{
	struct crypto_cipher *essiv_tfm;
	int err;

	/* Setup the essiv_tfm with the given salt */
	essiv_tfm = crypto_alloc_cipher(cd->cipher, 0, CRYPTO_ALG_ASYNC);

	if (IS_ERR(essiv_tfm)) {
		pr_err("Error allocating crypto tfm for ESSIV\n");
		return essiv_tfm;
	}

	if (crypto_cipher_blocksize(essiv_tfm) !=
	    crypto_skcipher_ivsize(any_tfm(cd))) {
		pr_err("Block size of ESSIV cipher does not match IV size of block cipher\n");
		crypto_free_cipher(essiv_tfm);
		return ERR_PTR(-EINVAL);
	}

	err = crypto_cipher_setkey(essiv_tfm, salt, saltsize);
	if (err) {
		pr_err("Failed to set key for ESSIV cipher\n");
		crypto_free_cipher(essiv_tfm);
		return ERR_PTR(err);
	}
	return essiv_tfm;
}

static void crypt_iv_essiv_dtr(struct geniv_ctx_data *cd)
{
	struct crypto_cipher *essiv_tfm;
	struct geniv_essiv_private *essiv = &cd->iv_gen_private.essiv;

	crypto_free_ahash(essiv->hash_tfm);
	essiv->hash_tfm = NULL;

	kzfree(essiv->salt);
	essiv->salt = NULL;

	essiv_tfm = cd->iv_private;

	if (essiv_tfm)
		crypto_free_cipher(essiv_tfm);

	cd->iv_private = NULL;
}

static int crypt_iv_essiv_ctr(struct geniv_ctx_data *cd)
{
	struct crypto_cipher *essiv_tfm = NULL;
	struct crypto_ahash *hash_tfm = NULL;
	u8 *salt = NULL;
	int err;

	if (!cd->ivopts) {
		pr_err("Digest algorithm missing for ESSIV mode\n");
		return -EINVAL;
	}

	/* Allocate hash algorithm */
	hash_tfm = crypto_alloc_ahash(cd->ivopts, 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(hash_tfm)) {
		err = PTR_ERR(hash_tfm);
		pr_err("Error initializing ESSIV hash. err=%d\n", err);
		goto bad;
	}

	salt = kzalloc(crypto_ahash_digestsize(hash_tfm), GFP_KERNEL);
	if (!salt) {
		err = -ENOMEM;
		goto bad;
	}

	cd->iv_gen_private.essiv.salt = salt;
	cd->iv_gen_private.essiv.hash_tfm = hash_tfm;

	essiv_tfm = setup_essiv_cpu(cd, salt,
				crypto_ahash_digestsize(hash_tfm));
	if (IS_ERR(essiv_tfm)) {
		crypt_iv_essiv_dtr(cd);
		return PTR_ERR(essiv_tfm);
	}
	cd->iv_private = essiv_tfm;

	return 0;

bad:
	if (hash_tfm && !IS_ERR(hash_tfm))
		crypto_free_ahash(hash_tfm);
	kfree(salt);
	return err;
}

static int crypt_iv_essiv_gen(struct geniv_ctx_data *cd, u8 *iv,
			      struct dm_crypt_request *dmreq)
{
	struct crypto_cipher *essiv_tfm = cd->iv_private;

	memset(iv, 0, cd->iv_size);
	*(__le64 *)iv = cpu_to_le64(dmreq->iv_sector);
	crypto_cipher_encrypt_one(essiv_tfm, iv, iv);

	return 0;
}

static int crypt_iv_benbi_ctr(struct geniv_ctx_data *cd)
{
	unsigned int bs = crypto_skcipher_blocksize(any_tfm(cd));
	int log = ilog2(bs);

	/* we need to calculate how far we must shift the sector count
	 * to get the cipher block count, we use this shift in _gen
	 */

	if (1 << log != bs) {
		pr_err("cypher blocksize is not a power of 2\n");
		return -EINVAL;
	}

	if (log > 9) {
		pr_err("cypher blocksize is > 512\n");
		return -EINVAL;
	}

	cd->iv_gen_private.benbi.shift = 9 - log;

	return 0;
}

static int crypt_iv_benbi_gen(struct geniv_ctx_data *cd, u8 *iv,
			      struct dm_crypt_request *dmreq)
{
	__be64 val;

	memset(iv, 0, cd->iv_size - sizeof(u64)); /* rest is cleared below */

	val = cpu_to_be64(((u64) dmreq->iv_sector <<
			  cd->iv_gen_private.benbi.shift) + 1);
	put_unaligned(val, (__be64 *)(iv + cd->iv_size - sizeof(u64)));

	return 0;
}

static int crypt_iv_null_gen(struct geniv_ctx_data *cd, u8 *iv,
			     struct dm_crypt_request *dmreq)
{
	memset(iv, 0, cd->iv_size);

	return 0;
}

static void crypt_iv_lmk_dtr(struct geniv_ctx_data *cd)
{
	struct geniv_lmk_private *lmk = &cd->iv_gen_private.lmk;

	if (lmk->hash_tfm && !IS_ERR(lmk->hash_tfm))
		crypto_free_shash(lmk->hash_tfm);
	lmk->hash_tfm = NULL;

	kzfree(lmk->seed);
	lmk->seed = NULL;
}

static int crypt_iv_lmk_ctr(struct geniv_ctx_data *cd)
{
	struct geniv_lmk_private *lmk = &cd->iv_gen_private.lmk;

	lmk->hash_tfm = crypto_alloc_shash("md5", 0, 0);
	if (IS_ERR(lmk->hash_tfm)) {
		pr_err("Error initializing LMK hash; err=%ld\n",
				PTR_ERR(lmk->hash_tfm));
		return PTR_ERR(lmk->hash_tfm);
	}

	/* No seed in LMK version 2 */
	if (cd->key_parts == cd->tfms_count) {
		lmk->seed = NULL;
		return 0;
	}

	lmk->seed = kzalloc(LMK_SEED_SIZE, GFP_KERNEL);
	if (!lmk->seed) {
		crypt_iv_lmk_dtr(cd);
		pr_err("Error kmallocing seed storage in LMK\n");
		return -ENOMEM;
	}

	return 0;
}

static int crypt_iv_lmk_init(struct geniv_ctx_data *cd)
{
	struct geniv_lmk_private *lmk = &cd->iv_gen_private.lmk;
	int subkey_size = cd->key_size / cd->key_parts;

	/* LMK seed is on the position of LMK_KEYS + 1 key */
	if (lmk->seed)
		memcpy(lmk->seed, cd->key + (cd->tfms_count * subkey_size),
		       crypto_shash_digestsize(lmk->hash_tfm));

	return 0;
}

static int crypt_iv_lmk_wipe(struct geniv_ctx_data *cd)
{
	struct geniv_lmk_private *lmk = &cd->iv_gen_private.lmk;

	if (lmk->seed)
		memset(lmk->seed, 0, LMK_SEED_SIZE);

	return 0;
}

static int crypt_iv_lmk_one(struct geniv_ctx_data *cd, u8 *iv,
			    struct dm_crypt_request *dmreq, u8 *data)
{
	struct geniv_lmk_private *lmk = &cd->iv_gen_private.lmk;
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
	buf[0] = cpu_to_le32(dmreq->iv_sector & 0xFFFFFFFF);
	buf[1] = cpu_to_le32((((u64)dmreq->iv_sector >> 32) & 0x00FFFFFF)
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
	memcpy(iv, &md5state.hash, cd->iv_size);

	return 0;
}

static int crypt_iv_lmk_gen(struct geniv_ctx_data *cd, u8 *iv,
			      struct dm_crypt_request *dmreq)
{
	u8 *src;
	int r = 0;

	if (bio_data_dir(dmreq->ctx->bio_in) == WRITE) {
		src = kmap_atomic(sg_page(&dmreq->sg_in));
		r = crypt_iv_lmk_one(cd, iv, dmreq, src + dmreq->sg_in.offset);
		kunmap_atomic(src);
	} else
		memset(iv, 0, cd->iv_size);

	return r;
}

static int crypt_iv_lmk_post(struct geniv_ctx_data *cd, u8 *iv,
			     struct dm_crypt_request *dmreq)
{
	u8 *dst;
	int r;

	if (bio_data_dir(dmreq->ctx->bio_in) == WRITE)
		return 0;

	dst = kmap_atomic(sg_page(&dmreq->sg_out));
	r = crypt_iv_lmk_one(cd, iv, dmreq, dst + dmreq->sg_out.offset);

	/* Tweak the first block of plaintext sector */
	if (!r)
		crypto_xor(dst + dmreq->sg_out.offset, iv, cd->iv_size);

	kunmap_atomic(dst);
	return r;
}

static void crypt_iv_tcw_dtr(struct geniv_ctx_data *cd)
{
	struct geniv_tcw_private *tcw = &cd->iv_gen_private.tcw;

	kzfree(tcw->iv_seed);
	tcw->iv_seed = NULL;
	kzfree(tcw->whitening);
	tcw->whitening = NULL;

	if (tcw->crc32_tfm && !IS_ERR(tcw->crc32_tfm))
		crypto_free_shash(tcw->crc32_tfm);
	tcw->crc32_tfm = NULL;
}

static int crypt_iv_tcw_ctr(struct geniv_ctx_data *cd)
{
	struct geniv_tcw_private *tcw = &cd->iv_gen_private.tcw;

	if (cd->key_size <= (cd->iv_size + TCW_WHITENING_SIZE)) {
		pr_err("Wrong key size (%d) for TCW. Choose a value > %d bytes\n",
			cd->key_size,
			cd->iv_size + TCW_WHITENING_SIZE);
		return -EINVAL;
	}

	tcw->crc32_tfm = crypto_alloc_shash("crc32", 0, 0);
	if (IS_ERR(tcw->crc32_tfm)) {
		pr_err("Error initializing CRC32 in TCW; err=%ld\n",
			PTR_ERR(tcw->crc32_tfm));
		return PTR_ERR(tcw->crc32_tfm);
	}

	tcw->iv_seed = kzalloc(cd->iv_size, GFP_KERNEL);
	tcw->whitening = kzalloc(TCW_WHITENING_SIZE, GFP_KERNEL);
	if (!tcw->iv_seed || !tcw->whitening) {
		crypt_iv_tcw_dtr(cd);
		pr_err("Error allocating seed storage in TCW\n");
		return -ENOMEM;
	}

	return 0;
}

static int crypt_iv_tcw_init(struct geniv_ctx_data *cd)
{
	struct geniv_tcw_private *tcw = &cd->iv_gen_private.tcw;
	int key_offset = cd->key_size - cd->iv_size - TCW_WHITENING_SIZE;

	memcpy(tcw->iv_seed, &cd->key[key_offset], cd->iv_size);
	memcpy(tcw->whitening, &cd->key[key_offset + cd->iv_size],
	       TCW_WHITENING_SIZE);

	return 0;
}

static int crypt_iv_tcw_wipe(struct geniv_ctx_data *cd)
{
	struct geniv_tcw_private *tcw = &cd->iv_gen_private.tcw;

	memset(tcw->iv_seed, 0, cd->iv_size);
	memset(tcw->whitening, 0, TCW_WHITENING_SIZE);

	return 0;
}

static int crypt_iv_tcw_whitening(struct geniv_ctx_data *cd,
				  struct dm_crypt_request *dmreq, u8 *data)
{
	struct geniv_tcw_private *tcw = &cd->iv_gen_private.tcw;
	__le64 sector = cpu_to_le64(dmreq->iv_sector);
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
	for (i = 0; i < ((1 << SECTOR_SHIFT) / 8); i++)
		crypto_xor(data + i * 8, buf, 8);
out:
	memzero_explicit(buf, sizeof(buf));
	return r;
}

static int crypt_iv_tcw_gen(struct geniv_ctx_data *cd, u8 *iv,
			      struct dm_crypt_request *dmreq)
{
	struct geniv_tcw_private *tcw = &cd->iv_gen_private.tcw;
	__le64 sector = cpu_to_le64(dmreq->iv_sector);
	u8 *src;
	int r = 0;

	/* Remove whitening from ciphertext */
	if (bio_data_dir(dmreq->ctx->bio_in) != WRITE) {
		src = kmap_atomic(sg_page(&dmreq->sg_in));
		r = crypt_iv_tcw_whitening(cd, dmreq,
					   src + dmreq->sg_in.offset);
		kunmap_atomic(src);
	}

	/* Calculate IV */
	memcpy(iv, tcw->iv_seed, cd->iv_size);
	crypto_xor(iv, (u8 *)&sector, 8);
	if (cd->iv_size > 8)
		crypto_xor(&iv[8], (u8 *)&sector, cd->iv_size - 8);

	return r;
}

static int crypt_iv_tcw_post(struct geniv_ctx_data *cd, u8 *iv,
			     struct dm_crypt_request *dmreq)
{
	u8 *dst;
	int r;

	if (bio_data_dir(dmreq->ctx->bio_in) != WRITE)
		return 0;

	/* Apply whitening on ciphertext */
	dst = kmap_atomic(sg_page(&dmreq->sg_out));
	r = crypt_iv_tcw_whitening(cd, dmreq, dst + dmreq->sg_out.offset);
	kunmap_atomic(dst);

	return r;
}

static struct geniv_operations crypt_iv_plain_ops = {
	.generator = crypt_iv_plain_gen
};

static struct geniv_operations crypt_iv_plain64_ops = {
	.generator = crypt_iv_plain64_gen
};

static struct geniv_operations crypt_iv_essiv_ops = {
	.ctr       = crypt_iv_essiv_ctr,
	.dtr       = crypt_iv_essiv_dtr,
	.init      = crypt_iv_essiv_init,
	.wipe      = crypt_iv_essiv_wipe,
	.generator = crypt_iv_essiv_gen
};

static struct geniv_operations crypt_iv_benbi_ops = {
	.ctr	   = crypt_iv_benbi_ctr,
	.generator = crypt_iv_benbi_gen
};

static struct geniv_operations crypt_iv_null_ops = {
	.generator = crypt_iv_null_gen
};

static struct geniv_operations crypt_iv_lmk_ops = {
	.ctr	   = crypt_iv_lmk_ctr,
	.dtr	   = crypt_iv_lmk_dtr,
	.init	   = crypt_iv_lmk_init,
	.wipe	   = crypt_iv_lmk_wipe,
	.generator = crypt_iv_lmk_gen,
	.post	   = crypt_iv_lmk_post
};

static struct geniv_operations crypt_iv_tcw_ops = {
	.ctr	   = crypt_iv_tcw_ctr,
	.dtr	   = crypt_iv_tcw_dtr,
	.init	   = crypt_iv_tcw_init,
	.wipe	   = crypt_iv_tcw_wipe,
	.generator = crypt_iv_tcw_gen,
	.post	   = crypt_iv_tcw_post
};

static int geniv_setkey_set(struct geniv_ctx_data *cd)
{
	int ret = 0;

	if (cd->iv_gen_ops && cd->iv_gen_ops->init)
		ret = cd->iv_gen_ops->init(cd);
	return ret;
}

static int geniv_setkey_wipe(struct geniv_ctx_data *cd)
{
	int ret = 0;

	if (cd->iv_gen_ops && cd->iv_gen_ops->wipe) {
		ret = cd->iv_gen_ops->wipe(cd);
		if (ret)
			return ret;
	}
	return ret;
}

static int geniv_setkey_init_ctx(struct geniv_ctx_data *cd)
{
	int ret = -EINVAL;

	pr_debug("IV Generation algorithm : %s\n", cd->ivmode);

	if (cd->ivmode == NULL)
		cd->iv_gen_ops = NULL;
	else if (strcmp(cd->ivmode, "plain") == 0)
		cd->iv_gen_ops = &crypt_iv_plain_ops;
	else if (strcmp(cd->ivmode, "plain64") == 0)
		cd->iv_gen_ops = &crypt_iv_plain64_ops;
	else if (strcmp(cd->ivmode, "essiv") == 0)
		cd->iv_gen_ops = &crypt_iv_essiv_ops;
	else if (strcmp(cd->ivmode, "benbi") == 0)
		cd->iv_gen_ops = &crypt_iv_benbi_ops;
	else if (strcmp(cd->ivmode, "null") == 0)
		cd->iv_gen_ops = &crypt_iv_null_ops;
	else if (strcmp(cd->ivmode, "lmk") == 0)
		cd->iv_gen_ops = &crypt_iv_lmk_ops;
	else if (strcmp(cd->ivmode, "tcw") == 0) {
		cd->iv_gen_ops = &crypt_iv_tcw_ops;
		cd->key_parts += 2; /* IV + whitening */
		cd->key_extra_size = cd->iv_size + TCW_WHITENING_SIZE;
	} else {
		ret = -EINVAL;
		pr_err("Invalid IV mode %s\n", cd->ivmode);
		goto end;
	}

	/* Allocate IV */
	if (cd->iv_gen_ops && cd->iv_gen_ops->ctr) {
		ret = cd->iv_gen_ops->ctr(cd);
		if (ret < 0) {
			pr_err("Error creating IV for %s\n", cd->ivmode);
			goto end;
		}
	}

	/* Initialize IV (set keys for ESSIV etc) */
	if (cd->iv_gen_ops && cd->iv_gen_ops->init) {
		ret = cd->iv_gen_ops->init(cd);
		if (ret < 0)
			pr_err("Error creating IV for %s\n", cd->ivmode);
	}
	ret = 0;
end:
	return ret;
}

static int crypto_geniv_set_ctx(struct crypto_skcipher *cipher,
				void *newctx, unsigned int len)
{
	struct geniv_ctx *ctx = crypto_skcipher_ctx(cipher);
	/*
	 * TODO:
	 * Do we really need this API or can we append the context
	 * 'struct geniv_ctx' to the cipher from dm-crypt and use
	 * the same here.
	 */
	memcpy(ctx, (char *) newctx, len);
	return geniv_setkey_init_ctx(&ctx->data);
}

static int crypto_geniv_setkey(struct crypto_skcipher *parent,
				const u8 *key, unsigned int keylen)
{
	struct geniv_ctx *ctx = crypto_skcipher_ctx(parent);
	struct crypto_skcipher *child = ctx->child;
	int err;

	pr_debug("SETKEY Operation : %d\n", ctx->data.keyop);

	switch (ctx->data.keyop) {
	case SETKEY_OP_INIT:
		err = geniv_setkey_init_ctx(&ctx->data);
		break;
	case SETKEY_OP_SET:
		err = geniv_setkey_set(&ctx->data);
		break;
	case SETKEY_OP_WIPE:
		err = geniv_setkey_wipe(&ctx->data);
		break;
	}

	crypto_skcipher_clear_flags(child, CRYPTO_TFM_REQ_MASK);
	crypto_skcipher_set_flags(child, crypto_skcipher_get_flags(parent) &
					 CRYPTO_TFM_REQ_MASK);
	err = crypto_skcipher_setkey(child, key, keylen);
	crypto_skcipher_set_flags(parent, crypto_skcipher_get_flags(child) &
					  CRYPTO_TFM_RES_MASK);
	return err;
}

static struct dm_crypt_request *dmreq_of_req(struct crypto_skcipher *tfm,
					     struct skcipher_request *req)
{
	struct geniv_ctx *ctx;

	ctx = crypto_skcipher_ctx(tfm);
	return (struct dm_crypt_request *) ((char *) req + ctx->data.dmoffset);
}


static void geniv_async_done(struct crypto_async_request *async_req, int error)
{
	struct skcipher_request *req = async_req->data;
	struct crypto_skcipher *tfm = crypto_skcipher_reqtfm(req);
	struct geniv_ctx *ctx = crypto_skcipher_ctx(tfm);
	struct geniv_ctx_data *cd = &ctx->data;
	struct dm_crypt_request *dmreq = dmreq_of_req(tfm, req);
	struct convert_context *cctx = dmreq->ctx;
	unsigned long align = crypto_skcipher_alignmask(tfm);
	struct crypto_geniv_req_ctx *rctx =
		(void *) PTR_ALIGN((u8 *)skcipher_request_ctx(req), align + 1);
	struct skcipher_request *subreq = &rctx->subreq;

	/*
	 * A request from crypto driver backlog is going to be processed now,
	 * finish the completion and continue in crypt_convert().
	 * (Callback will be called for the second time for this request.)
	 */
	if (error == -EINPROGRESS) {
		complete(&cctx->restart);
		return;
	}

	if (!error && cd->iv_gen_ops && cd->iv_gen_ops->post)
		error = cd->iv_gen_ops->post(cd, req->iv, dmreq);

	skcipher_request_set_callback(subreq, req->base.flags,
				      req->base.complete, req->base.data);
	skcipher_request_complete(req, error);
}

static inline int crypto_geniv_crypt(struct skcipher_request *req, bool encrypt)
{
	struct crypto_skcipher *tfm = crypto_skcipher_reqtfm(req);
	struct geniv_ctx *ctx = crypto_skcipher_ctx(tfm);
	struct geniv_ctx_data *cd = &ctx->data;
	struct crypto_skcipher *child = ctx->child;
	struct dm_crypt_request *dmreq;
	unsigned long align = crypto_skcipher_alignmask(tfm);
	struct crypto_geniv_req_ctx *rctx =
		(void *) PTR_ALIGN((u8 *)skcipher_request_ctx(req), align + 1);
	struct skcipher_request *subreq = &rctx->subreq;
	int ret = 0;
	u8 *iv = req->iv;

	dmreq = dmreq_of_req(tfm, req);

	if (cd->iv_gen_ops)
		ret = cd->iv_gen_ops->generator(cd, iv, dmreq);

	if (ret < 0) {
		pr_err("Error in generating IV ret: %d\n", ret);
		goto end;
	}

	skcipher_request_set_tfm(subreq, child);
	skcipher_request_set_callback(subreq, req->base.flags,
				      geniv_async_done, req);
	skcipher_request_set_crypt(subreq, req->src, req->dst,
				   req->cryptlen, iv);

	if (encrypt)
		ret = crypto_skcipher_encrypt(subreq);
	else
		ret = crypto_skcipher_decrypt(subreq);

	if (!ret && cd->iv_gen_ops && cd->iv_gen_ops->post)
		ret = cd->iv_gen_ops->post(cd, iv, dmreq);

end:
	return ret;
}

static int crypto_geniv_encrypt(struct skcipher_request *req)
{
	return crypto_geniv_crypt(req, true);
}

static int crypto_geniv_decrypt(struct skcipher_request *req)
{
	return crypto_geniv_crypt(req, false);
}

static int crypto_geniv_init_tfm(struct crypto_skcipher *tfm)
{
	struct skcipher_instance *inst = skcipher_alg_instance(tfm);
	struct crypto_skcipher_spawn *spawn = skcipher_instance_ctx(inst);
	struct geniv_ctx *ctx = crypto_skcipher_ctx(tfm);
	struct geniv_ctx_data *cd;
	struct crypto_skcipher *cipher;
	unsigned long align;
	unsigned int reqsize, extrasize;

	cipher = crypto_spawn_skcipher2(spawn);
	if (IS_ERR(cipher))
		return PTR_ERR(cipher);

	ctx->child = cipher;

	/* Setup the current cipher's request structure */
	align = crypto_skcipher_alignmask(tfm);
	align &= ~(crypto_tfm_ctx_alignment() - 1);
	reqsize = align + sizeof(struct crypto_geniv_req_ctx) +
		  crypto_skcipher_reqsize(cipher);
	crypto_skcipher_set_reqsize(tfm, reqsize);

	/* Set the current cipher's extra context parameters
	 * Format of req structure, the context and the extra context
	 * This is set by the caller of the cipher
	 *   struct skcipher_request   --+
	 *      context                  |   Request context
	 *      padding                --+
	 *   struct dm_crypt_request   --+
	 *      padding                  |   Extra context
	 *   IV                        --+
	 */
	cd = &ctx->data;
	cd->dmoffset  = sizeof(struct skcipher_request);
	cd->dmoffset += crypto_skcipher_reqsize(tfm);
	cd->dmoffset  = ALIGN(cd->dmoffset,
			__alignof__(struct dm_crypt_request));
	extrasize = cd->dmoffset + sizeof(struct dm_crypt_request);

	return 0;
}

static void crypto_geniv_exit_tfm(struct crypto_skcipher *tfm)
{
	struct geniv_ctx *ctx = crypto_skcipher_ctx(tfm);
	struct geniv_ctx_data *cd = &ctx->data;

	if (cd->iv_gen_ops && cd->iv_gen_ops->dtr)
		cd->iv_gen_ops->dtr(cd);

	crypto_free_skcipher(ctx->child);
}

static void crypto_geniv_free(struct skcipher_instance *inst)
{
	struct crypto_skcipher_spawn *spawn = skcipher_instance_ctx(inst);

	crypto_drop_skcipher(spawn);
	kfree(inst);
}

static int crypto_geniv_create(struct crypto_template *tmpl,
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
	err = crypto_grab_skcipher2(spawn, cipher_name, 0,
				    crypto_requires_sync(algt->type,
							 algt->mask));

	if (err)
		goto err_free_inst;

	alg = crypto_spawn_skcipher_alg(spawn);

	/* We only support 16-byte blocks. */
	err = -EINVAL;
	/*
	 * if (crypto_skcipher_alg_ivsize(alg) != 16)
	 *	goto err_drop_spawn;
	 */

	if (!is_power_of_2(alg->base.cra_blocksize))
		goto err_drop_spawn;

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

	inst->alg.setkey = crypto_geniv_setkey;
	inst->alg.set_ctx = crypto_geniv_set_ctx;
	inst->alg.encrypt = crypto_geniv_encrypt;
	inst->alg.decrypt = crypto_geniv_decrypt;

	inst->alg.base.cra_ctxsize = sizeof(struct geniv_ctx);

	inst->alg.init = crypto_geniv_init_tfm;
	inst->alg.exit = crypto_geniv_exit_tfm;

	inst->free = crypto_geniv_free;

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
	return crypto_geniv_create(tmpl, tb, "plain");
}

static int crypto_plain64_create(struct crypto_template *tmpl,
				struct rtattr **tb)
{
	return crypto_geniv_create(tmpl, tb, "plain64");
}

static int crypto_essiv_create(struct crypto_template *tmpl,
				struct rtattr **tb)
{
	return crypto_geniv_create(tmpl, tb, "essiv");
}

static int crypto_benbi_create(struct crypto_template *tmpl,
				struct rtattr **tb)
{
	return crypto_geniv_create(tmpl, tb, "benbi");
}

static int crypto_null_create(struct crypto_template *tmpl,
				struct rtattr **tb)
{
	return crypto_geniv_create(tmpl, tb, "null");
}

static int crypto_lmk_create(struct crypto_template *tmpl,
				struct rtattr **tb)
{
	return crypto_geniv_create(tmpl, tb, "lmk");
}

static int crypto_tcw_create(struct crypto_template *tmpl,
				struct rtattr **tb)
{
	return crypto_geniv_create(tmpl, tb, "tcw");
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

static int __init crypto_geniv_module_init(void)
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

static void __exit crypto_geniv_module_exit(void)
{
	crypto_unregister_template(&crypto_plain_tmpl);
	crypto_unregister_template(&crypto_plain64_tmpl);
	crypto_unregister_template(&crypto_essiv_tmpl);
	crypto_unregister_template(&crypto_benbi_tmpl);
	crypto_unregister_template(&crypto_null_tmpl);
	crypto_unregister_template(&crypto_lmk_tmpl);
	crypto_unregister_template(&crypto_tcw_tmpl);
}

module_init(crypto_geniv_module_init);
module_exit(crypto_geniv_module_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("IV generation algorithms");
MODULE_ALIAS_CRYPTO("geniv");

