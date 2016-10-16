/*
 * geniv: common data structures for IV generation algorithms
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 */
#ifndef _CRYPTO_GENIV_
#define _CRYPTO_GENIV_

#define SECTOR_SHIFT            9

struct geniv_essiv_private {
	struct crypto_ahash *hash_tfm;
	u8 *salt;
};

struct geniv_benbi_private {
	int shift;
};

#define LMK_SEED_SIZE 64 /* hash + 0 */
struct geniv_lmk_private {
	struct crypto_shash *hash_tfm;
	u8 *seed;
};

#define TCW_WHITENING_SIZE 16
struct geniv_tcw_private {
	struct crypto_shash *crc32_tfm;
	u8 *iv_seed;
	u8 *whitening;
};

enum setkey_op {
	SETKEY_OP_INIT,
	SETKEY_OP_SET,
	SETKEY_OP_WIPE,
};

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

struct dm_crypt_request {
	struct convert_context *ctx;
	struct scatterlist sg_in;
	struct scatterlist sg_out;
	sector_t iv_sector;
};


struct geniv_ctx_data;

struct geniv_operations {
	int (*ctr)(struct geniv_ctx_data *cd);
	void (*dtr)(struct geniv_ctx_data *cd);
	int (*init)(struct geniv_ctx_data *cd);
	int (*wipe)(struct geniv_ctx_data *cd);
	int (*generator)(struct geniv_ctx_data *req, u8 *iv,
			 struct dm_crypt_request *dmreq);
	int (*post)(struct geniv_ctx_data *cd, u8 *iv,
			 struct dm_crypt_request *dmreq);
};

struct geniv_ctx_data {
	unsigned int tfms_count;
	char *ivmode;
	unsigned int iv_size;
	char *ivopts;
	unsigned int dmoffset;

	char *cipher;
	struct geniv_operations *iv_gen_ops;
	union {
		struct geniv_essiv_private essiv;
		struct geniv_benbi_private benbi;
		struct geniv_lmk_private lmk;
		struct geniv_tcw_private tcw;
	} iv_gen_private;
	void *iv_private;
	struct crypto_skcipher *tfm;
	unsigned int key_size;
	unsigned int key_extra_size;
	unsigned int key_parts;      /* independent parts in key buffer */
	enum setkey_op keyop;
	char *msg;
	u8 *key;
};

struct geniv_ctx {
	struct crypto_skcipher *child;
	struct geniv_ctx_data data;
};

#endif

