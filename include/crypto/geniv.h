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

#define SECTOR_SHIFT		9
#define SECTOR_SIZE		(1 << SECTOR_SHIFT)

#define LMK_SEED_SIZE		64 /* hash + 0 */
#define TCW_WHITENING_SIZE	16

enum setkey_op {
	SETKEY_OP_INIT,
	SETKEY_OP_SET,
	SETKEY_OP_WIPE,
};

struct geniv_key_info {
	enum setkey_op keyop;
	unsigned int tfms_count;
	char *cipher;
	u8 *key;
	u8 *subkey;
	unsigned int key_size;
	unsigned int subkey_size;
	unsigned int key_parts;
	char *ivmode;
	char *ivopts;
};

#define DECLARE_GENIV_KEY(c, op, n, p, k, sz, skey, ssz, kp, m, opts)	\
	struct geniv_key_info c = {					\
		.keyop = op,						\
		.tfms_count = n,					\
		.cipher = p,						\
		.key = k,						\
		.key_size = sz,						\
		.subkey = skey,						\
		.subkey_size = ssz,					\
		.key_parts = kp,					\
		.ivmode = m,						\
		.ivopts = opts,						\
	}

struct geniv_req_info {
	bool is_write;
	sector_t iv_sector;
	unsigned int nents;
	u8 *iv;
};

#endif

