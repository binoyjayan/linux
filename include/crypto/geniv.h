/*
 * geniv: common interface for IV generation algorithms
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 */
#ifndef _CRYPTO_GENIV_
#define _CRYPTO_GENIV_

#define SECTOR_SIZE		(1 << SECTOR_SHIFT)

enum setkey_op {
	SETKEY_OP_INIT,
	SETKEY_OP_SET,
	SETKEY_OP_WIPE,
};

struct geniv_key_info {
	enum setkey_op keyop;
	unsigned int tfms_count;
	u8 *key;
	unsigned int key_size;
	unsigned int key_parts;
	char *ivopts;
};

#define DECLARE_GENIV_KEY(c, op, n, k, sz, kp, opts)	\
	struct geniv_key_info c = {			\
		.keyop = op,				\
		.tfms_count = n,			\
		.key = k,				\
		.key_size = sz,				\
		.key_parts = kp,			\
		.ivopts = opts,				\
	}

struct geniv_req_info {
	bool is_write;
	sector_t iv_sector;
	unsigned int nents;
	u8 *iv;
};

#endif
