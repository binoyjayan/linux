/****************************************************************************
* The confidential and proprietary information contained in this file may    *
* only be used by a person authorised under and to the extent permitted      *
* by a subsisting licensing agreement from ARM Limited or its affiliates.    *
* 	(C) COPYRIGHT [2001-2016] ARM Limited or its affiliates.	     *
*	    ALL RIGHTS RESERVED						     *
* This entire notice must be reproduced on all copies of this file           *
* and copies of this file may only be made by a person if such person is     *
* permitted to do so under the terms of a subsisting license agreement       *
* from ARM Limited or its affiliates.					     *
*****************************************************************************/

#ifndef __SSI_FIPS_H__
#define __SSI_FIPS_H__


#ifndef INT32_MAX /* Missing in Linux kernel */
#define INT32_MAX 0x7FFFFFFFL
#endif


/*! 
@file
@brief This file contains FIPS related defintions and APIs.
*/

typedef enum ssi_fips_state {
        CC_FIPS_STATE_NOT_SUPPORTED = 0,
        CC_FIPS_STATE_SUPPORTED,
        CC_FIPS_STATE_ERROR,
        CC_FIPS_STATE_RESERVE32B = INT32_MAX
} ssi_fips_state_t;


typedef enum ssi_fips_error {
	CC_REE_FIPS_ERROR_OK = 0,
	CC_REE_FIPS_ERROR_GENERAL,
	CC_REE_FIPS_ERROR_FROM_TEE,
	CC_REE_FIPS_ERROR_AES_ECB_PUT,
	CC_REE_FIPS_ERROR_AES_CBC_PUT,
	CC_REE_FIPS_ERROR_AES_OFB_PUT,
	CC_REE_FIPS_ERROR_AES_CTR_PUT,
	CC_REE_FIPS_ERROR_AES_CBC_CTS_PUT,
	CC_REE_FIPS_ERROR_AES_XTS_PUT,
	CC_REE_FIPS_ERROR_AES_CMAC_PUT,
	CC_REE_FIPS_ERROR_AESCCM_PUT,
	CC_REE_FIPS_ERROR_AESGCM_PUT,
	CC_REE_FIPS_ERROR_DES_ECB_PUT,
	CC_REE_FIPS_ERROR_DES_CBC_PUT,
	CC_REE_FIPS_ERROR_SHA1_PUT,
	CC_REE_FIPS_ERROR_SHA256_PUT,
	CC_REE_FIPS_ERROR_SHA512_PUT,
	CC_REE_FIPS_ERROR_HMAC_SHA1_PUT,
	CC_REE_FIPS_ERROR_HMAC_SHA256_PUT,
	CC_REE_FIPS_ERROR_HMAC_SHA512_PUT,
	CC_REE_FIPS_ERROR_ROM_CHECKSUM,
	CC_REE_FIPS_ERROR_RESERVE32B = INT32_MAX
} ssi_fips_error_t;



int ssi_fips_get_state(ssi_fips_state_t *p_state);
int ssi_fips_get_error(ssi_fips_error_t *p_err);

#endif  /*__SSI_FIPS_H__*/

