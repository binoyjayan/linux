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


/**************************************************************
This file defines the driver FIPS APIs                                                             *
***************************************************************/

#include <linux/module.h>
#include "ssi_fips.h"


extern int ssi_fips_ext_get_state(ssi_fips_state_t *p_state);
extern int ssi_fips_ext_get_error(ssi_fips_error_t *p_err);

/*
This function returns the REE FIPS state.  
It should be called by kernel module. 
*/
int ssi_fips_get_state(ssi_fips_state_t *p_state)
{
        int rc = 0;

	if (p_state == NULL) {
		return -EINVAL;
	}

	rc = ssi_fips_ext_get_state(p_state);

	return rc;
}

EXPORT_SYMBOL(ssi_fips_get_state);

/*
This function returns the REE FIPS error.  
It should be called by kernel module. 
*/
int ssi_fips_get_error(ssi_fips_error_t *p_err)
{
        int rc = 0;

	if (p_err == NULL) {
		return -EINVAL;
	}

	rc = ssi_fips_ext_get_error(p_err);

	return rc;
}

EXPORT_SYMBOL(ssi_fips_get_error);
