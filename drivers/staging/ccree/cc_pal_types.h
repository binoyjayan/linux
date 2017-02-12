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

#ifndef CC_PAL_TYPES_H
#define CC_PAL_TYPES_H

/*! 
@file 
@brief This file contains platform-dependent definitions and types. 
@defgroup cc_pal_types CryptoCell PAL platform dependant types
@{
@ingroup cc_pal

*/
 
#include "cc_pal_types_plat.h"

/*! Boolean definition.*/
typedef enum {
	/*! Boolean false definition.*/
	CC_FALSE = 0,
	/*! Boolean true definition.*/
	CC_TRUE = 1
} CCBool;

/*! Success definition. */
#define CC_SUCCESS              0UL
/*! Failure definition. */
#define CC_FAIL		  	1UL

/*! Defintion of 1KB in bytes. */
#define CC_1K_SIZE_IN_BYTES	1024
/*! Defintion of number of bits in a byte. */
#define CC_BITS_IN_BYTE		8
/*! Defintion of number of bits in a 32bits word. */
#define CC_BITS_IN_32BIT_WORD	32
/*! Defintion of number of bytes in a 32bits word. */
#define CC_32BIT_WORD_SIZE	(sizeof(uint32_t))

/*! Success (OK) defintion. */
#define CC_OK   0

/*! Macro that handles unused parameters in the code (to avoid compilation warnings).  */
#define CC_UNUSED_PARAM(prm)  ((void)prm)

/*! Maximal uint32 value.*/
#define CC_MAX_UINT32_VAL 	(0xFFFFFFFF)


/* Minimum and Maximum macros */
#ifdef  min
/*! Definition for minimum. */
#define CC_MIN(a,b) min( a , b )
#else
/*! Definition for minimum. */
#define CC_MIN( a , b ) ( ( (a) < (b) ) ? (a) : (b) )
#endif

#ifdef max    
/*! Definition for maximum. */    
#define CC_MAX(a,b) max( a , b )
#else
/*! Definition for maximum. */    
#define CC_MAX( a , b ) ( ( (a) > (b) ) ? (a) : (b) )
#endif

/*! Macro that calculates number of full bytes from bits (i.e. 7 bits are 1 byte). */    
#define CALC_FULL_BYTES(numBits) 		((numBits)/CC_BITS_IN_BYTE + (((numBits) & (CC_BITS_IN_BYTE-1)) > 0)) 
/*! Macro that calculates number of full 32bits words from bits (i.e. 31 bits are 1 word). */    
#define CALC_FULL_32BIT_WORDS(numBits) 		((numBits)/CC_BITS_IN_32BIT_WORD +  (((numBits) & (CC_BITS_IN_32BIT_WORD-1)) > 0))   
/*! Macro that calculates number of full 32bits words from bytes (i.e. 3 bytes are 1 word). */    
#define CALC_32BIT_WORDS_FROM_BYTES(sizeBytes)  ((sizeBytes)/CC_32BIT_WORD_SIZE + (((sizeBytes) & (CC_32BIT_WORD_SIZE-1)) > 0)) 
/*! Macro that round up bits to 32bits words. */     
#define ROUNDUP_BITS_TO_32BIT_WORD(numBits) 	(CALC_FULL_32BIT_WORDS(numBits) * CC_BITS_IN_32BIT_WORD)
/*! Macro that round up bits to bytes. */    
#define ROUNDUP_BITS_TO_BYTES(numBits) 		(CALC_FULL_BYTES(numBits) * CC_BITS_IN_BYTE)
/*! Macro that round up bytes to 32bits words. */    
#define ROUNDUP_BYTES_TO_32BIT_WORD(sizeBytes) 	(CALC_32BIT_WORDS_FROM_BYTES(sizeBytes) * CC_32BIT_WORD_SIZE)     


/** 
@}
 */
#endif
