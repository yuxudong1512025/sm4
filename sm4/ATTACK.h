#pragma once
#include "pch.h"
#include "sm4.h"
#include "cuda.h"
#include "cuda_runtime.h"
#include "device_launch_parameters.h"

#define SM4_ENCRYPT     1
#define SM4_DECRYPT     0

#ifndef GET_ULONG_BE
#define GET_ULONG_BE(n,b,i)                             \
{                                                       \
    (n) = ( (unsigned long) (b)[(i)    ] << 24 )        \
        | ( (unsigned long) (b)[(i) + 1] << 16 )        \
        | ( (unsigned long) (b)[(i) + 2] <<  8 )        \
        | ( (unsigned long) (b)[(i) + 3]       );       \
}
#endif

#ifndef PUT_ULONG_BE
#define PUT_ULONG_BE(n,b,i)                             \
{                                                       \
    (b)[(i)    ] = (unsigned char) ( (n) >> 24 );       \
    (b)[(i) + 1] = (unsigned char) ( (n) >> 16 );       \
    (b)[(i) + 2] = (unsigned char) ( (n) >>  8 );       \
    (b)[(i) + 3] = (unsigned char) ( (n)       );       \
}
#endif

/*
 *rotate shift left marco definition
 *
 */
#define  SHL(x,n) (((x) & 0xFFFFFFFF) << n)
#define ROTL(x,n) (SHL((x),n) | ((x) >> (32 - n)))

#define SWAP(a,b) { unsigned long t = a; a = b; b = t; t = 0; }

extern "C"
u32 getKey_Stream(u32 *ciphertxt0, int Countn, const u32 &trueKey);

enum faultmode {
	ZeroFault, HalfZero, RandFault
};

class ATTACK :
	public sm4
{
	faultmode mode;
	u8 *plaintxt;
	u32 *ciphertxt;
	int countn;
	u32 truekey;
	u8 *fault;

public:
	ATTACK(int countn,faultmode i);
	ATTACK();
	~ATTACK();
	void sm4_one_round(u8 input[16],u8 fault,int round);
	void reset(int countn, faultmode i);
	void setRandPlaintxtAndFault(u32 seed = time(NULL));
	void test();
};

