#pragma once
#include"pch.h"
#include "cuda.h"
#include "cuda_runtime.h"
#include "device_launch_parameters.h"


#define SM4_ENCRYPT     1
#define SM4_DECRYPT     0

class sm4
{
protected:
	u8 key[16];
	int mode;                   /*!<  encrypt/decrypt   */
	u32 sk[32];       /*!<  SM4 subkeys       */
public:
	static const u8 SboxTable[16][16];
	static const u32 FK[4];
	static const u32 CK[32];

	u8 sm4Sbox(u8 inch);
	u32 sm4Lt(u32 ka);
	u32 sm4F(const u32 &x0, const u32 &x1, const u32 &x2, const u32 &x3, const u32 &rk);
	u32 sm4CalciRK(u32 ka);
	void setmode(int i);
	void setrandKey(u32 seed = (u32)time(NULL));
	void sm4_setkey();
	void sm4_one_round(u8 input[16],u8 output[16]);
	void init(u8 key[16], int mode);
	sm4(u8 key[16], int mode);
	sm4();
	~sm4();


};

