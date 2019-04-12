#include "pch.h"
#include "ATTACK.h"
#include "cuda.h"
#include "cuda_runtime.h"
#include "device_launch_parameters.h"

using namespace std;

extern "C"
u32 getKey_Stream(u32 *ciphertxt0, int Countn, const u32 &trueKey);

ATTACK::ATTACK(int countn,faultmode i)
{
	this->countn = countn;
	u32 truekey = sk[31];
	plaintxt = (u8*)malloc(sizeof(u8)*countn*16);
	ciphertxt = (u32*)malloc(sizeof(u32)*countn*2);
	fault = (u8*)malloc(sizeof(u8)*countn);
	mode = i;
}

ATTACK::ATTACK()
{
	mode = faultmode::ZeroFault;
	u32 truekey = sk[31];
}


ATTACK::~ATTACK()
{
	if (ciphertxt != NULL)free(ciphertxt);
	if (plaintxt != NULL)free(plaintxt);
	if (fault != NULL)free(fault);
}

void ATTACK::sm4_one_round(u8 input[16],u8 fault,int round)
{
	unsigned long i = 0;
	u32 ulbuf[36];

		memset(ulbuf, 0, sizeof(ulbuf));
		GET_ULONG_BE(ulbuf[0], input, 0)
		GET_ULONG_BE(ulbuf[1], input, 4)
		GET_ULONG_BE(ulbuf[2], input, 8)
		GET_ULONG_BE(ulbuf[3], input, 12)
		while (i < 32)
		{
			
			if (i == 28) {
				u32 inject = ((u32)fault << 24) | 0x00FFFFFF;
				//#ifdef _DEBUG
					//printf("%x\n", inject);
				//#endif
				
				ulbuf[i + 3] = ulbuf[i + 3] & inject;
			}

			ulbuf[i + 4] = sm4F(ulbuf[i], ulbuf[i + 1], ulbuf[i + 2], ulbuf[i + 3], sk[i]);
			//#ifdef _DEBUG
			//			printf("rk(%02d) = 0x%08x,  x(%02d) = 0x%08x \n", i, sk[i], i, ulbuf[i + 4]);
			//#endif
			
			if (i == 31) {
				ciphertxt[2 * round] = ulbuf[i + 1] ^ ulbuf[i + 2] ^ ulbuf[i + 3];
				ciphertxt[2 * round + 1] = ulbuf[i + 4];
			}
			i++;
		}
		
}

void ATTACK::reset(int countn, faultmode i)
{
	this->countn = countn;
	truekey = sk[31];
	mode = i;
	plaintxt = (u8*)malloc(sizeof(u8)*countn * 16);
	ciphertxt = (u32*)malloc(sizeof(u32)*countn * 2);
	fault = (u8*)malloc(sizeof(u8)*countn);
}

void ATTACK::setRandPlaintxtAndFault(u32 seed)
{
	srand(seed);
	for (int i = 0; i < countn * 16; i++) {
		plaintxt[i] = rand() * 1007 % 256;
	}
	srand(seed*rand());
	switch (mode)
	{
	case faultmode::ZeroFault:
		for (int i = 0; i < countn; i++) {
			fault[i] = 0;
		}
		break;
	case faultmode::HalfZero:
		for (int i = 0; i < countn; i++) {
			if(rand()*1007%countn>countn/2)
				fault[i] = rand() * 1007 % 256;
			else fault[i] = 0;
		}
		break;
	case faultmode::RandFault:
		for (int i = 0; i < countn; i++) {
			fault[i] = rand() * 1007 % 256;
		}
		break;
	default:
		break;
	}

	
}

void ATTACK::test()
{
	setRandPlaintxtAndFault();
	//#ifdef _DEBUG
	//	for (int i = 0; i < countn; i++) {
	//		for (int j = 0; j < 16; j++) {
	//			printf("%x ", *(plaintxt+i*16+j));
	//		}printf("\n");
	//	}
	//#endif
	for (int i = 0; i < countn; i++) {
		sm4_one_round(plaintxt + i * 16, fault[i], i);
		if (fault[i] != 0)
			printf("0x%x ", fault[i]);
		else printf("0x00 ");
	}printf("\n");
	//#ifdef _DEBUG
		//for (int i = 0; i < countn; i++) {
		//	printf("%x %x\n", *(ciphertxt+2*i), *(ciphertxt + 2 * i + 1));
		//}
	//#endif
	
	//u32 list[10];
	//for (int i = 0; i < countn; i++) {
	//	list[i]=ciphertxt[2 * i + 1] ^sm4Lt(ciphertxt[2*i]^truekey);
	//	printf("%x\n", list[i]);
	//}

	u32 guessKey = getKey_Stream(ciphertxt, countn, truekey);
	printf("trueKey=%x\n", truekey);
	if (truekey == guessKey)cout << "find" << endl;
	else cout << "fail" << endl;
}
