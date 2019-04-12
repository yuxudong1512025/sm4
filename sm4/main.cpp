#include"pch.h"
#include"sm4.h"
#include "cuda.h"
#include "cuda_runtime.h"
#include "device_launch_parameters.h"
#include"ATTACK.h"
using namespace std;
ATTACK ak;

#ifndef GET_ULONG_BE
#define GET_ULONG_BE(n,b,i)                             \
{                                                       \
    (n) = ( (unsigned long) (b)[(i)    ] << 24 )        \
        | ( (unsigned long) (b)[(i) + 1] << 16 )        \
        | ( (unsigned long) (b)[(i) + 2] <<  8 )        \
        | ( (unsigned long) (b)[(i) + 3]       );       \
}
#endif

int main() {

	int n, mode;
	cout << "请输入预设组数：" << endl;
	cin >> n;
	cout << "请输入故障模型：（1:0故障，2一半为0一半随机故障，3完全随机故障）" << endl;
	cin >> mode;
	switch (mode)
	{
	case 1:
		ak.reset(n, faultmode::ZeroFault);
		break;
	case 2:
		ak.reset(n, faultmode::HalfZero);
		break;
	case 3:
		ak.reset(n, faultmode::RandFault);
		break; 
	default:
		ak.reset(n, faultmode::ZeroFault);
		break;
	}
	ak.test();
	return 0;
}