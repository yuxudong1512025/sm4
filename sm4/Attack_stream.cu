#include "cuda.h"
#include "cuda_runtime.h"
#include "device_launch_parameters.h"
#include"thrust/extrema.h"
#include"thrust/device_vector.h"
#include"pch.h"
#include"sm4.h"

using namespace std;
#ifndef CHECK
#define  CHECK(call){\
	const cudaError_t error = call;\
	if (error != cudaSuccess) {\
		printf_s("Error: %s:%d, ", __FILE__, __LINE__);\
		printf_s("code:%d, reason: %s\n", error, cudaGetErrorString(error));\
		exit(-10 * error);\
	}\
}
#endif

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


#define  SHL(x,n) (((x) & 0xFFFFFFFF) << n)
#define ROTL(x,n) (SHL((x),n) | ((x) >> (32 - n)))
#define doublec(n) (u32)(n*n)


u8 SboxTable[256] = {
0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05,
0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99,
0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62,
0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,0x75,0x8f,0x3f,0xa6,
0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8,
0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b,0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35,
0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,0x22,0x7c,0x3b,0x01,0x21,0x78,0x87,
0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e,
0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1,
0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55,0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3,
0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60,0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f,
0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51,
0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8,
0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0,
0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84,
0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48
 };


/*(1024*2^14*256*1)*/
/*限定故障注入在C31第一个字节*/
/*ciphertxt[2 * n]=C32^C33^C34, ciphertxt[2 * n + 1]=C35    */
__global__ void kernel( u32 *maxSEI, u32 *ciphertxt, int countn,int p,u8 *Count,u8 *Sbox) {
	u32 ix = blockIdx.x*blockDim.x + threadIdx.x;
	u32 key = (p<<16)+ix;

	u32 MaxSei = 0,ka;
	u8 a=0x3f,b[4];
	
	for (int i = 0; i < countn; i++) {
		u32 temp = ciphertxt[2 * i],temp1= ciphertxt[2 * i + 1];
		ka = key ^ temp;
		
		b[0] = Sbox[(u8)(ka>>24)];
		b[1] = Sbox[(u8)(ka>>16)];
		b[2] = Sbox[(u8)(ka>>8)];
		b[3] = Sbox[(u8)ka];

		ka = ((u32)b[0] << 24) | ((u32)b[1] << 16) | ((u32)b[2] << 8) | ((u32)b[3]);
		
		b[0] = b[0] ^ b[3];
		b[0] = b[0]^(u8)(ka >> 6) ^ (u8)(ka >> 14) ^ (u8)(ka >> 22) ^ (u8)(temp1>>24);
		Count[b[0] * 65536 + ix]++;
	}
	for (int i = 0; i < 256; i++)
		MaxSei += doublec(Count[i * 65536 + ix]);

	maxSEI[ix] = MaxSei;
}


extern "C"
u32 getKey_Stream(u32 *ciphertxt0, int Countn, const u32 &trueKey) {

	FILE *fp = fopen("temp.txt", "a");
	//输出设备信息可以无视
	int dev = 0;
	cudaDeviceProp deviceProp;
	CHECK(cudaGetDeviceProperties(&deviceProp, dev));
	printf_s("using device %d : %s \n", dev, deviceProp.name);
	CHECK(cudaSetDevice(dev));
	//设置参数
	int size_16 = 1 << 16;
	int size_8 = 1 << 8;
	int size_24 = 1 << 24;
	int nsize = size_16 * Countn * sizeof(u8);
	//	printf_s("Matrix size:nx %d ny %d\n", nx, ny);

	//以下为定义的线程布局gird=（256，65536）个block=（256,1）个threads
	dim3 grid(size_8, 1);
	dim3 block(size_8, 1);
	///////////////////////////////////////////////////////

	//申请device内存并将host的内存拷贝到device上（输入）
	u32 *cipher;


	CHECK(cudaMalloc((void **)&cipher, Countn * 2 * sizeof(u32)));

	CHECK(cudaMemcpy(cipher, ciphertxt0, Countn * 2 * sizeof(u32), cudaMemcpyHostToDevice));
	//申请device内存作为输出空间（输出）
	u32 *maxSEI;
	u8 *Count, *SBOX;
	CHECK(cudaMalloc((void **)&maxSEI, size_16 * sizeof(u32)));
	CHECK(cudaMalloc((void **)&Count, size_16 * 256 * sizeof(u8)));
	CHECK(cudaMalloc((void **)&SBOX, 256 * sizeof(u8)));

	CHECK(cudaMemcpy(SBOX, SboxTable, 256 * sizeof(u8), cudaMemcpyHostToDevice));
	//申请循环结果存放空间

	thrust::device_vector<u32>ansSEI(size_16);
	thrust::device_vector<u32>ansKEY(size_16);
	u32 ansS[65536] = { 0 }, ansK[65536] = { 0 }, aS = 0, aK;



	for (int i = 0; i < size_16; i++) {
		CHECK(cudaMemset(Count, 0, size_16 * 256 * sizeof(u8)));
		//调用核函数计算SEI
		kernel << <grid, block >> > (maxSEI, cipher, Countn, i, Count, SBOX);
		CHECK(cudaDeviceSynchronize());//检查cuda设备同步情况
		//调用核函数求SEI最大的key

		auto ptr = thrust::max_element(thrust::device, maxSEI, maxSEI + 65536);
		ansSEI[i] = (*ptr);
		ansKEY[i] = ptr - maxSEI;

	}
	//thrust::host_vector<u32> host(65536),host2(65536);
	//thrust::copy(ansSEI.begin(), ansSEI.end(), host.begin());
	//thrust::copy(ansKEY.begin(), ansKEY.end(), host2.begin());
	//for (int i = 0; i < 65536; i++) {
	//	std::fprintf(fp, "%d %x\n", host[i],host2[i]);
	//}

	auto ptr = thrust::max_element(ansSEI.begin(), ansSEI.end());

	//输出结果用的
	thrust::device_vector<u32> D(2);
	thrust::host_vector<u32> H(2);
	D[0]=(*ptr);
	D[1]=(((ptr - ansSEI.begin()) << 16) + ansKEY[ptr - ansSEI.begin()]);
	
	thrust::copy(D.begin(), D.end(), H.begin());

	std::printf("最终找到的最大SEI和对应key：%d %x\n", H[0], H[1]);
	//释放占用空间
	CHECK(cudaFree(maxSEI));
	CHECK(cudaFree(cipher));
	CHECK(cudaFree(Count));
	CHECK(cudaFree(SBOX));

	return H[1];
}