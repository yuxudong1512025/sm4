#include "cuda.h"
#include "cuda_runtime.h"
#include "device_launch_parameters.h"
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
#define doublec(n) (n*n)


__device__ u8 SboxTable[256] = {
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
0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51,
0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8,
0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0,
0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84,
0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48
};



/*(256*65536*256*1)*/
/*限定故障注入在C31第一个字节*/
/*ciphertxt[2 * n]=C32^C33^C34, ciphertxt[2 * n + 1]=C35    */
__global__ void kernel(u32 *guessKey, u32 *maxSEI, u32 *ciphertxt, int countn) {
	u32 tdx = threadIdx.x;
	u32 ix = blockIdx.x*blockDim.x + threadIdx.x;
	u32 key = (ix << 16) + blockIdx.y;

	__shared__ u32 partialKey[256];
	__shared__ u32 partialSEI[256];

	u16 Count[256];
	u32 MaxSei=0;
	u32 ka, bb;
	u8 a[4], b[4];
	u8 c;
	for (int i = 0; i < 256; i += 8)
		Count[i] = Count[i + 1] = Count[i + 2] = Count[i + 3] = Count[i + 4] = Count[i + 5] = Count[i + 6] = Count[i + 7] = 0;

	for (int i = 0; i < countn; i++) {
		ka = key ^ ciphertxt[2 * i];
		bb = 0;
		c = 0;
		PUT_ULONG_BE(ka, a, 0)
		b[0] = SboxTable[a[0]];
		b[1] = SboxTable[a[1]];
		b[2] = SboxTable[a[2]];
		b[3] = SboxTable[a[3]];
		GET_ULONG_BE(bb, b, 0)
		c =b[0]^b[3]^(u8)(bb>>6)^ (u8)(bb >> 14);
		Count[c^ (u8)(ciphertxt[2 * i + 1]>>24)]++;
	}
	for (int i = 0; i < 256; i++)MaxSei += doublec(Count[i]);

	partialKey[tdx] = key;
	partialSEI[tdx] = MaxSei;

	__syncthreads();

	for (int stride = 256 / 2; stride > 0; stride = stride >> 1) {
		if (tdx < stride) {
			if (partialSEI[tdx] < partialSEI[tdx + stride]) {
				partialSEI[tdx] = partialSEI[tdx + stride];
				partialKey[tdx] = partialKey[tdx + stride];
			}
		}
		__syncthreads();
	}


	if (tdx == 0) {
		*(maxSEI + blockIdx.y * 256 + blockIdx.x) = partialSEI[tdx];
		*(guessKey + blockIdx.y * 256 + blockIdx.x) = partialKey[tdx];
	}
		
}


__global__ void getMaxSEI(u32 *maxSEI, u32 *maxKey, u32 *testkey) {//<<<(16384,1),(1024,1)>>>======<<<(256,1)(256,1)>>>
	const u32 tid = threadIdx.x;
	const u32 it = tid + blockIdx.x*blockDim.x;
	for (int stride = blockDim.x *gridDim.x / 2; stride > 0; stride = stride >> 1) {
		if (it < stride) {
			if (maxSEI[it] < maxSEI[it + stride]) {
				maxSEI[it] = maxSEI[it + stride];
				maxKey[it] = maxKey[it + stride];
			}
			__syncthreads();
		}
		__syncthreads();
	}

	if (it == 0)(*testkey) = maxKey[it];
}

extern "C"
u32 getKey(u32 *ciphertxt0, int Countn, const u32 &trueKey) {
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
	int nsize = size_24 * Countn * sizeof(u8);
	//	printf_s("Matrix size:nx %d ny %d\n", nx, ny);

	//以下为定义的线程布局gird=（256，65536）个block=（256,1）个threads
	dim3 grid(size_16, size_8);
	dim3 block(size_8, 1);
	///////////////////////////////////////////////////////
	u16 left = trueKey >> 16, right = (u16)trueKey;

	//申请device内存并将host的内存拷贝到device上（输入）
	u32 *cipher;
	CHECK(cudaMalloc((void **)&cipher, Countn * 2 * sizeof(u32)));

	CHECK(cudaMemcpy(cipher, ciphertxt0, Countn * 2 * sizeof(u32), cudaMemcpyHostToDevice));
	//申请device内存作为输出空间（输出）
	u32 *maxSEI;
	u32 *maxKey;

	cudaMalloc((void **)&maxSEI, nsize);
	cudaMalloc((void **)&maxKey, nsize);

	//调用核函数计算SEI
	kernel << <grid, block >> > (maxKey，maxSEI,cipher，Countn);
	CHECK(cudaDeviceSynchronize());//检查cuda设备同步情况

	//归约最大值
	//定义参数
	dim3 grid2(size_16, 1);
	dim3 block2(size_8, 1);
	//定义读取数据的内存空间
	u32 *guesskey,*ans;
	ans = (u32 *)malloc(sizeof(u32));
	CHECK(cudaMalloc((void **)&guesskey, sizeof(u32)));


	//调用核函数求SEI最大的key
	getMaxSEI << <grid2, block2 >> > (maxSEI, maxKey, &guesskey);
	CHECK(cudaDeviceSynchronize());//检查cuda设备同步情况


	//拷贝结果到主机host
	CHECK(cudaMemcpy(ans, guesskey, Countn * 2 * sizeof(u32), cudaMemcpyDeviceToHost));
	u32 returnans = (*ans);
	free(ans);
	CHECK(cudaFree(guesskey));

	//释放占用空间
	CHECK(cudaFree(maxSEI));
	CHECK(cudaFree(maxKey));
	CHECK(cudaFree(cipher));

	return returnans;
}