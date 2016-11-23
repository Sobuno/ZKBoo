/*
 ============================================================================
 Name        : MPC_SHA256.c
 Author      : Sobuno
 Version     : 0.1
 Description : MPC SHA1 for one block only
 ============================================================================
 */


#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "shared.h"
#include "omp.h"


#define CH(e,f,g) ((e & f) ^ ((~e) & g))


int totalRandom = 0;
int totalSha = 0;
int totalSS = 0;
int totalHash = 0;



//static View views[3];

uint32_t rand32() {
	uint32_t x;
	x = rand() & 0xff;
	x |= (rand() & 0xff) << 8;
	x |= (rand() & 0xff) << 16;
	x |= (rand() & 0xff) << 24;

	return x;
}

void printbits(uint32_t n) {
	if (n) {
		printbits(n >> 1);
		printf("%d", n & 1);
	}

}



void mpc_XOR(uint32_t x[3], uint32_t y[3], uint32_t z[3]) {
	z[0] = x[0] ^ y[0];
	z[1] = x[1] ^ y[1];
	z[2] = x[2] ^ y[2];
}



void mpc_AND(uint32_t x[3], uint32_t y[3], uint32_t z[3], unsigned char *randomness[3], int* randCount, View views[3], int* countY) {
	//uint32_t r[3] = { newRandom(&ctx[0]), newRandom(&ctx[1]),newRandom(&ctx[2]) };
	uint32_t r[3] = { getRandom32(randomness[0], *randCount), getRandom32(randomness[1], *randCount), getRandom32(randomness[2], *randCount)};
	*randCount += 4;
	//kCount++;
	uint32_t t[3] = { 0 };

	t[0] = (x[0] & y[1]) ^ (x[1] & y[0]) ^ (x[0] & y[0]) ^ r[0] ^ r[1];
	t[1] = (x[1] & y[2]) ^ (x[2] & y[1]) ^ (x[1] & y[1]) ^ r[1] ^ r[2];
	t[2] = (x[2] & y[0]) ^ (x[0] & y[2]) ^ (x[2] & y[2]) ^ r[2] ^ r[0];
	z[0] = t[0];
	z[1] = t[1];
	z[2] = t[2];
	views[0].y[*countY] = z[0];
	views[1].y[*countY] = z[1];
	views[2].y[*countY] = z[2];
	(*countY)++;
}



void mpc_NEGATE(uint32_t x[3], uint32_t z[3]) {
	z[0] = ~x[0];
	z[1] = ~x[1];
	z[2] = ~x[2];
}



void mpc_ADD(uint32_t x[3], uint32_t y[3], uint32_t z[3], unsigned char *randomness[3], int* randCount, View views[3], int* countY) {
	uint32_t c[3] = { 0 };
	uint32_t r[3] = { getRandom32(randomness[0], *randCount), getRandom32(randomness[1], *randCount), getRandom32(randomness[2], *randCount)};
	*randCount += 4;

	uint8_t a[3], b[3];

	uint8_t t;

	for(int i=0;i<31;i++)
	{
		a[0]=GETBIT(x[0]^c[0],i);
		a[1]=GETBIT(x[1]^c[1],i);
		a[2]=GETBIT(x[2]^c[2],i);

		b[0]=GETBIT(y[0]^c[0],i);
		b[1]=GETBIT(y[1]^c[1],i);
		b[2]=GETBIT(y[2]^c[2],i);

		t = (a[0]&b[1]) ^ (a[1]&b[0]) ^ GETBIT(r[1],i);
		SETBIT(c[0],i+1, t ^ (a[0]&b[0]) ^ GETBIT(c[0],i) ^ GETBIT(r[0],i));

		t = (a[1]&b[2]) ^ (a[2]&b[1]) ^ GETBIT(r[2],i);
		SETBIT(c[1],i+1, t ^ (a[1]&b[1]) ^ GETBIT(c[1],i) ^ GETBIT(r[1],i));

		t = (a[2]&b[0]) ^ (a[0]&b[2]) ^ GETBIT(r[0],i);
		SETBIT(c[2],i+1, t ^ (a[2]&b[2]) ^ GETBIT(c[2],i) ^ GETBIT(r[2],i));


	}

	z[0]=x[0]^y[0]^c[0];
	z[1]=x[1]^y[1]^c[1];
	z[2]=x[2]^y[2]^c[2];


	views[0].y[*countY] = c[0];
	views[1].y[*countY] = c[1];
	views[2].y[*countY] = c[2];
	*countY += 1;

	/*views[0].y[countY] = z[0];
	views[1].y[countY] = z[1];
	views[2].y[countY] = z[2];
	countY++;*/
}


void mpc_ADDK(uint32_t x[3], uint32_t y, uint32_t z[3], unsigned char *randomness[3], int* randCount, View views[3], int* countY) {
	uint32_t c[3] = { 0 };
	uint32_t r[3] = { getRandom32(randomness[0], *randCount), getRandom32(randomness[1], *randCount), getRandom32(randomness[2], *randCount)};
	*randCount += 4;

	uint8_t a[3], b[3];

	uint8_t t;

	for(int i=0;i<31;i++)
	{
		a[0]=GETBIT(x[0]^c[0],i);
		a[1]=GETBIT(x[1]^c[1],i);
		a[2]=GETBIT(x[2]^c[2],i);

		b[0]=GETBIT(y^c[0],i);
		b[1]=GETBIT(y^c[1],i);
		b[2]=GETBIT(y^c[2],i);

		t = (a[0]&b[1]) ^ (a[1]&b[0]) ^ GETBIT(r[1],i);
		SETBIT(c[0],i+1, t ^ (a[0]&b[0]) ^ GETBIT(c[0],i) ^ GETBIT(r[0],i));

		t = (a[1]&b[2]) ^ (a[2]&b[1]) ^ GETBIT(r[2],i);
		SETBIT(c[1],i+1, t ^ (a[1]&b[1]) ^ GETBIT(c[1],i) ^ GETBIT(r[1],i));

		t = (a[2]&b[0]) ^ (a[0]&b[2]) ^ GETBIT(r[0],i);
		SETBIT(c[2],i+1, t ^ (a[2]&b[2]) ^ GETBIT(c[2],i) ^ GETBIT(r[2],i));


	}

	z[0]=x[0]^y^c[0];
	z[1]=x[1]^y^c[1];
	z[2]=x[2]^y^c[2];


	views[0].y[*countY] = c[0];
	views[1].y[*countY] = c[1];
	views[2].y[*countY] = c[2];
	*countY += 1;

}


int sha1(unsigned char* result, unsigned char* input, int numBits) {
	uint32_t hA[5] = { 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476,
			0xC3D2E1F0};


	if (numBits > 447) {
		printf("Input too long, aborting!");
		return -1;
	}
	int chars = numBits >> 3;
	unsigned char* chunk = calloc(64, 1); //512 bits
	memcpy(chunk, input, chars);
	chunk[chars] = 0x80;
	//Last 8 chars used for storing length of input without padding, in big-endian.
	//Since we only care for one block, we are safe with just using last 9 bits and 0'ing the rest

	//chunk[60] = numBits >> 24;
	//chunk[61] = numBits >> 16;
	chunk[62] = numBits >> 8;
	chunk[63] = numBits;

	uint32_t w[80];
	int i;
	for (i = 0; i < 16; i++) {
		w[i] = (chunk[i * 4] << 24) | (chunk[i * 4 + 1] << 16)
						| (chunk[i * 4 + 2] << 8) | chunk[i * 4 + 3];
	}

	for (i = 16; i < 80; i++) {
		w[i] = LEFTROTATE((w[i - 3] ^ w[i-8] ^ w[i-14] ^ w[i-16]), 1);
		printf("W[%d]: %02X\n", i, w[i]);
	}

	uint32_t a, b, c, d, e, f, k, temp;
	a = hA[0];
	b = hA[1];
	c = hA[2];
	d = hA[3];
	e = hA[4];

	for (i = 0; i < 80; i++) {
		if(i <= 19) {
			f = (b & c) | ((~b) & d);
			k = 0x5A827999;
		}
		else if(i <= 39) {
			f = b ^ c ^ d;
			k = 0x6ED9EBA1;
		}
		else if(i <= 59) {
			f = (b & c) | (b & d) | (c & d);
			k = 0x8F1BBCDC;
		}
		else {
			f = b ^c ^ d;
			k = 0xCA62C1D6;
		}
		printf("F[%d]: %04X\n", i, f);

		temp = (LEFTROTATE(a,5))+f+e+k+w[i];
		e = d;
		d = c;
		c = LEFTROTATE(b,30);
		b = a;
		a = temp;
	}

	hA[0] += a;
	hA[1] += b;
	hA[2] += c;
	hA[3] += d;
	hA[4] += e;

	for (i = 0; i < 5; i++) {
		result[i * 4] = (hA[i] >> 24);
		result[i * 4 + 1] = (hA[i] >> 16);
		result[i * 4 + 2] = (hA[i] >> 8);
		result[i * 4 + 3] = hA[i];
	}
	return 0;
}

void mpc_RIGHTROTATE(uint32_t x[], int i, uint32_t z[]) {
	z[0] = RIGHTROTATE(x[0], i);
	z[1] = RIGHTROTATE(x[1], i);
	z[2] = RIGHTROTATE(x[2], i);
}

void mpc_LEFTROTATE(uint32_t x[], int i, uint32_t z[]) {
	z[0] = LEFTROTATE(x[0], i);
	z[1] = LEFTROTATE(x[1], i);
	z[2] = LEFTROTATE(x[2], i);
}





void mpc_RIGHTSHIFT(uint32_t x[3], int i, uint32_t z[3]) {
	z[0] = x[0] >> i;
	z[1] = x[1] >> i;
	z[2] = x[2] >> i;
}





void mpc_MAJ(uint32_t a[], uint32_t b[3], uint32_t c[3], uint32_t z[3], unsigned char randomness[3][1472], int* randCount, View views[3], int* countY) {
	uint32_t t0[3];
	uint32_t t1[3];

	mpc_XOR(a, b, t0);
	mpc_XOR(a, c, t1);
	mpc_AND(t0, t1, z, randomness, randCount, views, countY);
	mpc_XOR(z, a, z);
}


void mpc_CH(uint32_t e[], uint32_t f[3], uint32_t g[3], uint32_t z[3], unsigned char randomness[3][1472], int* randCount, View views[3], int* countY) {
	uint32_t t0[3];
	/*
	//t0 = e & f
	mpc_AND(e, f, t0, true);

	//t1 = (~e) & g

	mpc_NEGATE(e, t1);
	mpc_AND(t1, g, t1, true);

	//z = temp1 ^ t1
	mpc_XOR(t0, t1, z);

	 */
	//Alternative, rewritten as e & (f^g) ^ g

	mpc_XOR(f,g,t0);
	mpc_AND(e,t0,t0, randomness, randCount, views, countY);
	mpc_XOR(t0,g,z);

}



int mpc_sha1(unsigned char* results[3], unsigned char* inputs[3], int numBits, unsigned char *randomness[3], View views[3], int* countY) {



	if (numBits > 447) {
		printf("Input too long, aborting!");
		return -1;
	}

	int* randCount = calloc(1, sizeof(int));

	int chars = numBits >> 3;
	unsigned char* chunks[3];
	uint32_t w[80][3];

	for (int i = 0; i < 3; i++) {
		chunks[i] = calloc(64, 1); //512 bits
		memcpy(chunks[i], inputs[i], chars);
		chunks[i][chars] = 0x80;
		//Last 8 chars used for storing length of input without padding, in big-endian.
		//Since we only care for one block, we are safe with just using last 9 bits and 0'ing the rest

		//chunk[60] = numBits >> 24;
		//chunk[61] = numBits >> 16;
		chunks[i][62] = numBits >> 8;
		chunks[i][63] = numBits;
		memcpy(views[i].x, chunks[i], 64);

		for (int j = 0; j < 16; j++) {
			w[j][i] = (chunks[i][j * 4] << 24) | (chunks[i][j * 4 + 1] << 16)
							| (chunks[i][j * 4 + 2] << 8) | chunks[i][j * 4 + 3];

			//printf("%d: %02X %02X %02X %02X %02X\n", j, w[j][i], (chunks[i][j * 4]), (chunks[i][j * 4 + 1]), (chunks[i][j * 4 + 2]), chunks[i][j * 4 + 3]);
		}
		//printf("Chars: %d\n", chars);
		free(chunks[i]);
	}

	uint32_t temp[3];
	uint32_t t0[3];
	for (int j = 16; j < 80; j++) {
		mpc_XOR(w[j-3], w[j-8], temp);
		mpc_XOR(temp, w[j-14], temp);
		mpc_XOR(temp, w[j-16], temp);
		mpc_LEFTROTATE(temp,1,w[j]);

		//printf("W[%d]: %02X\n", j, w[j][0]^w[j][1]^w[j][2]);
	}

	uint32_t a[3] = { hA[0],hA[0],hA[0] };
	uint32_t b[3] = { hA[1],hA[1],hA[1] };
	uint32_t c[3] = { hA[2],hA[2],hA[2] };
	uint32_t d[3] = { hA[3],hA[3],hA[3] };
	uint32_t e[3] = { hA[4],hA[4],hA[4] };
	uint32_t f[3];
	uint32_t k;
	for (int i = 0; i < 80; i++) {
		if(i <= 19) {
			//f = d ^ (b & (c ^ d))
			mpc_XOR(c,d,f);

			mpc_AND(b, f, f, randomness, randCount, views, countY);

			mpc_XOR(d,f,f);
			k = 0x5A827999;
		}
		else if(i <= 39) {
			mpc_XOR(b,c,f);
			mpc_XOR(d,f,f);
			k = 0x6ED9EBA1;
		}
		else if(i <= 59) {
			//f = MAJ(b,c,d)

			mpc_MAJ(b,c,d,f,randomness, randCount, views, countY);

			k = 0x8F1BBCDC;
		}
		else {
			mpc_XOR(b,c,f);
			mpc_XOR(d,f,f);
			k = 0xCA62C1D6;
		}

		//temp = (a leftrotate 5) + f + e + k + w[i]
		mpc_LEFTROTATE(a,5,temp);
		mpc_ADD(f,temp,temp,randomness, randCount, views, countY);
		mpc_ADD(e,temp,temp,randomness, randCount, views, countY);
		mpc_ADDK(temp,k,temp,randomness, randCount, views, countY);
		mpc_ADD(w[i],temp,temp,randomness, randCount, views, countY);

		memcpy(e, d, sizeof(uint32_t) * 3);
		memcpy(d, c, sizeof(uint32_t) * 3);
		mpc_LEFTROTATE(b,30,c);
		memcpy(b, a, sizeof(uint32_t) * 3);
		memcpy(a, temp, sizeof(uint32_t) * 3);
	}

	uint32_t hHa[5][3] = { { hA[0],hA[0],hA[0]  }, { hA[1],hA[1],hA[1] }, { hA[2],hA[2],hA[2] }, { hA[3],hA[3],hA[3] },
			{ hA[4],hA[4],hA[4] }};
	mpc_ADD(hHa[0], a, hHa[0], randomness, randCount, views, countY);
	mpc_ADD(hHa[1], b, hHa[1], randomness, randCount, views, countY);
	mpc_ADD(hHa[2], c, hHa[2], randomness, randCount, views, countY);
	mpc_ADD(hHa[3], d, hHa[3], randomness, randCount, views, countY);
	mpc_ADD(hHa[4], e, hHa[4], randomness, randCount, views, countY);

	for (int i = 0; i < 5; i++) {
		mpc_RIGHTSHIFT(hHa[i], 24, t0);
		results[0][i * 4] = t0[0];
		results[1][i * 4] = t0[1];
		results[2][i * 4] = t0[2];
		mpc_RIGHTSHIFT(hHa[i], 16, t0);
		results[0][i * 4 + 1] = t0[0];
		results[1][i * 4 + 1] = t0[1];
		results[2][i * 4 + 1] = t0[2];
		mpc_RIGHTSHIFT(hHa[i], 8, t0);
		results[0][i * 4 + 2] = t0[0];
		results[1][i * 4 + 2] = t0[1];
		results[2][i * 4 + 2] = t0[2];

		results[0][i * 4 + 3] = hHa[i][0];
		results[1][i * 4 + 3] = hHa[i][1];
		results[2][i * 4 + 3] = hHa[i][2];
	}
	return 0;
}


int writeToFile(char filename[], void* data, int size, int numItems) {
	FILE *file;

	file = fopen(filename, "wb");
	if (!file) {
		printf("Unable to open file!");
		return 1;
	}
	fwrite(data, size, numItems, file);
	fclose(file);
	return 0;
}







a commit(int numBytes,unsigned char shares[3][numBytes], unsigned char *randomness[3], unsigned char rs[3][4], View views[3]) {

	unsigned char* inputs[3];
	inputs[0] = shares[0];
	inputs[1] = shares[1];
	inputs[2] = shares[2];
	unsigned char* hashes[3];
	hashes[0] = malloc(32);
	hashes[1] = malloc(32);
	hashes[2] = malloc(32);


	int* countY = calloc(1, sizeof(int));
	mpc_sha1(hashes, inputs, numBytes * 8, randomness, views, countY);

	//Explicitly add y to view
	for(int i = 0; i<5; i++) {
		views[0].y[*countY] = 		(hashes[0][i * 4] << 24) | (hashes[0][i * 4 + 1] << 16)
											| (hashes[0][i * 4 + 2] << 8) | hashes[0][i * 4 + 3];

		views[1].y[*countY] = 		(hashes[1][i * 4] << 24) | (hashes[1][i * 4 + 1] << 16)
											| (hashes[1][i * 4 + 2] << 8) | hashes[1][i * 4 + 3];
		views[2].y[*countY] = 		(hashes[2][i * 4] << 24) | (hashes[2][i * 4 + 1] << 16)
											| (hashes[2][i * 4 + 2] << 8) | hashes[2][i * 4 + 3];
		*countY += 1;
	}

	uint32_t* result1 = malloc(20);
	output(views[0], result1);
	uint32_t* result2 = malloc(20);
	output(views[1], result2);
	uint32_t* result3 = malloc(20);
	output(views[2], result3);

	a a;
	memcpy(a.yp[0], result1, 20);
	memcpy(a.yp[1], result2, 20);
	memcpy(a.yp[2], result3, 20);

	return a;
}

z prove(int e, unsigned char keys[3][16], unsigned char rs[3][4], View views[3]) {
	z z;
	memcpy(z.ke, keys[e], 16);
	memcpy(z.ke1, keys[(e + 1) % 3], 16);
	z.ve = views[e];
	z.ve1 = views[(e + 1) % 3];
	memcpy(z.re, rs[e],4);
	memcpy(z.re1, rs[(e + 1) % 3],4);

	return z;
}



int main(void) {
	setbuf(stdout, NULL);
	srand((unsigned) time(NULL));
	init_EVP();
	openmp_thread_setup();

	unsigned char garbage[4];
	if(RAND_bytes(garbage, 4) != 1) {
		printf("RAND_bytes failed crypto, aborting\n");
		return 0;
	}
	
	printf("Enter the string to be hashed (Max 55 characters): ");
	char userInput[55]; //55 is max length as we only support 447 bits = 55.875 bytes
	fgets(userInput, sizeof(userInput), stdin);
	
	int i = strlen(userInput)-1; 
	printf("String length: %d\n", i);
	
	printf("Iterations of SHA: %d\n", NUM_ROUNDS);



	unsigned char input[i];
	for(int j = 0; j<i; j++) {
		input[j] = userInput[j];
	}
	
	clock_t begin = clock(), delta, deltaA;
	unsigned char rs[NUM_ROUNDS][3][4];
	unsigned char keys[NUM_ROUNDS][3][16];
	a as[NUM_ROUNDS];
	View localViews[NUM_ROUNDS][3];
	int totalCrypto = 0;
	
	//Generating keys
	clock_t beginCrypto = clock(), deltaCrypto;
	if(RAND_bytes(keys, NUM_ROUNDS*3*16) != 1) {
		printf("RAND_bytes failed crypto, aborting\n");
		return 0;
	}
	if(RAND_bytes(rs, NUM_ROUNDS*3*4) != 1) {
		printf("RAND_bytes failed crypto, aborting\n");
		return 0;
	}
	deltaCrypto = clock() - beginCrypto;
	int inMilliCrypto = deltaCrypto * 1000 / CLOCKS_PER_SEC;
	totalCrypto = inMilliCrypto;
	





	//Sharing secrets
	clock_t beginSS = clock(), deltaSS;
	unsigned char shares[NUM_ROUNDS][3][i];
	if(RAND_bytes(shares, NUM_ROUNDS*3*i) != 1) {
		printf("RAND_bytes failed crypto, aborting\n");
		return 0;
	}
	#pragma omp parallel for
	for(int k=0; k<NUM_ROUNDS; k++) {

		for (int j = 0; j < i; j++) {
			shares[k][2][j] = input[j] ^ shares[k][0][j] ^ shares[k][1][j];
		}

	}
	deltaSS = clock() - beginSS;
	int inMilli = deltaSS * 1000 / CLOCKS_PER_SEC;
	totalSS = inMilli;

	//Generating randomness
	clock_t beginRandom = clock(), deltaRandom;
	unsigned char *randomness[NUM_ROUNDS][3];
	#pragma omp parallel for
	for(int k=0; k<NUM_ROUNDS; k++) {
		for(int j = 0; j<3; j++) {
			randomness[k][j] = malloc(1472*sizeof(unsigned char));
			getAllRandomness(keys[k][j], randomness[k][j]);
		}
	}
	deltaRandom = clock() - beginRandom;
	inMilli = deltaRandom * 1000 / CLOCKS_PER_SEC;
	totalRandom = inMilli;

	//Running MPC-SHA1
	clock_t beginSha = clock(), deltaSha;
	#pragma omp parallel for
	for(int k=0; k<NUM_ROUNDS; k++) {
		as[k] = commit(i, shares[k], randomness[k], rs[k], localViews[k]);
		for(int j=0; j<3; j++) {
			free(randomness[k][j]);
		}
	}
	deltaSha = clock() - beginSha;
	inMilli = deltaSha * 1000 / CLOCKS_PER_SEC;
	totalSha = inMilli;
	
	//Committing
	clock_t beginHash = clock(), deltaHash;
	#pragma omp parallel for
	for(int k=0; k<NUM_ROUNDS; k++) {
		unsigned char hash1[SHA256_DIGEST_LENGTH];
		H(keys[k][0], localViews[k][0], rs[k][0], &hash1);
		memcpy(as[k].h[0], &hash1, 32);
		H(keys[k][1], localViews[k][1], rs[k][1], &hash1);
		memcpy(as[k].h[1], &hash1, 32);
		H(keys[k][2], localViews[k][2], rs[k][2], &hash1);
		memcpy(as[k].h[2], &hash1, 32);
	}
	deltaHash = clock() - beginHash;
				inMilli = deltaHash * 1000 / CLOCKS_PER_SEC;
				totalHash += inMilli;
				
	deltaA = clock() - begin;
	int inMilliA = deltaA * 1000 / CLOCKS_PER_SEC;

	//Generating E
	clock_t beginE = clock(), deltaE;
	int es[NUM_ROUNDS];
	uint32_t finalHash[8];
	for (int j = 0; j < 8; j++) {
		finalHash[j] = as[0].yp[0][j]^as[0].yp[1][j]^as[0].yp[2][j];
	}
	H3(finalHash, as, NUM_ROUNDS, es);
	deltaE = clock() - beginE;
	int inMilliE = deltaE * 1000 / CLOCKS_PER_SEC;


	//Packing Z
	clock_t beginZ = clock(), deltaZ;
	z* zs = malloc(sizeof(z)*NUM_ROUNDS);

	#pragma omp parallel for
	for(int i = 0; i<NUM_ROUNDS; i++) {
		zs[i] = prove(es[i],keys[i],rs[i], localViews[i]);
	}
	deltaZ = clock() - beginZ;
	int inMilliZ = deltaZ * 1000 / CLOCKS_PER_SEC;
	
	
	//Writing to file
	clock_t beginWrite = clock();
	FILE *file;

	char outputFile[3*sizeof(int) + 8];
	sprintf(outputFile, "out%i.bin", NUM_ROUNDS);
	file = fopen(outputFile, "wb");
	if (!file) {
		printf("Unable to open file!");
		return 1;
	}
	fwrite(as, sizeof(a), NUM_ROUNDS, file);
	fwrite(zs, sizeof(z), NUM_ROUNDS, file);

	fclose(file);

	clock_t deltaWrite = clock()-beginWrite;
	free(zs);
	int inMilliWrite = deltaWrite * 1000 / CLOCKS_PER_SEC;


	delta = clock() - begin;
	inMilli = delta * 1000 / CLOCKS_PER_SEC;

	int sumOfParts = 0;

	printf("Generating A: %ju\n", (uintmax_t)inMilliA);
	printf("	Generating keys: %ju\n", (uintmax_t)totalCrypto);
	sumOfParts += totalCrypto;
	printf("	Generating randomness: %ju\n", (uintmax_t)totalRandom);
	sumOfParts += totalRandom;
	printf("	Sharing secrets: %ju\n", (uintmax_t)totalSS);
	sumOfParts += totalSS;
	printf("	Running MPC-SHA2: %ju\n", (uintmax_t)totalSha);
	sumOfParts += totalSha;
	printf("	Committing: %ju\n", (uintmax_t)totalHash);
	sumOfParts += totalHash;
	printf("	*Accounted for*: %ju\n", (uintmax_t)sumOfParts);
	printf("Generating E: %ju\n", (uintmax_t)inMilliE);
	printf("Packing Z: %ju\n", (uintmax_t)inMilliZ);
	printf("Writing file: %ju\n", (uintmax_t)inMilliWrite);
	printf("Total: %d\n",inMilli);
	printf("\n");
	printf("Proof output to file %s", outputFile);

	openmp_thread_cleanup();
	cleanup_EVP();
	return EXIT_SUCCESS;
}
