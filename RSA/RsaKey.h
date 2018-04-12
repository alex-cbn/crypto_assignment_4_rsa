#pragma once
#include <openssl\bn.h>

#define RSA_PRIVATE_KEY 1
#define RSA_PUBLIC_KEY 2

class RsaKey
{
public:
	BIGNUM * e, *n, *d, *p, *q, *exp1, *exp2, *coefficient, *phi;
	int half_bits_;
	RsaKey();
	RsaKey(int bits);
	RsaKey(char* path, int mode);
	RsaKey(int bits, int exponent);
	void Initialize();
	int WritePrivateKeyToFile(char* path);
	int ReadPrivateKeyFromFile(char* path);
	int WritePublicKeyToFile(char* path);
	int ReadPublicKeyFromFile(char* path);
	int GenerateKey(int bits);
	int GenerateKey(int bits, int exponent);
};