#include "RsaKey.h"
#include <string.h>
#include <stdio.h>
#include <openssl\asn1.h>
#include <openssl\asn1t.h>
#include <openssl\x509.h>
#include <openssl\pem.h>
#include "Helper.h"

RsaKey::RsaKey()
{
	Initialize();
}

RsaKey::RsaKey(int bits)
{
	Initialize();
	GenerateKey(bits);
	half_bits_ = bits;
}

RsaKey::RsaKey(char * path, int mode)
{
	Initialize();
	if (mode == RSA_PRIVATE_KEY)
	{
		ReadPrivateKeyFromFile(path);
	}
	if (mode == RSA_PUBLIC_KEY)
	{
		ReadPublicKeyFromFile(path);
	}
}

RsaKey::RsaKey(int bits, int exponent)
{
	Initialize();
	GenerateKey(bits, exponent);
	half_bits_ = bits;
}

void RsaKey::Initialize()
{
	e = BN_new();
	d = BN_new();
	n = BN_new();
	p = BN_new();
	q = BN_new();
	exp1 = BN_new();
	exp2 = BN_new();
	coefficient = BN_new();
	phi = BN_new();
}

int RsaKey::WritePrivateKeyToFile(char* path)
{
	//This alternative way does not seem to work...
	//The program exits at line 75
	/*FILE* fp = fopen(path, "w");
	RSA* rsa_wrap = new RSA();
	rsa_wrap->version;
	rsa_wrap->d = d;
	rsa_wrap->e = e;
	rsa_wrap->n = n;
	rsa_wrap->dmp1 = exp1;
	rsa_wrap->dmq1 = exp2;
	rsa_wrap->iqmp = coefficient;
	rsa_wrap->p = p;
	rsa_wrap->q = q;
	rsa_wrap->bignum_data = NULL;
	BIGNUM* test = BN_new();
	BN_CTX* ctx = BN_CTX_new();
	BN_CTX_start(ctx);
	BN_mul(test, p, q, ctx);
	PEM_write_RSAPrivateKey(fp, rsa_wrap, 0, 0, 0, 0, 0);*/
	FILE* fp = fopen(path, "w");
	RSA* rsa_wrapper = new RSA;
	rsa_wrapper->version = 0;
	rsa_wrapper->d = d;
	rsa_wrapper->e = e;
	rsa_wrapper->n = n;
	rsa_wrapper->p = p;
	rsa_wrapper->q = q;
	rsa_wrapper->dmp1 = exp1;
	rsa_wrapper->dmq1 = exp2;
	rsa_wrapper->iqmp = coefficient;
	BIO *bio = BIO_new(BIO_s_mem());
	PEM_write_bio_RSAPrivateKey(bio, rsa_wrapper, NULL, NULL, NULL, NULL, NULL);
	int key_length = BIO_pending(bio);
	unsigned char* buffer = (unsigned char*)malloc(key_length + 1);
	BIO_read(bio, buffer, key_length);
	fwrite(buffer, 1, key_length, fp);
	fclose(fp);
	return 0;
}

int RsaKey::ReadPrivateKeyFromFile(char* path)
{
	RSA* rsa_wrapper = nullptr;
	FILE* fp = fopen(path, "r");
	BIO *bio = BIO_new(BIO_s_mem());
	unsigned char* buffer = (unsigned char*)malloc(40960);
	memset(buffer, 0, 40960);
	
	//read key from file in a buffer
	int key_length = fread(buffer, 1, 40960, fp);
	fclose(fp);

	//read bio from buffer into bio
	BIO_write(bio, buffer, key_length);
	//read RSA from bio
	PEM_read_bio_RSAPrivateKey(bio, &rsa_wrapper, 0, 0);

	//transfer data from RSA structure to key
	d = rsa_wrapper->d;
	e = rsa_wrapper->e;
	n = rsa_wrapper->n;
	p = rsa_wrapper->p;
	q = rsa_wrapper->q;
	exp1 = rsa_wrapper->dmp1;
	exp2 = rsa_wrapper->dmq1;
	coefficient = rsa_wrapper->iqmp;
	//maybe calculate phi
	
	//get them bits
	half_bits_ = BN_num_bits(n)/2;

	return 0;
}

int RsaKey::WritePublicKeyToFile(char * path)
{
	FILE* fp = fopen(path, "w");
	RSA* rsa_wrapper = new RSA;
	rsa_wrapper->version = 0;
	rsa_wrapper->d = d;
	rsa_wrapper->e = e;
	rsa_wrapper->n = n;
	rsa_wrapper->p = p;
	rsa_wrapper->q = q;
	rsa_wrapper->dmp1 = exp1;
	rsa_wrapper->dmq1 = exp2;
	rsa_wrapper->iqmp = coefficient;
	BIO *bio = BIO_new(BIO_s_mem());
	PEM_write_bio_RSAPublicKey(bio, rsa_wrapper);
	int key_length = BIO_pending(bio);
	unsigned char* buffer = (unsigned char*)malloc(key_length + 1);
	BIO_read(bio, buffer, key_length);
	fwrite(buffer, 1, key_length, fp);
	fclose(fp);
	return 0;
}

int RsaKey::ReadPublicKeyFromFile(char * path)
{
	RSA* rsa_wrapper = nullptr;
	FILE* fp = fopen(path, "r");
	BIO *bio = BIO_new(BIO_s_mem());
	unsigned char* buffer = (unsigned char*)malloc(40960);
	memset(buffer, 0, 40960);

	//read key from file in a buffer
	int key_length = fread(buffer, 1, 40960, fp);
	fclose(fp);

	//read bio from buffer into bio
	BIO_write(bio, buffer, key_length);
	//read RSA from bio
	PEM_read_bio_RSAPublicKey(bio, &rsa_wrapper, 0, 0);

	//transfer data from RSA structure to key
	d = rsa_wrapper->d;
	e = rsa_wrapper->e;
	n = rsa_wrapper->n;
	p = rsa_wrapper->p;
	q = rsa_wrapper->q;
	exp1 = rsa_wrapper->dmp1;
	exp2 = rsa_wrapper->dmq1;
	coefficient = rsa_wrapper->iqmp;
	//maybe calculate phi

	//get them bits
	half_bits_ = BN_num_bits(n)/2;

	return 0;
}

int RsaKey::GenerateKey(int bits)
{

	BN_CTX* ctx = BN_CTX_new();
	BN_CTX_start(ctx);
	BIGNUM* tmp = BN_new();
	BIGNUM* p_m_1 = BN_new();
	BIGNUM* q_m_1 = BN_new();
	//generate p,q
	if (!BN_generate_prime_ex(p, bits, NULL, NULL, NULL, NULL))
	{
		printf("Can't generate prime\n");
		return -2;
	}
	if (!BN_generate_prime_ex(q, bits, NULL, NULL, NULL, NULL))
	{
		printf("Can't generate prime\n");
		return -2;
	}
	if (!BN_is_prime_ex(p, 3, ctx, NULL)) {
		printf("FakePrime\n");
		return -3;
	}
	if (!BN_is_prime_ex(q, 3, ctx, NULL)) {
		printf("FakePrime\n");
		return -3;
	}
	//TODO check p!=q
	//compute n
	BN_mul(n, p, q, ctx);
	//compute phi(n) or totient of n
	BN_sub(p_m_1, p, BN_value_one());
	BN_sub(q_m_1, q, BN_value_one());
	BN_mul(phi, p_m_1, q_m_1, ctx);
	//find e
	int cmp;
	int cmp2;
	do {
		do
		{
			BN_generate_prime_ex(e, bits, NULL, NULL, NULL, NULL);
			cmp2 = BN_cmp(e, phi);
		} while (cmp2 != -1);
		BN_gcd(tmp, phi, e, ctx);//e must be prime with phi
		cmp = BN_cmp(tmp, BN_value_one());
	} while (cmp != 0);

	//choose e manually
	//BN_asc2bn(&e, "3");

	//compute private exponent
	BN_mod_inverse(d, e, phi, ctx);
	//exp1
	BN_mod(exp1, d, p_m_1, ctx);
	//exp2
	BN_mod(exp2, d, q_m_1, ctx);
	//coefficient
	BN_mod_inverse(coefficient, q, p, ctx);

	////TESTING
	BIGNUM* m = BN_new();
	BIGNUM* c = BN_new();
	BN_asc2bn(&m, "123");
	BN_mod_exp(c, m, e, n, ctx);
	BN_mod_exp(c, c, d, n, ctx);//if only c was now the same as m :(
	return 0;
}

int RsaKey::GenerateKey(int bits, int exponent)
{
	BN_CTX* ctx = BN_CTX_new();
	BN_CTX_start(ctx);
	BIGNUM* tmp = BN_new();
	BIGNUM* p_m_1 = BN_new();
	BIGNUM* q_m_1 = BN_new();
	//generate p,q
	if (!BN_generate_prime_ex(p, bits, NULL, NULL, NULL, NULL))
	{
		printf("Can't generate prime\n");
		return -2;
	}
	if (!BN_generate_prime_ex(q, bits, NULL, NULL, NULL, NULL))
	{
		printf("Can't generate prime\n");
		return -2;
	}
	//if (!BN_is_prime_ex(p, 2, ctx, NULL)) {
	//	printf("FakePrime\n");
	//	return -3;
	//}
	//if (!BN_is_prime_ex(q, 2, ctx, NULL)) {
	//	printf("FakePrime\n");
	//	return -3;
	//}
	//TODO check p!=q
	//compute n
	BN_mul(n, p, q, ctx);
	//compute phi(n) or totient of n
	BN_sub(p_m_1, p, BN_value_one());
	BN_sub(q_m_1, q, BN_value_one());
	BN_mul(phi, p_m_1, q_m_1, ctx);

	//choose e manually
	char aide[64];
	sprintf(aide, "%d", exponent);
	BN_asc2bn(&e, aide);
	BN_gcd(tmp, e, phi, ctx);
	if (!BN_is_one(tmp))
	{
		printf("Exponent prahit\n");
		return -3;
	}
	//compute private exponent
	BN_mod_inverse(d, e, phi, ctx);
	//exp1
	BN_mod(exp1, d, p_m_1, ctx);
	//exp2
	BN_mod(exp2, d, q_m_1, ctx);
	//coefficient
	BN_mod_inverse(coefficient, q, p, ctx);

	////TESTING
	//BIGNUM* m = BN_new();
	//BIGNUM* c = BN_new();
	//BN_asc2bn(&m, "123");
	//BN_mod_exp(c, m, e, n, ctx);
	//BN_mod_exp(c, c, d, n, ctx);//if only c was now the same as m :(
	return 0;
}
