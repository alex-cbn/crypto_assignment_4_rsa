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
	bits_ = bits;
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
	bits_ = bits;
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
	FILE* fp = fopen(path, "w");
	//int written_bytes = 0;
	//char dump_to_file[4096];
	//memset(dump_to_file, 0, 4096);
	//Helper::AppendEncodedBn(n, dump_to_file, written_bytes);
	//Helper::AppendEncodedBn(e, dump_to_file, written_bytes);
	//Helper::AppendEncodedBn(p, dump_to_file, written_bytes);
	//Helper::AppendEncodedBn(q, dump_to_file, written_bytes);
	//Helper::AppendEncodedBn(exp1, dump_to_file, written_bytes);
	//Helper::AppendEncodedBn(exp2, dump_to_file, written_bytes);
	//Helper::AppendEncodedBn(coefficient, dump_to_file, written_bytes);
	//
	////calculate sequence header
	//int sequence_length_length = 0;
	//int sequence_length = written_bytes;
	//char* encoded_sequence_length = Helper::lengthEncode(sequence_length, &sequence_length_length);
	////write sequence header
	//fwrite("\x30", 1, 1, fp);
	////write sequence length
	//fwrite(encoded_sequence_length, 1, sequence_length_length, fp);
	////write raw data
	//fwrite(dump_to_file, 1, written_bytes, fp);
	//ANGHELIZA S WAE
	unsigned char* der_encoded = nullptr;
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
	return 0;
}

int RsaKey::WritePublicKeyToFile(char * path)
{
	FILE* fp = fopen(path, "w");

	int written_bytes = 0;
	char dump_to_file[4096];
	memset(dump_to_file, 0, 4096);

	Helper::AppendEncodedBn(n, dump_to_file, written_bytes);
	Helper::AppendEncodedBn(e, dump_to_file, written_bytes);

	//calculate sequence header
	int sequence_length_length = 0;
	int sequence_length = written_bytes;
	char* encoded_sequence_length = Helper::lengthEncode(sequence_length, &sequence_length_length);
	fwrite("\x30", 1, 1, fp);
	fwrite(encoded_sequence_length, 1, sequence_length_length, fp);
	fwrite(dump_to_file, 1, written_bytes, fp);
	fclose(fp);
	return 0;
}

int RsaKey::ReadPublicKeyFromFile(char * path)
{
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
