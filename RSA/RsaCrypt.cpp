#include <openssl\bn.h>
#include <openssl\rand.h>
#include "RsaCrypt.h"
#include "RsaKey.h"
#include <string.h>

unsigned char* RsaCrypt::Encrypt(unsigned char* input, unsigned int length, RsaKey *key)
{
	//preliminary stuff
	int max_length = key->bits_ / 4; // cause it's bits_*2/8
	if (length + 11 > max_length)//checking length for padding
	{
		printf("Too much data for me\n");
		return nullptr;
	}
	int padding_length = max_length - length - 3;
	unsigned char* chipher_me = (unsigned char*)malloc(max_length + 1);
	memset(chipher_me, 0, max_length + 1);
	unsigned char* output = (unsigned char*)malloc(max_length + 1);
	memset(output, 0, max_length + 1);
	BN_CTX* ctx = BN_CTX_new();
	BN_CTX_start(ctx);
	BIGNUM* in = BN_new();

	//generating chipher_me
	chipher_me[1] = '\x2';
	//generating non null padding
	int padding_offset = 0;
	while (padding_offset < padding_length)
	{
		RAND_bytes(chipher_me + padding_offset + 2, 1);
		if (chipher_me[padding_offset + 2] != '\0')
		{
			padding_offset++;
		}
	}
	//copying the message into chipher_me
	memcpy(chipher_me+padding_length+3,input, length); 
	//storing input string as a bignum
	BN_bin2bn(chipher_me, max_length, in);
	//exponentiating
	BN_mod_exp(in, in, key->e, key->n, ctx);
	//writing the output
	BN_bn2bin(in, output);
	/*writing the output to asn1
	unsigned char* output = nullptr;
	ASN1_INTEGER out_asn1;
	BN_to_ASN1_INTEGER(in, &out_asn1);
	i2d_ASN1_INTEGER(&out_asn1, &output);*/

	return output;
}

unsigned char * RsaCrypt::Decrypt(unsigned char * input, unsigned int length, RsaKey * key)
{
	//preliminary stuff
	int max_length = key->bits_ / 4; // cause it's bits_*2/8
	if (length> max_length)
	{
		printf("Too much data for me\n");
		return nullptr;
	}
	unsigned char* output = (unsigned char*)malloc(max_length + 1);
	memset(output, 0, max_length + 1);
	BN_CTX* ctx = BN_CTX_new();
	BN_CTX_start(ctx);
	BIGNUM* in = BN_new();

	//storing input string as a bignum
	BN_bin2bn(input, length, in);
	//exponentiating
	BN_mod_exp(in, in, key->d, key->n, ctx);
	//writing the output
	BN_bn2bin(in, output);
	int offset = 1;
	if (output[0] != '\x2')
	{
		printf("Error while decrypting...\nWrong key perhaps\n");
		return nullptr;
	}
	while (offset<length)
	{
		if (output[offset] == '\0')
		{
			offset++;
			break;
		}
		offset++;
	}
	//BIGNUM* m = BN_new();
	//BIGNUM* c = BN_new();
	//BN_asc2bn(&m, "123");
	//BN_mod_exp(c, m, key->e, key->n, ctx);
	//BN_mod_exp(c, c, key->d, key->n, ctx);//if only c was now the same as m :(
	return output+offset;
}
