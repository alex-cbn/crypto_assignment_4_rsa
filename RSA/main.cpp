#include <openssl\bn.h>
#include <openssl\asn1.h>
#include <openssl\asn1t.h>
#include <string.h>
#include <stdio.h>
#include "RsaKey.h"
#include "RsaCrypt.h"
#include <openssl\x509.h>

#define RSA_PRIVATE_KEY 1
#define RSA_PUBLIC_KEY 2
//
//typedef struct rsa_pub_asn1_st {
//	ASN1_INTEGER* modulus;
//	ASN1_INTEGER* public_exponent;
//} RSA_PUB_KEY_ASN1;
//
//DECLARE_ASN1_FUNCTIONS(RSA_PUB_KEY_ASN1)
//ASN1_SEQUENCE(RSA_PUB_KEY_ASN1) = {
//	ASN1_SIMPLE(RSA_PUB_KEY_ASN1, modulus, ASN1_INTEGER),
//	ASN1_SIMPLE(RSA_PUB_KEY_ASN1, public_exponent, ASN1_INTEGER)
//}ASN1_SEQUENCE_END(RSA_PUB_KEY_ASN1)
//IMPLEMENT_ASN1_FUNCTIONS(RSA_PUB_KEY_ASN1)

int ex_main()
{
	unsigned char* data_in = nullptr;
	unsigned char* data_out = nullptr;
	int length = 6;
	unsigned char* input_string = (unsigned char*)malloc(length);
	strcpy((char*)input_string, "secret");
	RsaKey key(2048, 5);
	key.WritePrivateKeyToFile((char*)"1.txt");
	unsigned char* ciphertext = RsaCrypt::Encrypt(input_string, length, &key);
	unsigned char* plaintext = RsaCrypt::Decrypt(ciphertext, length, &key);

	//quick fix
	//i2d_RSAPrivateKey();

	return 0;
}

void rsa_homomorphic_property(unsigned char* a, unsigned char* b)
{
	RsaKey key(512, 3);
	unsigned char* axb = (unsigned char*)malloc(4);
	memset(axb, 0, 4);
	axb[0] = a[0] * b[0];
	unsigned char* a_ciphered = (unsigned char*)malloc(4);
	memset(a_ciphered, 0, 4);
	unsigned char* b_ciphered = (unsigned char*)malloc(4);
	memset(b_ciphered, 0, 4);
	unsigned char* axb_ciphered = (unsigned char*)malloc(4);
	memset(axb_ciphered, 0, 4);
	unsigned char* a_cipheredxb_chiphered = (unsigned char*)malloc(4);
	memset(a_cipheredxb_chiphered, 0, 4);
	a_ciphered = RsaCrypt::Encrypt(a, 1, &key);
	b_ciphered = RsaCrypt::Encrypt(b, 1, &key);
	axb_ciphered = RsaCrypt::Encrypt(axb, 1, &key);
	a_cipheredxb_chiphered[0] = a_ciphered[0] * b_ciphered[0];
	if (axb_ciphered[0] == a_cipheredxb_chiphered[0])
	{
		printf("Homomorphic enough\n");
	}
	else
	{
		printf("Pls only try small numbers such as \x2 and \x3 \n");
	}
}

int main(int argc, char** argv)
{
	unsigned char* a = (unsigned char*)malloc(2);
	unsigned char* b = (unsigned char*)malloc(2);

	strcpy((char*)a, "\x2");
	strcpy((char*)b, "\x3");

	//rsa_homomorphic_property(a,b);
	ex_main();//this is for testing
	int exp = 0;
	int key_length = 0;
	int data_length = 0;
	char* private_key_path = nullptr;
	char* public_key_path = nullptr;
	char* input_file_path = nullptr;
	char* output_file_path = nullptr;
	RsaKey* key = nullptr;
	if (argc == 5)
	{
		if (!strcmp(argv[1], "genkey"))
		{
			exp = atoi(argv[2]);
			key_length = atoi(argv[3]);
			private_key_path = argv[4];
			public_key_path = argv[5];
			key = new RsaKey(key_length, exp);
			key->WritePrivateKeyToFile(private_key_path);
			key->WritePublicKeyToFile(public_key_path);
		}
		else
		{
			printf("Incorrect arguments\n");
			return -1;
		}
		return 0;
	}
	if (argc == 4)
	{
		if (!strcmp(argv[1], "encrypt"))
		{
			//setting up key and others
			public_key_path = argv[2];
			input_file_path = argv[3];
			output_file_path = argv[4];
			key = new RsaKey(public_key_path, RSA_PUBLIC_KEY);
			key_length = key->bits_;

			//reading from file
			unsigned char* in_data = (unsigned char*)malloc(key_length / 4);
			unsigned char* out_data = nullptr;
			memset(in_data, 0, key_length / 4);
			FILE* f_in = fopen(input_file_path, "r");
			data_length = fread(in_data, 1, key_length / 4, f_in);
			fclose(f_in);

			//encrypt
			out_data = RsaCrypt::Encrypt(in_data, data_length, key);

			//write to file
			FILE* f_out = fopen(output_file_path, "w");
			fwrite(out_data, 1, key_length / 4, f_out);
			fclose(f_out);

			return 0;
		}
		if (!strcmp(argv[1], "decrypt"))
		{
			//setting up key and others
			private_key_path = argv[2];
			input_file_path = argv[3];
			output_file_path = argv[4];
			key = new RsaKey(private_key_path, RSA_PRIVATE_KEY);
			key_length = key->bits_;

			//reading from file
			unsigned char* in_data = (unsigned char*)malloc(key_length / 4);
			unsigned char* out_data = nullptr;
			memset(in_data, 0, key_length / 4);
			FILE* f_in = fopen(input_file_path, "r");
			data_length = fread(in_data, 1, key_length / 4, f_in);
			fclose(f_in);

			//decrypt
			out_data = RsaCrypt::Encrypt(in_data, key_length, key);

			//write to file
			FILE* f_out = fopen(output_file_path, "w");
			fwrite(out_data, 1, key_length / 4, f_out);
			fclose(f_out);

			return 0;
		}
		printf("Incorrect arguments\n");
		return -1;
	}
	printf("Incorrect number of arguments\n");
}