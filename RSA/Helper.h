#pragma once
#include <openssl\bn.h>
#include <openssl\asn1.h>
#include <string.h>
class Helper
{
public:
	static char* lengthEncode(int length, int* length_length);
	static int lengthDecode(char* decode_me, int* length_length);
	static void AppendEncodedBn(BIGNUM* n, char* append_to, int& written_bytes);
};