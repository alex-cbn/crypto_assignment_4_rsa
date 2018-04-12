#include "Helper.h"
#include <string.h>
#include <stdlib.h>
#include <math.h>

char* Helper::lengthEncode(int length, int* length_length)
{
	char* encoded_length = nullptr;

	//Daca lungimea <= 127 atunci se codifica pe un singur octet
	if (length <= 127)
	{
		*length_length = 1;
		encoded_length = (char*)malloc(1);
		encoded_length[0] = length;
		return encoded_length;
	}

	//Determinare numar de octeti necesari pentru codificarea lungimii
	float bitNr = log((float)(length + 1)) / log(2.0);
	float octNr = bitNr / 8.0;
	int octetNr = (int)octNr;
	if ((octNr - (float)octetNr) > 0)
		octetNr++;

	int lengthOfLengthOctet = octetNr | 128;

	*length_length = 1 + octetNr;
	encoded_length = (char*)malloc(*length_length);
	encoded_length[0] = lengthOfLengthOctet;

	for (int i = 0; i < *length_length; i++)
	{
		encoded_length[i + 1] = length >> (8 * (*length_length - 2 - i)) & 0xff;
	}
	return encoded_length;
}

int Helper::lengthDecode(char * decode_me, int* length_length)
{
	int offset = 0;
	int length = 0;
	int byte = decode_me[offset++];
	byte = byte & 0x000000FF;
	if (byte <= 127)
	{
		*length_length = offset;
		return byte;
	}

	byte = byte & 127;

	for (int i = 0; i < byte; i++)
	{
		length = length << 8;
		length = length | decode_me[offset++];
	}
	*length_length = offset;
	return length;
}

void Helper::AppendEncodedBn(BIGNUM * n, char * append_to, int & written_bytes)
{
	int length_length = 0;
	int item_length = 0;
	char* length_encoding = nullptr;
	ASN1_TYPE* encodin;
	unsigned char* encode_me = (unsigned char*)malloc(2048);
	char* dec = NULL;
	memset(encode_me, 0, 2048);
	strcpy((char*)encode_me, "INT:");
	//preparing for encoding
	dec = BN_bn2dec(n);
	strcat((char*)encode_me + 4, dec);
	//actual encoding
	encodin = ASN1_generate_nconf((char*)encode_me, NULL);
	//testing for the first byte of the structure
	if(encodin->value.integer->data[0]>unsigned char(128))
	{
		//writing type
		append_to[written_bytes++] = '\x2';
		//encoding length of asn1 object
		item_length = encodin->value.integer->length;
		length_encoding = Helper::lengthEncode(item_length + 1, &length_length); // added 1 to take into account the new value of 0x00
		//writing length to buffer and update offset
		memcpy_s(append_to + written_bytes, length_length, length_encoding, length_length);
		written_bytes += length_length;
		//writing the heading 0x00
		append_to[written_bytes++] = '\x0';
		//writing raw data to buffer and update offset
		memcpy_s(append_to + written_bytes, item_length, encodin->value.integer->data, item_length);
		written_bytes += item_length;
	}
	else
	{
		//writing type
		append_to[written_bytes++] = '\x2';
		//encoding length of asn1 object
		item_length = encodin->value.integer->length;
		length_encoding = Helper::lengthEncode(item_length, &length_length);
		//writing length to buffer and update offset
		memcpy_s(append_to + written_bytes, length_length, length_encoding, length_length);
		written_bytes += length_length;
		//writing raw data to buffer and update offset
		memcpy_s(append_to + written_bytes, item_length, encodin->value.integer->data, item_length);
		written_bytes += item_length;
	}
}
