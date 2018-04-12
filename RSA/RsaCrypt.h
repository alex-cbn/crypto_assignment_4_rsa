#pragma once
class RsaKey;

class RsaCrypt
{
public:
	static unsigned char* Encrypt(unsigned char* input, unsigned int length, RsaKey *key);
	static unsigned char* Decrypt(unsigned char* input, unsigned int length, RsaKey *key);
};

