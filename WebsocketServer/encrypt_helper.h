#include <iostream>
#include <iomanip>
#include <string>

#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <cryptopp/modes.h>
#include <cryptopp/base64.h>
#include <cryptopp/rsa.h>
#include <cryptopp/randpool.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <cryptopp/pssr.h>

#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#pragma warning(disable:4996)
#pragma comment (lib,"Crypt32.lib")
#pragma comment (lib,"ws2_32.lib")
static const std::string base64_table =
"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
"abcdefghijklmnopqrstuvwxyz"
"0123456789+/";
static inline bool is_base64_char(unsigned char c) {
	return (isalnum(c) || (c == '+') || (c == '/') || (c == '='));
}
static inline bool is_base64(std::string str) {
	if (str.length() % 4 != 0) {
		return false;
	}
	for (int a = 0; a < str.length(); a++) {
		if (!is_base64_char(str[a]))
			return false;
	}
	return true;
}
std::string base64_encode(std::string const& ori) {
	
		char const* bytes_to_encode = ori.c_str();
		size_t length = ori.length();
		std::string final_base64;
		int i = 0;
		int j = 0;
		unsigned char char_3[3];
		unsigned char char_4[4];

		while (length--) {
			char_3[i++] = *(bytes_to_encode++);
			if (i == 3) {
				char_4[0] = (char_3[0] & 0xfc) >> 2;
				char_4[1] = ((char_3[0] & 0x03) << 4) + ((char_3[1] & 0xf0) >> 4);
				char_4[2] = ((char_3[1] & 0x0f) << 2) + ((char_3[2] & 0xc0) >> 6);
				char_4[3] = char_3[2] & 0x3f;

				for (i = 0; (i < 4); i++)
					final_base64 += base64_table[char_4[i]];
				i = 0;
			}
		}

		if (i)
		{
			for (j = i; j < 3; j++)
				char_3[j] = '\0';

			char_4[0] = (char_3[0] & 0xfc) >> 2;
			char_4[1] = ((char_3[0] & 0x03) << 4) + ((char_3[1] & 0xf0) >> 4);
			char_4[2] = ((char_3[1] & 0x0f) << 2) + ((char_3[2] & 0xc0) >> 6);
			char_4[3] = char_3[2] & 0x3f;

			for (j = 0; (j < i + 1); j++)
				final_base64 += base64_table[char_4[j]];

			while ((i++ < 3))
				final_base64 += '=';

		}

		return final_base64;
	

}
inline unsigned char base64Lookup(unsigned char c) {
	if (c >= 'A' && c <= 'Z') return c - 'A';
	if (c >= 'a' && c <= 'z') return c - 71;
	if (c >= '0' && c <= '9') return c + 4;
	if (c == '+') return 62;
	if (c == '/') return 63;
	return 255;
}
inline std::string Decode(std::string const& base64) {
	size_t length = base64.size();
	int i = 0;
	int j = 0;
	int tmp = 0;
	unsigned char char_array_4[4], char_array_3[3];
	std::string decoded;
	while (length-- && (base64[tmp] != '=') && is_base64_char(base64[tmp])) {
		char_array_4[i++] = base64[tmp]; tmp++;
		if (i == 4) {
			for (i = 0; i < 4; i++)
				char_array_4[i] = base64Lookup(char_array_4[i]);

			char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
			char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
			char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

			for (i = 0; (i < 3); i++)
				decoded += char_array_3[i];
			i = 0;
		}
	}

	if (i) {
		for (j = i; j < 4; j++)
			char_array_4[j] = 0;

		for (j = 0; j < 4; j++)
			char_array_4[j] = base64Lookup(char_array_4[j]);

		char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
		char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
		char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

		for (j = 0; (j < i - 1); j++) decoded += char_array_3[j];
	}
}
std::string base64_aes_cbc_encrypt(const std::string& ori, unsigned char aes_key[], unsigned char aes_iv[]) {

	std::string encrypted;
	CryptoPP::AES::Encryption aesEncryption(aes_key, CryptoPP::AES::DEFAULT_KEYLENGTH);
	CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, aes_iv);
	CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink(encrypted));
	stfEncryptor.Put(reinterpret_cast<const unsigned char*>(ori.c_str()), ori.length());
	stfEncryptor.MessageEnd();

	std::string base64;
	CryptoPP::Base64Encoder encoder(nullptr, false);
	encoder.Attach(new CryptoPP::StringSink(base64));
	encoder.Put(reinterpret_cast<const unsigned char*>(encrypted.c_str()), encrypted.length());
	encoder.MessageEnd();
	
	return base64;
}

std::string base64_aes_cbc_decrypt(const std::string& base64_encrypted, unsigned char aes_key[], unsigned char aes_iv[]) {
	std::string decoded_base64;
	std::string decrypted;
	try {

		CryptoPP::Base64Decoder decoder;
		decoder.Attach(new CryptoPP::StringSink(decoded_base64));
		decoder.Put(reinterpret_cast<const unsigned char*>(base64_encrypted.c_str()), base64_encrypted.length());
		decoder.MessageEnd();

		CryptoPP::AES::Decryption aesDecryption(aes_key, CryptoPP::AES::DEFAULT_KEYLENGTH);
		CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, aes_iv);
		CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink(decrypted));
		stfDecryptor.Put(reinterpret_cast<const unsigned char*>(decoded_base64.c_str()), decoded_base64.size());
		stfDecryptor.MessageEnd();
	}
	catch (std::exception e) {
		throw "Decrypt Error > " + std::string(e.what());
	}
	return decrypted;
}

//calcu MD5
inline std::string MD5(const std::string& src) {
	MD5_CTX ctx;

	std::string md5_string;
	unsigned char md[16] = { 0 };
	char tmp[33] = { 0 };

	MD5_Init(&ctx);
	MD5_Update(&ctx, src.c_str(), src.size());
	MD5_Final(md, &ctx);

	for (int i = 0; i < 16; ++i)
	{
		memset(tmp, 0x00, sizeof(tmp));
		sprintf(tmp, "%02X", md[i]);
		md5_string += tmp;
	}
	return md5_string;
}
std::string md5(const std::string& in) {
	std::string str = MD5(in);
	std::transform(str.begin(), str.end(), str.begin(), tolower);
	return str;
}
std::string sha256(const std::string& str){
	unsigned char hash[SHA256_DIGEST_LENGTH];
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, str.c_str(), str.size());
	SHA256_Final(hash, &sha256);
	std::stringstream ss;
	for (int i = 0; i < SHA256_DIGEST_LENGTH; i++){
		ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
	}
	return ss.str();
}


RSA* createPublicRSA(std::string key) {
	RSA* rsa = NULL;
	BIO* keybio;
	const char* c_string = key.c_str();
	keybio = BIO_new_mem_buf((void*)c_string, -1);
	if (keybio == NULL) {
		return 0;
	}
	rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
	return rsa;
}

bool RSAVerifySignature(RSA* rsa,
	unsigned char* MsgHash,
	size_t MsgHashLen,
	const char* Msg,
	size_t MsgLen,
	bool* Authentic) {
	*Authentic = false;
	EVP_PKEY* pubKey = EVP_PKEY_new();
	EVP_PKEY_assign_RSA(pubKey, rsa);
	EVP_MD_CTX* m_RSAVerifyCtx = EVP_MD_CTX_create();

	if (EVP_DigestVerifyInit(m_RSAVerifyCtx, NULL, EVP_sha256(), NULL, pubKey) <= 0) {
		return false;
	}
	if (EVP_DigestVerifyUpdate(m_RSAVerifyCtx, Msg, MsgLen) <= 0) {
		return false;
	}
	int AuthStatus = EVP_DigestVerifyFinal(m_RSAVerifyCtx, MsgHash, MsgHashLen);
	if (AuthStatus == 1) {
		*Authentic = true;
		
		EVP_MD_CTX_free(m_RSAVerifyCtx);
		return true;
	}
	else if (AuthStatus == 0) {
		*Authentic = false;
		EVP_MD_CTX_free(m_RSAVerifyCtx);
		return true;
	}
	else {
		*Authentic = false;
		EVP_MD_CTX_free(m_RSAVerifyCtx);
		return false;
	}
}

size_t calcDecodeLength(const char* b64input) {
	size_t len = strlen(b64input), padding = 0;

	if (b64input[len - 1] == '=' && b64input[len - 2] == '=') //last two chars are =
		padding = 2;
	else if (b64input[len - 1] == '=') //last char is =
		padding = 1;
	return (len * 3) / 4 - padding;
}


bool verifySignature(std::string publicKey, std::string plainText,std::string& signatureBase64) {
	RSA* publicRSA = createPublicRSA(publicKey);
	if (publicRSA == nullptr) {
		return false;
	}
	std::string encMessage;
	bool authentic;
	CryptoPP::Base64Decoder decoder;
	decoder.Attach(new CryptoPP::StringSink(encMessage));
	decoder.Put(reinterpret_cast<const unsigned char*>(signatureBase64.c_str()), signatureBase64.length());
	decoder.MessageEnd();
	
	bool result = RSAVerifySignature(publicRSA, (unsigned char*)encMessage.c_str(), encMessage.length(), plainText.c_str(), plainText.length(), &authentic);
	return result & authentic;
}