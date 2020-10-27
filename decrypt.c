#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>
 
int padding = RSA_PKCS1_PADDING;
const char b64chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
int b64invs[] = { 	62, -1, -1, -1, 63, 52, 53, 54, 55, 56, 57, 58,
					          59, 60, 61, -1, -1, -1, -1, -1, -1, -1, 0, 1, 2, 3, 4, 5,
					          6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
					          21, 22, 23, 24, 25, -1, -1, -1, -1, -1, -1, 26, 27, 28,
					          29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42,
					          43, 44, 45, 46, 47, 48, 49, 50, 51 };


int b64_isvalidchar(char c) {
	if (c >= '0' && c <= '9')
		return 1;
	if (c >= 'A' && c <= 'Z')
		return 1;
	if (c >= 'a' && c <= 'z')
		return 1;
	if (c == '+' || c == '/' || c == '=')
		return 1;
	return 0;
}

size_t b64_encoded_size(size_t inlen) {
	size_t ret;

	ret = inlen;
	if (inlen % 3 != 0)
		ret += 3 - (inlen % 3);
	ret /= 3;
	ret *= 4;

	return ret;
}

size_t b64_decoded_size(const char *in) {
	size_t len;
	size_t ret;
	size_t i;

	if (in == NULL)
		return 0;

	len = strlen(in);
	ret = len / 4 * 3;

	for (i=len; i-->0; ) {
		if (in[i] == '=') {
			ret--;
		} else {
			break;
		}
	}

	return ret;
}

char *b64_encode(const unsigned char *in, size_t len) {
	char   *out;
	size_t  elen;
	size_t  i;
	size_t  j;
	size_t  v;

	if (in == NULL || len == 0)
		return NULL;

	elen = b64_encoded_size(len);
	out  = malloc(elen+1);
	out[elen] = '\0';

	for (i=0, j=0; i<len; i+=3, j+=4) {
		v = in[i];
		v = i+1 < len ? v << 8 | in[i+1] : v << 8;
		v = i+2 < len ? v << 8 | in[i+2] : v << 8;

		out[j]   = b64chars[(v >> 18) & 0x3F];
		out[j+1] = b64chars[(v >> 12) & 0x3F];
		if (i+1 < len) {
			out[j+2] = b64chars[(v >> 6) & 0x3F];
		} else {
			out[j+2] = '=';
		}
		if (i+2 < len) {
			out[j+3] = b64chars[v & 0x3F];
		} else {
			out[j+3] = '=';
		}
	}

	return out;
}

int b64_decode(const char *in, unsigned char *out, size_t outlen) {
	size_t len;
	size_t i;
	size_t j;
	int    v;

	if (in == NULL || out == NULL)
		return 0;

	len = strlen(in);
	if (outlen < b64_decoded_size(in) || len % 4 != 0)
		return 0;

	for (i=0; i<len; i++) {
		if (!b64_isvalidchar(in[i])) {
			return 0;
		}
	}

	for (i=0, j=0; i<len; i+=4, j+=3) {
		v = b64invs[in[i]-43];
		v = (v << 6) | b64invs[in[i+1]-43];
		v = in[i+2]=='=' ? v << 6 : (v << 6) | b64invs[in[i+2]-43];
		v = in[i+3]=='=' ? v << 6 : (v << 6) | b64invs[in[i+3]-43];

		out[j] = (v >> 16) & 0xFF;
		if (in[i+2] != '=')
			out[j+1] = (v >> 8) & 0xFF;
		if (in[i+3] != '=')
			out[j+2] = v & 0xFF;
	}

	return 1;
}
 
RSA * createRSA(unsigned char * key,int public) {
    RSA *rsa= NULL;
    BIO *keybio ;
    keybio = BIO_new_mem_buf(key, -1);
    if (keybio==NULL)
    {
        printf( "Failed to create key BIO");
        return 0;
    }
    if(public)
    {
        rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa,NULL, NULL);
    }
    else
    {
        rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa,NULL, NULL);
    }
    if(rsa == NULL)
    {
        printf( "Failed to create RSA");
    }
 
    return rsa;
}
 
int public_encrypt(unsigned char * data,int data_len,unsigned char * key, unsigned char *encrypted) {
    RSA * rsa = createRSA(key,1);
    int result = RSA_public_encrypt(data_len,data,encrypted,rsa,padding);
    return result;
}

int private_decrypt(unsigned char * enc_data,int data_len,unsigned char * key, unsigned char *decrypted) {
    RSA * rsa = createRSA(key,0);
    int  result = RSA_private_decrypt(data_len,enc_data,decrypted,rsa,padding);
    return result;
}
 
int private_encrypt(unsigned char * data,int data_len,unsigned char * key, unsigned char *encrypted) {
    RSA * rsa = createRSA(key,0);
    int result = RSA_private_encrypt(data_len,data,encrypted,rsa,padding);
    return result;
}

int public_decrypt(unsigned char * enc_data,int data_len,unsigned char * key, unsigned char *decrypted) {
    RSA * rsa = createRSA(key,1);
    int  result = RSA_public_decrypt(data_len,enc_data,decrypted,rsa,padding);
    return result;
}
 
void printLastError(char *msg) {
    char * err = malloc(130);;
    ERR_load_crypto_strings();
    ERR_error_string(ERR_get_error(), err);
    printf("%s ERROR: %s\n",msg, err);
    free(err);
}
 
int main(int argc, char *argv[]){
 
	char privateKey[]="-----BEGIN RSA PRIVATE KEY-----\n"\
"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\n"\
"-----END RSA PRIVATE KEY-----\n";
    
	unsigned char decrypted[8192]={};
	FILE *fileCrypt;
	char* asciiBase64Enc;
	long asciiBase64EncLen;
	
	for (int i = 1; i < argc; ++i) {
		char* fileName = argv[i];
		printf("Filename = %s\n",fileName);
        //cout << argv[i] << "\n"; 
	
		fileCrypt = fopen(fileName, "r");
		if (fileCrypt) {
			fseek (fileCrypt, 0, SEEK_END);
			asciiBase64EncLen = ftell (fileCrypt);
			fseek (fileCrypt, 0, SEEK_SET);
			asciiBase64Enc = malloc (asciiBase64EncLen);
			if (asciiBase64Enc) {
				fread (asciiBase64Enc, 1, asciiBase64EncLen, fileCrypt);
			}
			fclose (fileCrypt);
		}
		//printf("base64=%s\n", asciiBase64Enc);
		//printf("base64 len=%i\n", asciiBase64EncLen);
		
		char *binEnc;
		size_t binEncLen = b64_decoded_size(asciiBase64Enc)+1;
		binEnc = malloc(binEncLen);		
		b64_decode(asciiBase64Enc, (unsigned char *)binEnc, binEncLen);		
		//printf("bin=%s\n", binEnc);
		//printf("bin len=%i\n", strlen(binEnc));
		
		
		int encrypted_length = 512;
		int decrypted_length = private_decrypt(binEnc,512,privateKey, decrypted);
		if(decrypted_length == -1)
		{
			printLastError("Private Decrypt failed ");
			exit(0);
		}

		char newFileName[64] = "\0";
		sprintf(newFileName,"%s_DECRYPTED", fileName);
		printf("NewFileName = %s\n",newFileName);
		fileCrypt = fopen(newFileName, "w");
		fputs(decrypted, fileCrypt);
		fclose(fileCrypt);

		printf("Decrypted Text = \n%s\n\n\n",decrypted);
		//printf("Decrypted Length =%d\n",decrypted_length);

		
	}
	
	return 0;
}
