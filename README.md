# KeyloggerForWindows
Keylogger for Windows

Generate keys:
```markdown
openssl.exe genrsa -des3 -out private.pem 4096
openssl.exe rsa -in private.pem -outform PEM -pubout -out public.pem
```
And compile:
```markdown
gcc -static klg.c -o "klg.exe" -I C:\cygwin64\user\include\openssl\ -L C:\cygwin64\lib\ -lcrypto.dll
gcc -static decrypt.c -o decrypt.exe -I C:\cygwin64\user\include\openssl\ -L C:\cygwin64\lib\ -lcrypto.dll
```
