# aescrypt

aescrypt contains 3 classes which extend the CCryptKey object of the ATL server project.  This will make using AES encryption in Windows C++ source code projects very easy.

~~~~
// Example usage
CCryptImportAES256Key aesKey;
HRESULT hr = aesKey.Initialize(prov, (BYTE*)key, keyLen, CCryptKey::EmptyKey, 0);

hr = aesKey.EncryptString("input string", outputbuf, &outbuflen);
~~~~

This repository contains atlcrypt.h and atlcrypt.inl from the ATL Server project.  The full ATL Server source code can be found at: https://atlserver.codeplex.com/
