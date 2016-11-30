/*
MIT License

Copyright(c) Jon Erickson

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files(the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions :

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/


#ifndef __AESCRYPT_INL__
#define __AESCRYPT_INL__

#pragma once

#ifndef __AESCRYPT_H__
#error aescrypt.inl requires aescrypt.h to be included first
#endif

namespace ATL
{

	inline HRESULT CCryptImportAES128Key::Initialize(
		CCryptProv &Prov,
		BYTE * key,
		DWORD KeyLen,
		CCryptKey &PubKey,
		DWORD dwFlags) throw()
	{
		ATLASSUME(m_hKey == NULL);
		ATLASSUME(KeyLen == 16);

		AES128 aesKey;
		aesKey.pubKey.bType = PLAINTEXTKEYBLOB;
		aesKey.pubKey.bVersion = CUR_BLOB_VERSION;
		aesKey.pubKey.reserved = 0;
		aesKey.pubKey.aiKeyAlg = CALG_AES_128;
		
		aesKey.keyLen = KeyLen;
		memcpy_s(aesKey.key, sizeof(aesKey.key), key, KeyLen);


		if (!CryptImportKey(Prov.GetHandle(), (BYTE*)&aesKey, sizeof(aesKey), PubKey.GetHandle(), dwFlags, &m_hKey))
		{
			return AtlHresultFromLastError();
		}
		else return S_OK;
	}

	inline HRESULT CCryptImportAES192Key::Initialize(
		CCryptProv &Prov,
		BYTE * key,
		DWORD KeyLen,
		CCryptKey &PubKey,
		DWORD dwFlags) throw()
	{
		ATLASSUME(m_hKey == NULL);
		ATLASSUME(KeyLen == 24);

		AES192 aesKey;
		aesKey.pubKey.bType = PLAINTEXTKEYBLOB;
		aesKey.pubKey.bVersion = CUR_BLOB_VERSION;
		aesKey.pubKey.reserved = 0;
		aesKey.pubKey.aiKeyAlg = CALG_AES_192;

		aesKey.keyLen = KeyLen;
		memcpy_s(aesKey.key, sizeof(aesKey.key), key, KeyLen);


		if (!CryptImportKey(Prov.GetHandle(), (BYTE*)&aesKey, sizeof(aesKey), PubKey.GetHandle(), dwFlags, &m_hKey))
		{
			return AtlHresultFromLastError();
		}
		else return S_OK;
	}


	inline HRESULT CCryptImportAES256Key::Initialize(
		CCryptProv &Prov,
		BYTE * key,
		DWORD KeyLen,
		CCryptKey &PubKey,
		DWORD dwFlags) throw()
	{
		ATLASSUME(m_hKey == NULL);
		ATLASSUME(KeyLen == 32);

		AES256 aesKey;
		aesKey.pubKey.bType = PLAINTEXTKEYBLOB;
		aesKey.pubKey.bVersion = CUR_BLOB_VERSION;
		aesKey.pubKey.reserved = 0;
		aesKey.pubKey.aiKeyAlg = CALG_AES_256;

		aesKey.keyLen = KeyLen;
		memcpy_s(aesKey.key, sizeof(aesKey.key), key, KeyLen);

		if (!CryptImportKey(Prov.GetHandle(), (BYTE*)&aesKey, sizeof(aesKey), PubKey.GetHandle(), dwFlags, &m_hKey))
		{
			return AtlHresultFromLastError();
		}
		else return S_OK;
	}


}; // namespace ATL

#endif //__AESCRYPT_INL__
