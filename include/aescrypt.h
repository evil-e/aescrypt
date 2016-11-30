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

#ifndef __AESCRYPT_H__
#define __AESCRYPT_H__

#pragma once
#include <atlcrypt.h>

#pragma pack(push,_ATL_PACKING)

namespace ATL
{

typedef struct _AES128
{
	PUBLICKEYSTRUC pubKey;
	SIZE_T keyLen;
	BYTE key[16];
} AES128, *PAES128;


typedef struct _AES192
{
	PUBLICKEYSTRUC pubKey;
	SIZE_T keyLen;
	BYTE key[24];
} AES192, *PAES192;


typedef struct _AES256
{
	PUBLICKEYSTRUC pubKey;
	SIZE_T keyLen;
	BYTE key[32];
} AES256, *PAES256;


class CCryptImportAES128Key : public CCryptKey
{
public:
	HRESULT Initialize(
		CCryptProv &Prov,
		BYTE * pbData,
		DWORD dwDataLen,
		CCryptKey &PubKey,
		DWORD dwFlags) throw();
}; // class CCryptImportAES128Key


class CCryptImportAES192Key : public CCryptKey
{
public:
	HRESULT Initialize(
		CCryptProv &Prov,
		BYTE * pbData,
		DWORD dwDataLen,
		CCryptKey &PubKey,
		DWORD dwFlags) throw();
}; // class CCryptImportAES192Key


class CCryptImportAES256Key : public CCryptKey
{
public:
	HRESULT Initialize(
		CCryptProv &Prov,
		BYTE * pbData,
		DWORD dwDataLen,
		CCryptKey &PubKey,
		DWORD dwFlags) throw();
}; // class CCryptImportAES256Key



}; // namespace ATL

#include <aescrypt.inl>
#pragma pack(pop)
#endif  // __AESCRYPT_H__
