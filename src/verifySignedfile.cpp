// This file is part of Notepad++ project
// Copyright (C)2021 Don HO <don.h@free.fr>

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// at your option any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.


// VerifyDLL.cpp : Verification of an Authenticode signed DLL
//

#include <memory>
#include <windows.h>
#include <wintrust.h>
#include <softpub.h>
#include <wincrypt.h>
#include <sensapi.h>
#include <iomanip>
#include <sstream>
#include "verifySignedfile.h"
#include "Common.h"

using namespace std;


// Debug use
bool doLogCertifError = false;

bool SecurityGuard::verifySignedBinary(const std::wstring& filepath)
{
	wstring display_name;
	wstring key_id_hex;
	wstring subject;
	wstring authority_key_id_hex;

	if (doLogCertifError)
	{
		writeLog(L"c:\\tmp\\certifError.log", L"verifySignedBinary: ", filepath.c_str());
	}

	//
	// Signature verification
	//

	// Initialize the WINTRUST_FILE_INFO structure.
	LPCWSTR pwszfilepath = filepath.c_str();
	WINTRUST_FILE_INFO file_data = {};
	file_data.cbStruct = sizeof(WINTRUST_FILE_INFO);
	file_data.pcwszFilePath = pwszfilepath;

	// Initialise WinTrust data
	WINTRUST_DATA winTEXTrust_data = {};
	winTEXTrust_data.cbStruct = sizeof(winTEXTrust_data);
	winTEXTrust_data.dwUIChoice = WTD_UI_NONE;	         // do not display optional dialog boxes
	winTEXTrust_data.dwUnionChoice = WTD_CHOICE_FILE;        // we are not checking catalog signed files
	winTEXTrust_data.dwStateAction = WTD_STATEACTION_VERIFY; // only checking
	winTEXTrust_data.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;  // verify the whole certificate chain
	winTEXTrust_data.pFile = &file_data;

	if (!_doCheckRevocation)
	{
		winTEXTrust_data.fdwRevocationChecks = WTD_REVOKE_NONE;

		if (doLogCertifError)
			writeLog(L"c:\\tmp\\certifError.log", L"verifySignedBinary: ", L"certificate revocation checking is disabled");
	}
	else
	{
		// if offline, revocation is not checked
		// depending on windows version, this may introduce a latency on offline systems
		DWORD netstatus;
		QOCINFO oci;
		oci.dwSize = sizeof(oci);
		CONST wchar_t* msftTEXTest_site = L"http://www.msftncsi.com/ncsi.txt";

		bool online = IsNetworkAlive(&netstatus) != 0 && GetLastError() == 0 && IsDestinationReachable(msftTEXTest_site, &oci) == 0;

		if (!online)
		{
			winTEXTrust_data.fdwRevocationChecks = WTD_REVOKE_NONE;

			if (doLogCertifError)
				writeLog(L"c:\\tmp\\certifError.log", L"verifySignedBinary: ", L"system is offline - certificate revocation won't be checked");
		}
	}

	if (_doCheckChainOfTrust)
	{
		// Verify signature and cert-chain validity
		GUID policy = WINTRUST_ACTION_GENERIC_VERIFY_V2;
		LONG vtrust = ::WinVerifyTrust(NULL, &policy, &winTEXTrust_data);

		// Post check cleanup
		winTEXTrust_data.dwStateAction = WTD_STATEACTION_CLOSE;
		LONG t2 = ::WinVerifyTrust(NULL, &policy, &winTEXTrust_data);

		if (vtrust)
		{
			if (doLogCertifError)
				writeLog(L"c:\\tmp\\certifError.log", L"verifySignedBinary: ", L"trust verification failed");

			return false;
		}

		if (t2)
		{
			if (doLogCertifError)
				writeLog(L"c:\\tmp\\certifError.log", L"verifySignedBinary: ", L"error encountered while cleaning up after WinVerifyTrust");

			return false;
		}
	}

	//
	// Certificate verification
	//
	HCERTSTORE        hStore = nullptr;
	HCRYPTMSG         hMsg = nullptr;
	PCMSG_SIGNER_INFO pSignerInfo = nullptr;
	DWORD dwEncoding, dwContentType, dwFormatType;
	DWORD dwSignerInfo = 0L;
	bool status = true;

	try {
		BOOL result = ::CryptQueryObject(CERT_QUERY_OBJECT_FILE, filepath.c_str(),
			CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED, CERT_QUERY_FORMAT_FLAG_BINARY, 0,
			&dwEncoding, &dwContentType, &dwFormatType,
			&hStore, &hMsg, NULL);

		if (!result)
		{
			throw string("Checking certificate of ") + ws2s(filepath) + " : " + ws2s(GetLastErrorAsString(GetLastError()));
		}

		// Get signer information size.
		result = ::CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, NULL, &dwSignerInfo);
		if (!result)
		{
			throw string("CryptMsgGetParam first call: ") + ws2s(GetLastErrorAsString(GetLastError()));
		}

		// Get Signer Information.
		pSignerInfo = (PCMSG_SIGNER_INFO)LocalAlloc(LPTR, dwSignerInfo);
		if (NULL == pSignerInfo)
		{
			throw string("Failed to allocate memory for signature processing");
		}

		result = ::CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, (PVOID)pSignerInfo, &dwSignerInfo);
		if (!result)
		{
			throw string("CryptMsgGetParam: ") + ws2s(GetLastErrorAsString(GetLastError()));
		}

		// Get the signer certificate from temporary certificate store.
		CERT_INFO cert_info = {};
		cert_info.Issuer = pSignerInfo->Issuer;
		cert_info.SerialNumber = pSignerInfo->SerialNumber;
		PCCERT_CONTEXT context = ::CertFindCertificateInStore(hStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_FIND_SUBJECT_CERT, (PVOID)&cert_info, NULL);
		if (!context)
		{
			throw string("Certificate context: ") + ws2s(GetLastErrorAsString(GetLastError()));
		}

		// Getting the full subject
		auto subject_sze = ::CertNameToStr(X509_ASN_ENCODING, &context->pCertInfo->Subject, CERT_X500_NAME_STR, NULL, 0);
		if (subject_sze <= 1)
		{
			throw string("Getting x509 field size problem.");
		}

		std::unique_ptr<wchar_t[]> subject_buffer(new wchar_t[subject_sze]);
		if (::CertNameToStr(X509_ASN_ENCODING, &context->pCertInfo->Subject, CERT_X500_NAME_STR, subject_buffer.get(), subject_sze) <= 1)
		{
			throw string("Failed to get x509 field infos from certificate.");
		}
		subject = subject_buffer.get();

		// Getting key_id
		DWORD key_id_sze = 0;
		if (!::CertGetCertificateContextProperty(context, CERT_KEY_IDENTIFIER_PROP_ID, NULL, &key_id_sze))
		{
			throw string("x509 property not found") + ws2s(GetLastErrorAsString(GetLastError()));
		}

		std::unique_ptr<BYTE[]> key_id_buff(new BYTE[key_id_sze]);
		if (!::CertGetCertificateContextProperty(context, CERT_KEY_IDENTIFIER_PROP_ID, key_id_buff.get(), &key_id_sze))
		{
			throw string("Getting certificate property problem.") + ws2s(GetLastErrorAsString(GetLastError()));
		}

		wstringstream ss;
		for (unsigned i = 0; i < key_id_sze; i++)
		{
			ss << std::uppercase << std::setfill(wchar_t('0')) << std::setw(2) << std::hex
				<< key_id_buff[i];
		}
		key_id_hex = ss.str();

		if (doLogCertifError)
			writeLog(L"c:\\tmp\\certifError.log", L"verifySignedBinary: ", key_id_hex.c_str());

		// Getting the display name
		auto sze = ::CertGetNameString(context, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, NULL, 0);
		if (sze <= 1)
		{
			throw string("Getting data size problem.") + ws2s(GetLastErrorAsString(GetLastError()));
		}

		// Get display name.
		std::unique_ptr<wchar_t[]> display_name_buffer(new wchar_t[sze]);
		if (::CertGetNameString(context, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, display_name_buffer.get(), sze) <= 1)
		{
			throw string("Cannot get certificate info." + ws2s(GetLastErrorAsString(GetLastError())));
		}
		display_name = display_name_buffer.get();


		// --- Retrieve Authority Key Identifier (AKI) ---

		PCERT_EXTENSION pExtension = ::CertFindExtension(szOID_AUTHORITY_KEY_IDENTIFIER2, // OID for Authority Key Identifier (2.5.29.35)
			context->pCertInfo->cExtension,	context->pCertInfo->rgExtension);

		if (!pExtension)
			pExtension = ::CertFindExtension(szOID_AUTHORITY_KEY_IDENTIFIER, // OID for Authority Key Identifier (2.5.29.1)
				context->pCertInfo->cExtension, context->pCertInfo->rgExtension);

		if (pExtension)
		{
			DWORD dwAuthKeyIdSize = 0;
			PCERT_AUTHORITY_KEY_ID_INFO pAuthKeyIdInfo = nullptr;

			// Decode the extension
			if (::CryptDecodeObjectEx(
				X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
				szOID_AUTHORITY_KEY_IDENTIFIER2,
				pExtension->Value.pbData,
				pExtension->Value.cbData,
				CRYPT_DECODE_ALLOC_FLAG,
				NULL,
				&pAuthKeyIdInfo,
				&dwAuthKeyIdSize))
			{
				if (pAuthKeyIdInfo->KeyId.cbData > 0)
				{
					wstringstream auth_ss;
					for (unsigned i = 0; i < pAuthKeyIdInfo->KeyId.cbData; i++)
					{
						auth_ss << std::uppercase << std::setfill(wchar_t('0'))
							<< std::setw(2) << std::hex
							<< pAuthKeyIdInfo->KeyId.pbData[i];
					}
					authority_key_id_hex = auth_ss.str();
				}

				LocalFree(pAuthKeyIdInfo);
			}
		}
		else
		{
			// Authority Key Identifier extension not found
			if (doLogCertifError)
				writeLog(L"c:\\tmp\\certifError.log", L"Authority Key ID: ", L"Extension not found");
		}
		// --- End AKI Retrieval ---

	}
	catch (const string& s) {
		if (doLogCertifError)
		{
			writeLog(L"c:\\tmp\\certifError.log", L" verifySignedBinary: error while getting certificate information: ", s2ws(s).c_str());
		}
		status = false;
	}
	catch (...) {
		// Unknown error
		if (doLogCertifError)
			writeLog(L"c:\\tmp\\certifError.log", L"verifySignedBinary: ", L"error while getting certificate information");

		status = false;
	}

	//
	// fields verifications - if status is true, and string to compare (from the parameter) is not empty, then do compare
	//
	if (status &&  (!_signer_display_name.empty() && _signer_display_name != display_name))
	{
		status = false;

		if (doLogCertifError)
			writeLog(L"c:\\tmp\\certifError.log", L"verifySignedBinary: ", L"Invalid certificate display name");
	}

	if (status && (!_signer_subject.empty() && _signer_subject != subject))
	{
		status = false;

		if (doLogCertifError)
			writeLog(L"c:\\tmp\\certifError.log", L"verifySignedBinary: ", L"Invalid certificate subject");
	}

	if (status && (!_signer_key_id.empty() && stringToUpper(_signer_key_id) != key_id_hex))
	{
		status = false;

		if (doLogCertifError)
			writeLog(L"c:\\tmp\\certifError.log", L"verifySignedBinary: ", L"Invalid certificate key id");
	}

	if (status && (!_authority_key_id.empty() && stringToUpper(_authority_key_id) != authority_key_id_hex))
	{
		status = false;

		if (doLogCertifError)
			writeLog(L"c:\\tmp\\certifError.log", L"verifySignedBinary: ", L"Invalid authority key id");
	}

	// Clean up.

	if (hStore != NULL)       CertCloseStore(hStore, 0);
	if (hMsg != NULL)       CryptMsgClose(hMsg);
	if (pSignerInfo != NULL)  LocalFree(pSignerInfo);

	return status;
}
