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

#include <windows.h>
#include <msxml6.h>
#include <memory>
#include <wintrust.h>
#include <softpub.h>
#include <wincrypt.h>
#include <sensapi.h>
#include <iomanip>
#include <sstream>
#include <shlwapi.h>
#include <shlobj_core.h>
#include <comutil.h>
#include "verifySignedfile.h"
#include <ncrypt.h>
#include <bcrypt.h>
#include <vector>
#include <string>

#pragma comment(lib, "msxml6.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "ncrypt.lib")
#pragma comment(lib, "bcrypt.lib")

#import <msxml6.dll> exclude("ISequentialStream", "_FILETIME", "IStream", "IErrorInfo") rename_namespace("MSXML6")

using namespace std;

// Debug use
bool doLogCertifError = false;

//
// XML Signature (XMLDsig) Verification functions BEGIN
//

// Helper to decode Base64
std::vector<BYTE> base64Decode(const std::wstring& base64String)
{
    std::wstring cleaned;
    for (wchar_t c : base64String)
    {
        if (!iswspace(c))
            cleaned += c;
    }

    if (cleaned.empty())
        return std::vector<BYTE>();

    DWORD dwSize = 0;
    if (!CryptStringToBinaryW(cleaned.c_str(), (DWORD)cleaned.length(),
        CRYPT_STRING_BASE64, NULL, &dwSize, NULL, NULL))
    {
        return std::vector<BYTE>();
    }

    std::vector<BYTE> result(dwSize);
    if (!CryptStringToBinaryW(cleaned.c_str(), (DWORD)cleaned.length(), CRYPT_STRING_BASE64, result.data(), &dwSize, NULL, NULL))
    {
        return std::vector<BYTE>();
    }

    return result;
}

// Get node text content
std::wstring getNodeText(MSXML6::IXMLDOMNodePtr node)
{
    if (node == nullptr)
        return L"";

    _bstr_t text = node->Gettext();
    return std::wstring((wchar_t*)text);
}

// Compute SHA-256 hash using BCrypt
std::vector<BYTE> computeSHA256(const std::vector<BYTE>& data)
{
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    DWORD hashSize = 32;
    std::vector<BYTE> hash(hashSize);

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0) != 0)
        return std::vector<BYTE>();

    if (BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0) != 0)
    {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return std::vector<BYTE>();
    }

    BCryptHashData(hHash, (PUCHAR)data.data(), (ULONG)data.size(), 0);
    BCryptFinishHash(hHash, hash.data(), hashSize, 0);

    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    return hash;
}

// Verify certificate chain and validity
bool SecurityGuard::verifyXmlCertificate(PCCERT_CONTEXT pCertContext)
{
    // Check certificate validity period
    FILETIME currentTime;
    GetSystemTimeAsFileTime(&currentTime);

    if (CompareFileTime(&currentTime, &pCertContext->pCertInfo->NotBefore) < 0)
    {
        writeSecurityError(L"XML Signature - Certificate Error: ", L"Certificate is not yet valid");
        return false;
    }

    if (CompareFileTime(&currentTime, &pCertContext->pCertInfo->NotAfter) > 0)
    {
        writeSecurityError(L"XML Signature - Certificate Error: ", L"Certificate has expired");
        return false;
    }

    // Verify certificate chain
    CERT_CHAIN_PARA chainPara = { 0 };
    chainPara.cbSize = sizeof(CERT_CHAIN_PARA);

    PCCERT_CHAIN_CONTEXT pChainContext = NULL;

    if (!CertGetCertificateChain(
        NULL,
        pCertContext,
        NULL,
        NULL,
        &chainPara,
        CERT_CHAIN_REVOCATION_CHECK_CHAIN,
        NULL,
        &pChainContext))
    {
        DWORD dwErr = GetLastError();
        std::wstringstream ss;
        ss << L"Failed to get certificate chain, error: 0x" << std::hex << dwErr;
        writeSecurityError(L"XML Signature - Certificate Chain Error: ", ss.str());
        return false;
    }

    bool chainValid = false;

    // Check chain status
    if (pChainContext->TrustStatus.dwErrorStatus == CERT_TRUST_NO_ERROR)
    {
        chainValid = true;
    }
    else
    {
        std::wstringstream ss;
        ss << L"Certificate chain validation failed. Error status: 0x" << std::hex << pChainContext->TrustStatus.dwErrorStatus;

        if (pChainContext->TrustStatus.dwErrorStatus & CERT_TRUST_IS_NOT_TIME_VALID)
            ss << L" (NOT_TIME_VALID)";
        if (pChainContext->TrustStatus.dwErrorStatus & CERT_TRUST_IS_REVOKED)
            ss << L" (REVOKED)";
        if (pChainContext->TrustStatus.dwErrorStatus & CERT_TRUST_IS_NOT_SIGNATURE_VALID)
            ss << L" (SIGNATURE_INVALID)";
        if (pChainContext->TrustStatus.dwErrorStatus & CERT_TRUST_IS_UNTRUSTED_ROOT)
            ss << L" (UNTRUSTED_ROOT)";
        if (pChainContext->TrustStatus.dwErrorStatus & CERT_TRUST_IS_PARTIAL_CHAIN)
            ss << L" (PARTIAL_CHAIN)";

        writeSecurityError(L"XML Signature - Certificate Chain Error: ", ss.str());
    }

    CertFreeCertificateChain(pChainContext);

    return chainValid;
}

std::wstring rawDataToHexString(PCRYPT_DATA_BLOB pDataBlob)
{
    std::wstringstream ss;

    for (DWORD i = 0; i < pDataBlob->cbData; i++)
    {
        ss << std::hex << std::setw(2) << std::setfill(L'0') << (int)pDataBlob->pbData[i];
    }

    return ss.str();
}

// Verify that the certificate matches expected identity
// You can verify by thumbprint (SHA1 hash of entire cert) or Key ID (SHA1 hash of public key)
bool SecurityGuard::verifyXmlTrustedCertificate(PCCERT_CONTEXT pCertContext, const std::wstring& expectedThumbprint/* = L""*/)
{
    // Method 1: Verify by SHA1 thumbprint (most secure - identifies exact certificate)
    if (!expectedThumbprint.empty())
    {
        // Get certificate thumbprint
        BYTE thumbprint[20] = { 0 };
        DWORD thumbprintSize = sizeof(thumbprint);

        if (!CertGetCertificateContextProperty(pCertContext, CERT_SHA1_HASH_PROP_ID, thumbprint, &thumbprintSize))
        {
            writeSecurityError(L"XML Signature - Certificate Error: ", L"Failed to get certificate thumbprint");
            return false;
        }

        // Convert expected thumbprint from hex string to bytes
        std::wstring cleanThumbprint;
        for (wchar_t c : expectedThumbprint)
        {
            if (iswxdigit(c))
                cleanThumbprint += c;
        }

        if (cleanThumbprint.length() != 40) // SHA1 = 20 bytes = 40 hex chars
        {
            writeSecurityError(L"XML Signature - Configuration Error: ", L"Invalid thumbprint format");
            return false;
        }

        std::vector<BYTE> expectedThumbprintBytes;
        for (size_t i = 0; i < cleanThumbprint.length(); i += 2)
        {
            std::wstring byteStr = cleanThumbprint.substr(i, 2);
            BYTE byte = (BYTE)wcstol(byteStr.c_str(), nullptr, 16);
            expectedThumbprintBytes.push_back(byte);
        }

        // Compare thumbprints
        if (memcmp(thumbprint, expectedThumbprintBytes.data(), 20) != 0)
        {
            // Get certificate subject for error message
            DWORD dwSize = CertGetNameStringW(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE,0, NULL, NULL, 0);
            std::wstring subjectName(dwSize - 1, 0);
            CertGetNameStringW(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, &subjectName[0], dwSize);

            std::wstringstream ss;
            ss << L"Document signed by: " << subjectName;
            writeSecurityError(L"XML Signature - Certificate thumbprint mismatch Error: ", ss.str());
            return false;
        }

        return true; // Thumbprint matches
    }

    // Method 2: Verify by Subject Key Identifier (more flexible - identifies the key)
    if (!_signer_key_id_xml.empty())
    {
        // Get Subject Key Identifier extension
        PCERT_EXTENSION pExt = CertFindExtension(szOID_SUBJECT_KEY_IDENTIFIER, pCertContext->pCertInfo->cExtension, pCertContext->pCertInfo->rgExtension);

        if (pExt == nullptr)
        {
            writeSecurityError(L"XML Signature - Certificate Error: ", L"Certificate has no Subject Key Identifier");
            return false;
        }

        // Decode the extension
        DWORD cbKeyID = 0;
        PCRYPT_DATA_BLOB pKeyIDBlob = nullptr;

        if (!CryptDecodeObjectEx(X509_ASN_ENCODING, szOID_SUBJECT_KEY_IDENTIFIER, pExt->Value.pbData, pExt->Value.cbData, CRYPT_DECODE_ALLOC_FLAG, nullptr, &pKeyIDBlob, &cbKeyID))
        {
            writeSecurityError(L"XML Signature - Certificate Error: ", L"Failed to decode Subject Key Identifier");
            return false;
        }

        // Convert expected Key ID from hex string to bytes
        std::wstring cleanKeyID;
        for (wchar_t c : _signer_key_id_xml)
        {
            if (iswxdigit(c))
                cleanKeyID += c;
        }

        if (cleanKeyID.length() != 40) // SHA1 = 20 bytes = 40 hex chars
        {
            LocalFree(pKeyIDBlob);
            writeSecurityError(L"XML Signature - Configuration Error: ", L"Invalid Key ID format");
            return false;
        }

        std::vector<BYTE> expectedKeyIDBytes;
        for (size_t i = 0; i < cleanKeyID.length(); i += 2)
        {
            std::wstring byteStr = cleanKeyID.substr(i, 2);
            BYTE byte = (BYTE)wcstol(byteStr.c_str(), nullptr, 16);
            expectedKeyIDBytes.push_back(byte);
        }

        // Compare Key IDs
        bool match = (pKeyIDBlob->cbData == expectedKeyIDBytes.size()) && (memcmp(pKeyIDBlob->pbData, expectedKeyIDBytes.data(), pKeyIDBlob->cbData) == 0);

        if (!match)
        {
            DWORD dwSize = CertGetNameStringW(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, NULL, 0);
            std::wstring subjectName(dwSize - 1, 0);
            CertGetNameStringW(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, &subjectName[0], dwSize);

            wstring wrongKeyId = rawDataToHexString(pKeyIDBlob);

            std::wstringstream ss;
            ss << L"expected Key ID " << _signer_key_id_xml << L" vs " << L"wrong Key ID " << wrongKeyId << ", document signed by : " << subjectName;
            writeSecurityError(L"XML Signature - Certificate Key ID mismatch Error: ", ss.str());
            
            LocalFree(pKeyIDBlob);
            return false;
        }
        LocalFree(pKeyIDBlob);
        return true; // Key ID matches
    }

    return true; // No verification requested
}

bool SecurityGuard::verifyXmlSignature(const std::string& xmlData, const std::wstring& trustedThumbprint)
{
    HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    MSXML6::IXMLDOMDocument3Ptr pXMLDoc;

    try
    {
        // 1. Load XML document
        hr = pXMLDoc.CreateInstance(__uuidof(MSXML6::DOMDocument60));
        if (FAILED(hr))
        {
            writeSecurityError(L"XML Signature - XML Error: ", L"Failed to create XML document");
            return false;
        }

        pXMLDoc->put_preserveWhiteSpace(VARIANT_TRUE);
        pXMLDoc->async = VARIANT_FALSE;
        pXMLDoc->setProperty(_bstr_t("SelectionNamespaces"),
            _bstr_t("xmlns:ds='http://www.w3.org/2000/09/xmldsig#'"));

        if (pXMLDoc->loadXML(_bstr_t(xmlData.c_str())) == VARIANT_FALSE)
        {
            writeSecurityError(L"XML Signature - XML Error: ", L"Failed to load XML");
            return false;
        }

        // 2. Find Signature element
        MSXML6::IXMLDOMNodePtr pSigNode = pXMLDoc->selectSingleNode(L"//ds:Signature");
        if (pSigNode == nullptr)
        {
            writeSecurityError(L"XML Signature Error: ", L"The document is not signed - No Signature element found");
            return false;
        }

        // 3. Get SignedInfo element
        MSXML6::IXMLDOMNodePtr pSignedInfo = pSigNode->selectSingleNode(L"ds:SignedInfo");
        if (pSignedInfo == nullptr)
        {
            writeSecurityError(L"XML Signature Error: ", L"No SignedInfo element found");
            return false;
        }

        // 4. Get SignatureValue
        MSXML6::IXMLDOMNodePtr pSigValue = pSigNode->selectSingleNode(L"ds:SignatureValue");
        if (pSigValue == nullptr)
        {
            writeSecurityError(L"XML Signature Error: ", L"No SignatureValue element found");
            return false;
        }

        std::wstring sigValueB64 = getNodeText(pSigValue);
        std::vector<BYTE> signatureBytes = base64Decode(sigValueB64);

        if (signatureBytes.empty())
        {
            writeSecurityError(L"XML Signature Error: ", L"Failed to decode SignatureValue");
            return false;
        }

        // 5. FIRST: Verify the document digest (to detect modifications)
        // Get the DigestValue from SignedInfo
        MSXML6::IXMLDOMNodePtr pReference = pSignedInfo->selectSingleNode(L"ds:Reference");
        if (pReference == nullptr)
        {
            writeSecurityError(L"XML Signature Error: ", L"No Reference element found");
            return false;
        }

        MSXML6::IXMLDOMNodePtr pDigestValue = pReference->selectSingleNode(L"ds:DigestValue");
        if (pDigestValue == nullptr)
        {
            writeSecurityError(L"XML Signature Error: ", L"No DigestValue element found");
            return false;
        }

        std::wstring expectedDigestB64 = getNodeText(pDigestValue);
        std::vector<BYTE> expectedDigest = base64Decode(expectedDigestB64);

        if (expectedDigest.empty())
        {
            writeSecurityError(L"XML Signature Error: ", L"Failed to decode DigestValue");
            return false;
        }

        // Clone the document and remove the Signature element (enveloped signature transform)
        MSXML6::IXMLDOMDocument3Ptr pDocClone;
        hr = pDocClone.CreateInstance(__uuidof(MSXML6::DOMDocument60));
        if (FAILED(hr))
        {
            writeSecurityError(L"XML Error: ", L"Failed to create document clone");
            return false;
        }

        pDocClone->put_preserveWhiteSpace(VARIANT_TRUE);
        pDocClone->async = VARIANT_FALSE;

        _bstr_t originalXml = pXMLDoc->Getxml();
        pDocClone->loadXML(originalXml);

        // Remove Signature node from clone
        pDocClone->setProperty(_bstr_t("SelectionNamespaces"),
            _bstr_t("xmlns:ds='http://www.w3.org/2000/09/xmldsig#'"));

        MSXML6::IXMLDOMNodePtr pSigNodeClone = pDocClone->selectSingleNode(L"//ds:Signature");
        if (pSigNodeClone != nullptr)
        {
            MSXML6::IXMLDOMNodePtr pParent = pSigNodeClone->GetparentNode();
            if (pParent != nullptr)
            {
                pParent->removeChild(pSigNodeClone);
            }
        }

        // Compute digest of the document without signature
        _bstr_t docXml = pDocClone->Getxml();
        std::string docStr((char*)docXml);
        std::vector<BYTE> docBytes(docStr.begin(), docStr.end());
        std::vector<BYTE> actualDigest = computeSHA256(docBytes);

        // Compare digests
        if (actualDigest != expectedDigest)
        {
            writeSecurityError(L"XML Signature - Document Integrity Error: ", L"The document has been modified after signing. Digest verification failed.");
            return false;
        }

        // 6. Serialize SignedInfo to bytes (same way as signer)
        _bstr_t signedInfoXml = pSignedInfo->Getxml();
        std::string signedInfoStr((char*)signedInfoXml);
        std::vector<BYTE> signedInfoBytes(signedInfoStr.begin(), signedInfoStr.end());

        // 7. Compute hash of SignedInfo
        std::vector<BYTE> signedInfoHash = computeSHA256(signedInfoBytes);

        if (signedInfoHash.empty())
        {
            writeSecurityError(L"XML Signature - Hash Error", L"Failed to compute hash of SignedInfo");
            return false;
        }

        // 8. Get certificate from signature
        MSXML6::IXMLDOMNodePtr pX509Cert = pSigNode->selectSingleNode(L"ds:KeyInfo/ds:X509Data/ds:X509Certificate");

        if (pX509Cert == nullptr)
        {
            writeSecurityError(L"XML Signature - Certificate Error: ", L"No X509Certificate found in signature");
            return false;
        }

        std::wstring certB64 = getNodeText(pX509Cert);
        std::vector<BYTE> certBytes = base64Decode(certB64);

        if (certBytes.empty())
        {
            writeSecurityError(L"XML Signature - Certificate Error: ", L"Failed to decode certificate");
            return false;
        }

        // 9. Create certificate context
        PCCERT_CONTEXT pCertContext = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, certBytes.data(), (DWORD)certBytes.size());

        if (!pCertContext)
        {
            DWORD dwErr = GetLastError();
            std::wstringstream ss;
            ss << L"Failed to create certificate context. Error: 0x" << std::hex << dwErr;
            writeSecurityError(L"XML Signature - Certificate Error: ", ss.str());
            return false;
        }

        // 10. Verify certificate validity and chain
        if (!verifyXmlCertificate(pCertContext))
        {
            CertFreeCertificateContext(pCertContext);
            return false;
        }

        // 11. Verify this is YOUR trusted certificate (by thumbprint or key ID)
        if (!verifyXmlTrustedCertificate(pCertContext, trustedThumbprint))
        {
            CertFreeCertificateContext(pCertContext);
            return false;
        }

        // 12. Import public key and verify signature
        BCRYPT_KEY_HANDLE hKey = NULL;
        bool result = false;

        if (CryptImportPublicKeyInfoEx2(X509_ASN_ENCODING, &pCertContext->pCertInfo->SubjectPublicKeyInfo, 0, NULL, &hKey) != 0)
        {
            // Setup padding info for RSA-SHA256
            BCRYPT_PKCS1_PADDING_INFO paddingInfo = { 0 };
            paddingInfo.pszAlgId = BCRYPT_SHA256_ALGORITHM;

            // Verify signature
            NTSTATUS status = BCryptVerifySignature(
                hKey,
                &paddingInfo,
                signedInfoHash.data(),
                (ULONG)signedInfoHash.size(),
                signatureBytes.data(),
                (ULONG)signatureBytes.size(),
                BCRYPT_PAD_PKCS1);

            result = (status == 0);

            if (!result)
            {
                std::wstringstream ss;
                ss << L"BCrypt status: 0x" << std::hex << std::setw(8) << std::setfill(L'0') << status;

                if (status == 0xC000A000)
                    ss << L" (STATUS_INVALID_SIGNATURE)";

                writeSecurityError(L"XML Signature Verification Failed: ", ss.str().c_str());
            }

            BCryptDestroyKey(hKey);
        }
        else
        {
            DWORD dwErr = GetLastError();
            std::wstringstream ss;
            ss << L"Failed to import public key. Error: 0x" << std::hex << dwErr;
            writeSecurityError(L"XML Signature - Key Import Error", ss.str().c_str());
        }

        CertFreeCertificateContext(pCertContext);

        return result;
    }
    catch (_com_error& e)
    {
        writeSecurityError(L"XML Signature - COM Error: ", e.ErrorMessage());
        return false;
    }
    catch (...)
    {
        writeSecurityError(L"XML Signature - Unknown Error: ", L"An unexpected error occurred");
        return false;
    }
}

//
// XML Signature (XMLDsig) Verification functions END
//


void SecurityGuard::writeSecurityError(const std::wstring& prefix, const std::wstring& log2write) const
{
	// Expand the environment variable
	wstring expandedLogFileName = _errLogPath;
	expandEnv(expandedLogFileName);

	// Create the folder & sub-folders for the log file
	wchar_t logDir[MAX_PATH];
	lstrcpy(logDir, expandedLogFileName.c_str());
	::PathRemoveFileSpec(logDir);
	int result = SHCreateDirectoryEx(NULL, logDir, NULL);

	// If folder doesn't exit or folder creation failed
	if (result != ERROR_SUCCESS && result != ERROR_ALREADY_EXISTS)
	{
		// process %TEMP% treatment
		wchar_t* fileName = ::PathFindFileName(expandedLogFileName.c_str());
		expandedLogFileName = L"%TEMP%\\";
		expandedLogFileName += fileName;
		expandEnv(expandedLogFileName);
	}

	writeLog(expandedLogFileName.c_str(), prefix.c_str(), log2write.c_str());
}

bool SecurityGuard::verifySignedBinary(const std::wstring& filepath)
{
	wstring display_name;
	wstring key_id_hex;
	wstring subject;
	wstring authority_key_id_hex;

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
			writeSecurityError(filepath.c_str(), L": chain of trust verification failed");
			return false;
		}

		if (t2)
		{
			writeSecurityError(filepath.c_str(), L": error encountered while cleaning up after WinVerifyTrust");
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
			ss << std::uppercase << std::setfill(wchar_t('0')) << std::setw(2) << std::hex << key_id_buff[i];
		}
		key_id_hex = ss.str();

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
		// --- End AKI Retrieval ---

	}
	catch (const string& s) {
		writeSecurityError((filepath + L" - error while getting certificate information: ").c_str(), s2ws(s).c_str());
		status = false;
	}
	catch (...) {
		// Unknown error
		writeSecurityError(filepath.c_str(), L": Unknow error while getting certificate information");
		status = false;
	}

	//
	// fields verifications - if status is true, and demaded parameter string to compare (from the parameter) is not empty, then do compare
	//
	if (status &&  (!_signer_display_name.empty() && _signer_display_name != display_name))
	{
		status = false;
		wstring errMsg = L"Invalid certificate display name: ";
		errMsg += L"expected ";
		errMsg += _signer_display_name;
		errMsg += L" vs unexpected ";
		errMsg += display_name;
		writeSecurityError(filepath.c_str(), errMsg);
	}

	if (status && (!_signer_subject.empty() && _signer_subject != subject))
	{
		status = false;
		wstring errMsg = L"Invalid certificate subject: ";
		errMsg += L"expected ";
		errMsg += _signer_subject;
		errMsg += L" vs unexpected ";
		errMsg += subject;
		writeSecurityError(filepath.c_str(), errMsg);
	}

	if (status && (!_signer_key_id.empty() && stringToUpper(_signer_key_id) != key_id_hex))
	{
		status = false;
		wstring errMsg = L"Invalid certificate key id: ";
		errMsg += L"expected ";
		errMsg += _signer_key_id;
		errMsg += L" vs unexpected ";
		errMsg += key_id_hex;
		writeSecurityError(filepath.c_str(), errMsg);
	}

	if (status && (!_authority_key_id.empty() && stringToUpper(_authority_key_id) != authority_key_id_hex))
	{
		status = false;
		wstring errMsg = L"Invalid authority key id: ";
		errMsg += L"expected ";
		errMsg += _authority_key_id;
		errMsg += L" vs unexpected ";
		errMsg += authority_key_id_hex;
		writeSecurityError(filepath.c_str(), errMsg);
	}

	// Clean up.

	if (hStore != NULL)       CertCloseStore(hStore, 0);
	if (hMsg != NULL)       CryptMsgClose(hMsg);
	if (pSignerInfo != NULL)  LocalFree(pSignerInfo);

	return status;
}
