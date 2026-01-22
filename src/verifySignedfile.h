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


//#define VerifySignedLibrary_DISABLE_REVOCATION_CHECK "Don't check certificat revocation"

/*
* Verifies an Authenticde DLL signature and ownership
*
* Parameters:
*  @param filepath        path to the DLL file to examine
*  @param cert_display_name if specified, the signing certificate display name to compare to. Ignored if set to "", (weak comparison)
*  @param cert_subject    if specified, the full signing certificate subject name. Ignored if set to "" (strong comparison)
*  @param cert_key_id_hex if specified, the signing certificate key id (fingerprint), Ignored if set to "" (very strong comparison)
*
* @return true if the verification was positive, false if it was negative of encountered some error
*
* Dependencies:
*  This function uses 3 APIs: WinTrust, CryptoAPI, SENS API
*  It requires to link on : wintrust.lib, crypt32.lib (or crypt64.lib depending on the compilation target) and sensapi.lib
*  Those functions are available on Windows starting with Windows-XP
*
* Limitations:
*  Certificate revocation checking requires an access to Internet.
*  The functions checks for connectivity and will disable revocation checking if the machine is offline or if Microsoft
*  connectivity checking site is not reachable (supposely implying we are on an airgapped network).
*  Depending on Windows version, this test will be instantaneous (Windows 8 and up) or may take a few seconds.
*  This behaviour can be disabled by setting a define at compilation time.
*  If macro VerifySignedLibrary_DISABLE_REVOCATION_CHECK is defined, the revocation
*  state of the certificates will *not* be checked.
*
*/
#pragma once

#include <string>
#include <vector>
#include "Common.h"

class SecurityGuard final
{
public:
	SecurityGuard(){};
	bool initFromSelfCertif();

	bool verifySignatureAndGetInfo(const std::wstring& codeSigedBinPath, std::wstring& display_name, std::wstring& key_id_hex, std::wstring& subject, std::wstring& authority_key_id_hex);
	bool verifySignedBinary(const std::wstring& filepath);
	
	void enableChkRevoc() { _doCheckRevocation = true; }
	void enableChkTrustChain() { _doCheckChainOfTrust = true; }
	void setDisplayName(const std::wstring& signer_display_name) { _signer_display_name = signer_display_name; }
	void setSubjectName(const std::wstring& signer_subject) { _signer_subject = signer_subject; }
	void setKeyId(const std::wstring& signer_key_id) { _signer_key_id = signer_key_id; }
	void setAuthorityKeyId(const std::wstring& authority_key_id) { _authority_key_id = authority_key_id; }

	void setErrLogPath(std::wstring& errLogPath) { _errLogPath = errLogPath; }
	std::wstring errLogPath() const { return _errLogPath; }

	void writeSecurityError(const std::wstring& prefix, const std::wstring& log2write) const;

private:
	// Code signing certificate
	std::wstring _signer_display_name; // = L"Notepad++"
	std::wstring _signer_subject; // = L"C=FR, S=Ile-de-France, L=Saint Cloud, O=\"Notepad++\", CN=\"Notepad++\", E=don.h@free.fr"
	std::wstring _signer_key_id; // = L"7B4D26B77F8269B987AC3E8EBC3899E1A4176DFA" => Should be UPPERCASE
	std::wstring _authority_key_id; // = L"8BDE0FA542DB39D347AF06A83AC9D09D421D1366" => Should be UPPERCASE

	bool _doCheckRevocation = false;
	bool _doCheckChainOfTrust = false;

	std::wstring _errLogPath = L"%LOCALAPPDATA%\\WinGUp\\log\\securityError.log"; // By default, but overrideable
};

