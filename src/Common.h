// This file is part of Notepad++ project
// Copyright (C)2025 Don HO <don.h@free.fr>

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

#pragma once

#include <string>

class ScopedCOMInit final // never use this in DllMain
{
public:
	ScopedCOMInit() {
		HRESULT hr = ::CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED); // attempt STA init 1st (older CoInitialize(NULL))

		if (hr == RPC_E_CHANGED_MODE)
		{
			hr = ::CoInitializeEx(nullptr, COINIT_MULTITHREADED); // STA init failed, switch to MTA
		}

		if (SUCCEEDED(hr))
		{
			// S_OK or S_FALSE, both needs subsequent CoUninitialize()
			_bInitialized = true;
		}
	}

	~ScopedCOMInit() {
		if (_bInitialized)
		{
			_bInitialized = false;
			::CoUninitialize();
		}
	}

	bool isInitialized() const {
		return _bInitialized;
	}

private:
	bool _bInitialized = false;

	ScopedCOMInit(const ScopedCOMInit&) = delete;
	ScopedCOMInit& operator=(const ScopedCOMInit&) = delete;
};

void expandEnv(std::wstring& s);
std::wstring getDateTimeStrFrom(const std::wstring& dateTimeFormat, const SYSTEMTIME& st);
void writeLog(const wchar_t* logFileName, const wchar_t* logSuffix, const wchar_t* log2write);
std::wstring s2ws(const std::string& str);
std::string ws2s(const std::wstring& wstr);
std::string getFileContentA(const char* file2read);
std::wstring GetLastErrorAsString(DWORD errorCode);
std::wstring stringToUpper(std::wstring strToConvert);
std::wstring stringToLower(std::wstring strToConvert);
std::wstring stringReplace(std::wstring subject, const std::wstring& search, const std::wstring& replace);
