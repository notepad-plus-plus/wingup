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


#include <fstream>
#include <algorithm>
#include <shlwapi.h>
#include <vector>
#include "Common.h"

using namespace std;

void writeLog(const wchar_t* logFileName, const wchar_t* logSuffix, const wchar_t* log2write)
{
	FILE* f = _wfopen(logFileName, L"a+, ccs=UTF-16LE");
	if (f)
	{
		wstring log = logSuffix;
		log += log2write;
		log += L'\n';
		fwrite(log.c_str(), sizeof(log.c_str()[0]), log.length(), f);
		fflush(f);
		fclose(f);
	}
}

wstring s2ws(const string& str)
{
	int len = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, NULL, 0);
	if (len > 0)
	{
		std::vector<wchar_t> vw(len);
		MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, &vw[0], len);
		return &vw[0];
	}
	return std::wstring();
}

string ws2s(const wstring& wstr)
{
	int len = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, NULL, 0, NULL, NULL);
	if (len > 0)
	{
		std::vector<char> vw(len);
		WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, &vw[0], len, NULL, NULL);
		return &vw[0];
	}
	return std::string();
}

string getFileContentA(const char* file2read)
{
	if (!::PathFileExistsA(file2read))
		return "";

	const size_t blockSize = 1024;
	char data[blockSize];
	string wholeFileContent = "";
	FILE* fp = fopen(file2read, "rb");
	if (!fp)
		return "";

	size_t lenFile = 0;
	do
	{
		lenFile = fread(data, 1, blockSize, fp);
		if (lenFile <= 0) break;
		wholeFileContent.append(data, lenFile);
	} while (lenFile > 0);

	fclose(fp);
	return wholeFileContent;
}

wstring GetLastErrorAsString(DWORD errorCode)
{
	wstring errorMsg(L"");
	// Get the error message, if any.
	// If both error codes (passed error n GetLastError) are 0, then return empty
	if (errorCode == 0)
		errorCode = GetLastError();
	if (errorCode == 0)
		return errorMsg; //No error message has been recorded

	LPWSTR messageBuffer = nullptr;
	FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		nullptr, errorCode, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPWSTR)&messageBuffer, 0, nullptr);

	errorMsg += messageBuffer;

	//Free the buffer.
	LocalFree(messageBuffer);

	return errorMsg;
}

wstring stringToUpper(wstring strToConvert)
{
	std::transform(strToConvert.begin(), strToConvert.end(), strToConvert.begin(),
		[](wchar_t ch) { return static_cast<wchar_t>(towupper(ch)); }
	);
	return strToConvert;
}

wstring stringToLower(wstring strToConvert)
{
	std::transform(strToConvert.begin(), strToConvert.end(), strToConvert.begin(), ::towlower);
	return strToConvert;
}

wstring stringReplace(wstring subject, const wstring& search, const wstring& replace)
{
	size_t pos = 0;
	while ((pos = subject.find(search, pos)) != std::string::npos)
	{
		subject.replace(pos, search.length(), replace);
		pos += replace.length();
	}
	return subject;
}
