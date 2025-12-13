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

void expandEnv(wstring& s)
{
	wchar_t buffer[MAX_PATH] = { '\0' };
	// This returns the resulting string length or 0 in case of error.
	DWORD ret = ExpandEnvironmentStrings(s.c_str(), buffer, static_cast<DWORD>(std::size(buffer)));
	if (ret != 0)
	{
		if (ret == static_cast<DWORD>(lstrlen(buffer) + 1))
		{
			s = buffer;
		}
		else
		{
			// Buffer was too small, try with a bigger buffer of the required size.
			std::vector<wchar_t> buffer2(ret, 0);
			ret = ExpandEnvironmentStrings(s.c_str(), buffer2.data(), static_cast<DWORD>(buffer2.size()));
			s = buffer2.data();
		}
	}
}

namespace
{
	constexpr wchar_t timeFmtEscapeChar = 0x1;
	constexpr wchar_t middayFormat[] = L"tt";

	// Returns AM/PM string defined by the system locale for the specified time.
	// This string may be empty or customized.
	wstring getMiddayString(const wchar_t* localeName, const SYSTEMTIME& st)
	{
		wstring midday;
		midday.resize(MAX_PATH);
		int ret = GetTimeFormatEx(localeName, 0, &st, middayFormat, &midday[0], static_cast<int>(midday.size()));
		if (ret > 0)
			midday.resize(ret - 1); // Remove the null-terminator.
		else
			midday.clear();
		return midday;
	}

	// Replaces conflicting time format specifiers by a special character.
	bool escapeTimeFormat(wstring& format)
	{
		bool modified = false;
		for (auto& ch : format)
		{
			if (ch == middayFormat[0])
			{
				ch = timeFmtEscapeChar;
				modified = true;
			}
		}
		return modified;
	}

	// Replaces special time format characters by actual AM/PM string.
	void unescapeTimeFormat(wstring& format, const wstring& midday)
	{
		if (midday.empty())
		{
			auto it = std::remove(format.begin(), format.end(), timeFmtEscapeChar);
			if (it != format.end())
				format.erase(it, format.end());
		}
		else
		{
			size_t i = 0;
			while ((i = format.find(timeFmtEscapeChar, i)) != wstring::npos)
			{
				if (i + 1 < format.size() && format[i + 1] == timeFmtEscapeChar)
				{
					// 'tt' => AM/PM
					format.erase(i, std::size(middayFormat) - 1);
					format.insert(i, midday);
				}
				else
				{
					// 't' => A/P
					format[i] = midday[0];
				}
			}
		}
	}
}

wstring getDateTimeStrFrom(const wstring& dateTimeFormat, const SYSTEMTIME& st)
{
	const wchar_t* localeName = LOCALE_NAME_USER_DEFAULT;
	const DWORD flags = 0;

	constexpr int bufferSize = MAX_PATH;
	wchar_t buffer[bufferSize] = {};
	int ret = 0;


	// 1. Escape 'tt' that means AM/PM or 't' that means A/P.
	// This is needed to avoid conflict with 'M' date format that stands for month.
	wstring newFormat = dateTimeFormat;
	const bool hasMiddayFormat = escapeTimeFormat(newFormat);

	// 2. Format the time (h/m/s/t/H).
	ret = GetTimeFormatEx(localeName, flags, &st, newFormat.c_str(), buffer, bufferSize);
	if (ret != 0)
	{
		// 3. Format the date (d/y/g/M). 
		// Now use the buffer as a format string to process the format specifiers not recognized by GetTimeFormatEx().
		ret = GetDateFormatEx(localeName, flags, &st, buffer, buffer, bufferSize, nullptr);
	}

	if (ret != 0)
	{
		if (hasMiddayFormat)
		{
			// 4. Now format only the AM/PM string.
			const wstring midday = getMiddayString(localeName, st);
			wstring result = buffer;
			unescapeTimeFormat(result, midday);
			return result;
		}
		return buffer;
	}

	return {};
}

void writeLog(const wchar_t* logFileName, const wchar_t* logPrefix, const wchar_t* log2write)
{
	FILE* f = _wfopen(logFileName, L"a+, ccs=UTF-16LE");
	if (f)
	{
		SYSTEMTIME currentTime = {};
		::GetLocalTime(&currentTime);
		wstring log2writeStr = getDateTimeStrFrom(L"yyyy-MM-dd HH:mm:ss", currentTime);

		log2writeStr += L"  ";
		log2writeStr += logPrefix;
		log2writeStr += L" ";
		log2writeStr += log2write;
		log2writeStr += L'\n';
		fwrite(log2writeStr.c_str(), sizeof(log2writeStr.c_str()[0]), log2writeStr.length(), f);
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
