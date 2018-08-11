/*
 Copyright 2007 Don HO <don.h@free.fr>

 This file is part of GUP.

 GUP is free software: you can redistribute it and/or modify
 it under the terms of the GNU Lesser General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 GUP is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU Lesser General Public License for more details.

 You should have received a copy of the GNU Lesser General Public License
 along with GUP.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "../ZipLib/ZipFile.h"
#include "../ZipLib/utils/stream_utils.h"

#include <stdint.h>
#include <sys/stat.h>
#include <windows.h>
#include <fstream>
#include <string>
#include <commctrl.h>
#include "resource.h"
#include <shlwapi.h>
#include "xmlTools.h"
#include <Uxtheme.h>
#define CURL_STATICLIB
#include "../curl/include/curl/curl.h"

using namespace std;

typedef vector<string> ParamVector;

HINSTANCE hInst;
HHOOK g_hMsgBoxHook;
static HWND hProgressDlg;
static HWND hProgressBar;
static bool doAbort = false;
static bool stopDL = false;
static bool IsUpdateInBackground = false;
static string msgBoxTitle = "";
static string abortOrNot = "";
static string proxySrv = "0.0.0.0";
static long proxyPort  = 0;
static string winGupUserAgent = "WinGup/";
static string dlFileName = "";
static string appIconFile = "";
static string defaultSilentInstallParam = "/S";

const char FLAG_OPTIONS[] = "-options";
const char FLAG_VERBOSE[] = "-verbose";
const char FLAG_HELP[] = "--help";
const char FLAG_UUZIP[] = "-unzipTo";
const char FLAG_CLEANUP[] = "-clean";

const char MSGID_NOUPDATE[] = "No update is available.";
const char MSGID_UPDATEAVAILABLE[] = "An update package is available, do you want to download it?";
const char MSGID_UPDATEINBACKGROUND[] = "Update in background. (Updater will be running silently.)";
const char MSGID_DOWNLOADSTOPPED[] = "Download is stopped by user. Update is aborted.";
const char MSGID_CLOSEAPP[] = " is opened.\rUpdater will close it in order to process the installation.\rContinue?";
const char MSGID_ABORTORNOT[] = "Do you want to abort update download?";
const char MSGID_UNZIPFAILED[] = "Can't unzip:\nOperation not permitted or decompression failed";
const char MSGID_HELP[] = "Usage :\r\
\r\
gup --help\r\
gup -options\r\
gup [-verbose] [-vVERSION_VALUE] [-pCUSTOM_PARAM]\r\
gup -clean FOLDER_TO_ACTION\r\
gup -unzipTo [-clean] FOLDER_TO_ACTION ZIP_URL\r\
\r\
    --help : Show this help message (and quit program).\r\
    -options : Show the proxy configuration dialog (and quit program).\r\
    -v : Launch GUP with VERSION_VALUE.\r\
         VERSION_VALUE is the current version number of program to update.\r\
         If you pass the version number as the argument,\r\
         then the version set in the gup.xml will be overridden.\r\
	-p : Launch GUP with CUSTOM_PARAM.\r\
	     CUSTOM_PARAM will pass to destination by using GET method\r\
         with argument name \"param\"\r\
    -verbose : Show error/warning message if any.\r\
    -clean: Delete all files in FOLDER_TO_ACTION.\r\
    -unzipTo: Download zip file from ZIP_URL then unzip it into FOLDER_TO_ACTION.\r\
    ZIP_URL: The URL to download zip file.\r\
    FOLDER_TO_ACTION: The folder where we clean or/and unzip to.\r\
	";

std::string thirdDoUpdateDlgButtonLabel = "";
std::string updateAvailable = MSGID_UPDATEAVAILABLE;
std::string updateInBackground = MSGID_UPDATEINBACKGROUND;

//commandLine should contain path to n++ executable running
void parseCommandLine(const char* commandLine, ParamVector& paramVector)
{
	if (!commandLine)
		return;

	char* cmdLine = new char[lstrlenA(commandLine) + 1];
	lstrcpyA(cmdLine, commandLine);

	char* cmdLinePtr = cmdLine;

	bool isInFile = false;
	bool isInWhiteSpace = true;
	size_t commandLength = lstrlenA(cmdLinePtr);
	std::vector<char *> args;
	for (size_t i = 0; i < commandLength; ++i)
	{
		switch (cmdLinePtr[i])
		{
			case '\"': //quoted filename, ignore any following whitespace
			{
				if (!isInFile)	//" will always be treated as start or end of param, in case the user forgot to add an space
				{
					args.push_back(cmdLinePtr + i + 1);	//add next param(since zero terminated original, no overflow of +1)
				}
				isInFile = !isInFile;
				isInWhiteSpace = false;
				//because we dont want to leave in any quotes in the filename, remove them now (with zero terminator)
				cmdLinePtr[i] = 0;
			}
			break;

			case '\t': //also treat tab as whitespace
			case ' ':
			{
				isInWhiteSpace = true;
				if (!isInFile)
					cmdLinePtr[i] = 0;		//zap spaces into zero terminators, unless its part of a filename	
			}
			break;

			default: //default char, if beginning of word, add it
			{
				if (!isInFile && isInWhiteSpace)
				{
					args.push_back(cmdLinePtr + i);	//add next param
					isInWhiteSpace = false;
				}
			}
		}
	}
	paramVector.assign(args.begin(), args.end());
	delete[] cmdLine;
};

bool isInList(const char* token2Find, ParamVector & params)
{
	size_t nbItems = params.size();

	for (size_t i = 0; i < nbItems; ++i)
	{
		if (!strcmp(token2Find, params.at(i).c_str()))
		{
			params.erase(params.begin() + i);
			return true;
		}
	}
	return false;
};

bool getParamVal(char c, ParamVector & params, string & value)
{
	value = "";
	size_t nbItems = params.size();

	for (size_t i = 0; i < nbItems; ++i)
	{
		const char* token = params.at(i).c_str();
		if (token[0] == '-' && strlen(token) >= 2 && token[1] == c) {	//dash, and enough chars
			value = (token + 2);
			params.erase(params.begin() + i);
			return true;
		}
	}
	return false;
}

class ZipOperation
{
public:
	void setUnzipOp(bool isUnzip) {
		if (isUnzip) _op |= unzipOp;
		else _op ^= unzipOp;	
	};
	
	void setCleanupOp(bool isClean) {
		if (isClean) _op |= cleanOp;
		else _op ^= cleanOp;
	};

	void setDestFolder(const string& destFolder) {
		_destFolder = destFolder;
	}
	string getDestFolder() const { return _destFolder; }

	void setDownloadZipUrl(const string& downloadZipUrl) {
		_downloadZipUrl = downloadZipUrl;
	}
	string getDownloadZipUrl() const { return _downloadZipUrl; }

	bool isUnzipReady() const {
		return (_op & unzipOp) && !_downloadZipUrl.empty() && !_destFolder.empty();
	};

	bool isCleanupReady() const {
		return (_op & cleanOp) && !_destFolder.empty();
	};

	bool isReady2Go() const {
		return isUnzipReady() || isCleanupReady();
	}

private:
	const unsigned char unzipOp = 1;
	const unsigned char cleanOp = 2;
	unsigned char _op = 0;

	string _destFolder;
	string _downloadZipUrl;
};


string PathAppend(string& strDest, const string& str2append)
{
	if (strDest.empty() && str2append.empty()) // "" + ""
	{
		strDest = "\\";
		return strDest;
	}

	if (strDest.empty() && !str2append.empty()) // "" + titi
	{
		strDest = str2append;
		return strDest;
	}

	if (strDest[strDest.length() - 1] == '\\' && (!str2append.empty() && str2append[0] == '\\')) // toto\ + \titi
	{
		strDest.erase(strDest.length() - 1, 1);
		strDest += str2append;
		return strDest;
	}

	if ((strDest[strDest.length() - 1] == '\\' && (!str2append.empty() && str2append[0] != '\\')) // toto\ + titi
		|| (strDest[strDest.length() - 1] != '\\' && (!str2append.empty() && str2append[0] == '\\'))) // toto + \titi
	{
		strDest += str2append;
		return strDest;
	}

	// toto + titi
	strDest += "\\";
	strDest += str2append;

	return strDest;
};

vector<string> tokenizeString(const string & tokenString, const char delim)
{
	//Vector is created on stack and copied on return
	std::vector<string> tokens;

	// Skip delimiters at beginning.
	string::size_type lastPos = tokenString.find_first_not_of(delim, 0);
	// Find first "non-delimiter".
	string::size_type pos = tokenString.find_first_of(delim, lastPos);

	while (pos != std::string::npos || lastPos != std::string::npos)
	{
		// Found a token, add it to the vector.
		tokens.push_back(tokenString.substr(lastPos, pos - lastPos));
		// Skip delimiters.  Note the "not_of"
		lastPos = tokenString.find_first_not_of(delim, pos);
		// Find next "non-delimiter"
		pos = tokenString.find_first_of(delim, lastPos);
	}
	return tokens;
};

bool deleteFileOrFolder(const string& f2delete)
{
	auto len = f2delete.length();
	LPSTR actionFolder = new char[len + 2];
	strcpy(actionFolder, f2delete.c_str());
	actionFolder[len] = 0;
	actionFolder[len + 1] = 0;

	SHFILEOPSTRUCTA fileOpStruct = { 0 };
	fileOpStruct.hwnd = NULL;
	fileOpStruct.pFrom = actionFolder;
	fileOpStruct.pTo = NULL;
	fileOpStruct.wFunc = FO_DELETE;
	fileOpStruct.fFlags = FOF_NOCONFIRMATION | FOF_SILENT | FOF_ALLOWUNDO;
	fileOpStruct.fAnyOperationsAborted = false;
	fileOpStruct.hNameMappings = NULL;
	fileOpStruct.lpszProgressTitle = NULL;

	int res = SHFileOperationA(&fileOpStruct);

	delete[] actionFolder;
	return (res == 0);
};

bool decompress(const string& zipFullFilePath, const string& unzipDestTo)
{
	// if destination folder doesn't exist, create it.
	if (!::PathFileExistsA(unzipDestTo.c_str()))
	{
		if (!::CreateDirectoryA(unzipDestTo.c_str(), NULL))
			return false;
	}

	ZipArchive::Ptr archive = ZipFile::Open(zipFullFilePath.c_str());

	std::istream* decompressStream = nullptr;
	auto count = archive->GetEntriesCount();

	if (!count) // wrong archive format
		return false;

	for (size_t i = 0; i < count; ++i)
	{
		ZipArchiveEntry::Ptr entry = archive->GetEntry(static_cast<int>(i));
		assert(entry != nullptr);

		//("[+] Trying no pass...\n");
		decompressStream = entry->GetDecompressionStream();
		assert(decompressStream != nullptr);

		string file2extrait = entry->GetFullName();
		string extraitFullFilePath = unzipDestTo;
		PathAppend(extraitFullFilePath, file2extrait);

		ZipArchiveEntry::Attributes attr = entry->GetAttributes();

		//auto pos = extraitFullFilePath.find_last_of('/');
		//if (pos == extraitFullFilePath.length() - 1) // it's a folder to created
		if (attr == ZipArchiveEntry::Attributes::Directory)
		{
			// if folder doesn't exist, create it.
			if (!::PathFileExistsA(extraitFullFilePath.c_str()))
			{
				char msg[1024];
				sprintf(msg, "[+] Create folder '%s'\n", file2extrait.c_str());
				OutputDebugStringA(msg);

				if (!::CreateDirectoryA(extraitFullFilePath.c_str(), NULL))
					return false;
			}
		}
		else
		{
			char msg[1024];
			sprintf(msg, "[+] Extracting file '%s'\n", file2extrait.c_str());
			OutputDebugStringA(msg);

			std::ofstream destFile;
			destFile.open(extraitFullFilePath, std::ios::binary | std::ios::trunc);

			//
			// We try to catch the wrong detection of folder entry from ZipLib here
			//
			if (!destFile.is_open())
			{
				// file2extrait be separated into an array
				vector<string> strArray = tokenizeString(file2extrait, '/');

				// loop unzipDestTo + file2extraitVector[i] to create directory (by checking existing file length is 0, and removing existing file)
				if (strArray.size() > 1)
				{
					for (size_t j = 0; j < strArray.size() - 1; ++j)
					{
						string folderFullFilePath = unzipDestTo;
						PathAppend(folderFullFilePath, strArray[j]);

						BOOL isCreateFolderOK = FALSE;
						if (::PathFileExistsA(folderFullFilePath.c_str()))
						{
							// check if it is 0 length
							struct _stat64 buf;
							_stat64(folderFullFilePath.c_str(), &buf);

							if (buf.st_size == 0)
							{
								// if 0 length remove it
								deleteFileOrFolder(folderFullFilePath);
							}
							else
							{
								return false;
							}

							// create it
							isCreateFolderOK = ::CreateDirectoryA(folderFullFilePath.c_str(), NULL);
						}
						else
						{
							// create it
							isCreateFolderOK = ::CreateDirectoryA(folderFullFilePath.c_str(), NULL);
						}

						// check if directory creation failed
						if (!isCreateFolderOK)
							return false;

					}
					// copy again
					std::ofstream destFile2;
					destFile2.open(extraitFullFilePath, std::ios::binary | std::ios::trunc);

					if (!destFile2.is_open())
					{
						return false;
					}
				}
			}

			utils::stream::copy(*decompressStream, destFile);

			destFile.flush();
			destFile.close();
		}
	}

	return true;
};

class CUXHelper
{
public:
	CUXHelper()
	{
		_hUXTheme = ::LoadLibrary(TEXT("uxtheme.dll"));
		if (_hUXTheme)
			_enableThemeDialogTextureFuncAddr = reinterpret_cast<ETDTProc>(::GetProcAddress(_hUXTheme, "EnableThemeDialogTexture"));

		g_hMsgBoxHook = SetWindowsHookEx(WH_CALLWNDPROC, CallWndProc, NULL, GetCurrentThreadId());
	}

	~CUXHelper()
	{
		if (_hUXTheme)
			::FreeLibrary(_hUXTheme);

		UnhookWindowsHookEx(g_hMsgBoxHook);
	}

	void goToScreenCenter(HWND hwnd)
	{
		RECT screenRc;
		::SystemParametersInfo(SPI_GETWORKAREA, 0, &screenRc, 0);

		POINT center;
		center.x = screenRc.left + (screenRc.right - screenRc.left) / 2;
		center.y = screenRc.top + (screenRc.bottom - screenRc.top) / 2;

		RECT rc;
		::GetWindowRect(hwnd, &rc);
		int x = center.x - (rc.right - rc.left) / 2;
		int y = center.y - (rc.bottom - rc.top) / 2;

		::SetWindowPos(hwnd, HWND_TOP, x, y, rc.right - rc.left, rc.bottom - rc.top, SWP_SHOWWINDOW);
	}

	void enableDlgTheme(HWND hwnd)
	{
		if (_enableThemeDialogTextureFuncAddr)
		{
			_enableThemeDialogTextureFuncAddr(hwnd, ETDT_ENABLETAB);
			redraw(hwnd);
		}
	}

	static LRESULT CALLBACK CallWndProc(int nCode, WPARAM wParam, LPARAM lParam)
	{
		if (nCode == HC_ACTION)
		{
			CWPSTRUCT* pcwp = (CWPSTRUCT*)lParam;

			if (pcwp->message == WM_INITDIALOG)
			{
				setIcon(pcwp->hwnd, appIconFile);
			}
		}

		return CallNextHookEx(g_hMsgBoxHook, nCode, wParam, lParam);
	}

	static void setIcon(HWND hwnd, string iconFile)
	{
		if (!iconFile.empty())
		{
			HICON hIcon = nullptr, hIconSm = nullptr;

			hIcon = reinterpret_cast<HICON>(LoadImageA(NULL, iconFile.c_str(), IMAGE_ICON, 32, 32, LR_LOADFROMFILE));
			hIconSm = reinterpret_cast<HICON>(LoadImageA(NULL, iconFile.c_str(), IMAGE_ICON, 16, 16, LR_LOADFROMFILE));
			if (hIcon && hIconSm)
			{
				SendMessage(hwnd, WM_SETICON, ICON_BIG, (LPARAM)hIcon);
				SendMessage(hwnd, WM_SETICON, ICON_SMALL, (LPARAM)hIconSm);
			}
		}
	}

private:
	void redraw(HWND hwnd, bool forceUpdate = false) const
	{
		::InvalidateRect(hwnd, nullptr, TRUE);
		if (forceUpdate)
			::UpdateWindow(hwnd);
	}

private:
	HMODULE _hUXTheme = nullptr;
	using ETDTProc = HRESULT(WINAPI *) (HWND, DWORD);
	ETDTProc _enableThemeDialogTextureFuncAddr = nullptr;
};
CUXHelper uxHelper;


// This is the getUpdateInfo call back function used by curl
static size_t getUpdateInfoCallback(char *data, size_t size, size_t nmemb, std::string *updateInfo)
{
	// What we will return
	size_t len = size * nmemb;
	
	// Is there anything in the buffer?
	if (updateInfo != NULL)
	{
		// Append the data to the buffer
		updateInfo->append(data, len);
	}

	return len;
}

static size_t getDownloadData(unsigned char *data, size_t size, size_t nmemb, FILE *fp)
{
	if (doAbort)
		return 0;

	size_t len = size * nmemb;
	fwrite(data, len, 1, fp);
	return len;
};

static size_t downloadRatio = 0;

static size_t setProgress(HWND, double t, double d, double, double)
{
	// Once downloading is finish (100%) close the progress bar dialog
	// as there is no need to keep it opened because
	// new dailog asking to close the app will appear (if specified classname in configuration)
	static bool IsDialogClosed = false;
	if (!IsDialogClosed)
	{
		while (stopDL)
			::Sleep(1000);
		size_t step = size_t(d * 100.0 / t - downloadRatio);

		// Looks like sometime curl is not giving proper data, so workaround
		// Issue has been reported for Notepad++ (#4666 and #4069)
		size_t ratioTemp = size_t(d * 100.0 / t);
		if (ratioTemp <= 100)
			downloadRatio = ratioTemp;

		SendMessage(hProgressBar, PBM_SETSTEP, (WPARAM)step, 0);
		SendMessage(hProgressBar, PBM_STEPIT, 0, 0);

		char percentage[128];
		sprintf(percentage, "Downloading %s: %Iu %%", dlFileName.c_str(), downloadRatio);
		::SetWindowTextA(hProgressDlg, percentage);

		if (downloadRatio == 100)
		{
			SendMessage(hProgressDlg, WM_COMMAND, IDOK, 0);
			IsDialogClosed = true;
		}
	}
	return 0;
};

LRESULT CALLBACK progressBarDlgProc(HWND hWndDlg, UINT Msg, WPARAM wParam, LPARAM )
{
	INITCOMMONCONTROLSEX InitCtrlEx;

	InitCtrlEx.dwSize = sizeof(INITCOMMONCONTROLSEX);
	InitCtrlEx.dwICC  = ICC_PROGRESS_CLASS;
	InitCommonControlsEx(&InitCtrlEx);

	switch(Msg)
	{
		case WM_INITDIALOG:
			hProgressDlg = hWndDlg;
			hProgressBar = CreateWindowEx(0, PROGRESS_CLASS, NULL, WS_CHILD | WS_VISIBLE,
										  20, 20, 280, 17,
										  hWndDlg, NULL, hInst, NULL);
			SendMessage(hProgressBar, PBM_SETRANGE, 0, MAKELPARAM(0, 100)); 
			SendMessage(hProgressBar, PBM_SETSTEP, 1, 0);
			CUXHelper::setIcon(hProgressDlg, appIconFile);
			uxHelper.goToScreenCenter(hWndDlg);
			uxHelper.enableDlgTheme(hWndDlg);
			return TRUE; 

		case WM_COMMAND:
			switch(wParam)
			{
			case IDOK:
				EndDialog(hWndDlg, 0);
				return TRUE;
			case IDCANCEL:
				stopDL = true;
				if (abortOrNot == "")
					abortOrNot = MSGID_ABORTORNOT;
				int abortAnswer = ::MessageBoxA(hWndDlg, abortOrNot.c_str(), msgBoxTitle.c_str(), MB_YESNO);
				if (abortAnswer == IDYES)
				{
					doAbort = true;
					EndDialog(hWndDlg, 0);
				}
				stopDL = false;
				return TRUE;
			}
			break;
	}

	return FALSE;
}


LRESULT CALLBACK yesNoNeverDlgProc(HWND hWndDlg, UINT message, WPARAM wParam, LPARAM)
{
	switch (message)
	{
		case WM_INITDIALOG:
		{
			if (!thirdDoUpdateDlgButtonLabel.empty())
				::SetDlgItemTextA(hWndDlg, IDCANCEL, thirdDoUpdateDlgButtonLabel.c_str());
			else
				::ShowWindow(::GetDlgItem(hWndDlg, IDCANCEL), FALSE);

			::SetWindowTextA(hWndDlg, msgBoxTitle.c_str());
			::SetWindowTextA(::GetDlgItem(hWndDlg, IDC_YESNONEVERMSG), updateAvailable.c_str());
			::SetWindowTextA(::GetDlgItem(hWndDlg, IDC_CHK_IN_BACKGROUND), updateInBackground.c_str());

			uxHelper.goToScreenCenter(hWndDlg);
			uxHelper.enableDlgTheme(hWndDlg);
			return TRUE;
		}

		case WM_COMMAND:
		{
			switch (wParam)
			{
				case IDYES:
				case IDNO:
				case IDCANCEL:
					EndDialog(hWndDlg, wParam);
					return TRUE;

				case IDC_CHK_IN_BACKGROUND:
					IsUpdateInBackground ^= 1; // toggle the value
					return TRUE;

				default:
					break;
			}
		}

		case WM_DESTROY:
		{
			return TRUE;
		}
	}
	return FALSE;
}

LRESULT CALLBACK proxyDlgProc(HWND hWndDlg, UINT Msg, WPARAM wParam, LPARAM)
{

	switch(Msg)
	{
		case WM_INITDIALOG:
			::SetDlgItemTextA(hWndDlg, IDC_PROXYSERVER_EDIT, proxySrv.c_str());
			::SetDlgItemInt(hWndDlg, IDC_PORT_EDIT, proxyPort, FALSE);
			uxHelper.goToScreenCenter(hWndDlg);
			uxHelper.enableDlgTheme(hWndDlg);
			return TRUE; 

		case WM_COMMAND:
			switch(wParam)
			{
				case IDOK:
				{
					char proxyServer[MAX_PATH];
					::GetDlgItemTextA(hWndDlg, IDC_PROXYSERVER_EDIT, proxyServer, MAX_PATH);
					proxySrv = proxyServer;
					proxyPort = ::GetDlgItemInt(hWndDlg, IDC_PORT_EDIT, NULL, FALSE);
					EndDialog(hWndDlg, 1);
					return TRUE;
				}
				case IDCANCEL:
					EndDialog(hWndDlg, 0);
					return TRUE;
			}
			break;
	}

	return FALSE;
}

static DWORD WINAPI launchProgressBar(void *)
{
	::DialogBox(hInst, MAKEINTRESOURCE(IDD_PROGRESS_DLG), NULL, reinterpret_cast<DLGPROC>(progressBarDlgProc));
	return 0;
}

bool downloadBinary(const string& urlFrom, const string& destTo, pair<string, int> proxyServerInfo, bool isSilentMode, const pair<string, string>& stoppedMessage)
{
	FILE* pFile = fopen(destTo.c_str(), "wb");

	//  Download the install package from indicated location
	char errorBuffer[CURL_ERROR_SIZE] = { 0 };
	CURLcode res = CURLE_FAILED_INIT;
	CURL* curl = curl_easy_init();
	if (curl)
	{
		curl_easy_setopt(curl, CURLOPT_URL, urlFrom.c_str());
		curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, TRUE);

		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, getDownloadData);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, pFile);

		curl_easy_setopt(curl, CURLOPT_NOPROGRESS, FALSE);
		curl_easy_setopt(curl, CURLOPT_PROGRESSFUNCTION, setProgress);
		curl_easy_setopt(curl, CURLOPT_PROGRESSDATA, hProgressBar);

		curl_easy_setopt(curl, CURLOPT_USERAGENT, winGupUserAgent.c_str());
		curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errorBuffer);

		if (!proxyServerInfo.first.empty() && proxyServerInfo.second != -1)
		{
			curl_easy_setopt(curl, CURLOPT_PROXY, proxyServerInfo.first.c_str());
			curl_easy_setopt(curl, CURLOPT_PROXYPORT, proxyServerInfo.second);
		}
		curl_easy_setopt(curl, CURLOPT_SSL_OPTIONS, CURLSSLOPT_ALLOW_BEAST | CURLSSLOPT_NO_REVOKE);

		res = curl_easy_perform(curl);

		curl_easy_cleanup(curl);
	}

	if (res != CURLE_OK)
	{
		if (!isSilentMode && doAbort == false)
			::MessageBoxA(NULL, errorBuffer, "curl error", MB_OK);
		if (doAbort)
		{
			::MessageBoxA(NULL, stoppedMessage.first.c_str(), stoppedMessage.second.c_str(), MB_OK);
		}
		doAbort = false;
		return false;
	}

	fflush(pFile);
	fclose(pFile);

	return true;
}

bool getUpdateInfo(const string& info2get, const GupParameters& gupParams, const GupExtraOptions& proxyServer, const string& customParam, const string& version)
{
	char errorBuffer[CURL_ERROR_SIZE] = { 0 };

	// Check on the web the availability of update
	// Get the update package's location
	CURL *curl;
	CURLcode res = CURLE_FAILED_INIT;

	curl = curl_easy_init();
	if (curl)
	{
		std::string urlComplete = gupParams.getInfoLocation() + "?version=";
		if (!version.empty())
			urlComplete += version;
		else
			urlComplete += gupParams.getCurrentVersion();

		if (!customParam.empty())
		{
			string customParamPost = "&param=";
			customParamPost += customParam;
			urlComplete += customParamPost;
		}
		else if (!gupParams.getParam().empty())
		{
			string customParamPost = "&param=";
			customParamPost += gupParams.getParam();
			urlComplete += customParamPost;
		}

		curl_easy_setopt(curl, CURLOPT_URL, urlComplete.c_str());


		curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, TRUE);

		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, getUpdateInfoCallback);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &info2get);

		string ua = gupParams.getSoftwareName();

		winGupUserAgent += VERSION_VALUE;
		if (ua != "")
		{
			ua += "/";
			ua += version;
			ua += " (";
			ua += winGupUserAgent;
			ua += ")";

			winGupUserAgent = ua;
		}

		curl_easy_setopt(curl, CURLOPT_USERAGENT, winGupUserAgent.c_str());
		curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errorBuffer);

		if (proxyServer.hasProxySettings())
		{
			curl_easy_setopt(curl, CURLOPT_PROXY, proxyServer.getProxyServer().c_str());
			curl_easy_setopt(curl, CURLOPT_PROXYPORT, proxyServer.getPort());
		}

		curl_easy_setopt(curl, CURLOPT_SSL_OPTIONS, CURLSSLOPT_ALLOW_BEAST | CURLSSLOPT_NO_REVOKE);

		res = curl_easy_perform(curl);

		curl_easy_cleanup(curl);
	}

	if (res != CURLE_OK)
	{
		if (!gupParams.isSilentMode())
			::MessageBoxA(NULL, errorBuffer, "curl error", MB_OK);
		return false;
	}
	return true;
}

bool runInstaller(const string& app2runPath, const string& app2runParam, const string& binWindowsClassName, const string& closeMsg, const string& closeMsgTitle)
{

	if (!binWindowsClassName.empty())
	{
		HWND h = ::FindWindowExA(NULL, NULL, binWindowsClassName.c_str(), NULL);

		if (h)
		{
			if (false == IsUpdateInBackground)
			{
				int installAnswer = ::MessageBoxA(NULL, closeMsg.c_str(), closeMsgTitle.c_str(), MB_YESNO);

				if (installAnswer == IDNO)
				{
					return 0;
				}

				// kill all process of binary needs to be updated.
				while (h)
				{
					::SendMessage(h, WM_CLOSE, 0, 0);
					h = ::FindWindowExA(NULL, NULL, binWindowsClassName.c_str(), NULL);
				}
			}
			else
			{
				do
				{
					DWORD dwProcessID = 0;
					DWORD dwThreadID = ::GetWindowThreadProcessId(h, &dwProcessID);
					if (0 != dwThreadID)
					{
						HANDLE hProcess = ::OpenProcess(SYNCHRONIZE, FALSE, dwProcessID);
						if (NULL != hProcess)
						{
							::WaitForSingleObject(hProcess, INFINITE);
							CloseHandle(hProcess);
						}
					}
					h = ::FindWindowExA(NULL, NULL, binWindowsClassName.c_str(), NULL);
				} while (h);
			}
		}
	}

	// execute the installer
	BOOL bShow = IsUpdateInBackground ? SW_HIDE : SW_SHOW;
	HINSTANCE result = ::ShellExecuteA(NULL, "open", app2runPath.c_str(), app2runParam.c_str(), ".", bShow);

	if (result <= (HINSTANCE)32) // There's a problem (Don't ask me why, ask Microsoft)
	{
		return false;
	}

	return true;
}


int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR lpszCmdLine, int)
{
	bool isSilentMode = false;
	FILE *pFile = NULL;

	string version;
	string customParam;
	ZipOperation zipOp;

	ParamVector params;
	parseCommandLine(lpszCmdLine, params);

	bool launchSettingsDlg = isInList(FLAG_OPTIONS, params);
	bool isVerbose = isInList(FLAG_VERBOSE, params);
	bool isHelp = isInList(FLAG_HELP, params);
	bool isCleanUp = isInList(FLAG_CLEANUP, params);
	bool isUnzip = isInList(FLAG_UUZIP, params);
	
	getParamVal('v', params, version);
	getParamVal('p', params, customParam);

	// Object (gupParams) is moved here because we need app icon form configuration file
	GupParameters gupParams("gup.xml");
	appIconFile = gupParams.getSoftwareIcon();

	if (isHelp)
	{
		::MessageBoxA(NULL, MSGID_HELP, "GUP Command Argument Help", MB_OK);
		return 0;
	}

	if (isCleanUp || isUnzip)
	{
		// retrieve the dir to clean up and url to download
		size_t nbParam = params.size();

		if (nbParam == 1) // only clean
		{
			if (isUnzip)
				return -1;

			zipOp.setDestFolder(params[0]);
		}
		else if (nbParam == 2) // must be unzipTo
		{
			if (!isUnzip)
				return -1;

			zipOp.setDestFolder(params[0]);
			zipOp.setDownloadZipUrl(params[1]);
		}
		else
		{
			return -1;
		}
		zipOp.setCleanupOp(isCleanUp);
		zipOp.setUnzipOp(isUnzip);
	}

	GupExtraOptions extraOptions("gupOptions.xml");
	GupNativeLang nativeLang("nativeLang.xml");

	if (zipOp.isReady2Go())
	{
		// if -unzip is present, -clean will be ignored
		if (!zipOp.isUnzipReady() && zipOp.isCleanupReady())
		{
			deleteFileOrFolder(zipOp.getDestFolder());
		}
		
		if (zipOp.isUnzipReady())
		{
			std::string dlDest = std::getenv("TEMP");
			dlDest += "\\";
			dlDest += ::PathFindFileNameA(zipOp.getDownloadZipUrl().c_str());

			char *ext = ::PathFindExtensionA(dlDest.c_str());
			if (strcmp(ext, ".zip") != 0)
				dlDest += ".zip";

			dlFileName = ::PathFindFileNameA(zipOp.getDownloadZipUrl().c_str());


			string dlStopped = nativeLang.getMessageString("MSGID_DOWNLOADSTOPPED");
			if (dlStopped == "")
				dlStopped = MSGID_DOWNLOADSTOPPED;


			bool isSuccessful = downloadBinary(zipOp.getDownloadZipUrl(), dlDest, pair<string, int>(extraOptions.getProxyServer(), extraOptions.getPort()), true, pair<string, string>(dlStopped, gupParams.getMessageBoxTitle()));
			if (!isSuccessful)
			{
				return -1;
			}

			// check if renamed folder exist, if it does, delete it
			string backup4RestoreInCaseOfFailedPath = zipOp.getDestFolder() + ".backup4RestoreInCaseOfFailed";
			if (::PathFileExistsA(backup4RestoreInCaseOfFailedPath.c_str()))
				deleteFileOrFolder(backup4RestoreInCaseOfFailedPath);

			// rename the folder with suffix ".backup4RestoreInCaseOfFailed"
			::MoveFileA(zipOp.getDestFolder().c_str(), backup4RestoreInCaseOfFailedPath.c_str());

			isSuccessful = decompress(dlDest, zipOp.getDestFolder());
			if (!isSuccessful)
			{
				string unzipFailed = nativeLang.getMessageString("MSGID_UNZIPFAILED");
				if (unzipFailed == "")
					unzipFailed = MSGID_UNZIPFAILED;

				::MessageBoxA(NULL, unzipFailed.c_str(), gupParams.getMessageBoxTitle().c_str(), MB_OK);

				// Delete incomplete unzipped folder
				deleteFileOrFolder(zipOp.getDestFolder());

				// rename back the folder
				::MoveFileA(backup4RestoreInCaseOfFailedPath.c_str(), zipOp.getDestFolder().c_str());

				return -1;
			}

			// delete the folder with suffix ".backup4RestoreInCaseOfFailed"
			deleteFileOrFolder(backup4RestoreInCaseOfFailedPath);

		}

		return 0;
	}

	hInst = hInstance;
	try
	{
		if (launchSettingsDlg)
		{
			if (extraOptions.hasProxySettings())
			{
				proxySrv = extraOptions.getProxyServer();
				proxyPort = extraOptions.getPort();
			}
			if (::DialogBox(hInst, MAKEINTRESOURCE(IDD_PROXY_DLG), NULL, reinterpret_cast<DLGPROC>(proxyDlgProc)))
				extraOptions.writeProxyInfo("gupOptions.xml", proxySrv.c_str(), proxyPort);

			return 0;
		}

		msgBoxTitle = gupParams.getMessageBoxTitle();
		abortOrNot = nativeLang.getMessageString("MSGID_ABORTORNOT");

		//
		// Get update info
		//
		std::string updateInfo;

		// Get your software's current version.
		// If you pass the version number as the argument
		// then the version set in the gup.xml will be overridden
		if (!version.empty())
			gupParams.setCurrentVersion(version.c_str());

		// override silent mode if "-isVerbose" is passed as argument
		if (isVerbose)
			gupParams.setSilentMode(false);

		isSilentMode = gupParams.isSilentMode();

		bool getUpdateInfoSuccessful = getUpdateInfo(updateInfo, gupParams, extraOptions, customParam, version);

		if (!getUpdateInfoSuccessful)
			return -1;
		

		GupDownloadInfo gupDlInfo(updateInfo.c_str());

		if (!gupDlInfo.doesNeed2BeUpdated())
		{
			if (!isSilentMode)
			{
				string noUpdate = nativeLang.getMessageString("MSGID_NOUPDATE");
				if (noUpdate == "")
					noUpdate = MSGID_NOUPDATE;
				::MessageBoxA(NULL, noUpdate.c_str(), gupParams.getMessageBoxTitle().c_str(), MB_OK);
			}
			return 0;
		}


		//
		// Process Update Info
		//

		// Ask user if he/she want to do update
		updateAvailable = nativeLang.getMessageString("MSGID_UPDATEAVAILABLE");
		if (updateAvailable.empty())
			updateAvailable = MSGID_UPDATEAVAILABLE;

		updateInBackground = nativeLang.getMessageString("MSGID_UPDATEINBACKGROUND");
		if (updateInBackground.empty())
			updateInBackground = MSGID_UPDATEINBACKGROUND;

		int thirdButtonCmd = gupParams.get3rdButtonCmd();
		thirdDoUpdateDlgButtonLabel = gupParams.get3rdButtonLabel();

		int dlAnswer = 0;
		HWND hApp = ::FindWindowExA(NULL, NULL, gupParams.getClassName().c_str(), NULL);
		bool isModal = gupParams.isMessageBoxModal();
		dlAnswer = static_cast<int32_t>(::DialogBox(hInst, MAKEINTRESOURCE(IDD_YESNONEVERDLG), isModal ? hApp : NULL, reinterpret_cast<DLGPROC>(yesNoNeverDlgProc)));

		if (dlAnswer == IDNO)
		{
			return 0;
		}
		
		if (dlAnswer == IDCANCEL)
		{
			if (gupParams.getClassName() != "")
			{
				if (hApp)
				{
					::SendMessage(hApp, thirdButtonCmd, gupParams.get3rdButtonWparam(), gupParams.get3rdButtonLparam());
				}
			}
			return 0;
		}

		//
		// Download executable bin
		//
		if (!IsUpdateInBackground)
			::CreateThread(NULL, 0, launchProgressBar, NULL, 0, NULL);

		std::string dlDest = std::getenv("TEMP");
		dlDest += "\\";
		dlDest += ::PathFindFileNameA(gupDlInfo.getDownloadLocation().c_str());

        char *ext = ::PathFindExtensionA(gupDlInfo.getDownloadLocation().c_str());
        if (strcmp(ext, ".exe") != 0)
            dlDest += ".exe";

		dlFileName = ::PathFindFileNameA(gupDlInfo.getDownloadLocation().c_str());


		string dlStopped = nativeLang.getMessageString("MSGID_DOWNLOADSTOPPED");
		if (dlStopped == "")
			dlStopped = MSGID_DOWNLOADSTOPPED;

		bool dlSuccessful = downloadBinary(gupDlInfo.getDownloadLocation(), dlDest, pair<string, int>(extraOptions.getProxyServer(), extraOptions.getPort()), isSilentMode, pair<string, string>(dlStopped, gupParams.getMessageBoxTitle()));

		if (!dlSuccessful)
			return -1;


		//
		// Run executable bin
		//
		string msg = gupParams.getClassName();
		string closeApp = nativeLang.getMessageString("MSGID_CLOSEAPP");
		if (closeApp == "")
			closeApp = MSGID_CLOSEAPP;
		msg += closeApp;

		string installerParam = IsUpdateInBackground ? gupParams.getSilentInstallerParam() : gupParams.getNormalInstallerParam();
		if (installerParam.empty() && IsUpdateInBackground)
			installerParam = defaultSilentInstallParam;

		runInstaller(dlDest, installerParam, gupParams.getClassName(), msg, gupParams.getMessageBoxTitle().c_str());

		return 0;

	}
	catch (const exception& ex)
	{
		if (!isSilentMode)
			::MessageBoxA(NULL, ex.what(), "Xml Exception", MB_OK);

		if (pFile != NULL)
			fclose(pFile);

		return -1;
	}
	catch (...)
	{
		if (!isSilentMode)
			::MessageBoxA(NULL, "Unknown", "Unknown Exception", MB_OK);

		if (pFile != NULL)
			fclose(pFile);

		return -1;
	}
}
