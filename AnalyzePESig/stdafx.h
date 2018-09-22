// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

#include "targetver.h"

#include <codecvt>
#include <io.h>
#include <fcntl.h>

#ifdef  UNICODE
#define _O_TTEXT _O_WTEXT
#define TEXT_FILE_CCS ", ccs=UTF-8"
#define tostream wostream
#define tofstream wofstream
#define tifstream wifstream
#define tstreambuf wstreambuf
#define tcout wcout
#define tstring wstring
#define to_tstring to_wstring
#define Utf8LPSTR_to_tstring(p) std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>>().from_bytes(p)
#define LPWSTR_to_LPTSTR(dst, src) wcscpy_s(dst, src)
#define LPTSTR_to_wstring(p) wstring(p)
#else UNICODE
#define _O_TTEXT _O_TEXT
#define TEXT_FILE_CCS ""
#define tostream ostream
#define tofstream ofstream
#define tifstream ifstream
#define tstreambuf streambuf
#define tcout cout
#define tstring string
#define to_tstring to_string
#define Utf8LPSTR_to_tstring(p) string(p)
#define LPWSTR_to_LPTSTR(dst, src) { size_t stDummy; wcstombs_s(&stDummy, dst, src, ARRAYSIZE(dst)); }
#define LPTSTR_to_wstring(p) std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>>().from_bytes(p)
#endif UNICODE

#include "AnalysisFunctions.h"
