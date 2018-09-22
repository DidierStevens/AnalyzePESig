#include <stdio.h>
#include <tchar.h>
#include <Windows.h>
#include <TlHelp32.h>
#include <map>
#include <string>
#include <iostream>
#include <Softpub.h>
#include <wintrust.h>
#include <mscat.h>
#include <vector>
#include <Strsafe.h>
#include <fstream>
#include <list>
#include <algorithm>
#include <Shlwapi.h>

#include <aclapi.h>
#include <authz.h>

using namespace std;

tstring MyFormatMessage(DWORD);
BOOL CalculateMD5OfFile(tstring, tstring&, double&, tstring&);
BOOL GetVersionInfo(LPCTSTR, tstring&, tstring&, tstring&, tstring&);
BOOL IsFileDigitallySigned(LPCWSTR, BOOL, LPCWSTR, int&, unsigned int&, tstring&, tstring&, tstring&, tstring&, tstring&, tstring&, list<tstring>&, list<tstring>&, list<tstring>&, list<tstring>&, list <int>&, list<list<tstring>>&, list <int>&, list <int>&, list<tstring>&, list<tstring>&, long&);
BOOL GetFileInfo(tstring, tstring&, tstring&, tstring&, tstring&, DWORD&, unsigned int&, list<tstring>&, unsigned int&, unsigned int&, unsigned int&, unsigned int&, unsigned int&, tstring&, DWORD&, DWORD&, WORD&, WORD&, DWORD&, BOOL&, DWORD&, DWORD&, DWORD&, tstring&, DWORD&, tstring&, tstring&, tstring&);
BOOL IsPEFile(_TCHAR*);
BOOL GetFileSecurityInfo(tstring, LPTSTR, ACCESS_MASK&);
list<tstring> DisplayAccessMask(ACCESS_MASK);
BOOL GetUserFromProcess(const DWORD procId, tstring& user, tstring& domain);

#pragma comment(lib, "authz.lib")

