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

string MyFormatMessage(DWORD);
BOOL CalculateMD5OfFile(string, string&, double&, string&);
BOOL GetVersionInfo(LPCSTR, string&, string&, string&, string&);
BOOL IsFileDigitallySigned(LPCWSTR, BOOL, LPCWSTR, int&, unsigned int&, string&, string&, string&, string&, string&, string&, list<string>&, list<string>&, list<string>&, list<string>&, list <int>&, list<list<string>>&, list <int>&, list <int>&, list<string>&, list<string>&, long&);
BOOL GetFileInfo(string, string&, string&, string&, string&, DWORD&, unsigned int&, list<string>&, unsigned int&, unsigned int&, unsigned int&, unsigned int&, unsigned int&, string&, DWORD&, DWORD&, WORD&, WORD&, DWORD&, BOOL&, DWORD&, DWORD&, DWORD&, string&, DWORD&, string&, string&, string&);
BOOL IsPEFile(_TCHAR*);
BOOL GetFileSecurityInfo(string, LPTSTR, ACCESS_MASK&);
list<string> DisplayAccessMask(ACCESS_MASK);
BOOL GetUserFromProcess(const DWORD procId, string& user, string& domain);

#pragma comment(lib, "authz.lib")

