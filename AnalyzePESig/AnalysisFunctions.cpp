#include "stdafx.h"

#pragma comment (lib, "wintrust")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "Version.lib")

string MyFormatMessage(DWORD dwError)
{
	HLOCAL hlErrorMessage = NULL;
	string message;

	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER, NULL, dwError, MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL), (PTSTR) &hlErrorMessage, 0, NULL);
	if (NULL != hlErrorMessage)
	{
		message = string((TCHAR *) LocalLock(hlErrorMessage));
		message.erase(message.find_last_not_of(TEXT(" \n\r\t")) + 1);
		LocalFree(hlErrorMessage);
	}
	else
		message = "";

	return std::to_string((long long)dwError) + TEXT(" ") + message;
}

int IsCharacterToStrip(int character)
{
	return 0 == character || '\t' == character || '\n' == character || '\r' == character;
}

void StripString(string& stringArg)
{
	stringArg.erase(remove_if(stringArg.begin(), stringArg.end(), IsCharacterToStrip), stringArg.end());
}

#define BUFSIZE 2048
#define MD5LEN  16

double CalculateEntropy(BYTE *pbBuffer, SIZE_T sSize)
{
	BYTE *pbIter;
	SIZE_T asPrevelance[256];
	double dEntropy;
	double dPrevalence;
	int iIter;

	ZeroMemory(asPrevelance, sizeof(asPrevelance));
	for (pbIter = pbBuffer; pbIter < pbBuffer + sSize; pbIter++)
		asPrevelance[*pbIter]++;
		
	dEntropy = 0.0;
	for (iIter = 0; iIter < sizeof(asPrevelance)/sizeof(asPrevelance[0]); iIter++)
		if (asPrevelance[iIter] > 0)
		{
			dPrevalence = (double) asPrevelance[iIter] / (double) sSize;
			dEntropy += - dPrevalence * log10(dPrevalence) / log10(2.0);
		}
		
	return dEntropy;
}

string TimeToString(FILETIME *pftIn)
{
//	FILETIME localFt;
	SYSTEMTIME st;
	_TCHAR szBuffer[256];

//	FileTimeToLocalFileTime(pftIn, &localFt);
//	FileTimeToSystemTime(&localFt, &st);
	FileTimeToSystemTime(pftIn, &st);
	_sntprintf_s(szBuffer, 256, _TEXT("%04d/%02d/%02d %02d:%02d:%02d"), st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
	return string(szBuffer);
}

void GetFileTimes(HANDLE hFile, string& creationtime, string& lastwritetime, string& lastaccesstime)
{
	FILETIME ftCreation;
	FILETIME ftLastWrite;
	FILETIME ftLastAccess;

	if (GetFileTime(hFile, &ftCreation, &ftLastAccess, &ftLastWrite))
	{
		creationtime = TimeToString(&ftCreation);
		lastwritetime = TimeToString(&ftLastWrite);
		lastaccesstime = TimeToString(&ftLastAccess);
	}
	else
	{
		creationtime = "";
		lastwritetime = "";
		lastaccesstime = "";
	}
}

// http://msdn.microsoft.com/en-us/library/windows/desktop/aa446629%28v=vs.85%29.aspx
void GetOwnerName(HANDLE hFile, string& ownername)
{
	DWORD dwRtnCode = 0;
	PSID pSidOwner = NULL;
	BOOL bRtnBool = TRUE;
	LPTSTR AcctName = NULL;
	LPTSTR DomainName = NULL;
	DWORD dwAcctName = 1, dwDomainName = 1;
	SID_NAME_USE eUse = SidTypeUnknown;
	PSECURITY_DESCRIPTOR pSD = NULL;

	ownername = string(TEXT(""));

	// Get the owner SID of the file.
	dwRtnCode = GetSecurityInfo(
		hFile,
		SE_FILE_OBJECT,
		OWNER_SECURITY_INFORMATION,
		&pSidOwner,
		NULL,
		NULL,
		NULL,
		&pSD);

	// Check GetLastError for GetSecurityInfo error condition.
	if (dwRtnCode != ERROR_SUCCESS)
		return;

	// First call to LookupAccountSid to get the buffer sizes.
	bRtnBool = LookupAccountSid(
		NULL,           // local computer
		pSidOwner,
		AcctName,
		(LPDWORD)&dwAcctName,
		DomainName,
		(LPDWORD)&dwDomainName,
		&eUse);

	// Reallocate memory for the buffers.
	AcctName = (LPTSTR)GlobalAlloc(GMEM_FIXED, dwAcctName);

	// Check GetLastError for GlobalAlloc error condition.
	if (AcctName == NULL)
		return;

	DomainName = (LPTSTR)GlobalAlloc(GMEM_FIXED, dwDomainName);

	// Check GetLastError for GlobalAlloc error condition.
	if (DomainName == NULL)
	{
		GlobalFree(AcctName);
		return;
	}

	// Second call to LookupAccountSid to get the account name.
	bRtnBool = LookupAccountSid(
		NULL,                   // name of local or remote computer
		pSidOwner,              // security identifier
		AcctName,               // account name buffer
		(LPDWORD)&dwAcctName,   // size of account name buffer 
		DomainName,             // domain name
		(LPDWORD)&dwDomainName, // size of domain name buffer
		&eUse);                 // SID type

	// Check GetLastError for LookupAccountSid error condition.
	if (bRtnBool == TRUE)
		ownername = string(DomainName) + string(TEXT("\\")) + string(AcctName);

	GlobalFree(DomainName);
	GlobalFree(AcctName);
}

BOOL CalculateMD5OfFile(string filename, string& md5, double& dEntropy, string& error)
{
    DWORD dwLastError = 0;
    BOOL bResult = FALSE;
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    HANDLE hFile = NULL;
    BYTE rgbFile[BUFSIZE];
    DWORD cbRead = 0;
    BYTE rgbHash[MD5LEN];
    DWORD cbHash = 0;
	CHAR rgbDigits[] = TEXT("0123456789abcdef");
	BYTE *pbIter;
	SIZE_T asPrevelance[256];
	double dPrevalence;
	int iIter;
	SIZE_T sFileSize = 0;

	hFile = CreateFile(filename.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN | FILE_FLAG_BACKUP_SEMANTICS, NULL);

    if (INVALID_HANDLE_VALUE == hFile)
    {
        dwLastError = GetLastError();
        error = TEXT("*Error opening file ") + MyFormatMessage(dwLastError);
		return FALSE;
    }

    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
    {
        dwLastError = GetLastError();
        CloseHandle(hFile);
        error = TEXT("*Error CryptAcquireContext ") + MyFormatMessage(dwLastError);
		return FALSE;
    }

    if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
    {
        dwLastError = GetLastError();
        CloseHandle(hFile);
        CryptReleaseContext(hProv, 0);
        error = TEXT("*Error CryptCreateHash ") + MyFormatMessage(dwLastError);
		return FALSE;
    }

	ZeroMemory(asPrevelance, sizeof(asPrevelance));

	while (bResult = ReadFile(hFile, rgbFile, BUFSIZE, &cbRead, NULL))
    {
        if (0 == cbRead)
        {
            break;
        }

		sFileSize += cbRead;

        if (!CryptHashData(hHash, rgbFile, cbRead, 0))
        {
            dwLastError = GetLastError();
            CryptReleaseContext(hProv, 0);
            CryptDestroyHash(hHash);
            CloseHandle(hFile);
	        error = TEXT("*Error CryptHashData ") + MyFormatMessage(dwLastError);
			return FALSE;
        }

		for (pbIter = rgbFile; pbIter < rgbFile + cbRead; pbIter++)
			asPrevelance[*pbIter]++;
	}

    if (!bResult)
    {
        dwLastError = GetLastError();
        CryptReleaseContext(hProv, 0);
        CryptDestroyHash(hHash);
        CloseHandle(hFile);
	    error = TEXT("*Error ReadFile ") + MyFormatMessage(dwLastError);
		return FALSE;
    }

	dEntropy = 0.0;
	for (iIter = 0; iIter < sizeof(asPrevelance)/sizeof(asPrevelance[0]); iIter++)
		if (asPrevelance[iIter] > 0)
		{
			dPrevalence = (double) asPrevelance[iIter] / (double) sFileSize;
			dEntropy += - dPrevalence * log10(dPrevalence) / log10(2.0);
		}

	string md5Hash;
	char hexbyte[3];

    cbHash = MD5LEN;
	hexbyte[2] = '\0';
    if (CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0))
    {
        for (DWORD i = 0; i < cbHash; i++)
        {
			hexbyte[0] = rgbDigits[rgbHash[i] >> 4];
			hexbyte[1] = rgbDigits[rgbHash[i] & 0xf];
			md5Hash.append(hexbyte);
        }
    }
    else
    {
        dwLastError = GetLastError();
        CryptReleaseContext(hProv, 0);
        CryptDestroyHash(hHash);
        CloseHandle(hFile);
	    error = TEXT("*Error CryptGetHashParam ") + MyFormatMessage(dwLastError);
		return FALSE;
    }

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    CloseHandle(hFile);

	md5 = md5Hash;

    return TRUE; 
}

#define SHA1LEN  20

BOOL CalculateHashOfBytes(ALG_ID Algid, BYTE *pbBinary, DWORD dwBinary, string& hash, string& error)
{
    DWORD dwLastError = 0;
    BOOL bResult = FALSE;
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    BYTE rgbHash[SHA1LEN];
    DWORD cbHash = 0;
	CHAR rgbDigits[] = TEXT("0123456789abcdef");
	string calculatedHash;
	char hexbyte[3];

    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
    {
        dwLastError = GetLastError();
        error = TEXT("*Error CryptAcquireContext ") + MyFormatMessage(dwLastError);
		return FALSE;
    }

    if (!CryptCreateHash(hProv, Algid, 0, 0, &hHash))
    {
        dwLastError = GetLastError();
        CryptReleaseContext(hProv, 0);
        error = TEXT("*Error CryptCreateHash ") + MyFormatMessage(dwLastError);
		return FALSE;
    }

    if (!CryptHashData(hHash, pbBinary, dwBinary, 0))
    {
        dwLastError = GetLastError();
        CryptReleaseContext(hProv, 0);
        CryptDestroyHash(hHash);
	    error = TEXT("*Error CryptHashData ") + MyFormatMessage(dwLastError);
		return FALSE;
    }

	if (CALG_SHA1 == Algid)
		cbHash = SHA1LEN;
	else if (CALG_MD5 == Algid)
		cbHash = MD5LEN;
	else
		cbHash = 0;
	hexbyte[2] = '\0';
    if (CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0))
    {
        for (DWORD i = 0; i < cbHash; i++)
        {
			hexbyte[0] = rgbDigits[rgbHash[i] >> 4];
			hexbyte[1] = rgbDigits[rgbHash[i] & 0xf];
			calculatedHash.append(hexbyte);
        }
    }
    else
    {
        dwLastError = GetLastError();
        CryptReleaseContext(hProv, 0);
        CryptDestroyHash(hHash);
	    error = TEXT("*Error CryptGetHashParam ") + MyFormatMessage(dwLastError);
		return FALSE;
    }

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);

	hash = calculatedHash;

    return TRUE; 
}

//// http://msdn.microsoft.com/en-us/library/windows/desktop/aa382384%28v=vs.85%29.aspx
//BOOL VerifyEmbeddedSignature(LPCWSTR pwszSourceFile)
//{
//    LONG lStatus;
//    DWORD dwLastError;
//	BOOL bResult = FALSE;
//
//    // Initialize the WINTRUST_FILE_INFO structure.
//
//    WINTRUST_FILE_INFO FileData;
//    memset(&FileData, 0, sizeof(FileData));
//    FileData.cbStruct = sizeof(WINTRUST_FILE_INFO);
//    FileData.pcwszFilePath = pwszSourceFile;
//    FileData.hFile = NULL;
//    FileData.pgKnownSubject = NULL;
//
//    /*
//    WVTPolicyGUID specifies the policy to apply on the file
//    WINTRUST_ACTION_GENERIC_VERIFY_V2 policy checks:
//    
//    1) The certificate used to sign the file chains up to a root 
//    certificate located in the trusted root certificate store. This 
//    implies that the identity of the publisher has been verified by 
//    a certification authority.
//    
//    2) In cases where user interface is displayed (which this example
//    does not do), WinVerifyTrust will check for whether the  
//    end entity certificate is stored in the trusted publisher store,  
//    implying that the user trusts content from this publisher.
//    
//    3) The end entity certificate has sufficient permission to sign 
//    code, as indicated by the presence of a code signing EKU or no 
//    EKU.
//    */
//
//    GUID WVTPolicyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
//    WINTRUST_DATA WinTrustData;
//
//    // Initialize the WinVerifyTrust input data structure.
//
//    // Default all fields to 0.
//    memset(&WinTrustData, 0, sizeof(WinTrustData));
//
//    WinTrustData.cbStruct = sizeof(WinTrustData);
//    
//    // Use default code signing EKU.
//    WinTrustData.pPolicyCallbackData = NULL;
//
//    // No data to pass to SIP.
//    WinTrustData.pSIPClientData = NULL;
//
//    // Disable WVT UI.
//    WinTrustData.dwUIChoice = WTD_UI_NONE;
//
//    // No revocation checking.
//    WinTrustData.fdwRevocationChecks = WTD_REVOKE_NONE; 
//
//    // Verify an embedded signature on a file.
//    WinTrustData.dwUnionChoice = WTD_CHOICE_FILE;
//
//    // Default verification.
//    WinTrustData.dwStateAction = 0;
//
//    // Not applicable for default verification of embedded signature.
//    WinTrustData.hWVTStateData = NULL;
//
//    // Not used.
//    WinTrustData.pwszURLReference = NULL;
//
//    // This is not applicable if there is no UI because it changes 
//    // the UI to accommodate running applications instead of 
//    // installing applications.
//    WinTrustData.dwUIContext = 0;
//
//    // Set pFile.
//    WinTrustData.pFile = &FileData;
//
//    // WinVerifyTrust verifies signatures as specified by the GUID 
//    // and Wintrust_Data.
//    lStatus = WinVerifyTrust(
//        NULL,
//        &WVTPolicyGUID,
//        &WinTrustData);
//
//    switch (lStatus) 
//    {
//        case ERROR_SUCCESS:
//            /*
//            Signed file:
//                - Hash that represents the subject is trusted.
//
//                - Trusted publisher without any verification errors.
//
//                - UI was disabled in dwUIChoice. No publisher or 
//                    time stamp chain errors.
//
//                - UI was enabled in dwUIChoice and the user clicked 
//                    "Yes" when asked to install and run the signed 
//                    subject.
//            */
//            wprintf_s(L"The file \"%s\" is signed and the signature "
//                L"was verified.\n",
//                pwszSourceFile);
//			bResult = TRUE;
//            break;
//        
//        case TRUST_E_NOSIGNATURE:
//            // The file was not signed or had a signature 
//            // that was not valid.
//
//            // Get the reason for no signature.
//            dwLastError = GetLastError();
//            if (TRUST_E_NOSIGNATURE == dwLastError ||
//                    TRUST_E_SUBJECT_FORM_UNKNOWN == dwLastError ||
//                    TRUST_E_PROVIDER_UNKNOWN == dwLastError) 
//            {
//                // The file was not signed.
//                wprintf_s(L"The file \"%s\" is not signed.\n",
//                    pwszSourceFile);
//            } 
//            else 
//            {
//                // The signature was not valid or there was an error 
//                // opening the file.
//                wprintf_s(L"An unknown error occurred trying to "
//                    L"verify the signature of the \"%s\" file.\n",
//                    pwszSourceFile);
//            }
//			bResult = FALSE;
//            break;
//
//        case TRUST_E_EXPLICIT_DISTRUST:
//            // The hash that represents the subject or the publisher 
//            // is not allowed by the admin or user.
//            wprintf_s(L"The signature is present, but specifically "
//                L"disallowed.\n");
//			bResult = FALSE;
//            break;
//
//        case TRUST_E_SUBJECT_NOT_TRUSTED:
//            // The user clicked "No" when asked to install and run.
//            wprintf_s(L"The signature is present, but not "
//                L"trusted.\n");
//			bResult = FALSE;
//            break;
//
//        case CRYPT_E_SECURITY_SETTINGS:
//            /*
//            The hash that represents the subject or the publisher 
//            was not explicitly trusted by the admin and the 
//            admin policy has disabled user trust. No signature, 
//            publisher or time stamp errors.
//            */
//            wprintf_s(L"CRYPT_E_SECURITY_SETTINGS - The hash "
//                L"representing the subject or the publisher wasn't "
//                L"explicitly trusted by the admin and admin policy "
//                L"has disabled user trust. No signature, publisher "
//                L"or timestamp errors.\n");
//			bResult = FALSE;
//            break;
//
//        default:
//            // The UI was disabled in dwUIChoice or the admin policy 
//            // has disabled user trust. lStatus contains the 
//            // publisher or time stamp chain error.
//            wprintf_s(L"Error is: 0x%x.\n",
//                lStatus);
//			bResult = FALSE;
//            break;
//    }
//
//    return bResult;
//}

#define ENCODING (X509_ASN_ENCODING | PKCS_7_ASN_ENCODING)

void GetChainHashAlgorithms(PCCERT_CONTEXT pCertContext)
{
/*
	DWORD dwFlags = 0;
	PCCERT_CHAIN_CONTEXT pChainContext;

	if (!CertGetCertificateChain(NULL, pCertContext, NULL, NULL, NULL, dwFlags, NULL, &pChainContext))
		return;
	CertFreeCertificateChain(pChainContext);
*/
}

// http://support.microsoft.com/kb/323809
BOOL GetTimeStampSignerInfo(PCMSG_SIGNER_INFO pSignerInfo, PCMSG_SIGNER_INFO *pCounterSignerInfo)
{   
    PCCERT_CONTEXT pCertContext = NULL;
    BOOL fReturn = FALSE;
    BOOL fResult;       
    DWORD dwSize;   

    __try
    {
        *pCounterSignerInfo = NULL;

        // Loop through unathenticated attributes for
        // szOID_RSA_counterSign OID.
        for (DWORD n = 0; n < pSignerInfo->UnauthAttrs.cAttr; n++)
        {
			if (lstrcmpA(pSignerInfo->UnauthAttrs.rgAttr[n].pszObjId, szOID_RSA_counterSign) == 0)
            {
				// Get size of CMSG_SIGNER_INFO structure.
                fResult = CryptDecodeObject(ENCODING,
                           PKCS7_SIGNER_INFO,
                           pSignerInfo->UnauthAttrs.rgAttr[n].rgValue[0].pbData,
                           pSignerInfo->UnauthAttrs.rgAttr[n].rgValue[0].cbData,
                           0,
                           NULL,
                           &dwSize);
                if (!fResult)
                {
                    _tprintf(_T("CryptDecodeObject failed with %x\n"), GetLastError());
                    __leave;
                }

                // Allocate memory for CMSG_SIGNER_INFO.
                *pCounterSignerInfo = (PCMSG_SIGNER_INFO)LocalAlloc(LPTR, dwSize);
                if (!*pCounterSignerInfo)
                {
                    _tprintf(_T("Unable to allocate memory for timestamp info.\n"));
                    __leave;
                }

                // Decode and get CMSG_SIGNER_INFO structure
                // for timestamp certificate.
                fResult = CryptDecodeObject(ENCODING,
                           PKCS7_SIGNER_INFO,
                           pSignerInfo->UnauthAttrs.rgAttr[n].rgValue[0].pbData,
                           pSignerInfo->UnauthAttrs.rgAttr[n].rgValue[0].cbData,
                           0,
                           (PVOID)*pCounterSignerInfo,
                           &dwSize);
                if (!fResult)
                {
                    _tprintf(_T("CryptDecodeObject failed with %x\n"), GetLastError());
                    __leave;
                }

                fReturn = TRUE;
                
                break; // Break from for loop.
            }           
		}
    }
    __finally
    {
        // Clean up.
        if (pCertContext != NULL) CertFreeCertificateContext(pCertContext);
    }

    return fReturn;
}

BOOL GetDateOfTimeStamp(PCMSG_SIGNER_INFO pSignerInfo, SYSTEMTIME *st)
{   
    BOOL fResult;
    FILETIME lft, ft;   
    DWORD dwData;
    BOOL fReturn = FALSE;
    
    // Loop through authenticated attributes and find
    // szOID_RSA_signingTime OID.
    for (DWORD n = 0; n < pSignerInfo->AuthAttrs.cAttr; n++)
    {           
        if (lstrcmpA(szOID_RSA_signingTime, 
                    pSignerInfo->AuthAttrs.rgAttr[n].pszObjId) == 0)
        {               
            // Decode and get FILETIME structure.
            dwData = sizeof(ft);
            fResult = CryptDecodeObject(ENCODING,
                        szOID_RSA_signingTime,
                        pSignerInfo->AuthAttrs.rgAttr[n].rgValue[0].pbData,
                        pSignerInfo->AuthAttrs.rgAttr[n].rgValue[0].cbData,
                        0,
                        (PVOID)&ft,
                        &dwData);
            if (!fResult)
            {
                _tprintf(_T("CryptDecodeObject failed with %x\n"),
                    GetLastError());
                break;
            }

            // Convert to local time.
            FileTimeToLocalFileTime(&ft, &lft);
            FileTimeToSystemTime(&lft, st);

            fReturn = TRUE;

            break; // Break from for loop.
                        
        } //lstrcmp szOID_RSA_signingTime
    } // for 

    return fReturn;
}

BOOL SafeToReadNBytes(DWORD dwSize, DWORD dwStart, DWORD dwRequestSize)
{
	return dwSize - dwStart >= dwRequestSize;
}

DWORD ReadNumberFromNBytes(PBYTE pbSignature, DWORD dwStart, DWORD dwRequestSize)
{
	DWORD dwNumber = 0;

	for (DWORD i = 0; i < dwRequestSize; i++)
		dwNumber = dwNumber * 0x100 + pbSignature[dwStart + i];
	return dwNumber;
}

void ParseDERType(BYTE bIn, int& iType, int& iClass)
{
	iType = bIn & 0x3F;
	iClass = bIn >> 6;
}

BOOL ParseDERSize(PBYTE pbSignature, DWORD dwSize, DWORD& dwSizefound, DWORD& dwBytesParsed)
{
	if (pbSignature[0] > 0x80 && !SafeToReadNBytes(dwSize, 1, pbSignature[0] - 0x80))
		return FALSE;
	if (pbSignature[0] <= 0x80)
	{
		dwSizefound = pbSignature[0];
		dwBytesParsed = 1;
	}
	else
	{
		dwSizefound = ReadNumberFromNBytes(pbSignature, 1, pbSignature[0] - 0x80);
		dwBytesParsed = 1 + pbSignature[0] - 0x80;
	}
	return TRUE;
}

BOOL ParseDERFindType(int iTypeSearch, PBYTE pbSignature, DWORD dwSize, DWORD& dwPositionFound, DWORD& dwLengthFound, DWORD& dwPositionError, int& iTypeError)
{
	int iType;
	int iClass;
	DWORD dwPosition = 0;
	DWORD dwSizeFound;
	DWORD dwBytesParsed;

	dwPositionFound = 0;
	dwPositionError = 0;
	dwLengthFound = 0;
	iTypeError = -1;

	if (NULL == pbSignature)
	{
		iTypeError = -1;
		return FALSE;
	}

	while (dwSize > dwPosition)
	{
		if (!SafeToReadNBytes(dwSize, dwPosition, 2))
		{
			dwPositionError = dwPosition;
			iTypeError = -2;
			return FALSE;
		}

		ParseDERType(pbSignature[dwPosition], iType, iClass);
#ifdef _DEBUG
		printf("<ParseDER %d %02x>\n", iClass, iType);
#endif
		switch (iType)
		{
		case 0x05: // NULL
			dwPosition++;
			if (pbSignature[dwPosition] != 0x00)
			{
				dwPositionError = dwPosition;
				iTypeError = -4;
				return FALSE;
			}
			dwPosition++;
			break;
		case 0x06: // OID
			dwPosition++;
			if (!SafeToReadNBytes(dwSize - dwPosition, 1, pbSignature[dwPosition]))
			{
				dwPositionError = dwPosition;
				iTypeError = -5;
				return FALSE;
			}
#ifdef _DEBUG
			for (int iIter = 0; iIter < pbSignature[dwPosition]; iIter++)
				printf("%02X ", pbSignature[dwPosition + 1 + iIter]);
			printf("\n");
#endif
			dwPosition += 1 + pbSignature[dwPosition];
			break;
		case 0x00: // ?
		case 0x01: // boolean
		case 0x02: // integer
		case 0x03: // bit string
		case 0x04: // octec string
		case 0x0A: // enumerated
		case 0x0C: // UTF8string
		case 0x13: // printable string
		case 0x14: // T61 string
		case 0x16: // IA5String
		case 0x17: // UTC time
		case 0x18: // Generalized time
		case 0x1E: // BMPstring
			dwPosition++;
			if (!ParseDERSize(pbSignature + dwPosition, dwSize - dwPosition, dwSizeFound, dwBytesParsed))
			{
				dwPositionError = dwPosition;
				iTypeError = -7;
				return FALSE;
			}
			dwPosition += dwBytesParsed;
			if (!SafeToReadNBytes(dwSize - dwPosition, 0, dwSizeFound))
			{
				dwPositionError = dwPosition;
				iTypeError = -8;
				return FALSE;
			}
			if (iTypeSearch == iType)
			{
				dwPositionFound = dwPosition;
				dwLengthFound = dwSizeFound;
				return TRUE;
			}
			dwPosition += dwSizeFound;
			break;
		case 0x20: // context specific
		case 0x21: // context specific
		case 0x23: // context specific
		case 0x24: // context specific
		case 0x30: // sequence
		case 0x31: // set
			dwPosition++;
			if (!ParseDERSize(pbSignature + dwPosition, dwSize - dwPosition, dwSizeFound, dwBytesParsed))
			{
				dwPositionError = dwPosition;
				iTypeError = -9;
				return FALSE;
			}
			dwPosition += dwBytesParsed;
			break;
		case 0x22: // ?
			dwPosition += 2;
			break;
		default:
#ifdef _DEBUG
			printf("<ParseDER %d %02x %d>\n", iClass, iType, dwPosition);
#endif
			dwPositionError = dwPosition;
			iTypeError = iType;
			return FALSE;
		}
	}

	return FALSE;
}

string GetGeneralizedTimeStampSignerInfo(PCMSG_SIGNER_INFO pSignerInfo)
{
	DWORD dwPositionFound;
	DWORD dwLengthFound;
	DWORD dwPositionError;
	int iTypeError;

	for (DWORD n = 0; n < pSignerInfo->UnauthAttrs.cAttr; n++)
	{
		if (lstrcmpA(pSignerInfo->UnauthAttrs.rgAttr[n].pszObjId, szOID_RFC3161_counterSign) == 0)
		{
			if (ParseDERFindType(0x04, pSignerInfo->UnauthAttrs.rgAttr[n].rgValue[0].pbData, pSignerInfo->UnauthAttrs.rgAttr[n].rgValue[0].cbData, dwPositionFound, dwLengthFound, dwPositionError, iTypeError))
			{
				PBYTE pbOctetString = &(pSignerInfo->UnauthAttrs.rgAttr[n].rgValue[0].pbData[dwPositionFound]);
				if (ParseDERFindType(0x18, pbOctetString, dwLengthFound, dwPositionFound, dwLengthFound, dwPositionError, iTypeError))
				{
					_TCHAR szBuffer[256];

					_tcsncpy_s(szBuffer, (_TCHAR*)&(pbOctetString[dwPositionFound]), dwLengthFound);
					szBuffer[dwLengthFound] = 0;
					return string(szBuffer);
				}
			}
		}
	}

	return string(TEXT(""));
}

bool GetSignerCertificateInfo(LPCWSTR filename, string& issuerName, string& subjectName, string& signatureHashAlgorithm, string& countersignTimestamp)
{
    HCERTSTORE hStore = NULL;
    HCRYPTMSG hMsg = NULL; 
	DWORD dwEncoding;
	DWORD dwContentType;
	DWORD dwFormatType;
	DWORD dwSignerInfo;
    PCMSG_SIGNER_INFO pSignerInfo = NULL;
    CERT_INFO CertInfo;     
    PCCERT_CONTEXT pCertContext = NULL;
    LPTSTR szName = NULL;
    DWORD dwData;
	PCMSG_SIGNER_INFO pCounterSignerInfo = NULL;

	if (!CryptQueryObject(CERT_QUERY_OBJECT_FILE, filename, CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED, CERT_QUERY_FORMAT_FLAG_BINARY, 0, &dwEncoding, &dwContentType, &dwFormatType, &hStore, &hMsg, NULL))
		return FALSE;

	if (!CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, NULL, &dwSignerInfo))
	{
		CertCloseStore(hStore, 0);
		CryptMsgClose(hMsg);
		return FALSE;
	}

	pSignerInfo = (PCMSG_SIGNER_INFO) LocalAlloc(LPTR, dwSignerInfo);
    if (!pSignerInfo)
    {
		CertCloseStore(hStore, 0);
		CryptMsgClose(hMsg);
		return FALSE;
	}

	if (!CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, (PVOID) pSignerInfo, &dwSignerInfo))
	{
		LocalFree(pSignerInfo);
		CertCloseStore(hStore, 0);
		CryptMsgClose(hMsg);
		return FALSE;
	}

	countersignTimestamp = string(_TEXT(""));
	if (GetTimeStampSignerInfo(pSignerInfo, &pCounterSignerInfo))
	{
		SYSTEMTIME st;
		_TCHAR szBuffer[256];

		if (GetDateOfTimeStamp(pCounterSignerInfo, &st))
		{
			_sntprintf_s(szBuffer, 256, _TEXT("%04d/%02d/%02d %02d:%02d:%02d"), st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
			countersignTimestamp = string(szBuffer);
		}
	}
	else
		countersignTimestamp = GetGeneralizedTimeStampSignerInfo(pSignerInfo);

	if (!strcmp(pSignerInfo->HashAlgorithm.pszObjId, szOID_OIWSEC_sha1))
		signatureHashAlgorithm = _TEXT("SHA1");
	else if (!strcmp(pSignerInfo->HashAlgorithm.pszObjId, szOID_RSA_MD5))
		signatureHashAlgorithm = _TEXT("MD5");
	else if (!strcmp(pSignerInfo->HashAlgorithm.pszObjId, szOID_NIST_sha256))
		signatureHashAlgorithm = _TEXT("SHA256");
	else
//		signatureHashAlgorithm = pSignerInfo->HashAlgorithm.pszObjId; //a// _TEXT
		signatureHashAlgorithm = string(pSignerInfo->HashAlgorithm.pszObjId);
	StripString(signatureHashAlgorithm);

    CertInfo.Issuer = pSignerInfo->Issuer;
    CertInfo.SerialNumber = pSignerInfo->SerialNumber;

    pCertContext = CertFindCertificateInStore(hStore, ENCODING, 0, CERT_FIND_SUBJECT_CERT, (PVOID) &CertInfo, NULL);

    if (!pCertContext)
    {
		LocalFree(pSignerInfo);
		CertCloseStore(hStore, 0);
		CryptMsgClose(hMsg);
		return FALSE;
    }

    if (!(dwData = CertGetNameString(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG, NULL, NULL, 0)))
    {
		LocalFree(pSignerInfo);
		CertCloseStore(hStore, 0);
		CryptMsgClose(hMsg);
		return FALSE;
    }

    szName = (LPTSTR)LocalAlloc(LPTR, dwData * sizeof(TCHAR));
    if (!szName)
    {
		LocalFree(pSignerInfo);
		CertCloseStore(hStore, 0);
		CryptMsgClose(hMsg);
		return FALSE;
    }

    if (!(CertGetNameString(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG, NULL, szName, dwData)))
    {
	    LocalFree(szName);
		LocalFree(pSignerInfo);
		CertCloseStore(hStore, 0);
		CryptMsgClose(hMsg);
		return FALSE;
    }

	issuerName = string(szName);
	StripString(issuerName);

    LocalFree(szName);
    szName = NULL;

    if (!(dwData = CertGetNameString(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, NULL, 0)))
    {
		LocalFree(pSignerInfo);
		CertCloseStore(hStore, 0);
		CryptMsgClose(hMsg);
		return FALSE;
    }

    // Allocate memory for subject name.
    szName = (LPTSTR)LocalAlloc(LPTR, dwData * sizeof(TCHAR));
    if (!szName)
    {
		LocalFree(pSignerInfo);
		CertCloseStore(hStore, 0);
		CryptMsgClose(hMsg);
		return FALSE;
    }

    // Get subject name.
    if (!(CertGetNameString(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, szName, dwData)))
    {
	    LocalFree(szName);
		LocalFree(pSignerInfo);
		CertCloseStore(hStore, 0);
		CryptMsgClose(hMsg);
		return FALSE;
    }

	subjectName = string(szName);
	StripString(subjectName);

	GetChainHashAlgorithms(pCertContext);
	LocalFree(szName);
	CertFreeCertificateContext(pCertContext);
	LocalFree(pSignerInfo);
	CertCloseStore(hStore, 0);
	CryptMsgClose(hMsg);

	return TRUE;
}

/*
30
  82 01 0a 
    02 82 01 01 
      00 bb 3b fa ed 24 59 06 69 08 61 eb d6 e4 ab a4 
      c2 2e b7 30 7d d4 2f 3d a9 3d d7 57 5d 41 4a 32 
      2d 54 1b b6 db 44 96 80 fd bc 00 72 c7 45 d5 e5 
      cc fe 40 03 27 2e 7c fa 9e 93 f3 04 0b 94 15 6a 
      a7 8c 78 8d ab 4f e2 b2 c9 6e 2f 80 d8 87 c0 b3 
      3d 50 5c 83 b8 f2 7f 52 72 5a 6f 31 03 d1 a6 9f 
      84 db be 57 fd 20 74 76 ee 94 b8 9c 1e 62 75 07 
      0d 5e 69 a5 8a e3 b3 67 48 85 bf 7e 99 cc ce c4 
      29 a4 61 89 8b 45 88 3f e4 a1 d5 44 8c 5c 09 40 
      5a 4d b8 f6 7a f7 44 87 15 b4 ce 1d 8b bc 81 3c 
      ff fb 3e 45 51 ec 23 c5 c9 00 b3 fe fb bf fa 84 
      e5 c9 1f 52 a4 de b4 9a 64 e6 28 7f 47 ae 4d 67 
      d7 2b f3 33 ca b7 1b 42 1a f0 79 8a 6d b7 fd 70 
      19 f6 45 30 19 5e 9d 20 bc de 96 59 91 21 fb be 
      3d 12 45 b9 4e 03 5c 55 21 fe 03 29 1d ab 82 9a 
      2b 76 30 0a 50 48 9f fd f0 63 91 dc 4b e4 2e 01 
      b1 
    02 03 01 00 01
*/

int ExtractKeyLength(BYTE *pbBinary, DWORD dwBinary)
{
	unsigned int uiIndexInteger;
	unsigned int uiIter;
	int iKeylength;

	if (pbBinary[0] != 0x30)
		return -1;
	if (pbBinary[1] < 0x80)
		uiIndexInteger = 2;
	else
		uiIndexInteger = 2 + pbBinary[1] - 0x80;
	if (pbBinary[uiIndexInteger] != 0x02)
		return -2;
	if (pbBinary[uiIndexInteger + 1] < 0x80)
		if (pbBinary[uiIndexInteger + 3] == 0)
			return (pbBinary[uiIndexInteger + 1] - 1) * 8;
		else
			return pbBinary[uiIndexInteger + 1] * 8;
	iKeylength = 0;
	for (uiIter = 0; uiIter < (unsigned int)(pbBinary[uiIndexInteger + 1] - 0x80); uiIter++)
		iKeylength = iKeylength * 0x100 + pbBinary[uiIndexInteger + 2 + uiIter];
	if (pbBinary[uiIndexInteger + 2 + pbBinary[uiIndexInteger + 1] - 0x80] == 0)
		return (iKeylength - 1) * 8;
	else
		return iKeylength * 8;
}

void DumpExtensions(PCERT_INFO pCertInfo, list<string>& extensions)
{
	DWORD dwIter;

	extensions.clear();
	for (dwIter = 0; dwIter < pCertInfo->cExtension; dwIter++)
	{
		extensions.push_back(string(pCertInfo->rgExtension[dwIter].pszObjId) + (pCertInfo->rgExtension[dwIter].fCritical ? "C" : ""));
	}
}

void GetFileSigner(HANDLE hStateData, string& signatureTimestamp, list<string>& subjectNameChain, list<string>& signatureHashAlgorithmChain, list<string>& serialChain, list<string>& thumbprintChain, list<int>& keylengthChain, list<list<string>>& extensionsChain, list<int>& issuerUniqueIdChain, list<int>& subjectUniqueIdChain, list<string>& notBeforeChain, list<string>& notAfterChain)
{
	CRYPT_PROVIDER_DATA *ProviderData;
	list<string> extensions;
//	_TCHAR szID[1024];
//	_TCHAR szHex[10];

	signatureTimestamp = string(_TEXT(""));
	subjectNameChain.clear();
	signatureHashAlgorithmChain.clear();
	serialChain.clear();
	thumbprintChain.clear();
	keylengthChain.clear();
	extensionsChain.clear();
	issuerUniqueIdChain.clear();
	subjectUniqueIdChain.clear();
	notBeforeChain.clear();
	notAfterChain.clear();

	ProviderData = WTHelperProvDataFromStateData(hStateData);

	if( ProviderData )
	{
		CRYPT_PROVIDER_SGNR *SignerData;

		SignerData = WTHelperGetProvSignerFromChain(ProviderData, 0, 0, 0);

		if (SignerData)
		{
			CRYPT_PROVIDER_CERT *CertChain;
			CHAR NameBuffer[0x400];
			BYTE abSerial[0x400];
			DWORD CertCounter = 0;
			DWORD dwSize;
			FILETIME localFt;
			SYSTEMTIME st;
			_TCHAR szBuffer[256];

			FileTimeToLocalFileTime(&SignerData->sftVerifyAsOf, &localFt);
			FileTimeToSystemTime(&localFt, &st);
			_sntprintf_s(szBuffer, 256, _TEXT("%04d/%02d/%02d %02d:%02d:%02d"), st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
			signatureTimestamp = string(szBuffer);

			//OK, we got stuff!
			CertChain = SignerData->pasCertChain;

			//Loop and verify.
			while (TRUE)
			{
				//Check if we stop.
				if (CertCounter >= SignerData->csCertChain)
					break;
				if (CertCounter >= 20)
					break;

				//Get name.
				if (CertNameToStr(X509_ASN_ENCODING, &CertChain->pCert->pCertInfo->Subject, CERT_X500_NAME_STR, NameBuffer, 0x400))
				{
					string temp(NameBuffer);
					StripString(temp);
					subjectNameChain.push_back(temp);
					if (!strcmp(CertChain->pCert->pCertInfo->SignatureAlgorithm.pszObjId, szOID_RSA_SHA1RSA))
						temp = string(_TEXT("sha1RSA(RSA)"));
					else if (!strcmp(CertChain->pCert->pCertInfo->SignatureAlgorithm.pszObjId, szOID_OIWSEC_sha1RSASign))
						temp = string(_TEXT("sha1RSA(OIW)"));
					else if (!strcmp(CertChain->pCert->pCertInfo->SignatureAlgorithm.pszObjId, szOID_RSA_MD5RSA))
						temp = string(_TEXT("md5RSA(RSA)"));
					else if (!strcmp(CertChain->pCert->pCertInfo->SignatureAlgorithm.pszObjId, szOID_OIWSEC_md5RSA))
						temp = string(_TEXT("md5RSA(OIW)"));
					else if (!strcmp(CertChain->pCert->pCertInfo->SignatureAlgorithm.pszObjId, szOID_RSA_MD2RSA))
						temp = string(_TEXT("md2RSA(RSA)"));
					else if (!strcmp(CertChain->pCert->pCertInfo->SignatureAlgorithm.pszObjId, szOID_RSA_SHA256RSA))
						temp = string(_TEXT("sha256RSA(RSA)"));
					else
						temp = string(CertChain->pCert->pCertInfo->SignatureAlgorithm.pszObjId);
					StripString(temp);
					signatureHashAlgorithmChain.push_back(temp);

/*
					StringCchCopy(szID, MAX_PATH, _TEXT(""));
					for (unsigned int uiIter = 0; uiIter < CertChain->pCert->pCertInfo->SubjectPublicKeyInfo.PublicKey.cbData; uiIter++)
					{
						StringCchPrintf(szHex, 10, _TEXT("%02x"), CertChain->pCert->pCertInfo->SubjectPublicKeyInfo.PublicKey.pbData[uiIter]);
						StringCchCat(szID, 1024, szHex);
					}
					nameRoot = string(szID);
*/

					dwSize = 0x400;
					for (unsigned int uiIter = 0; uiIter < CertChain->pCert->pCertInfo->SerialNumber.cbData && uiIter < 0x400; uiIter++)
						abSerial[uiIter] = CertChain->pCert->pCertInfo->SerialNumber.pbData[CertChain->pCert->pCertInfo->SerialNumber.cbData - 1 - uiIter];
					if (CryptBinaryToString(abSerial, CertChain->pCert->pCertInfo->SerialNumber.cbData, CRYPT_STRING_HEX, NameBuffer, &dwSize))
					{
						DWORD dwIter1 = 0;
						DWORD dwIter2 = 0;
						for (dwIter1 = 0; dwIter1 < dwSize; dwIter1++)
							if (!isspace(NameBuffer[dwIter1]))
								NameBuffer[dwIter2++] = NameBuffer[dwIter1];
						NameBuffer[dwIter2] = '\0';
						temp = string(NameBuffer);
						StripString(temp);
						serialChain.push_back(temp);
					}

					string sha1;
					string error;
					if (CalculateHashOfBytes(CALG_SHA1, CertChain->pCert->pbCertEncoded, CertChain->pCert->cbCertEncoded, sha1, error))
						thumbprintChain.push_back(sha1);

					keylengthChain.push_back(ExtractKeyLength(CertChain->pCert->pCertInfo->SubjectPublicKeyInfo.PublicKey.pbData, CertChain->pCert->pCertInfo->SubjectPublicKeyInfo.PublicKey.cbData));

					DumpExtensions(CertChain->pCert->pCertInfo, extensions);
					extensionsChain.push_back(extensions);
					
					issuerUniqueIdChain.push_back(CertChain->pCert->pCertInfo->IssuerUniqueId.cbData);

					subjectUniqueIdChain.push_back(CertChain->pCert->pCertInfo->SubjectUniqueId.cbData);

					notBeforeChain.push_back(TimeToString(&CertChain->pCert->pCertInfo->NotBefore));
					notAfterChain.push_back(TimeToString(&CertChain->pCert->pCertInfo->NotAfter));

/*
					unsigned int uiIter;
					for (uiIter = 0; uiIter < CertChain->pCert->pCertInfo->cExtension; uiIter++)
					{
						cout << CertChain->pCert->pCertInfo->rgExtension[uiIter].pszObjId << endl;
					}
					cout << endl;

					dwSize = 0x400;
					if (CryptBinaryToString(CertChain->pCert->pCertInfo->SubjectPublicKeyInfo.PublicKey.pbData, CertChain->pCert->pCertInfo->SubjectPublicKeyInfo.PublicKey.cbData, CRYPT_STRING_HEX, NameBuffer, &dwSize))
					{
						DWORD dwIter1 = 0;
						DWORD dwIter2 = 0;
						for (dwIter1 = 0; dwIter1 < dwSize; dwIter1++)
							if (!isspace(NameBuffer[dwIter1]))
								NameBuffer[dwIter2++] = NameBuffer[dwIter1];
						NameBuffer[dwIter2] = '\0';
						cout << NameBuffer << endl << endl;
					}
*/
					//Get next in chain.
					CertChain = (CRYPT_PROVIDER_CERT*)((PCHAR)CertChain + CertChain->cbStruct);
				}

				CertCounter++;
			}
		}
	}

//	cout << nameRoot << endl;

	return;
}

// http://forum.sysinternals.com/howto-verify-the-digital-signature-of-a-file_topic19247.html
BOOL IsFileDigitallySigned(LPCWSTR FilePath, BOOL bNoRevocation, LPCWSTR CatalogFile, int& catalog, unsigned int& uiCountCatalogContexts, string& catalogFilename, string& issuerName, string& subjectName, string& signatureHashAlgorithm, string& signatureTimestamp, string& countersignTimestamp, list<string>& subjectNameChain, list<string>& signatureHashAlgorithmChain, list<string>& serialChain, list<string>& thumbprintChain, list<int>& keylengthChain, list<list<string>>& extensionsChain, list<int>& issuerUniqueIdChain, list<int>& subjectUniqueIdChain, list<string>& notBeforeChain, list<string>& notAfterChain, long& lError)
{
	//Author: AD, 2009
	PVOID Context;
	HANDLE FileHandle;
	DWORD HashSize = 0;
	PBYTE Buffer;
	HCATINFO CatalogContext;
	CATALOG_INFO InfoStruct;
	WINTRUST_DATA WintrustStructure;
	WINTRUST_CATALOG_INFO WintrustCatalogStructure;
	WINTRUST_FILE_INFO WintrustFileStructure;
	PWCHAR MemberTag;
	BOOLEAN ReturnFlag = FALSE;
	ULONG ReturnVal;
	GUID ActionGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;

	catalog = 0;
	lError = 0;
	issuerName = TEXT("");
	subjectName = TEXT("");
	signatureHashAlgorithm = TEXT("");
	countersignTimestamp = TEXT("");
	catalogFilename = TEXT("");
	uiCountCatalogContexts = 0;

	//Zero our structures.
	memset(&InfoStruct, 0, sizeof(CATALOG_INFO));
	InfoStruct.cbStruct = sizeof(CATALOG_INFO);
	memset(&WintrustCatalogStructure, 0, sizeof(WINTRUST_CATALOG_INFO));
	WintrustCatalogStructure.cbStruct = sizeof(WINTRUST_CATALOG_INFO);
	memset(&WintrustFileStructure, 0, sizeof(WINTRUST_FILE_INFO));
	WintrustFileStructure.cbStruct = sizeof(WINTRUST_FILE_INFO);
	memset(&WintrustStructure, 0, sizeof(WINTRUST_DATA));
	WintrustStructure.cbStruct = sizeof(WINTRUST_DATA);

	//Get a context for signature verification.
	if (!CryptCATAdminAcquireContext(&Context, NULL, 0))
		return FALSE;

	//Open file.
	FileHandle = CreateFileW(FilePath, GENERIC_READ, 7, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
	if (INVALID_HANDLE_VALUE == FileHandle)
	{
		CryptCATAdminReleaseContext(Context, 0);
		return FALSE;
	}

	//Get the size we need for our hash.
	CryptCATAdminCalcHashFromFileHandle(FileHandle, &HashSize, NULL, 0);
	if (0 == HashSize)
	{
		//0-sized has means error!
		lError = GetLastError();
		CryptCATAdminReleaseContext(Context, 0);
		CloseHandle(FileHandle);
		return FALSE;
	}

	//Allocate memory.
	Buffer = (PBYTE)calloc(HashSize, 1);

	//Actually calculate the hash
	if (!CryptCATAdminCalcHashFromFileHandle(FileHandle, &HashSize, Buffer, 0))
	{
		CryptCATAdminReleaseContext(Context, 0);
		free(Buffer);
		CloseHandle(FileHandle);
		return FALSE;
	}

	//Convert the hash to a string.
	MemberTag = (PWCHAR)calloc((HashSize * 2) + 1, sizeof(WCHAR));
	for (unsigned int i = 0; i < HashSize; i++)
		StringCchPrintfW(&MemberTag[i * 2], (HashSize * 2) + 1, L"%02X", Buffer[i]);

	if (CatalogFile == NULL)
	{
		//Get catalog for our context.
		CatalogContext = CryptCATAdminEnumCatalogFromHash(Context, Buffer, HashSize, 0, NULL);
		while (CatalogContext)
		{
			uiCountCatalogContexts++;
			CatalogContext = CryptCATAdminEnumCatalogFromHash(Context, Buffer, HashSize, 0, &CatalogContext);
		}
		for (unsigned int uiIter = 0; uiIter < uiCountCatalogContexts; uiIter++)
			CatalogContext = CryptCATAdminEnumCatalogFromHash(Context, Buffer, HashSize, 0, &CatalogContext);

		if (CatalogContext)
		{
			//If we couldn't get information
			if (!CryptCATCatalogInfoFromContext(CatalogContext, &InfoStruct, 0))
			{
				//Release the context and set the context to null so it gets picked up below.
				CryptCATAdminReleaseCatalogContext(Context, CatalogContext, 0);
				CatalogContext = NULL;
			}
		}
	}
	else
		CatalogContext = NULL;
        
	//If we have a valid context, we got our info.  
	//Otherwise, we attempt to verify the internal signature.
	if (!CatalogContext && !CatalogFile)
	{
		WintrustFileStructure.cbStruct = sizeof(WINTRUST_FILE_INFO);
		WintrustFileStructure.pcwszFilePath = FilePath;
		WintrustFileStructure.hFile = NULL;
		WintrustFileStructure.pgKnownSubject = NULL;

		WintrustStructure.dwUnionChoice = WTD_CHOICE_FILE;
		WintrustStructure.pFile = &WintrustFileStructure;
		WintrustStructure.dwUIChoice = WTD_UI_NONE;
		WintrustStructure.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
		WintrustStructure.dwStateAction = WTD_STATEACTION_VERIFY;
//		WintrustStructure.dwProvFlags = WTD_SAFER_FLAG;
		WintrustStructure.dwProvFlags = bNoRevocation ? WTD_CACHE_ONLY_URL_RETRIEVAL : WTD_REVOCATION_CHECK_CHAIN;
		WintrustStructure.hWVTStateData = NULL;
		WintrustStructure.pwszURLReference = NULL;
	}
	else
	{
		CHAR szCatalogFile[MAX_PATH];
		size_t stDummy;

		//If we get here, we have catalog info!  Verify it.
		WintrustStructure.pPolicyCallbackData = 0;
		WintrustStructure.pSIPClientData = 0;
		WintrustStructure.dwUIChoice = WTD_UI_NONE;
		WintrustStructure.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
		WintrustStructure.dwUnionChoice = WTD_CHOICE_CATALOG;
		WintrustStructure.pCatalog = &WintrustCatalogStructure;
		WintrustStructure.dwStateAction = WTD_STATEACTION_VERIFY;
		WintrustStructure.hWVTStateData = NULL;
		WintrustStructure.pwszURLReference = NULL;
//		WintrustStructure.dwProvFlags = 0;
		WintrustStructure.dwProvFlags = bNoRevocation ? WTD_CACHE_ONLY_URL_RETRIEVAL : WTD_REVOCATION_CHECK_CHAIN;
		WintrustStructure.dwUIContext = WTD_UICONTEXT_EXECUTE;

		//Fill in catalog info structure.
		WintrustCatalogStructure.cbStruct = sizeof(WINTRUST_CATALOG_INFO);
		WintrustCatalogStructure.dwCatalogVersion = 0;
		WintrustCatalogStructure.pcwszCatalogFilePath = CatalogFile != NULL ? CatalogFile : InfoStruct.wszCatalogFile;
		WintrustCatalogStructure.pcwszMemberTag = MemberTag;
		WintrustCatalogStructure.pcwszMemberFilePath = FilePath;
		WintrustCatalogStructure.hMemberFile = NULL;

		if (CatalogFile != NULL)
		{
			wcstombs_s(&stDummy, szCatalogFile, CatalogFile, MAX_PATH);
			uiCountCatalogContexts = 1;
		}
		else
			wcstombs_s(&stDummy, szCatalogFile, InfoStruct.wszCatalogFile, MAX_PATH);
		catalogFilename = string(szCatalogFile);
	}

	catalog = CatalogContext != NULL || CatalogFile != NULL ? 1 : 0;

	//Call our verification function.
	ReturnVal = WinVerifyTrust(0, &ActionGuid, &WintrustStructure);

	//Check return.
	ReturnFlag = 0 == ReturnVal;

	if (CatalogContext)
		GetSignerCertificateInfo(InfoStruct.wszCatalogFile, issuerName, subjectName, signatureHashAlgorithm, countersignTimestamp);
	else if (CatalogFile)
		GetSignerCertificateInfo(CatalogFile, issuerName, subjectName, signatureHashAlgorithm, countersignTimestamp);
	else
		GetSignerCertificateInfo(FilePath, issuerName, subjectName, signatureHashAlgorithm, countersignTimestamp);

	lError = ReturnFlag ? 0 : ReturnVal;

	//Free context.
	if (CatalogContext)
		CryptCATAdminReleaseCatalogContext(Context, CatalogContext, 0);

	GetFileSigner(WintrustStructure.hWVTStateData, signatureTimestamp, subjectNameChain, signatureHashAlgorithmChain, serialChain, thumbprintChain, keylengthChain, extensionsChain, issuerUniqueIdChain, subjectUniqueIdChain, notBeforeChain, notAfterChain);

	//If we successfully verified, we need to free.
	if (ReturnFlag)
	{
		WintrustStructure.dwStateAction = WTD_STATEACTION_CLOSE;
		WinVerifyTrust(0, &ActionGuid, &WintrustStructure);
	}

	//Free memory.
	free(MemberTag);
	free(Buffer);
	CloseHandle(FileHandle);
	CryptCATAdminReleaseContext(Context, 0);

	return ReturnFlag;
}

BOOL GetVersionInfo(LPCSTR szFilename, string& fileDescription, string& companyName, string& fileVersion, string& productVersion)
{
	DWORD dummy;
    DWORD dwSize;
    LPVOID pvVariable = NULL;
    unsigned int iVariableLength = 0;
    unsigned int iTranslations = 0;
	TCHAR pszDest[256];

	struct LANGANDCODEPAGE
	{
		WORD wLanguage;
		WORD wCodePage;
	} *lpTranslate;

	fileDescription = TEXT("");
	companyName = TEXT("");

	dwSize = GetFileVersionInfoSize(szFilename, &dummy);
	if (dwSize == 0)
        return FALSE;

    std::vector<BYTE> data(dwSize);

    if (!GetFileVersionInfo(szFilename, NULL, dwSize, &data[0]))
        return FALSE;

	if (!VerQueryValue(&data[0], TEXT("\\VarFileInfo\\Translation"), (LPVOID*)&lpTranslate, &iTranslations))
        return FALSE;

	if (FAILED(StringCchPrintf(pszDest, 256, TEXT("\\StringFileInfo\\%04x%04x\\FileDescription"), lpTranslate[0].wLanguage, lpTranslate[0].wCodePage)))
	    return FALSE;
	if (!VerQueryValue(&data[0], pszDest, &pvVariable, &iVariableLength))
	    return FALSE;
	fileDescription = string((TCHAR *)pvVariable, iVariableLength);
	StripString(fileDescription);

	if (FAILED(StringCchPrintf(pszDest, 256, TEXT("\\StringFileInfo\\%04x%04x\\CompanyName"), lpTranslate[0].wLanguage, lpTranslate[0].wCodePage)))
	    return FALSE;
	if (!VerQueryValue(&data[0], pszDest, &pvVariable, &iVariableLength))
	    return FALSE;
	companyName = string((TCHAR *)pvVariable, iVariableLength);
	StripString(companyName);

	if (FAILED(StringCchPrintf(pszDest, 256, TEXT("\\StringFileInfo\\%04x%04x\\FileVersion"), lpTranslate[0].wLanguage, lpTranslate[0].wCodePage)))
	    return FALSE;
	if (!VerQueryValue(&data[0], pszDest, &pvVariable, &iVariableLength))
	    return FALSE;
	fileVersion = string((TCHAR *)pvVariable, iVariableLength);
	StripString(fileVersion);

	if (FAILED(StringCchPrintf(pszDest, 256, TEXT("\\StringFileInfo\\%04x%04x\\ProductVersion"), lpTranslate[0].wLanguage, lpTranslate[0].wCodePage)))
	    return FALSE;
	if (!VerQueryValue(&data[0], pszDest, &pvVariable, &iVariableLength))
	    return FALSE;
	productVersion = string((TCHAR *)pvVariable, iVariableLength);
	StripString(productVersion);

	return TRUE;
}

BOOL ReadBytes(HANDLE hFile, LPVOID buffer, DWORD size, string& error)
{
	DWORD bytes;
	DWORD dwLastError = 0;

	if (!ReadFile(hFile, buffer, size, &bytes, NULL))
	{
		dwLastError = GetLastError();
		error = TEXT("*Error reading file ") + MyFormatMessage(dwLastError);
		return TRUE;
	}
	else if (size != bytes)
	{
		error = TEXT("*Read the wrong number of bytes");
		return TRUE;
	}
	return FALSE;
}

DWORD AbsoluteSeek(HANDLE hFile, DWORD offset, string &error)
{
    DWORD newOffset;
	DWORD dwLastError = 0;

	newOffset = SetFilePointer(hFile, offset, NULL, FILE_BEGIN);
    if (INVALID_SET_FILE_POINTER == newOffset)
	{
		dwLastError = GetLastError();
		error = TEXT("*Error SetFilePointer ") + MyFormatMessage(dwLastError);
	}

    return newOffset;
}

#define MAX_NUMBER_OF_SECTIONS 0x100

BOOL AnalyzeSections(HANDLE hFile, WORD wNumberOfSections, list<string>& sections, DWORD& dwVirtualAddress, DWORD& dwPointerToRawData, string& error)
{
	PIMAGE_SECTION_HEADER pimage_section_header;
    BYTE abBuffer[sizeof(IMAGE_SECTION_HEADER) * MAX_NUMBER_OF_SECTIONS];
	CHAR szBuffer[256];
	WORD wIter;

	dwVirtualAddress = 0;
	dwPointerToRawData = 0;
	sections.clear();
	if (ReadBytes(hFile, abBuffer, min(sizeof(abBuffer), sizeof(IMAGE_SECTION_HEADER) * wNumberOfSections), error))
		return FALSE;
	for (wIter = 0; wIter < min(wNumberOfSections, MAX_NUMBER_OF_SECTIONS); wIter++)
	{
		pimage_section_header = (PIMAGE_SECTION_HEADER) (abBuffer + wIter * sizeof(IMAGE_SECTION_HEADER));
		strncpy_s(szBuffer, (CHAR *)pimage_section_header->Name, 8);
		sections.push_back(szBuffer);
		if (!strcmp(szBuffer, ".text"))
		{
			dwVirtualAddress = pimage_section_header->VirtualAddress;
			dwPointerToRawData = pimage_section_header->PointerToRawData;
		}
	}
	return TRUE;
}

typedef struct 
{
	DWORD dwSize;
	WORD wMajorVersion;
	WORD wMinorVersion;
	DWORD dwCLRRVA;
} CLR_HEADER;

typedef struct 
{
	DWORD dwMagic;
	DWORD dwDummy1;
	DWORD dwDummy2;
	DWORD dwVersionSize;
	BYTE abVersion[16];
} CLR_METADATA;

BOOL ParseDER(PBYTE pbSignature, DWORD dwSize, HCRYPTHASH hHash, DWORD& dwPositionError, int& iTypeError)
{
	int iType;
	int iClass;
	DWORD dwPosition = 0;
	DWORD dwSizeFound;
	DWORD dwBytesParsed;

	dwPositionError = 0;
	iTypeError = -1;

	if (NULL == pbSignature)
	{
		iTypeError = -1;
		return FALSE;
	}

	while (dwSize > dwPosition)
	{
		if (!SafeToReadNBytes(dwSize, dwPosition, 2))
		{
			dwPositionError = dwPosition;
			iTypeError = -2;
			return FALSE;
		}

		ParseDERType(pbSignature[dwPosition], iType, iClass);
#ifdef _DEBUG
		printf("<ParseDER %d %02x>\n", iClass, iType);
#endif
		if (!CryptHashData(hHash, pbSignature + dwPosition, 1, 0))
		{
			dwPositionError = dwPosition;
			iTypeError = -3;
			return FALSE;
		}
		switch (iType)
		{
			case 0x05: // NULL
				dwPosition++;
				if (pbSignature[dwPosition] != 0x00)
				{
					dwPositionError = dwPosition;
					iTypeError = -4;
					return FALSE;
				}
				dwPosition++;
				break;
			case 0x06: // OID
				dwPosition++;
				if (!SafeToReadNBytes(dwSize - dwPosition, 1, pbSignature[dwPosition]))
				{
					dwPositionError = dwPosition;
					iTypeError = -5;
					return FALSE;
				}
#ifdef _DEBUG
				for (int iIter = 0; iIter < pbSignature[dwPosition]; iIter++)
					printf("%02X ", pbSignature[dwPosition + 1 + iIter]);
				printf("\n");
#endif
				if (!CryptHashData(hHash, pbSignature + dwPosition + 1, pbSignature[dwPosition], 0))
				{
					dwPositionError = dwPosition;
					iTypeError = -6;
					return FALSE;
				}
				dwPosition += 1 + pbSignature[dwPosition];
				break;
			case 0x00: // ?
			case 0x01: // boolean
			case 0x02: // integer
			case 0x03: // bit string
			case 0x04: // octec string
			case 0x0A: // enumerated
			case 0x0C: // UTF8string
			case 0x13: // printable string
			case 0x14: // T61 string
			case 0x16: // IA5String
			case 0x17: // UTC time
			case 0x18: // Generalized time
			case 0x1E: // BMPstring
				dwPosition++;
				if (!ParseDERSize(pbSignature + dwPosition, dwSize - dwPosition, dwSizeFound, dwBytesParsed))
				{
					dwPositionError = dwPosition;
					iTypeError = -7;
					return FALSE;
				}
				dwPosition += dwBytesParsed;
				if (!SafeToReadNBytes(dwSize - dwPosition, 0, dwSizeFound))
				{
					dwPositionError = dwPosition;
					iTypeError = -8;
					return FALSE;
				}
				dwPosition += dwSizeFound;
				break;
			case 0x20: // context specific
			case 0x21: // context specific
			case 0x23: // context specific
			case 0x24: // context specific
			case 0x30: // sequence
			case 0x31: // set
				dwPosition++;
				if (!ParseDERSize(pbSignature + dwPosition, dwSize - dwPosition, dwSizeFound, dwBytesParsed))
				{
				dwPositionError = dwPosition;
					iTypeError = -9;
					return FALSE;
				}
				dwPosition += dwBytesParsed;
				break;
			case 0x22: // ?
				dwPosition += 2;
				break;
			default:
#ifdef _DEBUG
				printf("<ParseDER %d %02x %d>\n", iClass, iType, dwPosition);
#endif
				dwPositionError = dwPosition;
				iTypeError = iType;
				return FALSE;
		}
	}

	return TRUE;
}

#define SHA256LEN 32

string CalculateDEROIDHash(PBYTE pbSignature, DWORD dwSize)
{
	HCRYPTPROV hProv = 0;
	HCRYPTHASH hHash = 0;
	string result = string();
	DWORD cbHash = SHA256LEN;
	BYTE rgbHash[SHA256LEN];
	CHAR rgbDigits[] = TEXT("0123456789abcdef");
	char hexbyte[3];
	DWORD dwPositionError = 0;
	int iTypeError = 0;
	BOOL bResult;

	if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
		return result;

	if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash))
	{
		CryptReleaseContext(hProv, 0);
		return result;
	}

	bResult = ParseDER(pbSignature, dwSize, hHash, dwPositionError, iTypeError);
	if (!bResult)
		result = string(TEXT("!"));

	hexbyte[2] = '\0';
	if (CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0))
	{
		for (DWORD i = 0; i < cbHash; i++)
		{
			hexbyte[0] = rgbDigits[rgbHash[i] >> 4];
			hexbyte[1] = rgbDigits[rgbHash[i] & 0xf];
			result.append(hexbyte);
		}
	}
	else
	{
		CryptReleaseContext(hProv, 0);
		CryptDestroyHash(hHash);
		return result;
	}

	CryptDestroyHash(hHash);
	CryptReleaseContext(hProv, 0);

	if (!bResult)
	{
		result.append(_TEXT(":"));
		result.append(std::to_string(iTypeError));
		result.append(_TEXT(":"));
		result.append(std::to_string(dwPositionError));
	}
	return result;
}

BOOL ParsePKCS7DER(PBYTE pbSignature, DWORD dwSize, DWORD& dwPKCS7Size, DWORD& dwBytesAfterPKCS7, DWORD& dwBytesAfterPKCS7NotZero, string& signingtime)
{
	DWORD dwBytesParsed = 0;
	BYTE abSigningTime[] = { 0x30, 0x1C, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x05, 0x31, 0x0F, 0x17, 0x0D };
	char szSigningTime[0x0D + 1];

	if (NULL == pbSignature)
			return FALSE;
	if (!SafeToReadNBytes(dwSize, 0, 2))
		return FALSE;
	if (0x30 != pbSignature[0])
		return FALSE;
	if (pbSignature[1] > 0x80 && !SafeToReadNBytes(dwSize, 2, pbSignature[1] - 0x80))
		return FALSE;
	if (pbSignature[1] <= 0x80)
	{
		dwPKCS7Size = pbSignature[1];
		dwBytesParsed = 2;
	}
	else
	{
		dwPKCS7Size = ReadNumberFromNBytes(pbSignature, 2, pbSignature[1] - 0x80);
		dwBytesParsed = 2 + pbSignature[1] - 0x80;
	}
	if (!SafeToReadNBytes(dwSize, dwBytesParsed, dwPKCS7Size))
		return FALSE;

	dwBytesAfterPKCS7 = dwSize - dwBytesParsed - dwPKCS7Size;
	for (DWORD i = 0; i < dwBytesAfterPKCS7; i++)
	if (0x00 != pbSignature[dwBytesParsed + dwPKCS7Size + i])
		dwBytesAfterPKCS7NotZero++;

	for (DWORD i = 0; i < dwPKCS7Size - sizeof(abSigningTime); i++)
	if (pbSignature[dwBytesParsed + i] == abSigningTime[0])
	if (!memcmp(pbSignature + dwBytesParsed + i, abSigningTime, sizeof(abSigningTime)))
	{
		strncpy_s(szSigningTime, (char *)(pbSignature + dwBytesParsed + i + sizeof(abSigningTime)), 0x0D);
		signingtime = string(szSigningTime);
	}

	return TRUE;
}

void UnixTimeToFileTime(time_t t, LPFILETIME pft)
{
	// Note that LONGLONG is a 64-bit value
	LONGLONG ll;

	ll = Int32x32To64(t, 10000000) + 116444736000000000;
	pft->dwLowDateTime = (DWORD)ll;
	pft->dwHighDateTime = ll >> 32;
}

// http://support.microsoft.com/kb/90493
BOOL GetFileInfo(string filename, string& compiletime, string& creationtime, string& lastwritetime, string& lastaccesstime, DWORD& dwFileAttributes, unsigned int& uiCharacteristics, list<string>& sections, unsigned int& uiMagic, unsigned int& uiSubsystem, unsigned int& uiSizeOfCode, unsigned int& uiAddressOfEntryPoint, unsigned int& uiRVA15, string& clrVersion, DWORD& dwSignatureSize1, DWORD& dwSignatureSize2, WORD& wSignatureRevision, WORD& wSignatureCertificateType, DWORD& dwBytesAfterSignature, BOOL& bParsePKCS7DERResult, DWORD& dwPKCS7Size, DWORD& dwBytesAfterPKCS7, DWORD& dwBytesAfterPKCS7NotZero, string& signingtime, DWORD& dwFileSize, string& ownername, string& DEROIDHash, string& error)
{
	HANDLE hFile = NULL;
	DWORD dwLastError = 0;
	DWORD dwOffset;
	DWORD dwTextSectionVirtualAddress;
	DWORD dwTextSectionPointerToRawData;
	PBYTE pbSignature;
	DWORD dwRVASignature = 0;
	LARGE_INTEGER liFileSize;
	FILETIME ftCompiled;

	IMAGE_DOS_HEADER image_dos_header;
	union
	{
		IMAGE_NT_HEADERS32 image_nt_headers32;
		IMAGE_NT_HEADERS64 image_nt_headers64;
	};
	CLR_HEADER clr_header;
	CLR_METADATA clr_metadata;
	WIN_CERTIFICATE *psWC;

	uiCharacteristics = 0;
	uiMagic = 0;
	uiSubsystem = 0;
	uiSizeOfCode = 0;
	uiAddressOfEntryPoint = 0;
	uiRVA15 = 0;
	clrVersion = "";
	dwSignatureSize1 = 0;
	dwSignatureSize2 = 0;
	wSignatureRevision = 0;
	wSignatureCertificateType = 0;
	dwBytesAfterSignature = 0;
	bParsePKCS7DERResult = FALSE;
	dwPKCS7Size = 0;
	dwBytesAfterPKCS7 = 0;
	dwBytesAfterPKCS7NotZero = 0;
	signingtime = "";
	dwFileSize = 0;
	compiletime = "";
	ownername = "";
	DEROIDHash = "";

	hFile = CreateFile(filename.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN | FILE_FLAG_BACKUP_SEMANTICS, NULL);

	if (INVALID_HANDLE_VALUE == hFile)
	{
		dwLastError = GetLastError();
		error = TEXT("*Error opening file ") + MyFormatMessage(dwLastError);
		return FALSE;
	}

	if (!GetFileSizeEx(hFile, &liFileSize))
	{
		dwLastError = GetLastError();
		CloseHandle(hFile);
		error = TEXT("*Error getting filesize ") + MyFormatMessage(dwLastError);
		return FALSE;
	}

	if (0 != liFileSize.HighPart)
	{
		CloseHandle(hFile);
		error = TEXT("*Error filesize larger than 4GB");
		return FALSE;
	}

	dwFileSize = liFileSize.LowPart;

	if (ReadBytes(hFile, &image_dos_header, sizeof(IMAGE_DOS_HEADER), error))
	{
		CloseHandle(hFile);
		return FALSE;
	}
	if (IMAGE_DOS_SIGNATURE != image_dos_header.e_magic)
	{
		error = TEXT("*Error no IMAGE_DOS_SIGNATURE");
		CloseHandle(hFile);
		return FALSE;
	}

	dwOffset = AbsoluteSeek(hFile, image_dos_header.e_lfanew, error);
	if (INVALID_SET_FILE_POINTER == dwOffset)
	{
		CloseHandle(hFile);
		return FALSE;
	}

	if (ReadBytes(hFile, &image_nt_headers64, sizeof(image_nt_headers64), error))
	{
		CloseHandle(hFile);
		return FALSE;
	}
	if (IMAGE_NT_SIGNATURE != image_nt_headers32.Signature)
	{
		error = TEXT("*Error no IMAGE_NT_SIGNATURE");
		CloseHandle(hFile);
		return FALSE;
	}
	uiCharacteristics = image_nt_headers32.FileHeader.Characteristics;
	uiSubsystem = image_nt_headers32.OptionalHeader.Subsystem;
	uiSizeOfCode = image_nt_headers32.OptionalHeader.SizeOfCode;
	uiAddressOfEntryPoint = image_nt_headers32.OptionalHeader.AddressOfEntryPoint;
	uiMagic = image_nt_headers32.OptionalHeader.Magic;
	switch (uiMagic)
	{
		case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
			dwRVASignature = image_nt_headers32.OptionalHeader.DataDirectory[4].VirtualAddress;
			dwSignatureSize1 = image_nt_headers32.OptionalHeader.DataDirectory[4].Size;
			uiRVA15 = image_nt_headers32.OptionalHeader.DataDirectory[14].VirtualAddress;
			break;
		case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
			dwRVASignature = image_nt_headers64.OptionalHeader.DataDirectory[4].VirtualAddress;
			dwSignatureSize1 = image_nt_headers64.OptionalHeader.DataDirectory[4].Size;
			uiRVA15 = image_nt_headers64.OptionalHeader.DataDirectory[14].VirtualAddress;
			break;
	}
	dwOffset = AbsoluteSeek(hFile, image_dos_header.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + image_nt_headers32.FileHeader.SizeOfOptionalHeader, error);
	if (INVALID_SET_FILE_POINTER == dwOffset)
	{
		CloseHandle(hFile);
		return FALSE;
	}
	UnixTimeToFileTime(image_nt_headers32.FileHeader.TimeDateStamp, &ftCompiled);
	compiletime = TimeToString(&ftCompiled);
	if (!AnalyzeSections(hFile, image_nt_headers32.FileHeader.NumberOfSections, sections, dwTextSectionVirtualAddress, dwTextSectionPointerToRawData, error))
	{
		CloseHandle(hFile);
		return FALSE;
	}
	if (0 != uiRVA15)
	{
		dwOffset = AbsoluteSeek(hFile, dwTextSectionPointerToRawData + uiRVA15 - dwTextSectionVirtualAddress, error);
		if (INVALID_SET_FILE_POINTER != dwOffset && !ReadBytes(hFile, &clr_header, sizeof(clr_header), error) && clr_header.dwSize == 0x48)
		{
			dwOffset = AbsoluteSeek(hFile, dwTextSectionPointerToRawData + clr_header.dwCLRRVA - dwTextSectionVirtualAddress, error);
			if (INVALID_SET_FILE_POINTER != dwOffset && !ReadBytes(hFile, &clr_metadata, sizeof(clr_metadata), error) && clr_metadata.dwMagic == 0x424A5342)
			{
				CHAR szBuffer[17];

				strncpy_s(szBuffer, (CHAR *)clr_metadata.abVersion, 16);
				clrVersion = string(szBuffer);
			}
		}
	}
	if (0 != dwRVASignature)
		dwBytesAfterSignature = liFileSize.LowPart - dwRVASignature - dwSignatureSize1;
	if (dwSignatureSize1 > 8)
	{
		pbSignature = (PBYTE) LocalAlloc(LPTR, dwSignatureSize1);
		if (!pbSignature)
		{
			dwLastError = GetLastError();
			CloseHandle(hFile);
			error = TEXT("*Error LocalAlloc failed ") + MyFormatMessage(dwLastError);
			return FALSE;
		}
		dwOffset = AbsoluteSeek(hFile, dwRVASignature, error);
		if (INVALID_SET_FILE_POINTER != dwOffset && !ReadBytes(hFile, pbSignature, dwSignatureSize1, error))
		{
			psWC = (WIN_CERTIFICATE *)pbSignature;
			dwSignatureSize2 = psWC->dwLength;
			wSignatureRevision = psWC->wRevision;
			wSignatureCertificateType = psWC->wCertificateType;
			bParsePKCS7DERResult = ParsePKCS7DER(pbSignature + 8, dwSignatureSize1 - 8, dwPKCS7Size, dwBytesAfterPKCS7, dwBytesAfterPKCS7NotZero, signingtime);
			DEROIDHash = CalculateDEROIDHash(pbSignature + 8, dwSignatureSize1 - 8 - dwBytesAfterPKCS7);
		}
		LocalFree(pbSignature);
	}

	GetFileTimes(hFile, creationtime, lastwritetime, lastaccesstime);

	GetOwnerName(hFile, ownername);

	CloseHandle(hFile);

	dwFileAttributes = GetFileAttributes(filename.c_str());

	return TRUE; 
}

BOOL IsPEFile(_TCHAR* pszArgument)
{
	HANDLE hFile = NULL;
	string error;

	IMAGE_DOS_HEADER image_dos_header;
	union
	{
		IMAGE_NT_HEADERS32 image_nt_headers32;
		IMAGE_NT_HEADERS64 image_nt_headers64;
	};

	hFile = CreateFile(pszArgument, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN | FILE_FLAG_BACKUP_SEMANTICS, NULL);

	if (INVALID_HANDLE_VALUE == hFile)
		return FALSE;

	if (ReadBytes(hFile, &image_dos_header, sizeof(IMAGE_DOS_HEADER), error))
	{
		CloseHandle(hFile);
		return FALSE;
	}
	if (IMAGE_DOS_SIGNATURE != image_dos_header.e_magic)
	{
		CloseHandle(hFile);
		return FALSE;
	}

	if (INVALID_SET_FILE_POINTER == AbsoluteSeek(hFile, image_dos_header.e_lfanew, error))
	{
		CloseHandle(hFile);
		return FALSE;
	}

	if (ReadBytes(hFile, &image_nt_headers64, sizeof(image_nt_headers64), error))
	{
		CloseHandle(hFile);
		return FALSE;
	}
	if (IMAGE_NT_SIGNATURE != image_nt_headers32.Signature)
	{
		CloseHandle(hFile);
		return FALSE;
	}

	CloseHandle(hFile);

	return TRUE;
}

LPTSTR lpServerName = NULL;

PSID ConvertNameToBinarySid(LPTSTR pAccountName)
{
	LPTSTR pDomainName = NULL;
	DWORD dwDomainNameSize = 0;
	PSID pSid = NULL;
	DWORD dwSidSize = 0;
	SID_NAME_USE sidType;
	BOOL fSuccess = FALSE;
	HRESULT hr = S_OK;

	__try
	{
		LookupAccountName(
			lpServerName,      // look up on local system
			pAccountName,
			pSid,              // buffer to receive name
			&dwSidSize,
			pDomainName,
			&dwDomainNameSize,
			&sidType);

		//  If the Name cannot be resolved, LookupAccountName will fail with
		//  ERROR_NONE_MAPPED.
		if (GetLastError() == ERROR_NONE_MAPPED)
		{
			printf_s(_T("LookupAccountName failed with %d\n"), GetLastError());
			__leave;
		}
		else if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
		{
			pSid = (LPTSTR)LocalAlloc(LPTR, dwSidSize * sizeof(TCHAR));
			if (pSid == NULL)
			{
				printf_s(_T("LocalAlloc failed with %d\n"), GetLastError());
				__leave;
			}

			pDomainName = (LPTSTR)LocalAlloc(LPTR, dwDomainNameSize * sizeof(TCHAR));
			if (pDomainName == NULL)
			{
				printf_s(_T("LocalAlloc failed with %d\n"), GetLastError());
				__leave;
			}

			if (!LookupAccountName(
				lpServerName,      // look up on local system
				pAccountName,
				pSid,              // buffer to receive name
				&dwSidSize,
				pDomainName,
				&dwDomainNameSize,
				&sidType))
			{
				printf_s(_T("LookupAccountName failed with %d\n"), GetLastError());
				__leave;
			}
		}

		//  Any other error code
		else
		{
			printf_s(_T("LookupAccountName failed with %d\n"), GetLastError());
			__leave;
		}

		fSuccess = TRUE;
	}
	__finally
	{
		if (pDomainName != NULL)
		{
			LocalFree(pDomainName);
			pDomainName = NULL;
		}

		//  Free pSid only if failed;
		//  otherwise, the caller has to free it after use.
		if (fSuccess == FALSE)
		{
			if (pSid != NULL)
			{
				LocalFree(pSid);
				pSid = NULL;
			}
		}
	}

	return pSid;
}


void DisplayError(char* pszAPI, DWORD dwError)
{
	LPVOID lpvMessageBuffer;

	if (!FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_HMODULE | FORMAT_MESSAGE_FROM_SYSTEM,
		GetModuleHandle("Kernel32.dll"), dwError,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),  // the user default language
		(LPTSTR)&lpvMessageBuffer, 0, NULL))
	{
		printf_s("FormatMessage failed with %d\n", GetLastError());
		ExitProcess(GetLastError());
	}

	//  ...now display this string.
	printf_s("ERROR: API        = %s.\n", (char *)pszAPI);
	printf_s("       error code = %08X.\n", dwError);
	printf_s("       message    = %s.\n", (char *)lpvMessageBuffer);

	//  Free the buffer allocated by the system.
	LocalFree(lpvMessageBuffer);

	ExitProcess(GetLastError());
}

list<string> DisplayAccessMask(ACCESS_MASK Mask)
{
	list<string> text;

	if (((Mask & GENERIC_ALL) == GENERIC_ALL) || ((Mask & FILE_ALL_ACCESS) == FILE_ALL_ACCESS))
	{
		text.push_back("Full Control");
		return text;
	}
	if (((Mask & GENERIC_READ) == GENERIC_READ) || ((Mask & FILE_GENERIC_READ) == FILE_GENERIC_READ))
		text.push_back("Generic Read");
	if (((Mask & GENERIC_WRITE) == GENERIC_WRITE) || ((Mask & FILE_GENERIC_WRITE) == FILE_GENERIC_WRITE))
		text.push_back("Generic Write");
	if (((Mask & GENERIC_EXECUTE) == GENERIC_EXECUTE) || ((Mask & FILE_GENERIC_EXECUTE) == FILE_GENERIC_EXECUTE))
		text.push_back("Generic Execute");
	return text;
}

DWORD GetAccess(AUTHZ_CLIENT_CONTEXT_HANDLE hAuthzClient, PSECURITY_DESCRIPTOR psd)
{
	AUTHZ_ACCESS_REQUEST AccessRequest = { 0 };
	AUTHZ_ACCESS_REPLY AccessReply = { 0 };
	BYTE     Buffer[1024];
	BOOL bRes = FALSE;  // assume error

	//  Do AccessCheck.
	AccessRequest.DesiredAccess = MAXIMUM_ALLOWED;
	AccessRequest.PrincipalSelfSid = NULL;
	AccessRequest.ObjectTypeList = NULL;
	AccessRequest.ObjectTypeListLength = 0;
	AccessRequest.OptionalArguments = NULL;

	RtlZeroMemory(Buffer, sizeof(Buffer));
	AccessReply.ResultListLength = 1;
	AccessReply.GrantedAccessMask = (PACCESS_MASK)(Buffer);
	AccessReply.Error = (PDWORD)(Buffer + sizeof(ACCESS_MASK));


	if (!AuthzAccessCheck(0,
		hAuthzClient,
		&AccessRequest,
		NULL,
		psd,
		NULL,
		0,
		&AccessReply,
		NULL)) {
		printf_s(_T("AuthzAccessCheck failed with %d\n"), GetLastError());
	}

	return *(PACCESS_MASK)(AccessReply.GrantedAccessMask);
}

DWORD GetEffectiveRightsForUser(AUTHZ_RESOURCE_MANAGER_HANDLE hManager,
	PSECURITY_DESCRIPTOR psd,
	LPTSTR lpszUserName)
{
	PSID pSid = NULL;
	BOOL bResult = FALSE;
	LUID unusedId = { 0 };
	AUTHZ_CLIENT_CONTEXT_HANDLE hAuthzClientContext = NULL;
	ACCESS_MASK am1 = 0;


	pSid = ConvertNameToBinarySid(lpszUserName);
	if (pSid != NULL)
	{
		bResult = AuthzInitializeContextFromSid(0,
			pSid,
			hManager,
			NULL,
			unusedId,
			NULL,
			&hAuthzClientContext);
		if (bResult)
		{
			am1 = GetAccess(hAuthzClientContext, psd);
			AuthzFreeContext(hAuthzClientContext);
		}
		else
			printf_s(_T("AuthzInitializeContextFromSid failed with %d\n"), GetLastError());
	}
	if (pSid != NULL)
	{
		LocalFree(pSid);
		pSid = NULL;
	}

	return am1;
}

DWORD UseAuthzSolution(PSECURITY_DESCRIPTOR psd, LPTSTR lpszUserName)
{
	AUTHZ_RESOURCE_MANAGER_HANDLE hManager;
	BOOL bResult = FALSE;
	ACCESS_MASK am1 = 0;

	bResult = AuthzInitializeResourceManager(AUTHZ_RM_FLAG_NO_AUDIT,
		NULL, NULL, NULL, NULL, &hManager);
	if (bResult)
	{
		am1 = GetEffectiveRightsForUser(hManager, psd, lpszUserName);
		AuthzFreeResourceManager(hManager);
	}
	else
		printf_s(_T("AuthzInitializeResourceManager failed with %d\n"), GetLastError());

	return am1;
}

BOOL GetFileSecurityInfo(string filename, LPTSTR pszUser, ACCESS_MASK& am)
{
	PACL                 pacl;
	PSECURITY_DESCRIPTOR psd;
	PSID                 psid = NULL;

	am = 0;

	if (GetNamedSecurityInfo(filename.c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION, NULL, NULL, &pacl, NULL, &psd) != ERROR_SUCCESS)
		return FALSE;

	am = UseAuthzSolution(psd, pszUser);


	if (psid != NULL)
	{
		LocalFree(psid);
		psid = NULL;
	};

	LocalFree(psd);

	return TRUE;
}

#define MAX_NAME 256
BOOL GetLogonFromToken(HANDLE hToken, string& user, string& domain)
{
	DWORD dwSize = MAX_NAME;
	BOOL bSuccess = FALSE;
	DWORD dwLength = 0;
	user = string("");
	domain = string("");
	PTOKEN_USER ptu = NULL;
	//Verify the parameter passed in is not NULL.
	if (NULL == hToken)
		goto Cleanup;

	if (!GetTokenInformation(
		hToken,         // handle to the access token
		TokenUser,    // get information about the token's groups 
		(LPVOID)ptu,   // pointer to PTOKEN_USER buffer
		0,              // size of buffer
		&dwLength       // receives required buffer size
		))
	{
		if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
			goto Cleanup;

		ptu = (PTOKEN_USER)HeapAlloc(GetProcessHeap(),
			HEAP_ZERO_MEMORY, dwLength);

		if (ptu == NULL)
			goto Cleanup;
	}

	if (!GetTokenInformation(
		hToken,         // handle to the access token
		TokenUser,    // get information about the token's groups 
		(LPVOID)ptu,   // pointer to PTOKEN_USER buffer
		dwLength,       // size of buffer
		&dwLength       // receives required buffer size
		))
	{
		goto Cleanup;
	}
	SID_NAME_USE SidType;
	char lpName[MAX_NAME];
	char lpDomain[MAX_NAME];

	if (LookupAccountSid(NULL, ptu->User.Sid, lpName, &dwSize, lpDomain, &dwSize, &SidType))
	{
		user = string(lpName);
		domain = string(lpDomain);
		bSuccess = TRUE;
	}

Cleanup:

	if (ptu != NULL)
		HeapFree(GetProcessHeap(), 0, (LPVOID)ptu);
	return bSuccess;
}

BOOL GetUserFromProcess(const DWORD procId, string& user, string& domain)
{
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, procId);
	if (hProcess == NULL)
		return E_FAIL;
	HANDLE hToken = NULL;

	if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken))
	{
		CloseHandle(hProcess);
		return E_FAIL;
	}
	BOOL bres = GetLogonFromToken(hToken, user, domain);

	CloseHandle(hToken);
	CloseHandle(hProcess);
	return bres;
}
