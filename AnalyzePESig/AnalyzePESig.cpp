/*
	AnalyzePESig
	Source code put in public domain by Didier Stevens, no Copyright
	https://DidierStevens.com
	Use at your own risk

	Editor tab stop value = 4

	Shortcomings, or todo's ;-)

	History:
		2012/06/14: 0.0.0.1 Start development
		2012/07/10: Added subjectNameChain, signatureHashAlgorithmChain
		2012/07/11: Added ProcessFiles and IsPEFile
		2012/07/16: Added options
		2012/08/28: Added serialChain and rootSerial
		2012/08/29: Replaced concatenated strings for chains with lists
		2012/09/06: Added option -o
		2012/09/07: Added thumbprint; option -x
		2012/09/10: Added keylengthChain
		2012/09/12: Added countersignTimestamp; added catalog
		2012/10/01: Reversed serialnumber byte array; added ParseArgs
		2012/10/15: 0.0.0.2 Added countCatalogs and catalogFilename
		2012/10/16: Added signatureTimestamp
		2012/10/18: Added creationtime, lastwritetime, lastaccesstime, dwFileAttributes and uiCharacteristics
		2012/10/19: Continued
		2012/10/23: Added extensions
		2012/10/24: Added issuer unique id
		2012/10/25: Continued
		2012/10/26: Added sections and subject unique id
		2012/10/27: Added notBeforeChain and notAfterChain
		2012/11/28: 0.0.0.3 Fix for extra \ in ProcessFiles
		2012/11/29: Added CurrentProcessAdjustToken
		2013/03/09: Added uiMagic
		2013/03/11: Added GetFileInfo; reprogrammed IsPEFile and moved to AnalysisFunctions; added clrVersion
		2013/04/29: Added PKCS7 signature extraction and parsing
		2013/05/04: Added option l
		2013/05/17: Added compiletime
		2013/08/07: Added uiSubsystem, uiIcons; used WIN_CERTIFICATE
		2013/08/08: Added option -r
		2013/08/14: Added SizeOfCode
		2014/01/24: 0.0.0.4 Added option -c catalogfile
		2014/01/30: Added extra arguments; added option -O
		2014/02/03: Added Extension
		2014/05/14: Added fileVersion and productVersion
		2014/05/15: Added @file processing
		2014/08/07: Added AddressOfEntryPoint
		2014/10/11: Added Quote
		2014/11/21: Added ownername
		2014/11/29: Fixed bug in ExtractKeyLength; start DEROIDHash
		2014/11/30: Continued DEROIDHash
		2014/12/02: Fixed bug SafeToReadNBytes
		2014/12/30: Continued DEROIDHash; intialized uiCountCatalogContexts properly
		2014/12/31: Bugfix DEROIDHash
		2015/01/11: Continued DEROIDHash
		2015/01/16: 0.0.0.5 Fix potential bug WintrustStructure
		2015/03/28: Replaced spaces with underscores in header
		2015/03/28: Replaced spaces with underscores in header
		2015/11/20: added FILE_FLAG_BACKUP_SEMANTICS to CreateFile calls
		2015/11/24: updated to parse countersignature timestamp szOID_RFC3161_counterSign
*/

#include "stdafx.h"

#pragma comment (lib, "Shlwapi.lib")

#define SEP _TEXT(";")

string ListToString(list<string> list1, string separator)
{
	string result = "";
	list<string>::iterator i;

	for (i=list1.begin(); i != list1.end(); i++)
		if (i == list1.begin())
			result = *i;
		else
			result += separator + *i;

	return result;
}

string ListToStringSort(list<string> list1, string separator)
{
	string result = "";
	list<string>::iterator i;

	list1.sort();

	for (i=list1.begin(); i != list1.end(); i++)
		if (i == list1.begin())
			result = *i;
		else
			result += separator + *i;

	return result;
}

string ListIntToString(list<int> list1)
{
	string result = "";
	list<int>::iterator i;
	_TCHAR szBuffer[10];

	for (i=list1.begin(); i != list1.end(); i++)
	{
		_itoa_s(*i, szBuffer, 10);
		if (i == list1.begin())
			result = string(szBuffer);
		else
			result += "|" + string(szBuffer);
	}

	return result;
}

string ListListToStringSort(list<list<string>> list1)
{
	string result = "";
	list<list<string>>::iterator i;

	for (i=list1.begin(); i != list1.end(); i++)
		if (i == list1.begin())
			result = ListToStringSort(*i, ",");
		else
			result += "|" + ListToStringSort(*i, ",");

	return result;
}

void SearchAndReplace(string& value, string& search, string& replace)
{
	string::size_type next;

	for (next = value.find(search); next != string::npos; next = value.find(search, next))
	{
		value.replace(next, search.length(), replace);
		next += replace.length();
	}
}

string XMLElementSingleLine(unsigned int uiIndentation, _TCHAR* element, string& value)
{
	unsigned int uiIter;
	string space = _TEXT("");

	SearchAndReplace(value, string(_TEXT("&")), string(_TEXT("&amp;")));
	SearchAndReplace(value, string(_TEXT("<")), string(_TEXT("&lt;")));
	SearchAndReplace(value, string(_TEXT(">")), string(_TEXT("&gt;")));
	for (uiIter = 0; uiIter < uiIndentation; uiIter++)
		space += _TEXT(" ");
	return space + string(_TEXT("<")) + string(element) + string(_TEXT(">")) + value + string(_TEXT("</")) + string(element) + string(_TEXT(">")) ;
}

string DecodeCharacteristics(unsigned int characteristics)
{
	string result = "";

	if (characteristics & 0x2)
		result += "exec";
	if (characteristics & 0x2000)
	{
		if (result != "")
			result += " ";
		result += "dll";
	}
	return result;
}

string DecodeFileAttributes(DWORD fileattributes)
{
	string result = "";

	if (fileattributes & 0x20)
		result += "A";
	if (fileattributes & 0x4)
		result += "S";
	if (fileattributes & 0x2)
		result += "H";
	if (fileattributes & 0x1)
		result += "R";
	return result;
}

string DecodeMagic(unsigned int magic)
{
	string result = "";

	if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
		result = "32-bit";
	else if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
		result = "64-bit";
	else if (magic == IMAGE_ROM_OPTIONAL_HDR_MAGIC)
		result = "ROM";
	return result;
}

string TwoListsToString(list<string> notBeforeChain, list<string> notAfterChain)
{
	list<string>::iterator i1;
	list<string>::iterator i2;

	string result;
	for(i1=notBeforeChain.begin(), i2=notAfterChain.begin(); i1 != notBeforeChain.end() && i2 != notAfterChain.end(); i1++, i2++)
		if (i1 == notBeforeChain.begin())
			result = *i1 + " - " + *i2;
		else
			result += "|" + *i1 + " - " + *i2;

	return result;
}

string Quote(string data)
{
	if (string::npos == data.find(SEP))
		return data;
	else
		return '"' + data + '"';
}

void AnalyzePEFile(string filename, _TCHAR* pszCatalogFile, ostream& output, BOOL bCSV, BOOL bXML, BOOL bNoRevocation)
{
	int catalog;
	unsigned int countCatalogs;
	string catalogFilename;
	string md5;
	string compiletime;
	string creationtime;
	string lastwritetime;
	string lastaccesstime;
	DWORD dwFileAttributes;
	unsigned int uiCharacteristics;
	unsigned int uiMagic;
	unsigned int uiSubsystem;
	unsigned int uiSizeOfCode;
	unsigned int uiAddressOfEntryPoint;
	unsigned int uiRVA15;
	double entropy;
	string error;
	int signature;
	long errorCode;
	string issuerName;
	string subjectName;
	string signatureHashAlgorithm;
	string signatureTimestamp;
	string countersignTimestamp;
	list<string> subjectNameChain;
	list<string> signatureHashAlgorithmChain;
	list<string> serialChain;
	list<string> thumbprintChain;
	list<int> keylengthChain;
	list<list<string>> extensionChain;
	list<int> issuerUniqueIdChain;
	list<int> subjectUniqueIdChain;
	list<string> notBeforeChain;
	list<string> notAfterChain;
	string fileDescription;
	string companyName;
	string fileVersion;
	string productVersion;
	list<string> sections;
	string clrVersion;
	DWORD dwSignatureSize1;
	DWORD dwSignatureSize2;
	WORD wSignatureRevision;
	WORD wSignatureCertificateType;
	DWORD dwBytesAfterSignature;
	BOOL bParsePKCS7DERResult;
	DWORD dwPKCS7Size;
	DWORD dwBytesAfterPKCS7;
	DWORD dwBytesAfterPKCS7NotZero;
	string signingtime;
	DWORD dwFileSize;
	unsigned int uiIcons;
	string extension;
	string ownername;
	string DEROIDHash;

	if (GetFileInfo(filename, compiletime, creationtime, lastwritetime, lastaccesstime, dwFileAttributes, uiCharacteristics, sections, uiMagic, uiSubsystem, uiSizeOfCode, uiAddressOfEntryPoint, uiRVA15, clrVersion, dwSignatureSize1, dwSignatureSize2, wSignatureRevision, wSignatureCertificateType, dwBytesAfterSignature, bParsePKCS7DERResult, dwPKCS7Size, dwBytesAfterPKCS7, dwBytesAfterPKCS7NotZero, signingtime, dwFileSize, ownername, DEROIDHash, error)
		&& CalculateMD5OfFile(filename, md5, entropy, error))
	{
		wstring wfilename = wstring(filename.begin(), filename.end());
		if (pszCatalogFile == NULL)
			signature = IsFileDigitallySigned(wfilename.c_str(), bNoRevocation, NULL, catalog, countCatalogs, catalogFilename, issuerName, subjectName, signatureHashAlgorithm, signatureTimestamp, countersignTimestamp, subjectNameChain, signatureHashAlgorithmChain, serialChain, thumbprintChain, keylengthChain, extensionChain, issuerUniqueIdChain, subjectUniqueIdChain, notBeforeChain, notAfterChain, errorCode);
		else
		{
			string catalogfilename = string(pszCatalogFile);
			wstring wcatalogfilename = wstring(catalogfilename.begin(), catalogfilename.end());
			signature = IsFileDigitallySigned(wfilename.c_str(), bNoRevocation, wcatalogfilename.c_str(), catalog, countCatalogs, catalogFilename, issuerName, subjectName, signatureHashAlgorithm, signatureTimestamp, countersignTimestamp, subjectNameChain, signatureHashAlgorithmChain, serialChain, thumbprintChain, keylengthChain, extensionChain, issuerUniqueIdChain, subjectUniqueIdChain, notBeforeChain, notAfterChain, errorCode);
		}
		GetVersionInfo(filename.c_str(), fileDescription, companyName, fileVersion, productVersion);
		uiIcons = ExtractIconEx(filename.c_str(), -1, NULL, NULL, 0);
		extension = string(PathFindExtension(filename.c_str()));
		std::transform(extension.begin(), extension.end(), extension.begin(), ::tolower);
		if (bCSV)
		{
			output << Quote(filename) << SEP << Quote(extension) << SEP << md5 << SEP << entropy << SEP << dwFileSize << SEP << creationtime << SEP << lastwritetime << SEP << lastaccesstime << SEP << ownername << SEP << std::hex << dwFileAttributes << SEP << DecodeFileAttributes(dwFileAttributes) << SEP << uiCharacteristics << SEP << DecodeCharacteristics(uiCharacteristics) << SEP << uiMagic << SEP << DecodeMagic(uiMagic) << SEP << uiSubsystem << SEP << std::dec << uiSizeOfCode << SEP << std::hex << uiAddressOfEntryPoint << SEP << compiletime << SEP << uiRVA15 << std::dec << SEP << clrVersion << SEP << Quote(ListToString(sections, "|")) << SEP << dwSignatureSize1 << SEP << dwSignatureSize2 << SEP << std::hex << wSignatureRevision << std::dec << SEP << wSignatureCertificateType << SEP << dwBytesAfterSignature << SEP << bParsePKCS7DERResult << SEP << dwPKCS7Size << SEP << dwBytesAfterPKCS7 << SEP << dwBytesAfterPKCS7NotZero << SEP << signingtime << SEP << DEROIDHash << SEP << signature << SEP << Quote(MyFormatMessage(errorCode)) << SEP << catalog << SEP << countCatalogs << SEP << Quote(catalogFilename) << SEP << Quote(issuerName) << SEP << Quote(subjectName) << SEP << (thumbprintChain.empty() ? _TEXT("") : thumbprintChain.front()) << SEP << signatureTimestamp << SEP << countersignTimestamp << SEP << (extensionChain.empty() ? _TEXT("") : ListToStringSort(extensionChain.front(), "|")) << SEP << Quote(subjectNameChain.empty() ? _TEXT("") : subjectNameChain.back()) << SEP << (thumbprintChain.empty() ? _TEXT("") : thumbprintChain.back()) << SEP << signatureHashAlgorithm << SEP << TwoListsToString(notBeforeChain, notAfterChain) << SEP << Quote(ListToString(subjectNameChain, "|")) << SEP << ListToString(signatureHashAlgorithmChain, "|") << SEP << ListToString(serialChain, "|") << SEP << ListToString(thumbprintChain, "|") << SEP << ListIntToString(keylengthChain) << SEP << ListIntToString(issuerUniqueIdChain) << SEP << ListIntToString(subjectUniqueIdChain) << SEP << ListListToStringSort(extensionChain) << SEP << Quote(fileDescription) << SEP << Quote(companyName) << SEP << fileVersion << SEP << productVersion << SEP << uiIcons << endl;
		}
		else if (bXML)
		{
			list<string>::iterator i1;
			list<int>::iterator i2;
			list<list<string>>::iterator i3;
			list<string>::iterator i4;

			output << _TEXT("  <file>") << endl;
			output << XMLElementSingleLine(4, _TEXT("filename"), filename) << endl;
			output << _TEXT("    <extension>") << extension << _TEXT("</extension>") << endl;
			output << XMLElementSingleLine(4, _TEXT("md5"), md5) << endl;
			output << _TEXT("    <entropy>") << entropy << _TEXT("</entropy>") << endl;
			output << _TEXT("    <filesize>") << dwFileSize << _TEXT("</filesize>") << endl;
			output << XMLElementSingleLine(4, _TEXT("creationtime"), creationtime) << endl;
			output << XMLElementSingleLine(4, _TEXT("lastwritetime"), lastwritetime) << endl;
			output << XMLElementSingleLine(4, _TEXT("lastaccesstime"), lastaccesstime) << endl;
			output << XMLElementSingleLine(4, _TEXT("ownername"), ownername) << endl;
			output << _TEXT("    <fileAttributes>") << std::hex << dwFileAttributes << _TEXT("</fileAttributes>") << endl;
			output << XMLElementSingleLine(4, _TEXT("fileAttributesDecode"), DecodeFileAttributes(dwFileAttributes)) << endl;
			output << _TEXT("    <characteristics>") << uiCharacteristics << _TEXT("</characteristics>") << endl;
			output << XMLElementSingleLine(4, _TEXT("characteristicsDecode"), DecodeCharacteristics(uiCharacteristics)) << endl;
			output << _TEXT("    <magic>") << uiMagic << _TEXT("</magic>") << endl;
			output << _TEXT("    <magicDecode>") << DecodeMagic(uiMagic) << _TEXT("</magicDecode>") << endl;
			output << _TEXT("    <subsystem>") << uiSubsystem << _TEXT("</susbsystem>") << endl;
			output << _TEXT("    <sizeOfCode>") << std::dec << uiSizeOfCode << std::hex << _TEXT("</sizeOfCode>") << endl;
			output << _TEXT("    <addressOfEntryPoint>") << uiAddressOfEntryPoint << _TEXT("</addressOfEntryPoint>") << endl;
			output << XMLElementSingleLine(4, _TEXT("compiletime"), compiletime) << endl;
			output << _TEXT("    <RVA15>") << uiRVA15 << _TEXT("</RVA15>") << std::dec << endl;
			output << _TEXT("    <clrVersion>") << clrVersion << _TEXT("</clrVersion>") << endl;
			output << _TEXT("    <sections>") << endl;
			for(i1=sections.begin(); i1 != sections.end(); i1++)
				output << XMLElementSingleLine(6, _TEXT("section"), *i1) << endl;
			output << _TEXT("    </sections>") << endl;
			output << _TEXT("    <signatureSize1>") << dwSignatureSize1 << _TEXT("</signatureSize1>") << endl;
			output << _TEXT("    <signatureSize2>") << dwSignatureSize1 << _TEXT("</signatureSize2>") << endl;
			output << _TEXT("    <signatureRevision>") << std::hex << wSignatureRevision << std::dec << _TEXT("</signatureRevision>") << endl;
			output << _TEXT("    <signatureCertificateType>") << wSignatureCertificateType << _TEXT("</signatureCertificateType>") << endl;
			output << _TEXT("    <bytesAfterSignature>") << dwBytesAfterSignature << _TEXT("</bytesAfterSignature>") << endl;
			output << _TEXT("    <ParsePKCS7DERResult>") << bParsePKCS7DERResult << _TEXT("</ParsePKCS7DERResult>") << endl;
			output << _TEXT("    <PKCS7Size>") << dwPKCS7Size << _TEXT("</PKCS7Size>") << endl;
			output << _TEXT("    <BytesAfterPKCS7>") << dwBytesAfterPKCS7 << _TEXT("</BytesAfterPKCS7>") << endl;
			output << _TEXT("    <BytesAfterPKCS7NotZero>") << dwBytesAfterPKCS7NotZero << _TEXT("</BytesAfterPKCS7NotZero>") << endl;
			output << _TEXT("    <PKCS7Signingtime>") << signingtime << _TEXT("</PKCS7Signingtime>") << endl;
			output << XMLElementSingleLine(4, _TEXT("DEROIDHash"), DEROIDHash) << endl;
			output << _TEXT("    <validSignature>") << signature << _TEXT("</validSignature>") << endl;
			output << XMLElementSingleLine(4, _TEXT("errorCode"), MyFormatMessage(errorCode)) << endl;
			output << _TEXT("    <catalog>") << catalog << _TEXT("</catalog>") << endl;
			output << _TEXT("    <countCatalogs>") << countCatalogs << _TEXT("</countCatalogs>") << endl;
			output << XMLElementSingleLine(4, _TEXT("catalogFilename"), issuerName) << endl;
			output << XMLElementSingleLine(4, _TEXT("issuerName"), issuerName) << endl;
			output << XMLElementSingleLine(4, _TEXT("subjectName"), subjectName) << endl;
			output << XMLElementSingleLine(4, _TEXT("subjectThumbprint"), (thumbprintChain.empty() ? _TEXT("") : thumbprintChain.front())) << endl;
			output << XMLElementSingleLine(4, _TEXT("signatureTimestamp"), signatureTimestamp) << endl;
			output << XMLElementSingleLine(4, _TEXT("countersignTimestamp"), countersignTimestamp) << endl;
			output << _TEXT("    <extensions>") << endl;
			if (!extensionChain.empty())
			{
				list<string> extensions = extensionChain.front();
				extensions.sort();
				for (i1=extensions.begin(); i1 != extensions.end(); i1++)
					output << XMLElementSingleLine(6, _TEXT("extension"), *i1) << endl;
			}
			output << _TEXT("    </extensions>") << endl;
			output << XMLElementSingleLine(4, _TEXT("rootName"), (subjectNameChain.empty() ? _TEXT("") : subjectNameChain.back())) << endl;
			output << XMLElementSingleLine(4, _TEXT("rootThumbprint"), (thumbprintChain.empty() ? _TEXT("") : thumbprintChain.back())) << endl;
			output << XMLElementSingleLine(4, _TEXT("signatureHashAlgorithm"), signatureHashAlgorithm) << endl;
			output << _TEXT("    <beforeAndAfterChain>") << endl;
			for(i1=notBeforeChain.begin(), i4=notAfterChain.begin(); i1 != notBeforeChain.end() && i4 != notAfterChain.end(); i1++, i4++)
			{
				output << _TEXT("      <beforeAndAfter>") << endl;
				output << XMLElementSingleLine(8, _TEXT("notBefore"), *i1) << endl;
				output << XMLElementSingleLine(8, _TEXT("notAfter"), *i4) << endl;
				output << _TEXT("      </beforeAndAfter>") << endl;
			}
			output << _TEXT("    </beforeAndAfterChain>") << endl;
			output << _TEXT("    <subjectNameChain>") << endl;
			for(i1=subjectNameChain.begin(); i1 != subjectNameChain.end(); i1++)
				output << XMLElementSingleLine(6, _TEXT("subjectName"), *i1) << endl;
			output << _TEXT("    </subjectNameChain>") << endl;
			output << _TEXT("    <signatureHashAlgorithmChain>") << endl;
			for(i1=signatureHashAlgorithmChain.begin(); i1 != signatureHashAlgorithmChain.end(); i1++)
				output << XMLElementSingleLine(6, _TEXT("signatureHashAlgorithm"), *i1) << endl;
			output << _TEXT("    </signatureHashAlgorithmChain>") << endl;
			output << _TEXT("    <serialChain>") << endl;
			for(i1=serialChain.begin(); i1 != serialChain.end(); i1++)
				output << XMLElementSingleLine(6, _TEXT("serial"), *i1) << endl;
			output << _TEXT("    </serialChain>") << endl;
			output << _TEXT("    <thumbprintChain>") << endl;
			for(i1=thumbprintChain.begin(); i1 != thumbprintChain.end(); i1++)
				output << XMLElementSingleLine(6, _TEXT("thumbprint"), *i1) << endl;
			output << _TEXT("    </thumbprintChain>") << endl;
			output << _TEXT("    <keylengthChain>") << endl;
			for(i2=keylengthChain.begin(); i2 != keylengthChain.end(); i2++)
				output << _TEXT("      <keylength>") << *i2 << _TEXT("</keylength>") << endl;
			output << _TEXT("    </keylengthChain>") << endl;
			output << _TEXT("    <issuerUniqueIdChain>") << endl;
			for(i2=issuerUniqueIdChain.begin(); i2 != issuerUniqueIdChain.end(); i2++)
				output << _TEXT("      <issuerUniqueId>") << *i2 << _TEXT("</issuerUniqueId>") << endl;
			output << _TEXT("    </issuerUniqueIdChain>") << endl;
			output << _TEXT("    <subjectUniqueIdChain>") << endl;
			for(i2=subjectUniqueIdChain.begin(); i2 != subjectUniqueIdChain.end(); i2++)
				output << _TEXT("      <subjectUniqueId>") << *i2 << _TEXT("</subjectUniqueId>") << endl;
			output << _TEXT("    </subjectUniqueIdChain>") << endl;
			output << _TEXT("    <extensionsChain>") << endl;
			for(i3=extensionChain.begin(); i3 != extensionChain.end(); i3++)
			{
				output << _TEXT("      <extensions>") << endl;
				for (i1=(*i3).begin(); i1 != (*i3).end(); i1++)
					output << XMLElementSingleLine(8, _TEXT("extension"), *i1) << endl;
				output << _TEXT("      </extensions>") << endl;
			}
			output << _TEXT("    </extensionsChain>") << endl;
			output << XMLElementSingleLine(4, _TEXT("fileDescription"), fileDescription) << endl;
			output << XMLElementSingleLine(4, _TEXT("companyName"), companyName) << endl;
			output << XMLElementSingleLine(4, _TEXT("fileVersion"), fileVersion) << endl;
			output << XMLElementSingleLine(4, _TEXT("productVersion"), productVersion) << endl;
			output << _TEXT("    <icons>") << uiIcons << _TEXT("</icons>") << endl;
			output << _TEXT("  </file>") << endl;
		}
		else
		{
			list<string>::iterator i1;
			list<int>::iterator i2;
			list<list<string>>::iterator i3;
			list<string>::iterator i4;

			output << _TEXT("Filename:                             ") << filename << endl;
			output << _TEXT("Extension:                            ") << extension << endl;
			output << _TEXT("MD5:                                  ") << md5 << endl;
			output << _TEXT("Entropy:                              ") << entropy << endl;
			output << _TEXT("Filesize:                             ") << dwFileSize << endl;
			output << _TEXT("Creation time:                        ") << creationtime << endl;
			output << _TEXT("Last write time:                      ") << lastwritetime << endl;
			output << _TEXT("Last access time:                     ") << lastaccesstime << endl;
			output << _TEXT("Owner name:                           ") << ownername << endl;
			output << _TEXT("File attributes:                      ") << std::hex << dwFileAttributes << endl;
			output << _TEXT("File attributes decode:               ") << DecodeFileAttributes(dwFileAttributes) << endl;
			output << _TEXT("Characteristics:                      ") << uiCharacteristics << endl;
			output << _TEXT("Characteristics decode:               ") << DecodeCharacteristics(uiCharacteristics) << endl;
			output << _TEXT("Magic:                                ") << uiMagic << endl;
			output << _TEXT("Magic decode:                         ") << DecodeMagic(uiMagic) << endl;
			output << _TEXT("Subsystem:                            ") << uiSubsystem << endl;
			output << _TEXT("Size of code:                         ") << std::dec << uiSizeOfCode << std::hex << endl;
			output << _TEXT("Address of entry point:               ") << uiAddressOfEntryPoint << endl;
			output << _TEXT("Compile time:                         ") << compiletime << endl;
			output << _TEXT("RVA15:                                ") << uiRVA15 << endl;
			output << _TEXT("CLR version:                          ") << clrVersion << endl;
			output << _TEXT("Sections:                             ") << ListToString(sections, ",") << endl;
			output << _TEXT("Signature size 1:                     ") << std::dec << dwSignatureSize1 << endl;
			output << _TEXT("Signature size 2:                     ") << dwSignatureSize2 << endl;
			output << _TEXT("Signature Revision:                   ") << std::hex << wSignatureRevision << std::dec << endl;
			output << _TEXT("Signature Certificate Type:           ") << wSignatureCertificateType << endl;
			output << _TEXT("Bytes after signature:                ") << dwBytesAfterSignature << endl;
			output << _TEXT("Result PKCS7 parser:                  ") << bParsePKCS7DERResult << endl;
			output << _TEXT("PKCS7 size:                           ") << dwPKCS7Size << endl;
			output << _TEXT("Bytes after PKCS7 signature:          ") << dwBytesAfterPKCS7 << endl;
			output << _TEXT("Bytes after PKCS7 signature not zero: ") << dwBytesAfterPKCS7NotZero << endl;
			output << _TEXT("PKCS7 signingtime:                    ") << signingtime << endl;
			output << _TEXT("DEROIDHash:                           ") << DEROIDHash << endl;
			output << _TEXT("Valid signature:                      ") << signature << endl;
			output << _TEXT("Error code:                           ") << MyFormatMessage(errorCode) << endl;
			output << _TEXT("From catalog file:                    ") << catalog << endl;
			output << _TEXT("Count catalog files:                  ") << countCatalogs << endl;
			output << _TEXT("Catalog filename:                     ") << catalogFilename << endl;
			output << _TEXT("Issuer name:                          ") << issuerName << endl;
			output << _TEXT("Subject name:                         ") << subjectName << endl;
			output << _TEXT("Subject thumbprint:                   ") << (thumbprintChain.empty() ? _TEXT("") : thumbprintChain.front()) << endl;
			output << _TEXT("Timestamp signature:                  ") << signatureTimestamp << endl;
			output << _TEXT("Timestamp countersignature:           ") << countersignTimestamp << endl;
			output << _TEXT("Extensions:                           ") << (extensionChain.empty() ? _TEXT("") : ListToStringSort(extensionChain.front(), ",")) << endl;
			output << _TEXT("Root name:                            ") << (subjectNameChain.empty() ? _TEXT("") : subjectNameChain.back()) << endl;
			output << _TEXT("Root thumbprint:                      ") << (thumbprintChain.empty() ? _TEXT("") : thumbprintChain.back()) << endl;
			output << _TEXT("Signature hash algorithm:             ") << signatureHashAlgorithm << endl;
			for(i1=notBeforeChain.begin(), i4=notAfterChain.begin(); i1 != notBeforeChain.end() && i4 != notAfterChain.end(); i1++, i4++)
			{
				output << _TEXT("Not before chain:                     ") << *i1 << endl;
				output << _TEXT("Not after chain:                      ") << *i4 << endl;
			}
			for(i1=subjectNameChain.begin(); i1 != subjectNameChain.end(); i1++)
				output << _TEXT("Subject name chain:                   ") << *i1 << endl;
			for(i1=signatureHashAlgorithmChain.begin(); i1 != signatureHashAlgorithmChain.end(); i1++)
				output << _TEXT("Signature hash algorithm chain:       ") << *i1 << endl;
			for(i1=serialChain.begin(); i1 != serialChain.end(); i1++)
				output << _TEXT("Serial number chain:                  ") << *i1 << endl;
			for(i1=thumbprintChain.begin(); i1 != thumbprintChain.end(); i1++)
				output << _TEXT("Thumbprint chain:                     ") << *i1 << endl;
			for(i2=keylengthChain.begin(); i2 != keylengthChain.end(); i2++)
				output << _TEXT("Keylength chain:                      ") << *i2 << endl;
			for(i2=issuerUniqueIdChain.begin(); i2 != issuerUniqueIdChain.end(); i2++)
				output << _TEXT("Issuer unique ID chain:               ") << *i2 << endl;
			for(i2=subjectUniqueIdChain.begin(); i2 != subjectUniqueIdChain.end(); i2++)
				output << _TEXT("Subject unique ID chain:              ") << *i2 << endl;
			for(i3=extensionChain.begin(); i3 != extensionChain.end(); i3++)
				output << _TEXT("Extensions chain:                     ") << ListToStringSort(*i3, ",") << endl;
			output << _TEXT("File description:                     ") << fileDescription << endl;
			output << _TEXT("Company name:                         ") << companyName << endl;
			output << _TEXT("File version:                         ") << fileVersion << endl;
			output << _TEXT("Product version:                      ") << productVersion << endl;
			output << _TEXT("Icons:                                ") << uiIcons << endl;
		}
	}
	else
	{
		if (bCSV)
			output << Quote(filename) << SEP << error << endl;
		else if (bXML)
		{
			output << _TEXT("  <file>") << endl;
			output << XMLElementSingleLine(4, _TEXT("filename"), filename) << endl;
			output << XMLElementSingleLine(4, _TEXT("error"), error) << endl;
			output << _TEXT("  </file>") << endl;
		}
		else
		{
			output << _TEXT("Filename: ") << filename << endl;
			output << _TEXT("Error:    ") << error << endl;
		}
	}
}

#define BUFSIZE 4

void ProcessFiles(const _TCHAR* pszArgument, ostream& output, BOOL bOutputToFile, _TCHAR* pszCatalogFile, BOOL bRecurse, BOOL bCSV, BOOL bPEFilesOnly, BOOL bXML, BOOL bReparsePointFollow, BOOL bNoRevocation)
{
#define MY_MAX_PATH MAX_PATH*2

	WIN32_FIND_DATA FindFileData;
	HANDLE hFind;
	_TCHAR szDirectory[MY_MAX_PATH];
	_TCHAR szFile[MY_MAX_PATH];
	static int iProgress = 0;
	DWORD dwAttributes;

	dwAttributes = GetFileAttributes(pszArgument);
	if (dwAttributes & FILE_ATTRIBUTE_DIRECTORY)
	{
		if (!(dwAttributes & FILE_ATTRIBUTE_REPARSE_POINT) || bReparsePointFollow)
		{
			StringCchCopy(szDirectory, MY_MAX_PATH, pszArgument);
			StringCchCat(szDirectory, MY_MAX_PATH, _TEXT("\\*"));
			hFind = FindFirstFile(szDirectory, &FindFileData);
			if (hFind == INVALID_HANDLE_VALUE) 
			{
				cout << _TEXT("FindFirstFile failed: error ") << GetLastError() << " directory " << szDirectory << endl;
				return;
			} 
			else 
			{
				do
				{
					StringCchCopy(szFile, MY_MAX_PATH, pszArgument);
					if (strlen(szFile) > 0 && '\\' != szFile[strlen(szFile) - 1])
						StringCchCat(szFile, MY_MAX_PATH, _TEXT("\\"));
					StringCchCat(szFile, MY_MAX_PATH, FindFileData.cFileName);
					if (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
					{
						if (bRecurse && strcmp(FindFileData.cFileName, ".") && strcmp(FindFileData.cFileName, ".."))
							ProcessFiles(szFile, output, bOutputToFile, pszCatalogFile, bRecurse, bCSV, bPEFilesOnly, bXML, bReparsePointFollow, bNoRevocation);
					}
					else
					{
						if (bOutputToFile)
							cout << "\b\b\b\b\b\b\b\b\b\b" << ++iProgress;
						if (!bPEFilesOnly || bPEFilesOnly && IsPEFile(szFile))
						{
							AnalyzePEFile(string(szFile), pszCatalogFile, output, bCSV, bXML, bNoRevocation);
						}
					}
				} while (FindNextFile(hFind, &FindFileData));
				FindClose(hFind);
			}
		}
	}
	else
	{
		if (bOutputToFile)
			cout << "\b\b\b\b\b\b\b\b\b\b" << ++iProgress;
		AnalyzePEFile(string(pszArgument), pszCatalogFile, output, bCSV, bXML, bNoRevocation);
	}
}

string RTrimSpaces(const string input)
{
	size_t endpos = input.find_last_not_of(TEXT(" "));
	if (string::npos == endpos)
		return input;
	else
		return input.substr(0, endpos+1);
}

string LTrimSpaces(const string input)
{
	size_t startpos = input.find_first_not_of(TEXT(" "));
	if (string::npos == startpos)
		return input;
	else
		return input.substr(startpos);
}

string TrimSpaces(const string input)
{
	return LTrimSpaces(RTrimSpaces(input));
}

BOOL StartsWith(const string input, const string prefix)
{
	return input.compare(0, prefix.size(), prefix) == 0;
}

void ProcessAtFile(_TCHAR* pszArgument, ostream& output, BOOL bOutputToFile, _TCHAR* pszCatalogFile, BOOL bRecurse, BOOL bCSV, BOOL bPEFilesOnly, BOOL bXML, BOOL bReparsePointFollow, BOOL bNoRevocation)
{
	cout << "@File: " << pszArgument << "\n";
	BOOL bErrorParsingFile = FALSE;
	string line;
	ifstream myfile(pszArgument);
	if (myfile.is_open())
	{
		while (myfile.good())
		{
			getline(myfile, line);
			line = TrimSpaces(line);
			if (line != TEXT("") && !StartsWith(line, TEXT("#")))
				ProcessFiles(line.c_str(), output, bOutputToFile, pszCatalogFile, bRecurse, bCSV, bPEFilesOnly, bXML, bReparsePointFollow, bNoRevocation);
		}
		myfile.close();
	}
	else
		bErrorParsingFile = TRUE;
}

typedef struct
{
	BOOL bRecurse;
	BOOL bCSV;
	BOOL bPEFilesOnly;
	BOOL bOutputToFile;
	BOOL bCatalogFile;
	BOOL bXML;
	BOOL bReparsePointFollow;
	BOOL bNoRevocation;
	BOOL bOutputToFileWithHostname;
	BOOL bGenerateOutputFilename;
	_TCHAR* pszOutputFile;
	_TCHAR* pszCatalogFile;
	_TCHAR** ppszTarget;
} OPTIONS;

int ParseArgs(int argc, char *argv[], OPTIONS *pOPTIONS)
{
	int iCountParameters = 0;
	int iFlagOutputFile = 0;
	int iFlagCatalogFile = 0;
	char *pcFlags;

	pOPTIONS->bRecurse = FALSE;
	pOPTIONS->bCSV = FALSE;
	pOPTIONS->bPEFilesOnly = FALSE;
	pOPTIONS->bOutputToFile = FALSE;
	pOPTIONS->bOutputToFileWithHostname = FALSE;
	pOPTIONS->bGenerateOutputFilename = FALSE;
	pOPTIONS->bXML = FALSE;
	pOPTIONS->bReparsePointFollow = FALSE;
	pOPTIONS->bNoRevocation = FALSE;
	pOPTIONS->pszOutputFile = NULL;
	pOPTIONS->bCatalogFile = FALSE;
	pOPTIONS->pszCatalogFile = NULL;

	pOPTIONS->ppszTarget = (_TCHAR**) LocalAlloc(LPTR, sizeof(_TCHAR*) * argc);
	if (pOPTIONS->ppszTarget == NULL)
	{
		cout << _TEXT("LocalAlloc error") << endl;
		return 1;
	}

	for (unsigned int uiIterArgv = 1; uiIterArgv < (unsigned int) argc; uiIterArgv++)
	{
		if (argv[uiIterArgv][0] == '-')
		{
  			if (iFlagOutputFile)
  				return 1;
  			if (iFlagCatalogFile)
  				return 1;
  			pcFlags = argv[uiIterArgv] + 1;
  			while (*pcFlags)
  				switch (*pcFlags++)
  				{
  					case 'e':
  						pOPTIONS->bPEFilesOnly = TRUE;
  						break;
  					case 'o':
  						iFlagOutputFile = 1;
  						break;
  					case 's':
  						pOPTIONS->bRecurse = TRUE;
  						break;
  					case 'v':
  						pOPTIONS->bCSV = TRUE;
  						break;
  					case 'x':
  						pOPTIONS->bXML = TRUE;
  						break;
  					case 'l':
  						pOPTIONS->bReparsePointFollow = TRUE;
  						break;
  					case 'r':
  						pOPTIONS->bNoRevocation = TRUE;
  						break;
  					case 'c':
  						iFlagCatalogFile = 1;
  						break;
  					case 'O':
  						pOPTIONS->bOutputToFileWithHostname = TRUE;
  						break;
  					case 'g':
  						pOPTIONS->bGenerateOutputFilename = TRUE;
  						break;
  					default:
  						return 1;
  				}
		}
		else if (iFlagOutputFile)
		{
			pOPTIONS->bOutputToFile = TRUE;
  			pOPTIONS->pszOutputFile = argv[uiIterArgv];
  			iFlagOutputFile = 0;
		}
		else if (iFlagCatalogFile)
		{
			pOPTIONS->bCatalogFile = TRUE;
  			pOPTIONS->pszCatalogFile = argv[uiIterArgv];
  			iFlagCatalogFile = 0;
		}
		else
  			pOPTIONS->ppszTarget[iCountParameters++] = argv[uiIterArgv];
	}
  	if (iFlagOutputFile)
  		return 1;
  	if (iFlagCatalogFile)
  		return 1;
	else if (iCountParameters == 0)
		return 1;
	else if (pOPTIONS->bCSV && pOPTIONS->bXML)
		return 1;
	else if (pOPTIONS->bOutputToFile && pOPTIONS->bOutputToFileWithHostname)
		return 1;
	else if (!pOPTIONS->bOutputToFile && pOPTIONS->bGenerateOutputFilename)
		return 1;
	else
		return 0;
}

//Adjust token privileges to enable SE_BACKUP_NAME
BOOL CurrentProcessAdjustToken(void)
{
  HANDLE hToken;
  TOKEN_PRIVILEGES sTP;

  if(OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
  {
		if (!LookupPrivilegeValue(NULL, SE_BACKUP_NAME, &sTP.Privileges[0].Luid))
		{
			CloseHandle(hToken);
			return FALSE;
		}
		sTP.PrivilegeCount = 1;
		sTP.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		if (!AdjustTokenPrivileges(hToken, 0, &sTP, sizeof(sTP), NULL, NULL))
		{
			CloseHandle(hToken);
			return FALSE;
		}
		CloseHandle(hToken);
		return TRUE;
  }
	return FALSE;
}

int _tmain(int argc, _TCHAR* argv[])
{
	OPTIONS sOptions;
	streambuf *streamBuffer;
	ofstream ofstreamOutputFile;

#ifdef AUTO

	_TCHAR aatcDrives[26][10];
	DWORD dwUnitmask;
	UINT uiDriveType;
	int iDriveCounter = 0;

	if (argc != 1)
	{
		cout << _TEXT("This version takes no arguments") << endl;

		return -1;
	}

	cout << _TEXT("AnalyzePESig auto mode") << endl;

	sOptions.bRecurse = TRUE;
	sOptions.bCSV = TRUE;
	sOptions.bPEFilesOnly = TRUE;
	sOptions.bOutputToFile = FALSE;
	sOptions.bOutputToFileWithHostname = TRUE;
	sOptions.bGenerateOutputFilename = FALSE;
	sOptions.bXML = FALSE;
	sOptions.bReparsePointFollow = FALSE;
	sOptions.bNoRevocation = FALSE;
	sOptions.pszOutputFile = NULL;
	sOptions.bCatalogFile = FALSE;
	sOptions.pszCatalogFile = NULL;
	sOptions.ppszTarget = (_TCHAR**) LocalAlloc(LPTR, sizeof(_TCHAR*) * 27);
	if (sOptions.ppszTarget == NULL)
	{
		cout << _TEXT("LocalAlloc error") << endl;
		return 1;
	}
	cout << _TEXT("Drives: ");
	dwUnitmask = GetLogicalDrives() >> 2;
	for (int iDrive = 2; iDrive < 26; iDrive++)
	{
		if (dwUnitmask & 1)
		{
			StringCchPrintf(aatcDrives[iDrive], sizeof(aatcDrives[iDrive])/sizeof(aatcDrives[iDrive][0]), TEXT("%c:\\"), iDrive + 'A');
			uiDriveType = GetDriveType(aatcDrives[iDrive]);
			switch (uiDriveType)
			{
				case DRIVE_FIXED:
					cout << aatcDrives[iDrive] << _TEXT(" ");
					sOptions.ppszTarget[iDriveCounter++] = aatcDrives[iDrive];
					break;
			}
		}
		dwUnitmask = dwUnitmask >> 1;
	}
	cout << endl;

#else

	if (ParseArgs(argc, argv, &sOptions))
	{
		cout << _TEXT("Usage: AnalyzePESig [options] [@]filename ...") << endl;
		cout << _TEXT("Version 0.0.0.4") << endl;
		cout << _TEXT(" -e Scan executable images only (regardless of their extension)") << endl;
		cout << _TEXT(" -o Output to file") << endl;
		cout << _TEXT(" -O Output to file with generated name") << endl;
		cout << _TEXT(" -g Generate output file name with option -o") << endl;
		cout << _TEXT(" -s Recurse subdirectories") << endl;
		cout << _TEXT(" -l Follow links (follow link when directory is a reparse point)") << endl;
		cout << _TEXT(" -r No revocation checks") << endl;
		cout << _TEXT(" -v CSV output") << endl;
		cout << _TEXT(" -x XML output") << endl;
		cout << _TEXT(" -c Use given catalog file") << endl;

		return -1;
	}

#endif

	if (sOptions.bOutputToFileWithHostname || (sOptions.bGenerateOutputFilename && sOptions.bOutputToFile))
	{
		TCHAR computerName[MAX_COMPUTERNAME_LENGTH + 1];
		TCHAR reportName[MAX_COMPUTERNAME_LENGTH + 256];
		DWORD computerNameSize;
		SYSTEMTIME sST;

		GetLocalTime(&sST);
		computerNameSize = MAX_COMPUTERNAME_LENGTH;
		GetComputerNameEx(ComputerNamePhysicalNetBIOS, computerName, &computerNameSize);
		if (sOptions.bOutputToFileWithHostname)
			StringCchPrintf(reportName, sizeof(reportName)/sizeof(reportName[0]), TEXT("AnalyzePESig-%s-%04d%02d%02d-%02d%02d%02d.csv"), computerName, sST.wYear, sST.wMonth, sST.wDay, sST.wHour, sST.wMinute, sST.wSecond);
		else
			StringCchPrintf(reportName, sizeof(reportName)/sizeof(reportName[0]), TEXT("AnalyzePESig-%s-%04d%02d%02d-%02d%02d%02d.csv"), sOptions.pszOutputFile, sST.wYear, sST.wMonth, sST.wDay, sST.wHour, sST.wMinute, sST.wSecond);
		ofstreamOutputFile.open(reportName);
		streamBuffer = ofstreamOutputFile.rdbuf();
	}
	else if (sOptions.bOutputToFile)
	{
		ofstreamOutputFile.open(sOptions.pszOutputFile);
		streamBuffer = ofstreamOutputFile.rdbuf();
	}
	else
		streamBuffer = cout.rdbuf();
	ostream output(streamBuffer);

	if (sOptions.bCSV)
	{
		output << _TEXT("Filename") << SEP << _TEXT("Extension") << SEP << _TEXT("MD5") << SEP << _TEXT("Entropy") << SEP << _TEXT("Filesize") << SEP << _TEXT("Creation_time") << SEP << _TEXT("Last_write_time") << SEP << _TEXT("Last_access_time") << SEP << _TEXT("Owner_name") << SEP << _TEXT("File_attributes") << SEP << _TEXT("File_attributes") << SEP << _TEXT("Characteristics") << SEP << _TEXT("Characteristics") << SEP << _TEXT("Magic") << SEP << _TEXT("Magic") << SEP << _TEXT("Subsystem") << SEP << _TEXT("Size_of_code") << SEP << _TEXT("Address_of_entry_point") << SEP << _TEXT("Compile_time") << SEP << _TEXT("RVA15") << SEP << _TEXT("CLR_Version") << SEP << _TEXT("Sections") << SEP << _TEXT("Signature_size_1") << SEP << _TEXT("Signature_size_2") << SEP << _TEXT("Signature_Revision") << SEP << _TEXT("Signature_Certificate_Type") << SEP << _TEXT("Bytes_after_signature") << SEP << _TEXT("Result_PKCS7_parser") << SEP << _TEXT("PKCS7_size") << SEP << _TEXT("Bytes_after_PKCS7_signature") << SEP << _TEXT("Bytes_after_PKCS7_signature_not_zero") << SEP << _TEXT("PKCS7_signingtime") << SEP << _TEXT("DEROIDHash") << SEP << _TEXT("Signature") << SEP << _TEXT("Error_code") << SEP << _TEXT("Catalog") << SEP << _TEXT("Catalogs") << SEP << _TEXT("Catalog_Filename") << SEP << _TEXT("Issuer_Name") << SEP << _TEXT("Subject_Name") << SEP << _TEXT("Subject_Thumbprint") << SEP << _TEXT("Signature_Timestamp") << SEP << _TEXT("Countersignature_Timestamp") << SEP << _TEXT("Extensions") << SEP << _TEXT("Root_Subject_Name") << SEP << _TEXT("Root_Thumbprint") << SEP << _TEXT("Signature_Hash_Algorithm") << SEP << _TEXT("Not_before_and_not_after") << SEP << _TEXT("Subject_Name_Chain") << SEP << _TEXT("Signature_Hash_Algorithm_Chain") << SEP << _TEXT("Serial_Chain") << SEP << _TEXT("Thumbprint_Chain") << SEP << _TEXT("Keylength_Chain") << SEP << _TEXT("Issuer_Unique_Id_Chain") << SEP << _TEXT("Subject_Unique_Id_Chain") << SEP << _TEXT("Extensions_Chain") << SEP << _TEXT("File_Description") << SEP << _TEXT("Company_Name") << SEP << _TEXT("File_Version") << SEP << _TEXT("Product_Version") << SEP << _TEXT("Icons") << endl;
	}
	if (sOptions.bXML)
		output << _TEXT("<files>") << endl;
	CurrentProcessAdjustToken();
	for (int iIter = 0; sOptions.ppszTarget[iIter] != NULL; iIter++)
		if (sOptions.ppszTarget[iIter][0] == '@')
			ProcessAtFile(sOptions.ppszTarget[iIter] + 1, output, sOptions.bOutputToFile || sOptions.bOutputToFileWithHostname, sOptions.bCatalogFile ? sOptions.pszCatalogFile : NULL, sOptions.bRecurse, sOptions.bCSV, sOptions.bPEFilesOnly, sOptions.bXML, sOptions.bReparsePointFollow, sOptions.bNoRevocation);
		else
			ProcessFiles(sOptions.ppszTarget[iIter], output, sOptions.bOutputToFile || sOptions.bOutputToFileWithHostname, sOptions.bCatalogFile ? sOptions.pszCatalogFile : NULL, sOptions.bRecurse, sOptions.bCSV, sOptions.bPEFilesOnly, sOptions.bXML, sOptions.bReparsePointFollow, sOptions.bNoRevocation);
	if (sOptions.bXML)
		output << _TEXT("</files>") << endl;

	if (sOptions.bOutputToFile || sOptions.bOutputToFileWithHostname)
		ofstreamOutputFile.close();

	LocalFree(sOptions.ppszTarget);

	return 0;
}
