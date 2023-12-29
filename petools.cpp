#include "peresource.h"

WORD ReadPELocation(HANDLE fileHandle){
    return ReadDOSHeader(fileHandle)->e_lfanew;
}

BOOL IsPEHeader(HANDLE fileHandle){
	return (ReadPEHeader(fileHandle)->Signature==IMAGE_NT_SIGNATURE);
}

DWORD EntryPointAddress(HANDLE fileHandle){
	return ReadPEHeader(fileHandle)->OptionalHeader.AddressOfEntryPoint;
}

PIMAGE_NT_HEADERS ReadPEHeader(HANDLE moduleHandle){
	WORD PELocation=ReadPELocation(moduleHandle);
	return (PIMAGE_NT_HEADERS)((DWORD)moduleHandle+PELocation);
}

PIMAGE_DOS_HEADER ReadDOSHeader(HANDLE moduleHandle){
	return (PIMAGE_DOS_HEADER)((DWORD)moduleHandle);
}
// https://stackoverflow.com/questions/77032798/strange-entry-type-4194304-while-reading-debug-directory (my question about debug directory)
PIMAGE_DEBUG_DIRECTORY DumpDebugDirectory(PVOID Base){
    ULONG bytes;
    PIMAGE_DEBUG_DIRECTORY debugDirectory;
    IMAGE_SECTION_HEADER debugSection; // optional, if you use 
                                       // ImageDirectoryEntryToData
    debugDirectory=ImageDirectoryEntryToData(Base, FALSE, 
                                               IMAGE_DIRECTORY_ENTRY_DEBUG, 
                                               &bytes);
    return DebugDirectory;
}
