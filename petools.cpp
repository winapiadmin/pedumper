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

PIMAGE_NT_HEADERS ReadPEHeader(HANDLE fileHandle){
	WORD PELocation=ReadPELocation(fileHandle);
	PIMAGE_NT_HEADERS data;
	DWORD number;
	if (SetFilePointer(fileHandle, PELocation, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER)
	{
		// Handle error
		return 0;
	}
	// Read PIMAGE_NT_HEADERS bytes from the file into data
	if (!ReadFile(fileHandle, &data, sizeof(data), &number, NULL))
	{
		// Handle error
		return 0;
	}
	return data;
}

PIMAGE_DOS_HEADER ReadDOSHeader(HANDLE fileHandle){
	if (SetFilePointer(fileHandle, 0x0, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER)
	{
		// Handle error
		return 0;
	}
	PIMAGE_DOS_HEADER data;
	DWORD number;
	// Read PIMAGE_NT_HEADERS bytes from the file into data
	if (!ReadFile(fileHandle, &data, sizeof(data), &number, NULL))
	{
		// Handle error
		return 0;
	}
	return data;
}
// https://stackoverflow.com/questions/77032798/strange-entry-type-4194304-while-reading-debug-directory (my question about debug directory)
BOOL DumpDebugDirectory(PVOID Base){
    ULONG bytes;
    PIMAGE_DEBUG_DIRECTORY debugDirectory;
    IMAGE_SECTION_HEADER debugSection; // optional, if you use 
                                       // ImageDirectoryEntryToData
    debugDirectory=ImageDirectoryEntryToDataEx(Base, FALSE, 
                                               IMAGE_DIRECTORY_ENTRY_DEBUG, 
                                               &bytes, debugSection);
    if (debugSection==NULL)
        return 1; // that mean there are no debug section
    printf("\t%s\tType",debugDirectory->Type);
    // do other stuff like printing PDB filename here
    return 0;
}
