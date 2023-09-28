#include "peresource.h"

WORD ReadPELocation(HANDLE fileHandle)
{
    WORD data;
    DWORD number;
    // Move the file pointer to the offset 0x3C
    if (SetFilePointer(fileHandle, 0x3C, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER)
    {
        // Handle error
        return 0;
    }
    // Read 2 bytes from the file into data
    if (!ReadFile(fileHandle, &data, 2, &number, NULL))
    {
        // Handle error
        return 0;
    }
    if (number != 2) return 0; // Handle error
    //data = ((data & 0x00FF) << 8) | ((data & 0xFF00) >> 8);
    // Return the data as the PE location
    return data;
}

BOOL IsPEHeader(HANDLE fileHandle){
	WORD PELocation=ReadPELocation(fileHandle);
	CHAR data[4];
	   DWORD number;
	if (PELocation==0) return 0;
	// Move the file pointer to the offset [PELocation]
	if (SetFilePointer(fileHandle, PELocation, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER)
	{
	    // Handle error
	    return 0;
	}
	// Read 4 bytes from the file into data
	if (!ReadFile(fileHandle, &data, 4, &number, NULL))
	{
	    // Handle error
	    return 0;
	}
	SetFilePointer(fileHandle, 0x00, NULL, FILE_BEGIN);
	if (data!="PE\0\0") return 0;
	return 1;
}

BOOL ReadMachine(HANDLE fileHandle){
	WORD PELocation=ReadPELocation(fileHandle);
	WORD data;
	DWORD number;
	if (PELocation==0) return 0;
	if (IsPEHeader(fileHandle)==1){
		if (SetFilePointer(fileHandle, PELocation+0x4, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER)
	    {
		// Handle error
		return 0;
	    }
	    // Read 2 bytes from the file into data
	    if (!ReadFile(fileHandle, &data, 2, &number, NULL))
	    {
		// Handle error
		return 0;
	    }
	    data = ((data & 0x00FF) << 8) | ((data & 0xFF00) >> 8);
	    return data;
	}
}

DWORD CodeSize(HANDLE fileHandle){
	WORD PELocation=ReadPELocation(fileHandle);
	DWORD data;
	DWORD number;
	if (PELocation==0) return 0;
	if (IsPEHeader(fileHandle)==1){
		if (SetFilePointer(fileHandle, PELocation+0x1C, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER)
	    	{
			// Handle error
			return 0;
	    	}
		// Read 4 bytes from the file into data
		if (!ReadFile(fileHandle, &data, 4, &number, NULL))
		{
			// Handle error
			return 0;
		}
		data = ((data & 0x0000FF) << 8) |((data & 0x00FF00) << 8) | ((data & 0xFF0000) >> 8);
		return data;
	}
}

DWORD EntryPointAddress(HANDLE fileHandle){
	WORD PELocation=ReadPELocation(fileHandle);
	DWORD data;
	DWORD number;
	if (PELocation==0) return 0;
	if (IsPEHeader(fileHandle)==1){
		if (SetFilePointer(fileHandle, PELocation+0x28, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER)
		{
			// Handle error
			return 0;
		}
		// Read 4 bytes from the file into data
		if (!ReadFile(fileHandle, &data, 4, &number, NULL))
		{
			// Handle error
			return 0;
		}
		data = ((data & 0x0000FF) << 8) |((data & 0x00FF00) << 8) | ((data & 0xFF0000) >> 8);
		return data;
	}
}

PIMAGE_NT_HEADERS ReadPEHeader(HANDLE fileHandle){
	WORD PELocation=ReadPELocation(fileHandle);
	PIMAGE_NT_HEADERS data;
	DWORD number;
	if (PELocation==0) return 0;
	if (IsPEHeader(fileHandle)==1){
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
VOID DumpDebugDirectory(PVOID FileBuffer, PIMAGE_NT_HEADERS NtHeaders)
{
    // get the data directory, which is at a different location for 32-bit and 64-bit executables
    PIMAGE_DATA_DIRECTORY DataDirectory = NULL;

    switch (NtHeaders->OptionalHeader.Magic)
    {
    case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
        DataDirectory = ((PIMAGE_NT_HEADERS32)NtHeaders)->OptionalHeader.DataDirectory;
        break;
    case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
        DataDirectory = ((PIMAGE_NT_HEADERS64)NtHeaders)->OptionalHeader.DataDirectory;
        break;
    }

    if (DataDirectory)
    {
        // get the debug directory entry
        PIMAGE_DATA_DIRECTORY DebugDirectoryEntry = &DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
        if (DebugDirectoryEntry->VirtualAddress)
        {
            // directory entry contains data; locate the section it resides in
            PIMAGE_SECTION_HEADER DebugSectionHeader = NULL;

            PIMAGE_SECTION_HEADER SectionHeaders = IMAGE_FIRST_SECTION(NtHeaders);
            for (WORD SectionIndex = 0; SectionIndex < NtHeaders->FileHeader.NumberOfSections; SectionIndex++)
            {
                PIMAGE_SECTION_HEADER SectionHeader = &SectionHeaders[SectionIndex];
                if ((DebugDirectoryEntry->VirtualAddress >= SectionHeader->VirtualAddress) && (DebugDirectoryEntry->VirtualAddress < (SectionHeader->VirtualAddress + SectionHeader->Misc.VirtualSize)))
                {
                    DebugSectionHeader = SectionHeader;
                    break;
                }
            }

            if (DebugSectionHeader)
            {
                // found the section; determine the relative offset and get the data
                PVOID SectionData = (PVOID)((ULONG_PTR)FileBuffer + DebugSectionHeader->PointerToRawData);
                DWORD RelativeOffset = (DebugDirectoryEntry->VirtualAddress - DebugSectionHeader->VirtualAddress);
                PIMAGE_DEBUG_DIRECTORY DebugDirectory = (PIMAGE_DEBUG_DIRECTORY)((ULONG_PTR)SectionData + RelativeOffset);
                // dump the data
                printf("DebugDirectory.Type: %u\n", DebugDirectory->Type);
            }
        }
    }
}
