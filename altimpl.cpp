#include "altimpl.h"
// Initialize the mapping table
std::unordered_map<DWORD,DWORD> mappingTable;
PVOID IMAGEAPI ImageDirectoryEntryToData(PVOID Base, BOOLEAN MappedAsImage, USHORT DirectoryEntry, PULONG Size) {
    if (!Base) { FAIL(D_DOS, ERROR_DOS); }

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)((DWORD_PTR)Base);
    PIMAGE_NT_HEADERS32 pNtHeaders32 = (PIMAGE_NT_HEADERS32)((DWORD_PTR)Base + pDosHeader->e_lfanew);
    PIMAGE_NT_HEADERS64 pNtHeaders64 = (PIMAGE_NT_HEADERS64)((DWORD_PTR)Base + pDosHeader->e_lfanew);
    IMAGE_DATA_DIRECTORY dataDirectory;

    switch (pNtHeaders32->OptionalHeader.Magic) {
        case 0x10B: // PE32
            dataDirectory = pNtHeaders32->OptionalHeader.DataDirectory[DirectoryEntry];
            break;
        case 0x20B: // PE32+
            dataDirectory = pNtHeaders64->OptionalHeader.DataDirectory[DirectoryEntry];
            break;
        default:
            FAIL(D_NIMP, ERROR_NIMP);
            break;
    }

    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(pNtHeaders32);
    PIMAGE_SECTION_HEADER targetSection = NULL;

    // Find section containing directory entry
    for (int i = 0; i < pNtHeaders32->FileHeader.NumberOfSections; i++) {
        if (sectionHeader->VirtualAddress <= dataDirectory.VirtualAddress &&
            dataDirectory.VirtualAddress < sectionHeader->VirtualAddress + sectionHeader->SizeOfRawData) {
            targetSection = sectionHeader;
            break;
        }
        sectionHeader++;
    }

    if (targetSection) {
        *Size = dataDirectory.Size;
        return (PVOID)((DWORD_PTR)Base + targetSection->PointerToRawData + dataDirectory.VirtualAddress - targetSection->VirtualAddress);
    } else {
        *Size = 0;
        return NULL;
    }
}
DECLSPEC_ALLOCATOR HLOCAL LocalAlloc(UINT   uFlags,
                                     SIZE_T uBytes
){
    if (uFlags==LPTR){
        return malloc(uBytes);
    }
    else{
        FAIL(D_NIMP,ERROR_NIMP);
    }
}
HLOCAL LocalFree(HLOCAL hMem){
    free(hMem);
    return NULL; //that SHOULD
}
#ifndef _MSC_VER
int _bittestandset(PLONG a, int b) {
    // Test the bit at position `b`
    int original_bit = (*a >> b) & 1;

    // Set the bit at position `b` to 1
    *a |= (1L << b);

    // Return the original value of the bit
    return original_bit;
}
#endif

// Helper function to convert RVA to file offset
DWORD RvaToFileOffset(DWORD rva) {
    auto it = mappingTable.find(rva);
    return (it != mappingTable.end()) ? it->second : 0;
}

// Enumerates resource names
bool EnumResourceNamesA(HMODULE hModule, LPCSTR lpType, ENUMRESNAMEPROCA lpEnumFunc, LONG_PTR lParam) {
    ULONG size;
    PIMAGE_RESOURCE_DIRECTORY resourceDir = (PIMAGE_RESOURCE_DIRECTORY)ImageDirectoryEntryToData(hModule, TRUE, IMAGE_DIRECTORY_ENTRY_RESOURCE, &size);
    if (!resourceDir) {
        return false;
    }

    PIMAGE_RESOURCE_DIRECTORY_ENTRY entry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((uintptr_t)resourceDir + sizeof(IMAGE_RESOURCE_DIRECTORY));

    // Enumerate named resource entries
    for (uint32_t i = 0; i < resourceDir->NumberOfNamedEntries; i++) {
        if (entry->Name & 0x80000000) {  // If high bit is set, it's an RVA to a string
            DWORD nameRva = entry->Name & 0x7FFFFFFF;  // Mask out high bit
            DWORD fileOffset = RvaToFileOffset(nameRva);
            if (fileOffset == 0) continue;

            char* resourceName = (char*)((uintptr_t)hModule + fileOffset);

            if (!lpEnumFunc(hModule, lpType, resourceName, lParam)) {
                return false;
            }
        } else {  // This is an integer ID
            uint32_t resourceId = entry->Name;
            std::string resourceIdStr = "#" + std::to_string(resourceId);
            if (!lpEnumFunc(hModule, lpType, const_cast<char*>(resourceIdStr.c_str()), lParam)) {
                return false;
            }
        }
        entry++;
    }

    return true;
}

// Finds a resource entry by name or ID
HRSRC FindResource(HMODULE hModule, LPCSTR lpName, LPCSTR lpType) {
    ULONG size;
    PIMAGE_RESOURCE_DIRECTORY resourceDir = (PIMAGE_RESOURCE_DIRECTORY)ImageDirectoryEntryToData(hModule, TRUE, IMAGE_DIRECTORY_ENTRY_RESOURCE, &size);
    if (!resourceDir) {
        return NULL;
    }

    PIMAGE_RESOURCE_DIRECTORY_ENTRY entry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((uintptr_t)resourceDir + sizeof(IMAGE_RESOURCE_DIRECTORY));

    // Search for named resources
    for (uint32_t i = 0; i < resourceDir->NumberOfNamedEntries; i++) {
        if (entry->Name & 0x80000000) {  // If high bit is set, it's an RVA to a string
            DWORD nameRva = entry->Name & 0x7FFFFFFF;
            DWORD fileOffset = RvaToFileOffset(nameRva);
            if (fileOffset == 0) continue;

            char* resourceName = (char*)((uintptr_t)hModule + fileOffset);
            if (strcmp(resourceName, lpName) == 0) {
                return (HRSRC)entry;
            }
        }
        entry++;
    }

    // Search for ID-based resources
    for (uint32_t i = 0; i < resourceDir->NumberOfIdEntries; i++) {
        if ((uintptr_t)lpName == entry->Name) {
            return (HRSRC)entry;
        }
        entry++;
    }

    return NULL;
}

// Retrieves the size of a given resource
DWORD SizeofResource(HMODULE hModule, HRSRC hResInfo) {
    if (!hResInfo) {
        return 0;
    }

    PIMAGE_RESOURCE_DIRECTORY_ENTRY resEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)hResInfo;
    DWORD offsetToData = resEntry->OffsetToData & 0x7FFFFFFF;  // Mask out high bits

    DWORD fileOffset = RvaToFileOffset(offsetToData);
    if (fileOffset == 0) return 0;

    PIMAGE_RESOURCE_DATA_ENTRY resourceDataEntry = (PIMAGE_RESOURCE_DATA_ENTRY)((uintptr_t)hModule + fileOffset);
    return resourceDataEntry->Size;
}
