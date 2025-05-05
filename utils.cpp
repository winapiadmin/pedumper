#include "utils.h"

void BuildRvaToFileOffsetTable(LPVOID baseAddress, std::unordered_map<DWORD,DWORD>& mappingTable) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)baseAddress;
    PIMAGE_NT_HEADERS32 ntHeaders = (PIMAGE_NT_HEADERS32)((DWORD_PTR)baseAddress + dosHeader->e_lfanew);

    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);

    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i, ++sectionHeader) {
        DWORD sectionStartRva = sectionHeader->VirtualAddress;
        DWORD sectionEndRva = sectionHeader->VirtualAddress + sectionHeader->SizeOfRawData;

        for (DWORD rva = sectionStartRva; rva < sectionEndRva; ++rva) {
            mappingTable[rva]=(rva - sectionHeader->VirtualAddress) + sectionHeader->PointerToRawData;
        }
    }
}
