#include <windows.h>
#include <dbghelp.h>
#include <vector>
#include "PDBFile.h"
#include <iostream>
#include "Debug.h"
#include "capstone/capstone.h"
using namespace std;
// safe-fail implementation for assert
#define FAIL(s,ln) printf("\tERROR: %s Line: %i\n",s,ln);return 1
#define WARN(s,ln) printf("\tWARNING: %s Line: %i\n",s,ln)
#define RtlOffsetToPointer(B,O)  ((ULONG_PTR)( ((ULONG_PTR)(B)) + ((ULONG_PTR)(O))  ))
#define RtlPointerToOffset(B,O)  ((ULONG_PTR)( ((ULONG_PTR)(B)) - ((ULONG_PTR)(O))  ))
#define DbgPrint printf
HANDLE hFile,hMapping;
HMODULE hmod;
BOOL CALLBACK ENUMRESPROCCALLBACK(	HMODULE hMod,
                                    LPCSTR lpType,
                                    LPSTR lpName,
                                    LONG_PTR lParam
                                 )
{
    HRSRC hResource=FindResource(hMod,lpName,lpType);
    printf("\t%02lX\t\tSize\n", SizeofResource(hMod,hResource));
    return TRUE;
}
WINBOOL WINAPI Handler(DWORD)
{
    if (hFile)
        CloseHandle(hFile);
    if (hMapping) CloseHandle(hMapping);
    if (hmod)
        FreeLibrary(hmod);
    return TRUE;
}
int main(int argc, char* argv[])
{
    if (argc==1)
    {
        printf("pedump filename\n");
        printf("By default it will dump all information");
        return 1;
    }
    SetConsoleCtrlHandler((PHANDLER_ROUTINE)Handler,TRUE);
    // Open the executable file you want to load
    hFile=CreateFile(argv[1], GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        FAIL("Failed to open file",24);
        // Handle error
        return 1;
    }

    // Create a file mapping object that represents the executable file
    hMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (hMapping == NULL)
    {
        CloseHandle(hFile);
        FAIL("Failed to create file maping",33);
        // Handle error
        return 1;
    }

    // Map a view of the file into your process's address space
    LPVOID lpBaseAddress = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (lpBaseAddress == NULL)
    {
        // Handle error
        CloseHandle(hMapping);
        CloseHandle(hFile);
        FAIL("Failed to map view file",43);
        return 1;
    }
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpBaseAddress;
    PIMAGE_NT_HEADERS32 pNtHeaders32 = (PIMAGE_NT_HEADERS32)((DWORD_PTR)lpBaseAddress + pDosHeader->e_lfanew);
    PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)((DWORD_PTR)pNtHeaders32+sizeof(DWORD)); //extra Signature
    PIMAGE_NT_HEADERS64 pNtHeaders64 = (PIMAGE_NT_HEADERS64)((DWORD_PTR)lpBaseAddress + pDosHeader->e_lfanew);
    printf("------ DOS HEADER ------\n");
    printf("\te_magic         %X\t(%sVALID)\n", pDosHeader->e_magic, pDosHeader->e_magic==IMAGE_DOS_SIGNATURE?"":"IN");
    if (pDosHeader->e_magic!=IMAGE_DOS_SIGNATURE)
    {
        CloseHandle(hMapping);
        CloseHandle(hFile);
        FAIL("Invalid DOS Header",55);
    }
    printf("\te_cblp          %X\n", pDosHeader->e_cblp);
    printf("\te_cp            %X\n", pDosHeader->e_cp);
    printf("\te_crlc          %X\n", pDosHeader->e_crlc);
    printf("\te_cparhdr       %X\n", pDosHeader->e_cparhdr);
    printf("\te_minalloc      %X\n", pDosHeader->e_minalloc);
    printf("\te_maxalloc      %X\n", pDosHeader->e_maxalloc);
    printf("\te_ss            %X\n", pDosHeader->e_ss);
    printf("\te_sp            %X\n", pDosHeader->e_sp);
    printf("\te_csum          %X\n", pDosHeader->e_csum);
    printf("\te_ip            %X\n", pDosHeader->e_ip);
    printf("\te_cs            %X\n", pDosHeader->e_cs);
    printf("\te_lfarlc        %X\n", pDosHeader->e_lfarlc);
    printf("\te_ovno          %X\n", pDosHeader->e_ovno);
    printf("\te_oemid         %X\n", pDosHeader->e_oemid);
    printf("\te_oeminfo       %X\n", pDosHeader->e_oeminfo);
    printf("\te_lfanew        %lX\n", pDosHeader->e_lfanew);
    printf("------ PE HEADER  ------\n");
    printf("\tSignature            %lX\n",pNtHeaders32->Signature);
    printf("\tMachine              %X\n\t",pFileHeader->Machine);
    switch(pFileHeader->Machine)
    {
    case IMAGE_FILE_MACHINE_I386:
        printf("\ti386\n");
        break;
    case IMAGE_FILE_MACHINE_R3000:
        printf("\tR3000\n");
        break;
    case IMAGE_FILE_MACHINE_R4000:
        printf("\tMIPS little endian\n");
        break;
    case IMAGE_FILE_MACHINE_R10000:
        printf("\tR10000\n");
        break;
    case IMAGE_FILE_MACHINE_WCEMIPSV2:
        printf("\tWCEMIPSV2\n");
        break;
    case IMAGE_FILE_MACHINE_ALPHA:
        printf("\tAlpha AXP, 32-bit address space\n");
        break;
    case IMAGE_FILE_MACHINE_SH3:
        printf("\tHitachi SH3");
        break;
    case IMAGE_FILE_MACHINE_SH3DSP:
        printf("\tHitachi SH3 DSP\n");
        break;
    case IMAGE_FILE_MACHINE_SH3E:
        printf("\tSH3E\n");
        break;
    case IMAGE_FILE_MACHINE_SH4:
        printf("\tHitachi SH4\n");
        break;
    case IMAGE_FILE_MACHINE_SH5:
        printf("\tHitachi SH5\n");
        break;
    case IMAGE_FILE_MACHINE_ARM:
        printf("\tARM little endian\n");
        break;
    case IMAGE_FILE_MACHINE_ARMV7:
        printf("\tARMv7\n");
        break;
    case IMAGE_FILE_MACHINE_ARM64:
        printf("\tARM64 little endian\n");
        break;
    case IMAGE_FILE_MACHINE_THUMB:
        printf("\tThumb\n");
        break;
    case IMAGE_FILE_MACHINE_AM33:
        printf("\tMatsushita AM33\n");
        break;
    case IMAGE_FILE_MACHINE_POWERPC:
        printf("\tPower PC little endian\n");
        break;
    case IMAGE_FILE_MACHINE_POWERPCFP:
        printf("\tPower PC with floating point support\n");
        break;
    case IMAGE_FILE_MACHINE_IA64:
        printf("\tIntel Itanium processor family\n");
        break;
    case IMAGE_FILE_MACHINE_MIPS16:
        printf("\tMIPS16\n");
        break;
    case IMAGE_FILE_MACHINE_ALPHA64:
        printf("\tAlpha 64, 64-bit address space\n");
        break;
    case IMAGE_FILE_MACHINE_MIPSFPU:
        printf("\tMIPS with FPU\n");
        break;
    case IMAGE_FILE_MACHINE_MIPSFPU16:
        printf("\tMIPS16 with FPU\n");
        break;
    case IMAGE_FILE_MACHINE_TRICORE:
        printf("\tTRICORE\n");
        break;
    case IMAGE_FILE_MACHINE_CEF:
        printf("\tCEF\n");
        break;
    case IMAGE_FILE_MACHINE_EBC:
        printf("\tEFI bytecode\n");
        break;
    case IMAGE_FILE_MACHINE_AMD64:
        printf("\tx64\n");
        break;
    case IMAGE_FILE_MACHINE_M32R:
        printf("\tMitsubishi M32R little endian");
        break;
    case IMAGE_FILE_MACHINE_CEE:
        printf("\tCEE\n");
        break;
    default:
        CloseHandle(hMapping);
        CloseHandle(hFile);
        FAIL("Unknown machine",172);
    }
    printf("\tNumber of Sections   %X\n",pFileHeader->NumberOfSections);
    printf("\tTime/Date Stamp      %li\n",pFileHeader->TimeDateStamp);
    printf("\tPtr to symbol table  %lX\n",pFileHeader->PointerToSymbolTable);
    printf("\tNumber of symbols    %li\n",pFileHeader->NumberOfSymbols);
    printf("\tOptional Header size %i\n",pFileHeader->SizeOfOptionalHeader);
    printf("\tCharacteristics\n");
    if (pFileHeader->Characteristics&IMAGE_FILE_RELOCS_STRIPPED) printf("\t\tRelocs stripped\n");
    if (pFileHeader->Characteristics&IMAGE_FILE_EXECUTABLE_IMAGE) printf("\t\tExecutable image\n");
    if (pFileHeader->Characteristics&IMAGE_FILE_LINE_NUMS_STRIPPED) printf("\t\tLine numbers information stripped\n");
    if (pFileHeader->Characteristics&IMAGE_FILE_LOCAL_SYMS_STRIPPED) printf("\t\tLocal symbols information stripped\n");
    if (pFileHeader->Characteristics&IMAGE_FILE_AGGRESIVE_WS_TRIM) printf("\t\tAggressive WS trim\n");
    if (pFileHeader->Characteristics&IMAGE_FILE_LARGE_ADDRESS_AWARE) printf("\t\tCan handle >2GB addresses\n");
    if (pFileHeader->Characteristics&IMAGE_FILE_BYTES_REVERSED_LO) printf("\t\tLittle-endian on file (deprecated)\n");
    if (pFileHeader->Characteristics&IMAGE_FILE_32BIT_MACHINE) printf("\t\tx86 word architecture\n");
    if (pFileHeader->Characteristics&IMAGE_FILE_DEBUG_STRIPPED) printf("\t\tDebug info stripped\n");
    if (pFileHeader->Characteristics&IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP||
            pFileHeader->Characteristics&IMAGE_FILE_NET_RUN_FROM_SWAP) printf("\t\tRun from swap file\n");
    if (pFileHeader->Characteristics&IMAGE_FILE_SYSTEM) printf("\t\tSystem file\n");
    if (pFileHeader->Characteristics&IMAGE_FILE_DLL) printf("\t\tDLL file\n");
    if (pFileHeader->Characteristics&IMAGE_FILE_UP_SYSTEM_ONLY) printf("\tShould run only on uniprocessor machine\n");
    if (pFileHeader->Characteristics&IMAGE_FILE_BYTES_REVERSED_HI) printf("\t\tBig-endian on file (deprecated)\n");
    printf("------ OPTIONAL HEADER ------\n");
    printf("\tMagic                     %03x\n",pNtHeaders32->OptionalHeader.Magic);
    switch(pNtHeaders32->OptionalHeader.Magic)
    {
    case 0x10B:
        printf("\t\tPE32\n");
        break;
    case 0x20B:
        printf("\t\tPE32+\n");
        break;
    case 0x107:
        printf("\t\tROM\n");
        break;
    default:
        CloseHandle(hMapping);
        CloseHandle(hFile);
        FAIL("Not implemented - might be invalid",209);
    }
    printf("\tLinker version            %i.%i\n",pNtHeaders32->OptionalHeader.MajorLinkerVersion,pNtHeaders32->OptionalHeader.MinorLinkerVersion);
    printf("\tCode size                 %li\n",pNtHeaders32->OptionalHeader.SizeOfCode);
    printf("\tInitialized data size     %li\n",pNtHeaders32->OptionalHeader.SizeOfInitializedData);
    printf("\tUninitialized data size   %li\n",pNtHeaders32->OptionalHeader.SizeOfUninitializedData);
    printf("\tEntry point address       %08lX\n",pNtHeaders32->OptionalHeader.AddressOfEntryPoint);
    printf("\tBase of code              %08lX\n",pNtHeaders32->OptionalHeader.BaseOfCode);
    const vector<const char*> DataDirectoriesName= {"Export table","Import table","Resource table","Exception table","Certificate table","Base Relocation table","Debug","Architecture","Global Ptr","TLS table","Load Config table","Bound import","IAT","Delay Import Descriptor","CLR Runtime Header", "Reversed"};
    const char *subsystems[] =
    {
        "Unknown",
        "Native",
        "GUI",
        "CUI",
        "OS/2 CUI",
        "Posix CUI",
        "Native Win9x driver",
        "Windows CE",
        "EFI application",
        "EFI driver with boot services",
        "EFI driver with run-time services",
        "EFI ROM",
        "XBOX",
        "Windows boot application"
    };
    IMAGE_DATA_DIRECTORY importDataDir;
    PIMAGE_ROM_OPTIONAL_HEADER ROMHdr=(PIMAGE_ROM_OPTIONAL_HEADER)((DWORD_PTR)pNtHeaders32+sizeof(IMAGE_FILE_HEADER));
    switch(pNtHeaders32->OptionalHeader.Magic)
    {
    case 0x10B:
        printf("\tBase of data              %08lX\n",pNtHeaders32->OptionalHeader.BaseOfData);
        printf("\tImage Base                %08lX\n",pNtHeaders32->OptionalHeader.ImageBase);
        printf("\tSection alignment         %08lX\n",pNtHeaders32->OptionalHeader.SectionAlignment);
        printf("\tFile alignment            %08lX\n",pNtHeaders32->OptionalHeader.FileAlignment);
        printf("\tRequired OS Major Version %i\n",pNtHeaders32->OptionalHeader.MajorOperatingSystemVersion);
        printf("\tRequired OS Minor Version %i\n",pNtHeaders32->OptionalHeader.MinorOperatingSystemVersion);
        printf("\tImage Major Version       %i\n",pNtHeaders32->OptionalHeader.MajorImageVersion);
        printf("\tImage Minor Version       %i\n",pNtHeaders32->OptionalHeader.MinorImageVersion);
        printf("\tSubsystem Major Version   %i\n",pNtHeaders32->OptionalHeader.MajorSubsystemVersion);
        printf("\tSubsystem Minor Version   %i\n",pNtHeaders32->OptionalHeader.MajorSubsystemVersion);
        printf("\tSize Of Image             %li\n",pNtHeaders32->OptionalHeader.SizeOfImage);
        printf("\tSize Of Headers           %li\n",pNtHeaders32->OptionalHeader.SizeOfHeaders);
        printf("\tChecksum                  %08lX\n",pNtHeaders32->OptionalHeader.CheckSum);
        printf("\tSubsystem\n");
        printf("\t\t%s\n",pNtHeaders32->OptionalHeader.Subsystem<=IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION?subsystems[pNtHeaders32->OptionalHeader.Subsystem]:subsystems[0]);
        printf("\tDLL characterics\n");
        if (pNtHeaders32->OptionalHeader.DllCharacteristics&IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA) printf("\t\tCan handle a high entropy 64-bit virtual address space\n");
        if (pNtHeaders32->OptionalHeader.DllCharacteristics&IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) printf("\t\tCan be relocated at load time\n");
        if (pNtHeaders32->OptionalHeader.DllCharacteristics&IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY) printf("\t\tCode Integrity checks are enforced\n");
        if (pNtHeaders32->OptionalHeader.DllCharacteristics&IMAGE_DLLCHARACTERISTICS_NX_COMPAT) printf("\t\tImage is NX compatible\n");
        if (pNtHeaders32->OptionalHeader.DllCharacteristics&IMAGE_DLLCHARACTERISTICS_NO_ISOLATION) printf("\t\tIsolation aware, but do not isolate the image\n");
        if (pNtHeaders32->OptionalHeader.DllCharacteristics&IMAGE_DLLCHARACTERISTICS_NO_SEH) printf("\t\tDoes not use SEH\n");
        if (pNtHeaders32->OptionalHeader.DllCharacteristics&IMAGE_DLLCHARACTERISTICS_NO_BIND) printf("\t\tDo not bind the image\n");
        if (pNtHeaders32->OptionalHeader.DllCharacteristics&IMAGE_DLLCHARACTERISTICS_APPCONTAINER) printf("\t\tImage must execute in an AppContainer\n");
        if (pNtHeaders32->OptionalHeader.DllCharacteristics&IMAGE_DLLCHARACTERISTICS_WDM_DRIVER) printf("\t\tIs WDM Driver\n");
        if (pNtHeaders32->OptionalHeader.DllCharacteristics&IMAGE_DLLCHARACTERISTICS_GUARD_CF) printf("\t\tHave GUARD_CF flag, not compressable!\n");
        if (pNtHeaders32->OptionalHeader.DllCharacteristics&IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE) printf("\t\tTerminal Server aware\n");
        printf("\tReverse stack size        %08lX\n",pNtHeaders32->OptionalHeader.SizeOfStackReserve);
        printf("\tCommite stack size        %08lX\n",pNtHeaders32->OptionalHeader.SizeOfStackCommit);
        printf("\tReverse heap size         %08lX\n",pNtHeaders32->OptionalHeader.SizeOfHeapReserve);
        printf("\tCommit heap size          %08lX\n",pNtHeaders32->OptionalHeader.SizeOfHeapReserve);
        printf("\n------Data Directories------\n");
        printf("\tName                    \tRVA    Size\n");
        for (int i=0; i < pNtHeaders32->OptionalHeader.NumberOfRvaAndSizes; i++)
        {
            printf("\t\t%-23s 0x%08lx 0x%08lx\n",DataDirectoriesName[i],pNtHeaders32->OptionalHeader.DataDirectory[i].VirtualAddress,pNtHeaders32->OptionalHeader.DataDirectory[i].Size);
            if (i==IMAGE_DIRECTORY_ENTRY_IMPORT)
                importDataDir=pNtHeaders64->OptionalHeader.DataDirectory[i];
        }
        break;
    case 0x20B:
        printf("\tImage Base                %016llX\n",pNtHeaders64->OptionalHeader.ImageBase);
        printf("\tSection alignment         %08lX\n",pNtHeaders64->OptionalHeader.SectionAlignment);
        printf("\tFile alignment            %08lX\n",pNtHeaders64->OptionalHeader.FileAlignment);
        printf("\tRequired OS Major Version %i\n",pNtHeaders64->OptionalHeader.MajorOperatingSystemVersion);
        printf("\tRequired OS Minor Version %i\n",pNtHeaders64->OptionalHeader.MinorOperatingSystemVersion);
        printf("\tImage Major Version       %i\n",pNtHeaders64->OptionalHeader.MajorImageVersion);
        printf("\tImage Minor Version       %i\n",pNtHeaders64->OptionalHeader.MinorImageVersion);
        printf("\tSubsystem Major Version   %i\n",pNtHeaders64->OptionalHeader.MajorSubsystemVersion);
        printf("\tSubsystem Minor Version   %i\n",pNtHeaders64->OptionalHeader.MajorSubsystemVersion);
        printf("\tSize Of Image             %08li\n",pNtHeaders64->OptionalHeader.SizeOfImage);
        printf("\tSize Of Headers           %08li\n",pNtHeaders64->OptionalHeader.SizeOfHeaders);
        printf("\tChecksum                  %08lX\n",pNtHeaders64->OptionalHeader.CheckSum);
        printf("\tSubsystem\n");
        printf("\t\t%s\n",pNtHeaders64->OptionalHeader.Subsystem<=IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION?subsystems[pNtHeaders64->OptionalHeader.Subsystem]:subsystems[0]);
        printf("\tDLL characterics\n");
        if (pNtHeaders64->OptionalHeader.DllCharacteristics&IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA) printf("\t\tCan handle a high entropy 64-bit virtual address space\n");
        if (pNtHeaders64->OptionalHeader.DllCharacteristics&IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) printf("\t\tCan be relocated at load time\n");
        if (pNtHeaders64->OptionalHeader.DllCharacteristics&IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY) printf("\t\tCode Integrity checks are enforced\n");
        if (pNtHeaders64->OptionalHeader.DllCharacteristics&IMAGE_DLLCHARACTERISTICS_NX_COMPAT) printf("\t\tImage is NX compatible\n");
        if (pNtHeaders64->OptionalHeader.DllCharacteristics&IMAGE_DLLCHARACTERISTICS_NO_ISOLATION) printf("\t\tIsolation aware, but do not isolate the image\n");
        if (pNtHeaders64->OptionalHeader.DllCharacteristics&IMAGE_DLLCHARACTERISTICS_NO_SEH) printf("\t\tDoes not use SEH\n");
        if (pNtHeaders64->OptionalHeader.DllCharacteristics&IMAGE_DLLCHARACTERISTICS_NO_BIND) printf("\t\tDo not bind the image\n");
        if (pNtHeaders64->OptionalHeader.DllCharacteristics&IMAGE_DLLCHARACTERISTICS_APPCONTAINER) printf("\t\tImage must execute in an AppContainer\n");
        if (pNtHeaders64->OptionalHeader.DllCharacteristics&IMAGE_DLLCHARACTERISTICS_WDM_DRIVER) printf("\t\tIs WDM Driver\n");
        if (pNtHeaders64->OptionalHeader.DllCharacteristics&IMAGE_DLLCHARACTERISTICS_GUARD_CF) printf("\t\tSupports GUARD_CF flag - do not compress!\n");
        if (pNtHeaders64->OptionalHeader.DllCharacteristics&IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE) printf("\t\tTerminal Server aware\n");
        printf("\tReverse stack size        %08llX\n",pNtHeaders64->OptionalHeader.SizeOfStackReserve);
        printf("\tCommite stack size        %08llX\n",pNtHeaders64->OptionalHeader.SizeOfStackCommit);
        printf("\tReverse heap size         %08llX\n",pNtHeaders64->OptionalHeader.SizeOfHeapReserve);
        printf("\tCommit heap size          %08llX\n",pNtHeaders64->OptionalHeader.SizeOfHeapReserve);
        printf("\n------Data Directories------\n");
        printf("\tName                    \tRVA    Size\n");
        for (int i=0; i < pNtHeaders64->OptionalHeader.NumberOfRvaAndSizes; i++)
        {
            printf("\t\t%-23s 0x%08lx 0x%08lx\n",DataDirectoriesName[i],pNtHeaders64->OptionalHeader.DataDirectory[i].VirtualAddress,pNtHeaders64->OptionalHeader.DataDirectory[i].Size);
            if (i==IMAGE_DIRECTORY_ENTRY_IMPORT)
                importDataDir=pNtHeaders64->OptionalHeader.DataDirectory[i];
        }
        break;
    case 0x107:
        printf("\tBase of data             %08lX\n",ROMHdr->BaseOfData);
        printf("\tBase of bss              %08lX\n",ROMHdr->BaseOfData);
        printf("\tGPR mask                 %08lX\n",ROMHdr->GprMask);
        printf("\tCPR mask                 %08lX %08lX %08lX %08lX\n",ROMHdr->CprMask[0],ROMHdr->CprMask[1],ROMHdr->CprMask[2],ROMHdr->CprMask[3]);
        printf("\tGP value                 %08lX\n",ROMHdr->GpValue);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        FAIL("ROM not implemented",310);
    default:
        CloseHandle(hMapping);
        CloseHandle(hFile);
        FAIL("Invalid magic number (OptionalHeader)",311);
    }
    //global parsing - not support ROM
    printf("------- SECTION HEADERS -------\n");
    DWORD_PTR sectionLocation = (DWORD_PTR)pNtHeaders32 + sizeof(DWORD) + (DWORD)(sizeof(IMAGE_FILE_HEADER)) + (DWORD)pFileHeader->SizeOfOptionalHeader;
    PIMAGE_SECTION_HEADER importSection=NULL;
    for (int i=0; i<pFileHeader->NumberOfSections; i++)
    {
        PIMAGE_SECTION_HEADER sectionHeader=(PIMAGE_SECTION_HEADER)sectionLocation;
        printf("\tName                           %s\n",sectionHeader->Name);
        printf("\t\tPhysical address       0x%08lx\n", sectionHeader->Misc.PhysicalAddress);
        printf("\t\tVirtual size           0x%08lx\n", sectionHeader->Misc.VirtualSize);
        printf("\t\tVirtual address        0x%08lx\n", sectionHeader->VirtualAddress);
        printf("\t\tSize of raw data       0x%08lx\n", sectionHeader->SizeOfRawData);
        printf("\t\tPointer to raw data    0x%08lx\n", sectionHeader->PointerToRawData);
        printf("\t\tPointer to relocations 0x%08lx\n", sectionHeader->PointerToRelocations);
        printf("\t\tPointer to linenumbers 0x%08lx\n", sectionHeader->PointerToLinenumbers);
        printf("\t\tNumber of relocations  0x%x\n", sectionHeader->NumberOfRelocations);
        printf("\t\tNumber of linenumbers  0x%x\n", sectionHeader->NumberOfLinenumbers);
        printf("\t\tCharacteristics        0x%08lx\n", sectionHeader->Characteristics);
        if (sectionHeader->Characteristics & IMAGE_SCN_TYPE_NO_PAD) printf("\t\t\tNo padding (obsolete)\n");
        if (sectionHeader->Characteristics & IMAGE_SCN_CNT_CODE) printf("\t\t\tContains executable code\n");
        if (sectionHeader->Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA) printf("\t\t\tContains initialized data\n");
        if (sectionHeader->Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) printf("\t\t\tContains uninitialized data\n");
        if (sectionHeader->Characteristics & IMAGE_SCN_LNK_OTHER) printf("\t\t\tOther data (reserved)\n");
        if (sectionHeader->Characteristics & IMAGE_SCN_LNK_INFO)
        {
            printf("\t\t\tContains linker info\n");
            FAIL("Flag only for COFF",330);
        }
        if (sectionHeader->Characteristics & IMAGE_SCN_LNK_REMOVE)
        {
            printf("\t\t\tWill become part of image\n");
            FAIL("Flag only for COFF",331);
        }
        if (sectionHeader->Characteristics & IMAGE_SCN_LNK_COMDAT)
        {
            printf("\t\t\tContains COMDAT data\n");
            FAIL("Flag only for COFF",332);
        }
        if (sectionHeader->Characteristics & IMAGE_SCN_GPREL) printf("\t\t\tContains data referenced through the global pointer\n");
        for (int i=1; i < 15; i++)
        {
            if (sectionHeader->Characteristics & (1<<20*i))
            {
                printf("\t\t\tAlign data on an %i-byte boundary\n",1<<i);
                FAIL("Flag only for COFF",335);
            }
        }
        if (sectionHeader->Characteristics & IMAGE_SCN_LNK_NRELOC_OVFL) printf("\t\t\tContains extended relocations\n");
        if (sectionHeader->Characteristics & IMAGE_SCN_MEM_DISCARDABLE) printf("\t\t\tCan discard if necessary\n");
        if (sectionHeader->Characteristics & IMAGE_SCN_MEM_NOT_CACHED) printf("\t\t\tCan't be cached\n");
        if (sectionHeader->Characteristics & IMAGE_SCN_MEM_NOT_PAGED) printf("\t\t\tNot pageable\n");
        if (sectionHeader->Characteristics & IMAGE_SCN_MEM_SHARED) printf("\t\t\tShared\n");
        if (sectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE) printf("\t\t\tCan execute\n");
        if (sectionHeader->Characteristics & IMAGE_SCN_MEM_READ) printf("\t\t\tCan read\n");
        if (sectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE) printf("\t\t\tCan write\n");
        // Check for Import Section
        if (importDataDir.VirtualAddress >= sectionHeader->VirtualAddress &&
                importDataDir.VirtualAddress < (sectionHeader->VirtualAddress + sectionHeader->SizeOfRawData))
        {
            importSection = sectionHeader;
        }
        sectionLocation+=sizeof(IMAGE_SECTION_HEADER);
    }
    printf("------ DLL IMPORTS ------\n");
    if (importSection!=NULL)
    {
        // Calculate raw offset
        DWORD_PTR rawOffset = (DWORD_PTR)lpBaseAddress + importSection->PointerToRawData;

        // Iterate over import descriptors
        PIMAGE_IMPORT_DESCRIPTOR importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(rawOffset + (importDataDir.VirtualAddress - importSection->VirtualAddress));
        for (; importDescriptor->Name != 0; importDescriptor++)
        {
            // Resolve imported module name
            char* moduleName = (char*)(rawOffset + (importDescriptor->Name - importSection->VirtualAddress));
            printf("\t%s\n", moduleName);
            printf("\t\tOrdinal\tFunction Name\n");
            // Resolve imported functions
            DWORD thunk = importDescriptor->OriginalFirstThunk == 0 ? importDescriptor->FirstThunk : importDescriptor->OriginalFirstThunk;
            PIMAGE_THUNK_DATA32 thunkData32 = (PIMAGE_THUNK_DATA32)(rawOffset + (thunk - importSection->VirtualAddress));
            PIMAGE_THUNK_DATA64 thunkData64 = (PIMAGE_THUNK_DATA64)(rawOffset + (thunk - importSection->VirtualAddress));

            switch (pNtHeaders32->OptionalHeader.Magic)
            {
            case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
                // 32-bit case
                for (; thunkData32->u1.AddressOfData != 0; thunkData32++)
                {
                    if (thunkData32->u1.Ordinal & IMAGE_ORDINAL_FLAG32)
                    {
                        printf("\t\t%x\t-\n", (WORD)thunkData32->u1.Ordinal & 0xFFFF);
                    }
                    else
                    {
                        PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)(rawOffset + (thunkData32->u1.AddressOfData - importSection->VirtualAddress));
                        char* decorated=(char*)malloc(256);
                        UnDecorateSymbolName(&importByName->Name[0],decorated,256,UNDNAME_COMPLETE);
                        printf("\t\t-\t%s\n", decorated);
                    }
                }
                break;
            case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
                // 64-bit case
                for (; thunkData64->u1.AddressOfData != 0; thunkData64++)
                {
                    if (thunkData64->u1.Ordinal & IMAGE_ORDINAL_FLAG64)
                    {
                        printf("\t\t%x\t-\n", (WORD)thunkData64->u1.Ordinal & 0xFFFF);
                    }
                    else
                    {
                        PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)(rawOffset + (thunkData64->u1.AddressOfData - importSection->VirtualAddress));
                        char* decorated=(char*)malloc(256);
                        UnDecorateSymbolName(&importByName->Name[0],decorated,256,UNDNAME_COMPLETE);
                        printf("\t\t-\t%s\n", decorated);
                    }
                }
                break;
            }
        }
    }
    else printf("\tEmpty\n");
    printf("------ DLL EXPORTS ------\n");
    ULONG size;
    hmod=LoadLibrary(argv[1]);
    PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)ImageDirectoryEntryToData(hmod, TRUE, IMAGE_DIRECTORY_ENTRY_EXPORT, &size);
    if (exports)
    {
        // Calculate raw offset
        printf("\tTime date stamp        %08lX\n",exports->TimeDateStamp);
        printf("\tVersion                %i.%i\n",exports->MajorVersion,exports->MinorVersion);
        printf("\tOrdinal base           %li\n",exports->Base);
        printf("\tNumber of entries      %08li\n",exports->NumberOfFunctions);
        printf("\tNumber of names        %08li\n",exports->NumberOfNames);
        printf("\tAddress of functions   %08li\n",exports->AddressOfFunctions);
        printf("\tAddress of names       %08li\n",exports->AddressOfNames);
        printf("\tAddress of ordinals    %08li\n",exports->AddressOfNameOrdinals);
        printf("\tEntries\n");
        printf("\tOrdinal RVA              Name\n");
        printf("\t----------------------------------------------\n");
        if (DWORD NumberOfFunctions = exports->NumberOfFunctions)
        {
            if (PLONG bits = (PLONG)LocalAlloc(LMEM_FIXED|LMEM_ZEROINIT, (NumberOfFunctions + 7) >> 3))
            {
                ULONG i;
                PULONG AddressOfFunctions = (PULONG)RtlOffsetToPointer(hmod, exports->AddressOfFunctions);
                if (DWORD NumberOfNames = exports->NumberOfNames)
                {
                    PULONG AddressOfNames = (PULONG)RtlOffsetToPointer(hmod, exports->AddressOfNames);
                    PUSHORT AddressOfNameOrdinals = (PUSHORT)RtlOffsetToPointer(hmod, exports->AddressOfNameOrdinals);
                    do
                    {
                        PCSTR Name = (PCSTR)RtlOffsetToPointer(hmod, *AddressOfNames++);

                        _bittestandset(bits, i = *AddressOfNameOrdinals++);

                        PVOID pv = (PVOID)RtlOffsetToPointer(hmod, AddressOfFunctions[i]);

                        if ((ULONG_PTR)pv - (ULONG_PTR)exports < size)
                        {
                            DbgPrint("\t%08lX    %016llX %s -> %s\r\n", exports->Base+i, RtlPointerToOffset(hmod, pv), Name, (char*)pv);
                        }
                        else
                        {
                            DbgPrint("\t%08lX    %016llX %s\r\n", exports->Base+i, RtlPointerToOffset(hmod, pv), Name);
                        }
                    }
                    while (--NumberOfNames);
                }

                DWORD Base = exports->Base;
                AddressOfFunctions += NumberOfFunctions;
                do
                {
                    --AddressOfFunctions;
                    if (!_bittestandset(bits, --NumberOfFunctions))
                    {
                        PVOID pv = (PVOID)RtlOffsetToPointer(hmod, *AddressOfFunctions);

                        if ((ULONG_PTR)pv - (ULONG_PTR)exports < size)
                        {
                            DbgPrint("%08lX    %016llX #%lu -> %s\r\n", Base+i, RtlPointerToOffset(hmod, pv), Base + NumberOfFunctions, (char*)pv);
                        }
                        else
                        {
                            DbgPrint("%08lX    %016llX #%lu\r\n",Base+ i, RtlPointerToOffset(hmod, pv), Base + NumberOfFunctions);
                        }
                    }
                }
                while (NumberOfFunctions);
                LocalFree(bits);
            }
        }
    }
    else printf("\tEmpty\n");
    printf("------ DEBUG INFOS ------\n");
    PIMAGE_DEBUG_DIRECTORY dbg = (PIMAGE_DEBUG_DIRECTORY)ImageDirectoryEntryToData(hmod, TRUE, IMAGE_DIRECTORY_ENTRY_DEBUG, &size);
    DWORD_PTR location;
    if (dbg)
    {
        printf("\tTime date stamp        %016lX\n",dbg->TimeDateStamp);
        printf("\tVersion                %i.%i\n",dbg->MajorVersion,dbg->MinorVersion);
        printf("\tType                   %lX\n", dbg->Type);
        switch(dbg->Type)
        {
        case 0:
            printf("\t\tUnknown\n");
            break;
        case 1:
            printf("\t\tCOFF\n");
            break;
        case 2:
            printf("\t\tCodeView\n");
            break;
        case 3:
            printf("\t\tFPO\n");
            break;
        case 4:
            printf("\t\tMiscellaneous\n");
            break;
        case 5:
            printf("\t\tException (copy of .pdata)\n");
            break;
        case 6:
            printf("\t\tFixup information\n");
            break;
        case 9:
            printf("\t\tBorland debugging information\n");
            break;
        default:
            WARN("Unknown debug type",545);
        }
        printf("\tSize of debugging info %lX\n",dbg->SizeOfData);
        printf("\tAddress of raw data    %lX\n",dbg->AddressOfRawData);
        printf("\tPointer to raw data    %lX\n",dbg->PointerToRawData);

        printf("------ SPECIFIC DEBUG INFORMATION ------\n");
        location=((DWORD_PTR)lpBaseAddress+dbg->PointerToRawData);
        NB10I* CVNB=(NB10I*)location;
        RSDSI* CVRS=(RSDSI*)location;
        FPO_DATA* FPO=(FPO_DATA*)location;
        PIMAGE_DEBUG_MISC misc=(PIMAGE_DEBUG_MISC)location;
        while (location<=((DWORD_PTR)lpBaseAddress+dbg->PointerToRawData+dbg->SizeOfData))
        {
            printf("\t------------------------------------------------------------------------------\n");
            printf("\tSignature                %lX\n",misc->DataType);
            switch(dbg->Type)
            {
            case 2:
                if (((PIMAGE_DEBUG_MISC)location)->DataType==RSDS)
                {
                    printf("\tGUID                     %04lX-%02X-%02X-%02X%02X-%02X%02X%02X%02X%02X%02X\n",
                           CVRS->guidSig.Data1, CVRS->guidSig.Data2, CVRS->guidSig.Data3,
                           CVRS->guidSig.Data4[0], CVRS->guidSig.Data4[1], CVRS->guidSig.Data4[2], CVRS->guidSig.Data4[3],
                           CVRS->guidSig.Data4[4], CVRS->guidSig.Data4[5], CVRS->guidSig.Data4[6], CVRS->guidSig.Data4[7]);
                    printf("\tTimes updated            %lu\n",CVRS->age);
                    printf("\tPDB path                 %s\n",CVRS->szPdb);
                    location+=sizeof(RSDSI);
                }
                else
                {
                    printf("\tSignature (CodeView)     %lX\n",CVNB->sig);
                    printf("\tTimes updated            %li\n",CVNB->age);
                    printf("\tPDB path                 %s\n",CVNB->szPdb);
                    location+=sizeof(CVNB);
                }
                CVRS=(RSDSI*)location;
                CVNB=(NB10I*)location;
                break;
            case 3:
                printf("\tFunction address          %08lX\n",FPO->ulOffStart);
                printf("\tFunction size             %08lX\n",FPO->cbProcSize);
                printf("\tFunction local size       %08lX\n",FPO->cdwLocals*4);
                printf("\tFunction param size       %08X\n",FPO->cdwParams*4);
                printf("\tFunction prolog size      %08X\n",FPO->cbProlog);
                printf("\tNumber of registers saved %X\n",FPO->cbRegs);
                printf("\tUse SEH                   %X\n",FPO->fHasSEH);
                printf("\tBP is allocated           %X\n",FPO->fUseBP);
                printf("\tFrame type                %X\n",FPO->cbFrame);
                location+=sizeof(FPO_DATA);
                FPO=(FPO_DATA*)location;
                break;
            case 4:
                printf("\tLength                    %08lX\n",misc->Length);
                printf("\tData                      %02x\n",misc->Data[0]);
                location+=sizeof(IMAGE_DEBUG_MISC);
                misc=(PIMAGE_DEBUG_MISC)location;
                break;
            default:
                location+=((DWORD_PTR)lpBaseAddress+dbg->PointerToRawData+dbg->SizeOfData);
                break;
            }
        }
    }
    else printf("\tEmpty\n");
    printf("------ EXCEPTION INFORMATION ------\n");
    location=(DWORD_PTR)ImageDirectoryEntryToData(hmod, TRUE, IMAGE_DIRECTORY_ENTRY_EXPORT, &size);
    if (location)
    {
        PIMAGE_FUNCTION_ENTRY entryx86=(PIMAGE_FUNCTION_ENTRY)location;
        PFUNCTION_ENTRY_MIPS entryx86MIPS=(PFUNCTION_ENTRY_MIPS)location;
        PFUNCTION_ENTRY_ARM_PP_SH34 x86=(PFUNCTION_ENTRY_ARM_PP_SH34)location;
        switch(pFileHeader->Machine)
        {
        case IMAGE_FILE_MACHINE_I386:
            printf("\tStarting address\tEnding address\tPrologue ending address\n");
            printf("\t-----------------------------------------------------------------------------\n");
            while (RtlPointerToOffset(entryx86,location)<size)
            {
                printf("\t%08lX\t\t",entryx86->StartingAddress);
                printf("\t%08lX\t\t",entryx86->EndingAddress);
                printf("\t%08lX\n",entryx86->EndOfPrologue);
                entryx86++;
            }
            break;
        case IMAGE_FILE_MACHINE_AMD64:
            printf("\tStarting address\tEnding address\tUnwind information address\n");
            printf("\t--------------------------------------------------------------------------------\n");
            while (RtlPointerToOffset(entryx86,location)<size)
            {
                printf("\t%08lX\t\t",entryx86->StartingAddress);
                printf("\t%08lX\t\t",entryx86->EndingAddress);
                printf("\t%08lX\n",entryx86->EndOfPrologue);
                entryx86++;
            }
        case IMAGE_FILE_MACHINE_IA64:
            break;
        case IMAGE_FILE_MACHINE_ARM:
            printf("\tStarting address\tProlog length\tFunction length\t32-bit flag\tException enabled\n");
            printf("\t------------------------------------------------------------------------------------------------------------------------------\n");
            while (RtlPointerToOffset(x86,location)<size)
            {
                printf("\t%08lX\t\t",x86->BeginAddress);
                printf("\t%02X\t\t",x86->PrologLength);
                printf("\t%08X\t\t",x86->FunctionLength);
                printf("\t%X\t\t",x86->x86);
                printf("\t%X\n",x86->x86);
                x86++;
            }
        case IMAGE_FILE_MACHINE_POWERPC:
        case IMAGE_FILE_MACHINE_SH3:
        case IMAGE_FILE_MACHINE_SH4:
            break;
        case IMAGE_FILE_MACHINE_MIPS16:
            printf("End address\tExcepion handler address   Handler data\tProlog ending address\n");
            printf("\t----------------------------------------------------------------------------------------------------\n");
            while (RtlPointerToOffset(entryx86MIPS,location)<size)
            {
                printf("\t%08lX\t\t",entryx86MIPS->BeginAddress);
                printf("\t%08lX\t\t\t",entryx86MIPS->EndAddress);
                printf("\t%08lX\t\t",entryx86MIPS->ExceptionHandler);
                printf("\t%08lX\t\t",entryx86MIPS->HandlerData);
                printf("\t%08lX\n",entryx86MIPS->PrologEndAddress);
                entryx86++;
            }
            break;
        }
    }
    else printf("\tEmpty\n");
    printf("------ RESOURCES ------\n");
    printf("------ Accelerators ------\n");
    EnumResourceNamesA(hmod,RT_ACCELERATOR,ENUMRESPROCCALLBACK,0L);
    printf("------ Animation cursors ------\n");
    EnumResourceNamesA(hmod,RT_ANICURSOR,ENUMRESPROCCALLBACK,0L);
    printf("------ Animation icons ------\n");
    EnumResourceNamesA(hmod,RT_ANIICON,ENUMRESPROCCALLBACK,0L);
    printf("------ Bitmaps ------\n");
    EnumResourceNamesA(hmod,RT_BITMAP,ENUMRESPROCCALLBACK,0L);
    printf("------ Cursors ------\n");
    EnumResourceNamesA(hmod,RT_CURSOR,ENUMRESPROCCALLBACK,0L);
    printf("------ Dialogs ------\n");
    EnumResourceNamesA(hmod,RT_DIALOG,ENUMRESPROCCALLBACK,0L);
    printf("------ Dialog includes ------\n");
    EnumResourceNamesA(hmod,RT_DLGINCLUDE,ENUMRESPROCCALLBACK,0L);
    printf("------ Fonts ------\n");
    EnumResourceNamesA(hmod,RT_FONT,ENUMRESPROCCALLBACK,0L);
    printf("------ Font directory ------\n");
    EnumResourceNamesA(hmod,RT_FONTDIR,ENUMRESPROCCALLBACK,0L);
    printf("------ Cursor groups ------\n");
    EnumResourceNamesA(hmod,RT_GROUP_CURSOR,ENUMRESPROCCALLBACK,0L);
    printf("------ Group of icons ------\n");
    EnumResourceNamesA(hmod,RT_GROUP_ICON,ENUMRESPROCCALLBACK,0L);
    printf("------ HTML documents ------\n");
    EnumResourceNamesA(hmod,RT_HTML,ENUMRESPROCCALLBACK,0L);
    printf("------ Icons ------\n");
    EnumResourceNamesA(hmod,RT_ICON,ENUMRESPROCCALLBACK,0L);
    printf("------ Manifest ------\n");
    EnumResourceNamesA(hmod,RT_MANIFEST,ENUMRESPROCCALLBACK,0L);
    printf("------ Menu ------\n");
    EnumResourceNamesA(hmod,RT_MENU,ENUMRESPROCCALLBACK,0L);
    printf("------ Message table ------\n");
    EnumResourceNamesA(hmod,RT_MESSAGETABLE,ENUMRESPROCCALLBACK,0L);
    printf("------ Plug and Play (PnP) ------\n");
    EnumResourceNamesA(hmod,RT_PLUGPLAY,ENUMRESPROCCALLBACK,0L);
    printf("------ Binary data ------\n");
    EnumResourceNamesA(hmod,RT_RCDATA,ENUMRESPROCCALLBACK,0L);
    printf("------ String table ------\n");
    EnumResourceNamesA(hmod,RT_STRING,ENUMRESPROCCALLBACK,0L);
    printf("------ Version table ------\n");
    EnumResourceNamesA(hmod,RT_VERSION,ENUMRESPROCCALLBACK,0L);
    printf("------ VXD (Win9x) ------\n");
    EnumResourceNamesA(hmod,RT_VXD,ENUMRESPROCCALLBACK,0L);
    /*
    printf("------ COFF SYMBOL TABLE ------\n");
    if (pFileHeader->PointerToSymbolTable){
        _COFF_SYMBOL
    }
    else printf("\tEmpty\n");*/
    printf("------ RELOCATIONS -------\n");
    if (PIMAGE_BASE_RELOCATION reloc=(PIMAGE_BASE_RELOCATION)ImageDirectoryEntryToData(hmod,TRUE,IMAGE_DIRECTORY_ENTRY_BASERELOC,&size))
    {
        while ((DWORD_PTR)reloc+8+2*(reloc->SizeOfBlock-8)<size)
        {
            printf("\t----------------------------------\n");
            printf("\t\tRVA of relocations        %08lX",reloc->VirtualAddress);
            printf("\t\tEntries                   %08lX",reloc->SizeOfBlock);
            for (DWORD i=0; i<(reloc->SizeOfBlock-8)/2; i+=2)
            {
                PRELOC preloc=(PRELOC)(i+reloc+8);
                printf("\t\t\t------ RELOCATION %li ------\n",i);
                printf("\t\t\t\tType of relocation        %04X\n",preloc->Type);
                switch (preloc->Type)
                {
                case 0:
                    printf("\t\t\t\t\tSkipped\n");
                    break;
                case 1:
                    printf("\t\t\t\t\tThe 16-bit field represents the high value of a 32-bit word\n");
                    break;
                case 2:
                    printf("\t\t\t\t\tThe 16-bit field represents the low half of a 32-bit word\n");
                    break;
                case 3:
                    printf("\t\t\t\t\tThe base relocation applies all 32 bits of the difference to the 32-bit field at offset\n");
                    break;
                case 4:
                    printf("\t\t\t\t\tOccupy two slots\n");
                    break;
                case 5 ... 9:
                    printf("\t\t\t\t\tProcessor-specific\n");
                    break;
                case 10:
                    printf("\t\t\t\t\tThe base relocation applies the difference to the 64-bit field at offset\n");
                    break;
                }
                printf("\t\t\t\tOffset                    %04X\n",preloc->Offset);
            }
            reloc+=8+2*(reloc->SizeOfBlock-8);
        }
    }
    else printf("\tEmpty\n");
    csh handle;
    cs_insn* insn;
    size_t count;
    cs_mode mode;
    cs_arch arch;
    switch(pFileHeader->Machine)
    {
    case IMAGE_FILE_MACHINE_I386:
        arch=CS_ARCH_X86;
        mode=CS_MODE_32;
        break;
    case IMAGE_FILE_MACHINE_AMD64:
        arch=CS_ARCH_X86;
        mode=CS_MODE_64;
        break;
    case IMAGE_FILE_MACHINE_ARM:
        arch=CS_ARCH_ARM;
        mode=CS_MODE_ARM;
        break;
    case IMAGE_FILE_MACHINE_ARM64:
        arch=CS_ARCH_ARM64;
        mode=CS_MODE_ARM;
        break;
    case IMAGE_FILE_MACHINE_MIPS16:
        arch=CS_ARCH_MIPS;
        mode=CS_MODE_MIPS32;
        break;
    case IMAGE_FILE_MACHINE_MIPSFPU:
        arch=CS_ARCH_MIPS;
        mode=CS_MODE_MIPS64;
        break;
    case IMAGE_FILE_MACHINE_SH4:
        arch=CS_ARCH_SH;
        mode=CS_MODE_SH4;
        break;
    case IMAGE_FILE_MACHINE_SH3:
        arch=CS_ARCH_SH;
        mode=CS_MODE_SH3;
        break;
    case IMAGE_FILE_MACHINE_SH3DSP:
        arch=CS_ARCH_SH;
        mode=CS_MODE_SHDSP;
        break;
    case IMAGE_FILE_MACHINE_THUMB:
        arch=CS_ARCH_ARM;
        mode=CS_MODE_THUMB;
        break;
    case IMAGE_FILE_MACHINE_POWERPC:
        arch=CS_ARCH_PPC;
        mode=CS_MODE_BIG_ENDIAN;
        break;
    default:
        arch=CS_ARCH_ALL;
        mode=CS_MODE_LITTLE_ENDIAN;
        break;
    }
    // Initialize Capstone (choose the appropriate architecture and mode)
    if (cs_open(arch, mode, &handle) != CS_ERR_OK)
    {
        CloseHandle(hMapping);
        CloseHandle(hFile);
        FAIL("Error initializing Capstone.",778);
    }
    // Disassemble instructions
    ULONGLONG ptr=pNtHeaders32->OptionalHeader.Magic==0x10B?(ULONGLONG)pNtHeaders32->OptionalHeader.ImageBase:pNtHeaders64->OptionalHeader.ImageBase+pNtHeaders32->OptionalHeader.AddressOfEntryPoint;
    count = cs_disasm(handle, (DWORD_PTR)hmod+pNtHeaders32->OptionalHeader.AddressOfEntryPoint, pNtHeaders32->OptionalHeader.SizeOfCode, ptr, 0, &insn);
    if (count > 0)
    {
        for (size_t i = 0; i < count; ++i)
        {
            if (insn[i].bytes[0]==0x90) continue;
            if (insn[i].bytes[0]==0x00&&insn[i].bytes[1]==0x00) continue;
            if (insn[i].bytes[0]==0xCC) continue; // never jumps to that part
            printf("0x%08llx: ",insn[i].address);
            for (size_t j = 0; j < insn[i].size; ++j)
            {
                printf("%02x ", insn[i].bytes[j]);
            }
            for (size_t j = 0; j < 15-insn[i].size; ++j)
            {
                printf("%s ", "  ");
            }
            printf("%s %s\n", insn[i].mnemonic, insn[i].op_str);

        }
        cs_free(insn, count);
    }
    else
    {
        CloseHandle(hMapping);
        CloseHandle(hFile);
        FAIL("Disassembly error",787);
    }

    cs_close(&handle);
    FreeLibrary(hmod);
    CloseHandle(hMapping);
    CloseHandle(hFile);
    return 0;
}