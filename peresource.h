#include <windows.h>
#include <string>
#include <dbghelp.h>
WORD ReadPELocation(HANDLE);
BOOL IsPEHeader(HANDLE);
BOOL ReadMachine(HANDLE fileHandle);
DWORD CodeSize(HANDLE fileHandle);
DWORD EntryPointAddress(HANDLE fileHandle);

PIMAGE_NT_HEADERS ReadPEHeader(HANDLE);
PIMAGE_DOS_HEADER ReadDOSHeader(HANDLE);
VOID DumpDebugDirectory(PVOID FileBuffer, PIMAGE_NT_HEADERS NtHeaders);
