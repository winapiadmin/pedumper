#include <windows.h>
#include <string>

WORD ReadPELocation(HANDLE);
BOOL IsPEHeader(HANDLE);
BOOL ReadMachine(HANDLE fileHandle);
DWORD CodeSize(HANDLE fileHandle);
DWORD EntryPointAddress(HANDLE fileHandle);

PIMAGE_NT_HEADERS ReadPEHeader(HANDLE);
PIMAGE_DOS_HEADER ReadDOSHeader(HANDLE);
