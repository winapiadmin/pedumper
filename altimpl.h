#pragma once
#include "types.h"
#define IMAGEAPI
#define DECLSPEC_ALLOCATOR
#define HLOCAL void*
#define LMEM_FIXED 0x0000
#define LMEM_ZEROINIT 0x0040
#define LPTR (LMEM_FIXED|LMEM_ZEROINIT)
PVOID IMAGEAPI ImageDirectoryEntryToData(PVOID,BOOLEAN,USHORT,PULONG);
DECLSPEC_ALLOCATOR HLOCAL LocalAlloc(UINT,SIZE_T);
HLOCAL LocalFree(HLOCAL);
#ifdef _MSC_VER
    #include <intrin.h>
#else
    int _bittestandset(PLONG, int);
#endif
typedef BOOL (CALLBACK *ENUMRESNAMEPROCA)(HMODULE,LPCSTR,LPSTR,LONG_PTR);
bool EnumResourceNamesA(HMODULE, LPCSTR, ENUMRESNAMEPROCA, LONG_PTR);
HRSRC FindResourceA(HMODULE,LPCSTR,LPCSTR);
#define FindResource FindResourceA
DWORD SizeofResource(HMODULE,HRSRC);
