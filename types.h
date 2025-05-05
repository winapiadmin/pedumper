#pragma once

#include <iostream>
#include <capstone/capstone.h>
#include <vector>
#include <unordered_map>
#include <cstdlib>  // Use <cstdlib> instead of <stdlib.h> for C++

#ifdef __cplusplus
extern "C" {
#endif

#include "errors.h"

// Cross-platform macros for failure handling
#ifdef _WIN32
    #define FAIL(s,c) printf("\tERROR: %s\n", s); CloseHandle(hMapping); CloseHandle(hFile); exit(c)
#else
    #define FAIL(s,c) printf("\tERROR: %s\n", s); exit(c)
#endif

// Fail-safe implementation for assert
#ifdef _WIN32
    #include <windows.h>
#else
    // Assume Linux/MacOS/*nix
    #include <fcntl.h>
    #include <sys/mman.h>
    #include <sys/stat.h>
    #include <unistd.h>  // POSIX system calls
    #include <stdint.h>
    #include "_mingw_dxhelper.h"
    #include <cstring>
    // Proper typedefs for cross-platform compatibility
    typedef uintptr_t   ULONG_PTR;
    typedef intptr_t    LONG_PTR;
    typedef ULONG_PTR   DWORD_PTR;
    typedef uint32_t    DWORD;
    typedef void*       PVOID, *LPVOID;
    typedef uint32_t    ULONG,*PULONG,UINT;
    typedef uint64_t    ULONGLONG;
    typedef int32_t     LONG,*PLONG;
    typedef uint16_t    USHORT, WORD,*PUSHORT;
    typedef int16_t     SHORT;
    typedef uint8_t     UCHAR;
    typedef char        CHAR;
    typedef UCHAR       BYTE;
    typedef size_t      SIZE_T;
    typedef int32_t     BOOLEAN,BOOL;
    typedef const char  *PCSTR,*LPCSTR;
    typedef char        *PSTR,*LPSTR;
    typedef wchar_t     WCHAR;
    typedef PVOID       HANDLE;
    typedef HANDLE      HMODULE,HRSRC;
    #define VOID void
    #define TRUE true
    #define FALSE false
    // Correcting typedef for GUID structure
    typedef struct _GUID {
        uint32_t  Data1;
        uint16_t  Data2;
        uint16_t  Data3;
        uint8_t   Data4[8];
    } GUID, CLSID;

    // Windows-specific macros removed or adjusted
    #define __stdcall    // Not used on Linux/macOS
    #define ANYSIZE_ARRAY   1
    #define _MAX_PATH       260

    #if defined(__arm__)
        #define NTAPI
        #define CALLBACK
    #else
        #define NTAPI __stdcall
        #define CALLBACK __stdcall
    #endif

    #include "ntimage.h"
#endif

// Cross-platform warning and debug print macros
#define WARN(s, c) printf("\tWARNING: %s\n", s)
#define DbgPrint printf

// Memory offset macros (unchanged)
#define RtlOffsetToPointer(B, O)  ((ULONG_PTR)((ULONG_PTR)(B) + (ULONG_PTR)(O)))
#define RtlPointerToOffset(B, O)  ((ULONG_PTR)((ULONG_PTR)(B) - (ULONG_PTR)(O)))

#ifdef __cplusplus
}
#endif
