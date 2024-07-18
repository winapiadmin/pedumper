#ifndef DEBUG_H_INCLUDED
#define DEBUG_H_INCLUDED
#include <windows.h>
typedef struct _FUNCTION_ENTRY_MIPS{
    DWORD BeginAddress;
    DWORD EndAddress;
    DWORD ExceptionHandler;
    DWORD HandlerData;
    DWORD PrologEndAddress;
} FUNCTION_ENTRY_MIPS,*PFUNCTION_ENTRY_MIPS;
typedef struct _FUNCTION_ENTRY_ARM_PP_SH34{
    DWORD BeginAddress;
    DWORD PrologLength:8;
    DWORD FunctionLength:22;
    DWORD x86:1;
    DWORD Exist:1;
}FUNCTION_ENTRY_ARM_PP_SH34,*PFUNCTION_ENTRY_ARM_PP_SH34;
typedef struct _COFF_SYMBOL{
    union{
        char Name[8];
        DWORD Zeroes;
        DWORD Offset;
    } Name;
    DWORD Value;
    WORD SectionNumber;
    WORD Type;
    BYTE StorageClass;
    BYTE NumberOfAuxSymbols;
} COFF_SYMBOL,*PCOFF_SYMBOL;
typedef struct _COFF_AUXFUNC{
    DWORD TagIndex;
    DWORD TotalSize;
    DWORD PointerToLineNumber;
    DWORD PointerToNextFunction;
    WORD unused;
} COFF_AUXFUNC,*PCOFF_AUXFUNC;
typedef struct _RELOC{
    WORD Type:4;
    WORD Offset:12;
}RELOC,*PRELOC;
#endif // DEBUG_H_INCLUDED
