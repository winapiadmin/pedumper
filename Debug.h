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


//
// Thread Local Storage (TLS)
//
typedef
VOID
(NTAPI *PIMAGE_TLS_CALLBACK) (
    PVOID DllHandle,
    ULONG Reason,
    PVOID Reserved
);

typedef struct _RELOC{
    WORD Type:4;
    WORD Offset:12;
}RELOC,*PRELOC;
#endif // DEBUG_H_INCLUDED
/*
typedef _IMAGE_SYMBOL COFF_Symbol;
// Function to read the symbol name
void readSymbolName(COFF_Symbol *symbol, char *name) {
    // Name is in the e_name field
    strncpy(name, symbol->N.ShortName, 8);
}

// Function to parse the COFF symbol table
void parseSymbolTable(COFF_Symbol *symbolTable, int numSymbols) {
    for (int i = 0; i < numSymbols; i++) {
        COFF_Symbol *symbol = &symbolTable[i];
        char name[256];

        // Read the symbol name
        readSymbolName(symbol, name);

        // Print the primary symbol information
        printf("\tSymbol                         %d\n", i);
        printf("\t\tName                         %s\n", name);
        printf("\t\tValue                        0x%08lX\n", symbol->Value);
        printf("\t\tSection Number               %d\n", symbol->SectionNumber);
        printf("\t\tType                         0x%04X\n", symbol->Type);
        switch(symbol->Type&0xFF){
        case IMAGE_SYM_TYPE_NULL:printf("\t\t\tUnknown");break;
        case IMAGE_SYM_TYPE_VOID:printf("\t\t\tvoid");break;
        case IMAGE_SYM_TYPE_CHAR:printf("\t\t\tsigned char");break;
        case IMAGE_SYM_TYPE_SHORT:printf("\t\t\tsigned short");break;
        case IMAGE_SYM_TYPE_INT:printf("\t\t\tsigned int");break;
        case IMAGE_SYM_TYPE_LONG:printf("\t\t\tsigned long");break;
        case IMAGE_SYM_TYPE_FLOAT:printf("\t\t\tfloat");break;
        case IMAGE_SYM_TYPE_DOUBLE:printf("\t\t\tdouble");break;
        case IMAGE_SYM_TYPE_STRUCT:printf("\t\t\tstruct");break;
        case IMAGE_SYM_TYPE_UNION:printf("\t\t\tunion");break;
        case IMAGE_SYM_TYPE_ENUM:printf("\t\t\tenum");break;
        case IMAGE_SYM_TYPE_MOE:break;
        case IMAGE_SYM_TYPE_BYTE:printf("\t\t\tunsigned char");break;
        case IMAGE_SYM_TYPE_WORD:printf("\t\t\tunsigned short");break;
        case IMAGE_SYM_TYPE_UINT:printf("\t\t\tunsigned int");break;
        case IMAGE_SYM_TYPE_DWORD:printf("\t\t\tunsigned long");break;
        }
        switch(symbol->Type&0xFF00){
            case IMAGE_SYM_DTYPE_POINTER:printf("*\n");break;
            case IMAGE_SYM_DTYPE_FUNCTION:printf("();\n");break;
            case IMAGE_SYM_DTYPE_ARRAY:printf("[]={};\n");break;
            default:printf("\n");break;
        }
        printf("\t\tStorage Class                0x%02X\n", symbol->StorageClass);
        printf("\t\tNumber of Auxiliary Symbols  %d\n", symbol->NumberOfAuxSymbols);

        // Skip the auxiliary symbols
        i += symbol->NumberOfAuxSymbols;
    }
}
    printf("------ SYMBOLS ------");
    parseSymbolTable((DWORD_PTR)lpBaseAddress+pFileHeader->PointerToSymbolTable, pFileHeader->NumberOfSymbols);
*/
