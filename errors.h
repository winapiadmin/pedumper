#pragma once
/*
	ERROR_HANDLER=1
	The signal handler failed to initialize.
*/
#define ERROR_HANDLER 1
#define D_EH "The signal handler failed to initialize."
/*
	ERROR_FILE=2
	Failed to open file
*/
#define ERROR_FILE 2
#define D_F "Failed to open file"
/*
	ERROR_MAPPING=3
	Failed to create file maping
*/
#define ERROR_MAPPING 3
#define D_MP "Failed to create file maping"
/*
	ERROR_VIEW=4
	Failed to map view file
*/
#define ERROR_VIEW 4
#define D_V "Failed to map view file"
/*
	ERROR_NIMP=5
	Not implemented
*/
#define ERROR_NIMP 5
#define D_NIMP "Not implemented"
/*
	ERROR_DOS=6
	Invalid DOS Header
*/
#define ERROR_DOS 6
#define D_DOS "Invalid DOS Header"
/*
	ERROR_MACHINE=7
	Invalid machine
*/
#define ERROR_MACHINE 7
#define D_MACHINE "Invalid machine"
/*
	ERROR_OPHM=8
	Invalid OptionalHeader Magic field
*/
#define ERROR_OPHM 8
#define D_OPHM "Invalid OptionalHeader Magic field"
/*
	ERROR_COFF=9
	COFF value only
*/
#define ERROR_COFF 9
#define D_COFF "COFF value only"
/*
    ERROR_CAPSTONE=10
    Error initializing Capstone
*/
#define ERROR_CAPSTONE 10
#define D_CAPSTONE "Error initializing Capstone."
/*
    ERROR_DISASM=11
    Disassembly error
*/
#define ERROR_DISASM 11
#define D_DISASM "Disassembly error"
/*
	ERROR_UMAP=12
	Failed to unmap view file
*/
#define ERROR_UMAP 12
#define D_UMP "Failed to unmap view file"
