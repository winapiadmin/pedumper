#include <windows.h>
enum CVSIG
{
    SIG02 = 0,                         // NB02 signature
    SIG05,                             // NB05 signature
    SIG06,                             // NB06 signature
    SIG07,                             // NB07 signature QCWIN 1.0 cvpacked
    SIG08,                             // NB08 signature C7.00 cvpacked
    SIG09,                             // NB08 signature C8.00 cvpacked
    SIG10,                             // NB10 signature VC 2.0
    SIG11,
    SIGOBSOLETE
};
typedef ULONG   SIG;        // unique (across PDB instances) signature
typedef ULONG   AGE;        // no. of times this instance has been updated
#define SIG02  0x32304E42
#define SIG05  0x37304E42
#define SIG06  0x38304E42
#define SIG07  0x39304E42
#define SIG08  0x3A304E42
#define SIG09  0x3B304E42
#define SIG010 0x30314E42
#define SIG011 0x30324E42
#define RSDS   0x53445352
typedef void *          PV;
    struct NB10I                       // NB10 debug info
    {
        DWORD   dwSig;                 // NB10
        DWORD   dwOffset;              // offset, always 0
        SIG     sig;
        AGE     age;
        char    szPdb[_MAX_PATH];
    };

    struct RSDSI                       // RSDS debug info
    {
        DWORD   dwSig;                 // RSDS
        GUID    guidSig;
        DWORD   age;
        char    szPdb[_MAX_PATH * 3];
    };
