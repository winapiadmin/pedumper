#include "types.h" //Failsafe - Linux doesn't have this :)
#include <iomanip>
#include <vector>
#include <sstream>
void processX86Disassembly(cs_insn *insn, size_t count, std::unordered_map<ULONGLONG, BYTE*> &addresses);
