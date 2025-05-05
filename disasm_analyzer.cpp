#include "disasm_analyzer.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unordered_map>

bool has_rip_relative_addressing(cs_insn *insn)
{
    for (size_t i = 0; i < insn->detail->x86.op_count; i++)
    {
        cs_x86_op *op = &(insn->detail->x86.operands[i]);
        if (op->type == X86_OP_MEM && op->mem.base == X86_REG_RIP)
        {
            return true;
        }
    }
    return false;
}

long long parse_rip_relative_addressing(cs_insn *insn)
{
    for (size_t i = 0; i < insn->detail->x86.op_count; i++)
    {
        cs_x86_op *op = &(insn->detail->x86.operands[i]);
        if (op->type == X86_OP_MEM && op->mem.base == X86_REG_RIP)
        {
            return op->mem.disp;
        }
    }
    return 0;
}

void processX86Disassembly(cs_insn *insn, size_t count, std::unordered_map<ULONGLONG, BYTE*> &addresses)
{
    if (count > 0)
    {
        // First pass: Populate the addresses map.
        for (size_t i = 0; i < count; ++i)
        {
            if (insn[i].bytes[0] == 0x90)
                continue; // padding
            if (insn[i].bytes[0] == 0x00 && insn[i].bytes[1] == 0x00)
                continue; // padding
            if (insn[i].bytes[0] == 0xCC)
                continue; // unreachable code

            uint64_t addr = 0;
            char *endptr = nullptr;
            char *str = (char *)malloc(21);
            if (!str) {
                fprintf(stderr, "Memory allocation failed\n");
                exit(EXIT_FAILURE);
            }

            switch (insn[i].bytes[0])
            {
                case 0x70 ... 0x7f:
                {
                    if (has_rip_relative_addressing(&insn[i]))
                        addr = insn[i].address + insn[i].size + parse_rip_relative_addressing(&insn[i]);
                    else
                    {
                        addr = strtoull(insn[i].op_str, &endptr, 16);
                        if (*endptr != '\0')
                        {
                            char *start_bracket = strchr(insn[i].op_str, '[');
                            if (start_bracket)
                            {
                                char *end_bracket = strchr(start_bracket, ']');
                                if (end_bracket)
                                {
                                    *end_bracket = '\0';
                                    addr = strtoull(start_bracket + 1, NULL, 16);
                                }
                            }
                        }
                    }
                    if (addresses.find(addr) == addresses.end())
                    {
                        sprintf(str, "loc_%llx", (unsigned long long)addr);
                        addresses[addr] = (BYTE *)str;
                    }
                    break;
                }
                case 0xe0 ... 0xe7:
                case 0xe9 ... 0xeb:
                {
                    break;
                }
                case 0xE8:
                {
                    if (has_rip_relative_addressing(&insn[i]))
                        addr = insn[i].address + insn[i].size + parse_rip_relative_addressing(&insn[i]);
                    else
                    {
                        addr = strtoull(insn[i].op_str, &endptr, 16);
                        if (*endptr != '\0')
                        {
                            char *start_bracket = strchr(insn[i].op_str, '[');
                            if (start_bracket)
                            {
                                char *end_bracket = strchr(start_bracket, ']');
                                if (end_bracket)
                                {
                                    *end_bracket = '\0';
                                    addr = strtoull(start_bracket + 1, NULL, 16);
                                }
                            }
                        }
                    }
                    if (addresses.find(addr) == addresses.end())
                    {
                        sprintf(str, "sub_%llx", (unsigned long long)addr);
                        addresses[addr] = (BYTE *)str;
                    }
                    break;
                }
                case 0x9a:
                {
                    break;
                }
                default:
                {
                    break;
                }
            }

            switch ((insn[i].bytes[0] << 8) | insn[i].bytes[1])
            {
                case 0x0f80 ... 0x0f8f:
                {
                    if (has_rip_relative_addressing(&insn[i]))
                        addr = insn[i].address + insn[i].size + parse_rip_relative_addressing(&insn[i]);
                    else
                    {
                        addr = strtoull(insn[i].op_str, &endptr, 16);
                        if (*endptr != '\0')
                        {
                            char *start_bracket = strchr(insn[i].op_str, '[');
                            if (start_bracket)
                            {
                                char *end_bracket = strchr(start_bracket, ']');
                                if (end_bracket)
                                {
                                    *end_bracket = '\0';
                                    addr = strtoull(start_bracket + 1, NULL, 16);
                                }
                            }
                        }
                    }
                    if (addresses.find(addr) == addresses.end())
                    {
                        sprintf(str, "loc_%llx", (unsigned long long)addr);
                        addresses[addr] = (BYTE *)str;
                    }
                    break;
                }
                case 0xff04 ... 0xff05:
                {
                    break;
                }
                case 0xff02 ... 0xff03:
                {
                    if (has_rip_relative_addressing(&insn[i]))
                        addr = insn[i].address + insn[i].size + parse_rip_relative_addressing(&insn[i]);
                    else
                    {
                        addr = strtoull(insn[i].op_str, &endptr, 16);
                        if (*endptr != '\0')
                        {
                            char *start_bracket = strchr(insn[i].op_str, '[');
                            if (start_bracket)
                            {
                                char *end_bracket = strchr(start_bracket, ']');
                                if (end_bracket)
                                {
                                    *end_bracket = '\0';
                                    addr = strtoull(start_bracket + 1, NULL, 16);
                                }
                            }
                        }
                    }
                    if (addresses.find(addr) == addresses.end())
                    {
                        sprintf(str, "sub_%llx", (unsigned long long)addr);
                        addresses[addr] = (BYTE *)str;
                    }
                    break;
                }
                case 0xFF15: // CALL qword ptr [rip + disp]
                {
                    if (has_rip_relative_addressing(&insn[i]))
                    {
                        long long disp = parse_rip_relative_addressing(&insn[i]);
                        addr = insn[i].address + insn[i].size + disp;
                        if (addresses.find(addr) == addresses.end())
                        {
                            sprintf(str, "qword_%llx", (unsigned long long)addr);
                            addresses[addr] = (BYTE *)str;
                        }
                    }
                    break;
                }
                default:
                {
                    break;
                }
            }

            /*
            Removed the unconditional block below because it overwrites the
            correct target addresses computed above (missing the addition
            of insn[i].size), causing a 6-byte discrepancy.

            if (has_rip_relative_addressing(&insn[i]))
            {
                addr = insn[i].address + parse_rip_relative_addressing(&insn[i]);
                sprintf(str, "sub_%llx", (unsigned long long)addr);
                addresses[addr] = (BYTE *)str;
            }
            */
        }

        // Second pass: Print the disassembled instructions.
        for (size_t i = 0; i < count; ++i)
        {
            if (insn[i].bytes[0] == 0x90)
                continue;

            if (addresses.find(insn[i].address) != addresses.end())
            {
                printf("%s:\n", addresses[insn[i].address]);
            }

            printf("0x%08llx: ", (unsigned long long)insn[i].address);
            for (size_t j = 0; j < insn[i].size; ++j)
            {
                printf("%02x ", insn[i].bytes[j]);
            }
            for (size_t j = 0; j < (size_t)(15 - insn[i].size); ++j)
            {
                printf("   ");
            }
            printf("%s ", insn[i].mnemonic);

            uint64_t addr = 0;
            char *endptr = nullptr;
            switch (insn[i].bytes[0])
            {
                case 0x70 ... 0x7f:
                {
                    if (has_rip_relative_addressing(&insn[i]))
                        addr = insn[i].address + insn[i].size + parse_rip_relative_addressing(&insn[i]);
                    else
                    {
                        addr = strtoull(insn[i].op_str, &endptr, 16);
                        if (*endptr != '\0')
                        {
                            char *start_bracket = strchr(insn[i].op_str, '[');
                            if (start_bracket)
                            {
                                char *end_bracket = strchr(start_bracket, ']');
                                if (end_bracket)
                                {
                                    *end_bracket = '\0';
                                    addr = strtoull(start_bracket + 1, NULL, 16);
                                }
                            }
                        }
                    }
                    if (addresses.find(addr) != addresses.end())
                        printf("%s\n", addresses[addr]);
                    else
                        printf("unknown\n");
                    break;
                }
                case 0xe0 ... 0xeb:
                case 0x9A:
                {
                    printf("%s\n", insn[i].op_str);
                    break;
                }
                case 0x0f:
                {
                    switch (insn[i].bytes[1])
                    {
                        case 0x80 ... 0x8f:
                        {
                            if (has_rip_relative_addressing(&insn[i]))
                                addr = insn[i].address + insn[i].size + parse_rip_relative_addressing(&insn[i]);
                            else
                            {
                                addr = strtoull(insn[i].op_str, &endptr, 16);
                                if (*endptr != '\0')
                                {
                                    char *start_bracket = strchr(insn[i].op_str, '[');
                                    if (start_bracket)
                                    {
                                        char *end_bracket = strchr(start_bracket, ']');
                                        if (end_bracket)
                                        {
                                            *end_bracket = '\0';
                                            addr = strtoull(start_bracket + 1, NULL, 16);
                                        }
                                    }
                                }
                            }
                            if (addresses.find(addr) != addresses.end())
                                printf("%s\n", addresses[addr]);
                            else
                                printf("unknown\n");
                            break;
                        }
                        default:
                        {
                            printf("%s\n", insn[i].op_str);
                            break;
                        }
                    }
                    break;
                }
                case 0xff:
                {
                    switch (insn[i].bytes[1])
                    {
                        case 0x15:
                        {
                            if (has_rip_relative_addressing(&insn[i]))
                            {
                                long long disp = parse_rip_relative_addressing(&insn[i]);
                                uint64_t call_addr = insn[i].address + insn[i].size + disp;
                                if (addresses.find(call_addr) != addresses.end())
                                    printf("%s\n", addresses[call_addr]);
                                else
                                    printf("unknown\n");
                            }
                            else
                            {
                                printf("%s\n", insn[i].op_str);
                            }
                            break;
                        }
                        default:
                        {
                            printf("%s\n", insn[i].op_str);
                            break;
                        }
                    }
                    break;
                }
                default:
                {
                    printf("%s\n", insn[i].op_str);
                    break;
                }
            }
        }
    }
}
