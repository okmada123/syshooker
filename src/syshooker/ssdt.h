#pragma once

#include "mm.h"
#include "img.h"

const void* GetSsdtAddress();
const void* GetSyscallAddress(size_t SyscallSsdtIndex, PCHAR SsdtAddress);

// values obtained from decompiling ntdll.dll with debug symbols
// we are interested in what's in eax at the time of invoking
// the syscall using the 'syscall' instruction
#define INDEX_NTOPENKEY 0x12
#define INDEX_NTOPENKEYEX 0x11a
#define INDEX_NTQUERYKEY 0x16
#define INDEX_NTENUMERATEKEY 0x32

// unused
// #define INDEX_NTCREATEKEY 0x1d
// #define INDEX_NTQUERYVALUEKEY 0x17
// #define INDEX_NTQUERYMULTIPLEVALUEKEY 0x14d