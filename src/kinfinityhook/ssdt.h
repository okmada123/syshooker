#pragma once

#include "mm.h"
#include "img.h"

const void* GetSsdtAddress();
const void* GetSyscallAddress(size_t SyscallSsdtIndex, PCHAR SsdtAddress);