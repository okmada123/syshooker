#include "stdafx.h"
#include "ssdt.h"

const void* GetSsdtAddress() {
	PVOID NtBaseAddress = NULL;
	ULONG SizeOfNt = 0;
	NtBaseAddress = ImgGetBaseAddress(NULL, &SizeOfNt);
	if (!NtBaseAddress) {
		kprintf("[-] syshooker: Failed to resolve NtBaseAddress.\n");
		return NULL;
	}
	else {
		kprintf("[+] syshooker: NtBaseAddress: %p, image size %d.\n", NtBaseAddress, SizeOfNt);
	}

	// size of ntkrnlmp.exe on W10 1809 17763.1
	// we don't actually need this because ImgGetBaseAddress
	// gets the image size as well
	// const size_t NtkrnlmpImageSize = 0x009F1000;

	/*
		kd> dps kiservicetable L2
		fffff806`54205e10  fd13b200`fccb5104
		fffff806`54205e18  03d23900`0219a602
	*/
	const UCHAR SsdtOffsetByteSignature[] = {
		0x04, 0x51, 0xcb, 0xfc, 0x00, 0xb2, 0x13, 0xfd, // first two SSDT offsets (because 1 entry in the table has 32-bits)
	};

	return MmSearchMemory(NtBaseAddress, SizeOfNt, SsdtOffsetByteSignature, RTL_NUMBER_OF(SsdtOffsetByteSignature));
}

const void* GetSyscallAddress(size_t SyscallSsdtIndex, PCHAR SsdtAddress) {
	PVOID OffsetAddress = (PVOID)(SsdtAddress + SyscallSsdtIndex * 4); // * 4 because the entries in SSDT are 32-bit (4 bytes) values
	int offset = *(int*)OffsetAddress;
	// kprintf("[+] syshooker: Offset for syscall is on address: %p.\n", OffsetAddress);
	// kprintf("[+] syshooker: Offset value: %d %x.\n", offset, offset);

	PVOID SyscallAddress = (SsdtAddress + (offset >> 4));
	// kprintf("[+] syshooker: Syscall address: %p\n", SyscallAddress);
	return SyscallAddress;
}