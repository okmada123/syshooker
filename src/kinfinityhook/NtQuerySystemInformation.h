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
        if (ProcessInformationPtr) {
            while (1) {
                kprintf("[+] infinityhook: NtQuerySystemInformation: PID: %d\n", ProcessInformationPtr->UniqueProcessId);
                WCHAR ProcessNameBuffer[MAX_PATH_SYSHOOKER] = { 0 };
                wcsncpy(ProcessNameBuffer, ProcessInformationPtr->ImageName.Buffer, MIN(ProcessInformationPtr->ImageName.Length, MAX_PATH_SYSHOOKER));
                /*for (size_t i = 0; i < ProcessInformationPtr->ImageName.Length / 2 && i < MAX_PATH_SYSHOOKER - 1; ++i) {
                    ProcessNameBuffer[i] = (ProcessInformationPtr->FileName)[i];
                }*/

                kprintf("[+] infinityhook: NtQuerySystemInformation: Process Name: %ws\n", ProcessNameBuffer);

                if (ProcessInformationPtr->NextEntryOffset == 0) break;
                ProcessInformationPtr = (SYSTEM_PROCESS_INFORMATION*)((PUINT8)ProcessInformationPtr + ProcessInformationPtr->NextEntryOffset); // Move the pointer to the next structure (NextEntryOffset is in bytes, so calculate using pointer to 8bits)
            }
        }
	}
	
	return OriginalStatus;
}