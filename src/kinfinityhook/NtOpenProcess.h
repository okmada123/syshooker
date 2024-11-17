#pragma once
#include "Settings.h"

typedef NTSTATUS(*NtOpenProcess_t)(
	_Out_ PHANDLE ProcessHandle,
	_In_ ACCESS_MASK AccessMask,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_ PCLIENT_ID ClientId
);

static UNICODE_STRING StringNtOpenProcess = RTL_CONSTANT_STRING(L"NtOpenProcess");
static NtOpenProcess_t OriginalNtOpenProcess = NULL;

NTSTATUS DetourNtOpenProcess(
	_Out_ PHANDLE ProcessHandle,
	_In_ ACCESS_MASK AccessMask,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_ PCLIENT_ID ClientId)
{
	//kprintf("[+] infinityhook: NtOpenProcess: ClientIdPtr %p\n", ClientId);
	if (ClientId != nullptr) {
		kprintf("[+] infinityhook: NtOpenProcess: ClientId: %p %p\n", ClientId->UniqueProcess, ClientId->UniqueThread);
	}
	//
	// call the original.
	//
	return OriginalNtOpenProcess(ProcessHandle, AccessMask, ObjectAttributes, ClientId);
}