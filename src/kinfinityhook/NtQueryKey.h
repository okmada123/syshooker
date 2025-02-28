#pragma once
#include "Settings.h"

// source: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ne-wdm-_key_information_class
//typedef enum _KEY_INFORMATION_CLASS {
//	KeyBasicInformation,
//	KeyNodeInformation,
//	KeyFullInformation,
//	KeyNameInformation,
//	KeyCachedInformation,
//	KeyFlagsInformation,
//	KeyVirtualizationInformation,
//	KeyHandleTagsInformation,
//	KeyTrustInformation,
//	KeyLayerInformation,
//	MaxKeyInfoClass
//} KEY_INFORMATION_CLASS;

// source: http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FKey%2FNtQueryKey.html
typedef NTSTATUS(*NtQueryKey_t)(
	_In_ HANDLE KeyHandle,
	_In_ KEY_INFORMATION_CLASS KeyInformationClass,
	_Out_ PVOID KeyInformation,
	_In_ unsigned long Length,
	_Out_ unsigned long* ResultLength
);

static UNICODE_STRING StringNtQueryKey = RTL_CONSTANT_STRING(L"NtQueryKey");
static NtQueryKey_t OriginalNtQueryKey = NULL;

NTSTATUS DetourNtQueryKey(
	_In_ HANDLE KeyHandle,
	_In_ KEY_INFORMATION_CLASS KeyInformationClass,
	_Out_ PVOID KeyInformation,
	_In_ unsigned long Length,
	_Out_ unsigned long* ResultLength)
{
	kprintf("[+] infinityhook: In Detoured NtQueryKey, calling the original now...\n");

	// call the original
	return OriginalNtQueryKey(KeyHandle, KeyInformationClass, KeyInformation, Length, ResultLength);
}