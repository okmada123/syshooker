#pragma once
#include "Settings.h"
#include "utils.h"

// source: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ne-wdm-_key_information_class
//typedef enum _KEY_INFORMATION_CLASS {
//	KeyBasicInformation,			// 0
//	KeyNodeInformation,				// 1
//	KeyFullInformation,				// 2
//	KeyNameInformation,				// 3
//	KeyCachedInformation,			// 4
//	KeyFlagsInformation,			// 5
//	KeyVirtualizationInformation,	// 6
//	KeyHandleTagsInformation,		// 7
//	KeyTrustInformation,			// 8
//	KeyLayerInformation,			// 9
//	MaxKeyInfoClass					// 10
//} KEY_INFORMATION_CLASS;

// source: http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FKey%2FNtQueryKey.html
typedef NTSTATUS(*NtQueryKey_t)(
	_In_ HANDLE KeyHandle,
	_In_ KEY_INFORMATION_CLASS KeyInformationClass,
	_Out_ PVOID KeyInformation,
	_In_ ULONG Length,
	_Out_ PULONG ResultLength
);

static UNICODE_STRING StringNtQueryKey = RTL_CONSTANT_STRING(L"NtQueryKey");
static NtQueryKey_t OriginalNtQueryKey = NULL;

NTSTATUS DetourNtQueryKey(
	_In_ HANDLE KeyHandle,
	_In_ KEY_INFORMATION_CLASS KeyInformationClass,
	_Out_ PVOID KeyInformation,
	_In_ ULONG Length,
	_Out_ PULONG ResultLength)
{
	PrintRegistryKeyHandleInformation(KeyHandle, L"NtQueryKey");
	return OriginalNtQueryKey(KeyHandle, KeyInformationClass, KeyInformation, Length, ResultLength);
	//if (KeyInformationClass == 3) {
	//	NTSTATUS status = OriginalNtQueryKey(KeyHandle, KeyInformationClass, KeyInformation, Length, ResultLength);
	//	if (NT_SUCCESS(status)) {
	//		kprintf("[+] infinityhook: NtQueryKey, class %d, after successful call, ResultLength: %d\n", KeyInformationClass, *ResultLength);
	//		PKEY_NAME_INFORMATION KeyNameInformationPtr = (PKEY_NAME_INFORMATION)KeyInformation;
	//		kprintf("[+] infinityhook: NtQueryKey: NameLength: %d\n", KeyNameInformationPtr->NameLength);

	//		wchar_t NameBuffer[MAX_PATH_SYSHOOKER] = { 0 };
	//		for (size_t i = 0; i < KeyNameInformationPtr->NameLength && i < MAX_PATH_SYSHOOKER; ++i) {
	//			NameBuffer[i] = KeyNameInformationPtr->Name[i];
	//		}
	//		kprintf("[+] infinityhook: NtQueryKey: Name: %ws\n", NameBuffer);
	//	}
	//	return status;
	//}
	//else if (KeyInformationClass == 4) {
	//	NTSTATUS status = OriginalNtQueryKey(KeyHandle, KeyInformationClass, KeyInformation, Length, ResultLength);
	//	if (NT_SUCCESS(status)) {
	//		kprintf("[+] infinityhook: NtQueryKey, class %d, after successful call, ResultLength: %d\n", KeyInformationClass, *ResultLength);
	//		PKEY_CACHED_INFORMATION KeyCachedInformationPtr = (PKEY_CACHED_INFORMATION)KeyInformation;
	//		kprintf("[+] infinityhook: NtQueryKey: SubKeys: %ul, MaxNameLen: %ul, Values: %ul, NameLength: %ul\n", KeyCachedInformationPtr->SubKeys, KeyCachedInformationPtr->MaxNameLen, KeyCachedInformationPtr->Values, KeyCachedInformationPtr->NameLength);

	//		/*wchar_t NameBuffer[MAX_PATH_SYSHOOKER] = { 0 };
	//		for (size_t i = 0; i < KeyNameInformationPtr->NameLength && i < MAX_PATH_SYSHOOKER; ++i) {
	//			NameBuffer[i] = KeyNameInformationPtr->Name[i];
	//		}
	//		kprintf("[+] infinityhook: NtQueryKey: Name: %ws\n", NameBuffer);*/
	//	}
	//	return status;
	//}
	//else {
	//	//kprintf("[+] infinityhook: In Detoured NtQueryKey, class: %d\n", KeyInformationClass);
	//	// call the original
	//	//return OriginalNtQueryKey(KeyHandle, KeyInformationClass, KeyInformation, Length, ResultLength);
	//}
}