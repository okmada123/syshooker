#include "RegistryUtils.h"
#include "stdafx.h"
#include "../Syshooker-Client/SyshookerCommon.h"

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