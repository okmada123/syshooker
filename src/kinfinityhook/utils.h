#pragma once
#include "stdafx.h"

void PrintRegistryKeyHandleInformation(HANDLE KeyHandle, const wchar_t* CallingFunctionName);
NTSTATUS RegistryKeyHideInformation(_In_ HANDLE KeyHandle, _Out_ PULONG HideSubkeyIndexesCount, _Out_ PULONG OkSubkeyIndexesCount, _Out_ PULONG* OkSubkeyIndexes);