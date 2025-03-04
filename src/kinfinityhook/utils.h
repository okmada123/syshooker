#pragma once
#include "stdafx.h"

void PrintRegistryKeyHandleInformation(HANDLE KeyHandle, const wchar_t* CallingFunctionName);
NTSTATUS RegistryKeyHideInformation(_In_ HANDLE KeyHandle, _Out_ PINT32 HideIndexesCount, _Out_ PINT32 OkIndexesCount, _Out_ PVOID OkIndexesPtr);