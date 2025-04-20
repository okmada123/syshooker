/*
* We have later found out that we do not really need to hook this function
* Therefore the detour does not do anything, it just calls the original syscall
*/

#pragma once
#include "Settings.h"

typedef NTSTATUS(*NtOpenKey_t)(
	_Out_ PHANDLE pKeyHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes
);

static UNICODE_STRING StringNtOpenKey = RTL_CONSTANT_STRING(L"NtOpenKey");
static NtOpenKey_t OriginalNtOpenKey = NULL;

NTSTATUS DetourNtOpenKey(
	_Out_ PHANDLE pKeyHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes)
{
	//kprintf("[+] syshooker: In Detoured NtOpenKey, calling the original now...\n");
	if (ObjectAttributes &&
		ObjectAttributes->ObjectName &&
		ObjectAttributes->ObjectName->Buffer)
	{
		//kprintf("[+] syshooker: NtOpenKey length: %d, name: %wZ\n", ObjectAttributes->ObjectName->Length, ObjectAttributes->ObjectName);
		
		/*PWCHAR ObjectName = (PWCHAR)ExAllocatePool(NonPagedPool, ObjectAttributes->ObjectName->Length + sizeof(wchar_t));
		if (ObjectName)
		{
			memset(ObjectName, 0, ObjectAttributes->ObjectName->Length + sizeof(wchar_t));
			memcpy(ObjectName, ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length);
		}*/

		//kprintf("[+] syshooker: NtOpenKey ObjectAttributes->ObjectName->Length: %d\n", ObjectAttributes->ObjectName->Length);
		// copy the name to our null-terminated buffer (dumb way, just testing what it contains...)
		/*wchar_t NameBuffer[MAX_PATH_SYSHOOKER] = { 0 };
		size_t NameLength = ObjectAttributes->ObjectName->Length;
		for (size_t i = 0; i < NameLength - 10; ++i) {
			NameBuffer[i] = ObjectAttributes->ObjectName->Buffer[i];
		}*/
		//kprintf("[+] syshooker: NtOpenKey ObjectAttributes->ObjectName: %ws\n", NameBuffer);
	}

	NTSTATUS result = OriginalNtOpenKey(pKeyHandle, DesiredAccess, ObjectAttributes);
	//kprintf("[+] syshooker: NtOpenKey status: %x, handle: %p %p\n", result, pKeyHandle, *pKeyHandle);
	return result;
	
	// call the original
	//return OriginalNtOpenKey(pKeyHandle, DesiredAccess, ObjectAttributes);
}