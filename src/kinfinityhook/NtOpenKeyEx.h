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

// STATUS_OBJECT_NAME_NOT_FOUND - return this status to indicate that the key does not exist

NTSTATUS DetourNtOpenKeyEx(
	_Out_ PHANDLE pKeyHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_ ULONG OpenOptions)
{
	kprintf("[+] infinityhook: In Detoured NtOpenKeyEx, calling the original now...\n");
	return OriginalNtOpenKeyEx(pKeyHandle, DesiredAccess, ObjectAttributes, OpenOptions);
	
	//if (ObjectAttributes &&
	//	ObjectAttributes->ObjectName &&
	//	ObjectAttributes->ObjectName->Buffer)
	//{
	//	kprintf("[+] infinityhook: NtOpenKeyEx length: %d, name: %wZ\n", ObjectAttributes->ObjectName->Length, ObjectAttributes->ObjectName);

	//	/*PWCHAR ObjectName = (PWCHAR)ExAllocatePool(NonPagedPool, ObjectAttributes->ObjectName->Length + sizeof(wchar_t));
	//	if (ObjectName)
	//	{
	//		memset(ObjectName, 0, ObjectAttributes->ObjectName->Length + sizeof(wchar_t));
	//		memcpy(ObjectName, ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length);
	//	}*/

	//	;		//kprintf("[+] infinityhook: NtOpenKeyEx ObjectAttributes->ObjectName->Length: %d\n", ObjectAttributes->ObjectName->Length);
	//			// copy the name to our null-terminated buffer (dumb way, just testing what it contains...)
	//			/*wchar_t NameBuffer[MAX_PATH_SYSHOOKER] = { 0 };
	//			size_t NameLength = ObjectAttributes->ObjectName->Length;
	//			for (size_t i = 0; i < NameLength - 10; ++i) {
	//				NameBuffer[i] = ObjectAttributes->ObjectName->Buffer[i];
	//			}*/
	//			//kprintf("[+] infinityhook: NtOpenKeyEx ObjectAttributes->ObjectName: %ws\n", NameBuffer);
	//}
	

	//NTSTATUS result = OriginalNtOpenKeyEx(pKeyHandle, DesiredAccess, ObjectAttributes);
	//kprintf("[+] infinityhook: NtOpenKeyEx status: %x, handle: %p %p\n", result, pKeyHandle, *pKeyHandle);
	//return result;

	// call the original
	//return OriginalNtOpenKeyEx(pKeyHandle, DesiredAccess, ObjectAttributes);
}