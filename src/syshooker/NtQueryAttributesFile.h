#pragma once
#include "Settings.h"

typedef NTSTATUS(*NtQueryAttributesFile_t)(
	_In_ POBJECT_ATTRIBUTES ObjectAttributes,
	_Out_ PFILE_BASIC_INFORMATION FileInformation
);

static UNICODE_STRING StringNtQueryAttributesFile = RTL_CONSTANT_STRING(L"NtQueryAttributesFile");
static NtQueryAttributesFile_t OriginalNtQueryAttributesFile = NULL;

NTSTATUS DetourNtQueryAttributesFile(
	_In_ POBJECT_ATTRIBUTES ObjectAttributes,
	_Out_ PFILE_BASIC_INFORMATION FileInformation)
{
	if (ObjectAttributes &&
		ObjectAttributes->ObjectName &&
		ObjectAttributes->ObjectName->Buffer)
	{

		PWCHAR FileName = (PWCHAR)ExAllocatePool(NonPagedPool, ObjectAttributes->ObjectName->Length + sizeof(wchar_t));

		if (FileName)
		{
			memset(FileName, 0, ObjectAttributes->ObjectName->Length + sizeof(wchar_t));
			memcpy(FileName, ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length);

			kprintf("[+] syshooker: NtQueryAttributesFile: %ws\n", FileName);

			/*if (matchSyshookerNames(FileName, (Target)TARGET_FILE))
			{
				kprintf("[+] syshooker: Denying direct open access to file: %wZ.\n", ObjectAttributes->ObjectName);

				ExFreePool(FileName);

				return STATUS_NO_SUCH_FILE;
			}*/

			ExFreePool(FileName);
		}
	}

	// we don't hide this file, return the original call
	return OriginalNtQueryAttributesFile(ObjectAttributes, FileInformation);
}