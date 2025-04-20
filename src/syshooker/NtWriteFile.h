// This was created during initial testing, it is not currently used in Syshooker
// This hook allows tracing and modifying all writes - leaving it here for potential future use

//#pragma once
//#include "Settings.h"

//typedef NTSTATUS(*NtWriteFile_t)(
//	_In_ HANDLE FileHandle,
//	_In_opt_ HANDLE Event,
//	_In_opt_ PIO_APC_ROUTINE ApcRoutine,
//	_In_opt_ PVOID ApcContext,
//	_Out_ PIO_STATUS_BLOCK IoStatusBlock,
//	_In_ PVOID Buffer,
//	_In_ ULONG Length,
//	_In_opt_ PLARGE_INTEGER ByteOffset,
//	_In_opt_ PULONG Key
//);
//
//static UNICODE_STRING StringNtWriteFile = RTL_CONSTANT_STRING(L"NtWriteFile");
//static NtWriteFile_t OriginalNtWriteFile = NULL;
//
//// NtWriteFile Detour
//NTSTATUS DetourNtWriteFile(
//	_In_ HANDLE FileHandle,
//	_In_opt_ HANDLE Event,
//	_In_opt_ PIO_APC_ROUTINE ApcRoutine,
//	_In_opt_ PVOID ApcContext,
//	_Out_ PIO_STATUS_BLOCK IoStatusBlock,
//	_In_ PVOID Buffer,
//	_In_ ULONG Length,
//	_In_opt_ PLARGE_INTEGER ByteOffset,
//	_In_opt_ PULONG Key)
//{
//	// Obtain Object Reference from the Handle to retrieve the filename
//	PVOID object = NULL;
//	NTSTATUS status = ObReferenceObjectByHandle(FileHandle, 0, *IoFileObjectType, KernelMode, &object, nullptr);
//	PWCHAR fileName = NULL;
//
//	if (!NT_SUCCESS(status)) {
//		kprintf("[+] syshooker: WriteFile status not success when obtaining Object info by Handle :(!\n");
//	}
//	else {
//		//kprintf("[+] syshooker: WriteFile status success!!!\n");
//		PFILE_OBJECT fileObject = (PFILE_OBJECT)object;
//		//kprintf("[+] syshooker: WriteFile filename direct (length: %d): %wZ\n", fileObject->FileName.Length, fileObject->FileName);
//
//		fileName = (PWCHAR)ExAllocatePool(NonPagedPool, fileObject->FileName.Length + sizeof(wchar_t));
//		//kprintf("[+] syshooker: WriteFile fileName pointer after allocation: %p\n", fileName);
//
//		if (fileName != NULL) {
//			memset(fileName, 0, fileObject->FileName.Length + sizeof(wchar_t));
//			memcpy(fileName, fileObject->FileName.Buffer, fileObject->FileName.Length);
//
//			//kprintf("[+] syshooker: fileName: %ws\n", fileName);
//
//			if (wcsstr(fileName, Settings.NtWriteFileMagicName))
//			{
//				kprintf("[+] syshooker: Logging call for NtWriteFile for file: %wZ.\n", fileObject->FileName);
//
//				// Change the first byte in the buffer to be 'X'
//				char* ptr = (char*)Buffer;
//				ptr[0] = 'X';
//
//				kprintf("[+] syshooker: NtWriteFile buffer: %s.\n", (char*)Buffer);
//			}
//
//			ExFreePool(fileName);
//		}
//
//	}
//
//	//
//	// Call the original after logging.
//	//
//	return OriginalNtWriteFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);
//}