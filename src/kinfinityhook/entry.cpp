/*
*	Module Name:
*		entry.cpp
*
*	Abstract:
*		Sample driver that implements infinity hook to detour
*		system calls.
*
*	Authors:
*		Nick Peterson <everdox@gmail.com> | http://everdox.net/
*
*	Special thanks to Nemanja (Nemi) Mulasmajic <nm@triplefault.io>
*	for his help with the POC.
*
*/

#include "stdafx.h"
#include "entry.h"
#include "infinityhook.h"

static wchar_t IfhMagicFileName[] = L"ifh--";
static wchar_t IfhMagicFileNameForWrite[] = L"wassup";

static UNICODE_STRING StringNtCreateFile = RTL_CONSTANT_STRING(L"NtCreateFile");
static NtCreateFile_t OriginalNtCreateFile = NULL;

static UNICODE_STRING StringNtWriteFile = RTL_CONSTANT_STRING(L"NtWriteFile");
static NtWriteFile_t OriginalNtWriteFile = NULL;

/*
*	The entry point of the driver. Initializes infinity hook and
*	sets up the driver's unload routine so that it can be gracefully 
*	turned off.
*/
extern "C" NTSTATUS DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject, 
	_In_ PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);

	//
	// Figure out when we built this last for debugging purposes.
	//
	kprintf("[+] infinityhook: Loaded.\n");
	
	//
	// Let the driver be unloaded gracefully. This also turns off 
	// infinity hook.
	//
	DriverObject->DriverUnload = DriverUnload;

	//
	// Demo detouring of nt!NtCreateFile.
	//
	OriginalNtCreateFile = (NtCreateFile_t)MmGetSystemRoutineAddress(&StringNtCreateFile);
	if (!OriginalNtCreateFile)
	{
		kprintf("[-] infinityhook: Failed to locate export: %wZ.\n", StringNtCreateFile);
		return STATUS_ENTRYPOINT_NOT_FOUND;
	}

	// Detour NtWriteFile
	OriginalNtWriteFile = (NtWriteFile_t)MmGetSystemRoutineAddress(&StringNtWriteFile);
	if (!OriginalNtWriteFile)
	{
		kprintf("[-] infinityhook: Failed to locate export: %wZ.\n", StringNtWriteFile);
		return STATUS_ENTRYPOINT_NOT_FOUND;
	}
	else {
		kprintf("[+] infinityhook: Function address found for: %wZ.\n", StringNtWriteFile);
	}

	//
	// Initialize infinity hook. Each system call will be redirected
	// to our syscall stub.
	//
	NTSTATUS Status = IfhInitialize(SyscallStub);
	if (!NT_SUCCESS(Status))
	{
		kprintf("[-] infinityhook: Failed to initialize with status: 0x%lx.\n", Status);
	}

	return Status;
}

/*
*	Turns off infinity hook.
*/
void DriverUnload(
	_In_ PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);

	//
	// Unload infinity hook gracefully.
	//
	IfhRelease();

	kprintf("\n[!] infinityhook: Unloading... BYE!\n");
}

/*
*	For each usermode syscall, this stub will be invoked.
*/
void __fastcall SyscallStub(
	_In_ unsigned int SystemCallIndex, 
	_Inout_ void** SystemCallFunction)
{
	// 
	// Enabling this message gives you VERY verbose logging... and slows
	// down the system. Use it only for debugging.
	//
	
#if 0
	kprintf("[+] infinityhook: SYSCALL %lu: 0x%p [stack: 0x%p].\n", SystemCallIndex, *SystemCallFunction, SystemCallFunction);
#endif

	UNREFERENCED_PARAMETER(SystemCallIndex);

	//
	// In our demo, we care only about nt!NtCreateFile calls.
	//
	if (*SystemCallFunction == OriginalNtCreateFile)
	{
		//
		// We can overwrite the return address on the stack to our detoured
		// NtCreateFile.
		//
		*SystemCallFunction = DetourNtCreateFile;
	}

	// Also detour NtWriteFile
	if (*SystemCallFunction == OriginalNtWriteFile)
	{
		*SystemCallFunction = DetourNtWriteFile;
	}
}

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
			if (wcsstr(ObjectName, IfhMagicFileName))
			{
				kprintf("[+] infinityhook: Denying access to file: %wZ.\n", ObjectAttributes->ObjectName);

				ExFreePool(ObjectName);

				//
				// The demo denies access to said file.
				//
				return STATUS_NO_SUCH_FILE;
			}

			ExFreePool(ObjectName);
		}
	}

	//
	// We're uninterested, call the original.
	//
	return OriginalNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
}

// NtWriteFile Detour
NTSTATUS DetourNtWriteFile(
  _In_ HANDLE FileHandle,
  _In_opt_ HANDLE Event,
  _In_opt_ PIO_APC_ROUTINE ApcRoutine,
  _In_opt_ PVOID ApcContext,
  _Out_ PIO_STATUS_BLOCK IoStatusBlock,
  _In_ PVOID Buffer,
  _In_ ULONG Length,
  _In_opt_ PLARGE_INTEGER ByteOffset,
  _In_opt_ PULONG Key)
{
	// Obtain Object Reference from the Handle to retrieve the filename
	PVOID object = NULL;
	NTSTATUS status = ObReferenceObjectByHandle(FileHandle, 0, *IoFileObjectType, KernelMode, &object, nullptr);
	PWCHAR fileName = NULL;

	if (!NT_SUCCESS(status)) {
		kprintf("[+] infinityhook: WriteFile status not success :(!\n");
	}
	else {
		//kprintf("[+] infinityhook: WriteFile status success!!!\n");
		PFILE_OBJECT fileObject = (PFILE_OBJECT)object;
		//kprintf("[+] infinityhook: WriteFile filename direct (length: %d): %wZ\n", fileObject->FileName.Length, fileObject->FileName);

		fileName = (PWCHAR)ExAllocatePool(NonPagedPool, fileObject->FileName.Length + sizeof(wchar_t));
		//kprintf("[+] infinityhook: WriteFile fileName pointer after allocation: %p\n", fileName);

		if (fileName != NULL) {
			memset(fileName, 0, fileObject->FileName.Length + sizeof(wchar_t));
			memcpy(fileName, fileObject->FileName.Buffer, fileObject->FileName.Length);

			//kprintf("[+] infinityhook: fileName: %ws\n", fileName);

			if (wcsstr(fileName, IfhMagicFileNameForWrite))
			{
				kprintf("[+] infinityhook: Logging call for NtWriteFile for file: %wZ.\n", fileObject->FileName);
				kprintf("[+] infinityhook: NtWriteFile buffer: %s.\n", (char*)Buffer);
			}

			ExFreePool(fileName);
		}

	}

	//
	// Call the original after logging.
	//
	return OriginalNtWriteFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);

}
