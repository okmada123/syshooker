#pragma once

struct SyshookerSettings {
	wchar_t NtCreateFileMagicName[MAX_PATH_SYSHOOKER];
	wchar_t NtWriteFileMagicName[MAX_PATH_SYSHOOKER];
	wchar_t NtQueryDirectoryFileExMagicName[MAX_PATH_SYSHOOKER];
};

SyshookerSettings Settings = { L"ifh--", L"wassup", L"hideme" };