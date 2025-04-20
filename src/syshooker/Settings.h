#pragma once
#define SYSHOOKER_SYSTEM_INFORMATION_CLASS_PROCESS 5 // defined in 'ntint.h'

typedef struct NameNode {
	struct NameNode* Next;
	wchar_t* NameBuffer; // ensure that this is zero-terminated!
	size_t NameLength; // length WITHOUT '\0' (for example L"aaa" will have length 3)
};

struct SyshookerSettings {
	NameNode* FileSyshookerNamesHead;
	NameNode* ProcessSyshookerNamesHead;
	NameNode* RegistrySyshookerNamesHead;
};
extern SyshookerSettings Settings;