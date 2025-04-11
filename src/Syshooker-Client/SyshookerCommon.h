#pragma once

#define MAX_PATH_SYSHOOKER 256

struct WriteHookData {
	wchar_t NameBuffer[256];
	int BufferLength;
};

typedef enum {
	OPERATION_ADD,
	OPERATION_REMOVE,
	OPERATION_TOGGLE,
} Operation;

typedef enum {
	TARGET_FILE,
	TARGET_PROCESS,
	TARGET_REGISTRY
} Target;

struct SyshookerApiWriteRequest {
	Operation Operation;
	Target Target;
	wchar_t NameBuffer[MAX_PATH_SYSHOOKER];
	size_t NameLength;
};