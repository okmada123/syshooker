#pragma once
#define SYSHOOKER_MAX_NAME_LENGTH 256

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
	wchar_t NameBuffer[SYSHOOKER_MAX_NAME_LENGTH];
	size_t NameLength;
};