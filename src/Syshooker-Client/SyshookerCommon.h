#pragma once

#define MAX_PATH_SYSHOOKER 256

struct WriteHookData {
	wchar_t NameBuffer[256];
	int BufferLength;
};

enum Operation {
	ADD,
	REMOVE
};

enum Target {
	FILENAME,
	PROCESS,
	REGISTRY
};

struct SyshookerApiWriteRequest {
	enum Operation;
	enum Target;
	wchar_t NameBuffer[MAX_PATH_SYSHOOKER];
	size_t NameLength;
};