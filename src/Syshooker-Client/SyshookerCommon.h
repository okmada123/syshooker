#pragma once

#define MAX_PATH_SYSHOOKER 256

struct WriteHookData {
	wchar_t NameBuffer[256];
	int BufferLength;
};