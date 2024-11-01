#include <iostream>
#include <Windows.h>
#include "SyshookerCommon.h"

int Error(const char* message) {
	printf("%s (error=%u)\n", message, GetLastError());
	return 1;
}

int main() {
	WriteHookData setHookData;
	wchar_t path[MAX_PATH_SYSHOOKER];
	printf("Enter path: ");
	wscanf(L"%256ws", path);

	size_t index = 0;
	for (const auto& ch : path) {
		setHookData.NameBuffer[index] = ch;
		index++;
	}
	setHookData.NameBuffer[index] = L'\0';
	setHookData.BufferLength = index;

	HANDLE hDevice = CreateFile(L"\\\\.\\Syshooker", GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
	if (hDevice == INVALID_HANDLE_VALUE)
		return Error("Failed to open Syshooker driver device");

	DWORD returned;
	BOOL success = WriteFile(hDevice,
		&setHookData, sizeof(setHookData), // buffer and length
		&returned, nullptr);
	if (!success)
		return Error("Something failed...!");
	
	return 0;
}