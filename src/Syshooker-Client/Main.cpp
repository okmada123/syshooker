#include <iostream>
#include <Windows.h>
#include "SyshookerCommon.h"

int Error(const char* message) {
	printf("%s (error=%u)\n", message, GetLastError());
	return 1;
}

int main(int argc, char* argv[]) {
	if (argc <= 1) {
		printf("Empty args. Quitting.\n");
		exit(1);
	}

	HANDLE hDevice = CreateFile(L"\\\\.\\Syshooker", GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
	if (hDevice == INVALID_HANDLE_VALUE)
		return Error("Failed to open Syshooker driver device");

	if (strcmp(argv[1], "write") == 0) {
		if (argc < 3) {
			printf("Need 1 more argument (file name).\n");
			exit(1);
		}
		SyshookerApiWriteRequest request;

		// Determine the length needed for the wchar_t buffer
		size_t length = mbstowcs(NULL, argv[2], 0) + 1; // +1 for the null terminator

		// Convert the char* buffer to a wchar_t* buffer
		mbstowcs(request.NameBuffer, argv[2], length);

		//request.NameBuffer[index] = L'\0';
		request.NameLength = length - 1;
		request.Operation = OPERATION_ADD;
		request.Target = TARGET_FILE;

		DWORD returned;
		BOOL success = WriteFile(hDevice,
			&request, sizeof(request), // buffer and length
			&returned, nullptr);
		if (!success)
			return Error("Something failed...!");
	}
	else if (strcmp(argv[1], "read") == 0) {
		char buffer[1024] = { 0 };
		DWORD responseLength = 0;
		BOOL success = ReadFile(hDevice, buffer, sizeof(buffer), &responseLength, nullptr);
		if (!success) return Error("Reading failed for some reason...");
		else {
			printf("Data from driver: %s\n", buffer);
		}
	}

	BOOL closeStatus = CloseHandle(hDevice);
	printf("CloseStatus: %d (success == nonzero status)\n", closeStatus);


	return 0;
}
