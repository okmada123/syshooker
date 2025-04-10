#include <iostream>
#include <Windows.h>
#include "SyshookerCommon.h"

int Error(const char* message) {
	printf("%s (error=%u)\n", message, GetLastError());
	return 1;
}

void PrintRequest(const SyshookerApiWriteRequest* request) {
	printf("[DEBUG] Request:\nOperation: %d\nTarget: %d\nName: %ws\nNameLength: %d\n",
		request->Operation,
		request->Target,
		request->NameBuffer,
		request->NameLength);

}

int main(int argc, char* argv[]) {
	if (argc <= 1) {
		printf("Empty args. Quitting. TODO - add help message.\n");
		exit(1);
	}

	SyshookerApiWriteRequest request;
	if (strcmp(argv[1], "add") == 0) {
		request.Operation = OPERATION_ADD;

		if (argc < 4) {
			printf("Need more arguments. TODO - add help message.\n");
			exit(1);
		}

		// handle target
		if (strcmp(argv[2], "file") == 0) {
			request.Target = TARGET_FILE;
		}
		else if (strcmp(argv[2], "process") == 0) {
			request.Target = TARGET_PROCESS;
		}
		else if (strcmp(argv[2], "registry") == 0) {
			request.Target = TARGET_REGISTRY;
		}
		else {
			printf("Invalid target. TODO - add help message.\n");
			exit(1);
		}

		size_t NameLength = strlen(argv[3]) + 1; // + 1 because of null-terminator
		if (NameLength > MAX_PATH_SYSHOOKER) {
			printf("Name too long. TODO - add help message.\n");
			exit(1);
		}

		// copy the char* buffer to the request.NameBuffer (wchar_t)
		mbstowcs(request.NameBuffer, argv[3], NameLength);
		request.NameLength = NameLength - 1;

		PrintRequest(&request);

		HANDLE hDevice = CreateFile(L"\\\\.\\Syshooker", GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
		if (hDevice == INVALID_HANDLE_VALUE)
			return Error("Failed to open Syshooker driver device");

		DWORD returned;
		BOOL success = WriteFile(hDevice,
			&request, sizeof(request), // buffer and length
			&returned, nullptr);
		if (!success)
			return Error("Something failed...!");

		BOOL closeStatus = CloseHandle(hDevice);
		printf("CloseStatus: %d (success == nonzero status)\n", closeStatus);
	}
	else if (strcmp(argv[1], "read") == 0) {
		HANDLE hDevice = CreateFile(L"\\\\.\\Syshooker", GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
		if (hDevice == INVALID_HANDLE_VALUE)
			return Error("Failed to open Syshooker driver device");


		char buffer[1024] = { 0 };
		DWORD responseLength = 0;
		BOOL success = ReadFile(hDevice, buffer, sizeof(buffer), &responseLength, nullptr);
		if (!success) return Error("Reading failed for some reason...");
		else {
			printf("Data from driver: %s\n", buffer);
		}
		BOOL closeStatus = CloseHandle(hDevice);
		printf("CloseStatus: %d (success == nonzero status)\n", closeStatus);
	}
	else {
		printf("Invalid operation. TODO - add help message.\n");
		exit(1);
	}

	return 0;
}
