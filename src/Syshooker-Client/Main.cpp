#include <iostream>
#include <Windows.h>
#include "SyshookerCommon.h"
constexpr size_t READ_BUFFER_SIZE_BYTES = 1024 * 1024; // 1 MB

DWORD Error(const char* message) {
	DWORD LastErrorCode = GetLastError();
	printf("%s (error=%u)\n", message, LastErrorCode);
	return LastErrorCode;
}

void PrintRequest(const SyshookerApiWriteRequest* request) {
	printf("[DEBUG] Request:\nOperation: %d\nTarget: %d\nName: %ws\nNameLength: %d\n",
		request->Operation,
		request->Target,
		request->NameBuffer,
		request->NameLength);
}

void PrintResponseBuffer(const char* Buffer, const size_t BufferSize) {
	printf("[DEBUG] Response Buffer: ");
	for (size_t i = 0; i < BufferSize; i++) {
		printf("%x ", Buffer[i]);
	}
	printf("\n");
}

void PrintHelpMessage() {
	printf(
		"\nUsage: Syshooker-Client.exe <operation> [<target>] [<name>]\n\n"
		"Operations:\n"
		"- add <target> <name>    : Adds a new entry for the specified target with the given name.\n"
		"- remove <target> <name> : Removes an existing entry for the specified target with the given name.\n"
		"- toggle                 : Toggles the current state (running/stopped) of Syshooker.\n"
		"- read                   : Displays the current settings and status of Syshooker.\n\n"
		"Targets:\n"
		"- file     : File name.\n"
		"- process  : Process name.\n"
		"- registry : Registry key.\n\n"
		"Name:\n"
		"- The name associated with the target. The name length cannot exceed %d characters (defined in MAX_PATH_SYSHOOKER).\n\n"
		"Examples:\n"
		"- Syshooker-Client.exe add file example.txt\n"
		"- Syshooker-Client.exe remove process explorer.exe\n"
		"- Syshooker-Client.exe toggle\n"
		"- Syshooker-Client.exe read\n\n"
	, SYSHOOKER_MAX_NAME_LENGTH);
}

BOOL SendWriteRequest(const SyshookerApiWriteRequest* request) {
	// debug - print request
	// PrintRequest(request);

	HANDLE hDevice = CreateFile(L"\\\\.\\Syshooker", GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
	if (hDevice == INVALID_HANDLE_VALUE)
		return Error("Failed to open Syshooker driver device");

	DWORD returned;
	BOOL success = WriteFile(hDevice,
		request, sizeof(*request), // buffer and length
		&returned, nullptr);
	if (!success) {
		DWORD status = Error("[DEBUG]: WriteFile not successful...");
		if (status == ERROR_DUP_NAME) {
			printf("[INFO]: The name already exists.\n");
		}
	}

	if (CloseHandle(hDevice) == 0) {
		printf("[ERROR]: Failed to close the Device Driver handle\n");
	}

	return success;
}

void GetAndPrintSettings() {
	HANDLE hDevice = CreateFile(L"\\\\.\\Syshooker", GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);
	if (hDevice == INVALID_HANDLE_VALUE) {
		Error("Failed to open Syshooker driver device");
		return;
	}

	char* buffer = (char*)calloc(READ_BUFFER_SIZE_BYTES, sizeof(char));
	if (buffer == nullptr) {
		printf("[ERROR]: Buffer allocation failed.\n");
		CloseHandle(hDevice);
		return;
	}

	DWORD responseLength = 0;
	BOOL success = ReadFile(hDevice, buffer, READ_BUFFER_SIZE_BYTES, &responseLength, nullptr);
	if (!success) {
		DWORD status = Error("[DEBUG]: Reading settings failed...");
		if (status == ERROR_INSUFFICIENT_BUFFER) {
			printf("[INFO]: Buffer too small.\n");
;		}
	}
	else {
		// debug print of the response buffer
		// PrintResponseBuffer(buffer, responseLength);

		printf("Syshooker status: %s\n", buffer[0] == 0 ? "Stopped" : "Running");

		size_t NamesToParseSize = (responseLength - 1) / 2;
		wchar_t* NamesBuffer = (wchar_t*)(buffer + 1); // + 1 because the first byte is for the status
		size_t index = 0;

		printf("\n----- File names -----\n");
		while (index < NamesToParseSize && NamesBuffer[index] != L'\0') {
			printf("%wc", NamesBuffer[index] == L'\\' ? L'\n' : NamesBuffer[index]);
			index++;
		}
		index++;

		printf("\n\n----- Process names -----\n");
		while (index < NamesToParseSize && NamesBuffer[index] != L'\0') {
			printf("%wc", NamesBuffer[index] == L'\\' ? L'\n' : NamesBuffer[index]);
			index++;
		}
		index++;

		printf("\n\n----- Registry names -----\n");
		while (index < NamesToParseSize && NamesBuffer[index] != L'\0') {
			printf("%wc", NamesBuffer[index] == L'\\' ? L'\n' : NamesBuffer[index]);
			index++;
		}

	}
	free(buffer);
	CloseHandle(hDevice);
}

int main(int argc, char* argv[]) {
	if (argc <= 1) {
		printf("[ERROR]: Empty arguments\n");
		PrintHelpMessage();
		exit(1);
	}

	SyshookerApiWriteRequest request;
	if (strcmp(argv[1], "add") == 0) {
		request.Operation = OPERATION_ADD;

		if (argc < 4) {
			printf("[ERROR]: Need more arguments.\n");
			PrintHelpMessage();
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
			printf("[ERROR]: Invalid target.\n");
			PrintHelpMessage();
			exit(1);
		}

		size_t NameLength = strlen(argv[3]) + 1; // + 1 because of null-terminator
		if (NameLength > SYSHOOKER_MAX_NAME_LENGTH) {
			printf("[ERROR]: Name too long.\n");
			PrintHelpMessage();
			exit(1);
		}

		// copy the char* buffer to the request.NameBuffer (wchar_t)
		mbstowcs(request.NameBuffer, argv[3], NameLength);
		request.NameLength = NameLength - 1;

		if (SendWriteRequest(&request)) {
			printf("[INFO]: OK.\n\n");
			GetAndPrintSettings();
		}
	}
	else if (strcmp(argv[1], "remove") == 0) {
		request.Operation = OPERATION_REMOVE;

		if (argc < 4) {
			printf("[ERROR]: Need more arguments.\n");
			PrintHelpMessage();
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
			printf("[ERROR]: Invalid target.\n");
			PrintHelpMessage();
			exit(1);
		}

		size_t NameLength = strlen(argv[3]) + 1; // + 1 because of null-terminator
		if (NameLength > SYSHOOKER_MAX_NAME_LENGTH) {
			printf("[ERROR]: Name too long.\n");
			PrintHelpMessage();
			exit(1);
		}

		// copy the char* buffer to the request.NameBuffer (wchar_t)
		mbstowcs(request.NameBuffer, argv[3], NameLength);
		request.NameLength = NameLength - 1;

		if (SendWriteRequest(&request)) {
			printf("[INFO]: OK.\n\n");
			GetAndPrintSettings();
		}

	}
	else if (strcmp(argv[1], "toggle") == 0) {
		request.Operation = OPERATION_TOGGLE;

		if (SendWriteRequest(&request)) {
			printf("[INFO]: OK.\n\n");
			GetAndPrintSettings();
		}
	}
	else if (strcmp(argv[1], "read") == 0) {
		GetAndPrintSettings();
	}
	else {
		printf("[ERROR]: Invalid operation.\n");
		PrintHelpMessage();
		exit(1);
	}

	return 0;
}
