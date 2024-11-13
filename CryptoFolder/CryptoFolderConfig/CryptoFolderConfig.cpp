#include "pch.h"
#include <stdlib.h>
#include <stdio.h>
#include <winioctl.h>
#include <string.h>
#include <crtdbg.h>
#include <assert.h>
#include <fltuser.h>
#include <ntstatus.h>
#include "CryptoFolderConfig.h"

#pragma comment(lib,"fltlib.lib")

int Error(const char* text) 
{
	printf("\n%s (%d)\n", text, ::GetLastError());
	return 1;
}

int PrintUsage() 
{
	printf("Usage: CryptoFolderConfig <-dir|-pid> <add|remove|clear|list> [directory|process_id]\n");
	printf("\tExample: -dir add C:\TestDir\n");
	printf("\t         -pid remove 3546\n");
	printf("\t         -dir list\n");
	printf("\t         -pid clear\n");
	return 0;
}

int wmain(int argc, const wchar_t* argv[]) 
{
	DWORD returned = 0;
	BOOL success = false;
	HRESULT status = S_FALSE;
	HANDLE hPort = INVALID_HANDLE_VALUE;
	HANDLE hDevice = NULL;
	DWORD IoctlCode = 0;
	COMMAND cmd;

	if (argc < 3)
		return PrintUsage();

	RtlZeroMemory(&cmd, sizeof(cmd));

	if (::_wcsicmp(argv[1], L"-dir") == 0)
	{
		if (::_wcsicmp(argv[2], L"add") == 0)
		{
			if (argc < 4)
				return PrintUsage();

			IoctlCode = static_cast<DWORD>(Ioctls::ConfigAddDirectory);
			cmd.Command = ConfigAddDirectory;
			cmd.BufferLength = ((DWORD)::wcslen(argv[3]) + 1) * sizeof(WCHAR);
			::wcscpy_s(cmd.Buffer, argv[3]);
		}
		else if (::_wcsicmp(argv[2], L"remove") == 0)
		{
			if (argc < 4)
				return PrintUsage();

			IoctlCode = static_cast<DWORD>(Ioctls::ConfigRemoveDirectory);
			cmd.Command = ConfigRemoveDirectory;
			cmd.BufferLength = ((DWORD)::wcslen(argv[3]) + 1) * sizeof(WCHAR);
			::wcscpy_s(cmd.Buffer, argv[3]);
		}
		else if (::_wcsicmp(argv[2], L"clear") == 0)
		{
			IoctlCode = static_cast<DWORD>(Ioctls::ConfigClearDirectory);
			cmd.Command = ConfigClearDirectory;
		}
		else if (::_wcsicmp(argv[2], L"list") == 0)
		{
			IoctlCode = static_cast<DWORD>(Ioctls::ConfigListDirectory);
			cmd.Command = ConfigListDirectory;
		}
		else
		{
			return Error("Unknown option.");
		}
	}
	else if (::_wcsicmp(argv[1], L"-pid") == 0)
	{
		if (::_wcsicmp(argv[2], L"add") == 0)
		{
			if (argc < 4)
				return PrintUsage();

			IoctlCode = static_cast<DWORD>(Ioctls::ConfigAddProcess);
			cmd.Command = ConfigAddProcess;
			cmd.BufferLength = ((DWORD)::wcslen(argv[3]) + 1) * sizeof(WCHAR);
			::wcscpy_s(cmd.Buffer, argv[3]);
		}
		else if (::_wcsicmp(argv[2], L"remove") == 0)
		{
			if (argc < 4)
				return PrintUsage();

			IoctlCode = static_cast<DWORD>(Ioctls::ConfigRemoveProcess);
			cmd.Command = ConfigRemoveProcess;
			cmd.BufferLength = ((DWORD)::wcslen(argv[3]) + 1) * sizeof(WCHAR);
			::wcscpy_s(cmd.Buffer, argv[3]);
		}
		else if (::_wcsicmp(argv[2], L"clear") == 0)
		{
			IoctlCode = static_cast<DWORD>(Ioctls::ConfigClearProcess);
			cmd.Command = ConfigClearProcess;
		}
		else if (::_wcsicmp(argv[2], L"list") == 0)
		{
			IoctlCode = static_cast<DWORD>(Ioctls::ConfigListProcess);
			cmd.Command = ConfigListProcess;
		}
		else
		{
			return Error("Unknown option.");
		}
	}

	int mode = 0;
	printf("\nSelect communication mode:\n\t1- DeviceIoControl\n\t2- FilterSendMessage\n\tMode: ");
	if (scanf_s("%d", &mode) <= 0)
		return Error("[-] Error reading input!");

	switch (mode)
	{
	case 1:
		printf("\n[+] Creating device...");

		hDevice = ::CreateFile(DeviceName, GENERIC_WRITE | GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
		if (hDevice == INVALID_HANDLE_VALUE)
			return Error("[-] Failed to open handle to device");
		printf("\tOk!");

		success = ::DeviceIoControl(hDevice, IoctlCode, (LPVOID)&cmd, sizeof(cmd), nullptr, 0, &returned, nullptr);
		if (!success)
			return Error("[-] Failed in operation");

		printf("\n[*] DeviceIoControl Sent");
		::CloseHandle(hDevice);
		break;
	case 2:
		printf("\n[+] Connecting to filter port...");

		status = ::FilterConnectCommunicationPort(FilterPort, 0, nullptr, 0, nullptr, &hPort);
		if (FAILED(status))
		{
			printf("[-] Error connecting to port (HR=0x%08X)\n", status);
			return 1;
		}
		printf("\tOk!");

		status = FilterSendMessage(hPort, (LPVOID)&cmd, sizeof(cmd), NULL, 0, &returned);
		if (status != S_OK)
		{
			status = FILTER_FLT_NTSTATUS_FROM_HRESULT(status);
			fprintf(stderr, "[-] Failed to close message to the minifilter.\nStatus = 0x%X\n", status);
			return status;
		}
		printf("\n[*] FilterSendMessage Sent");
		break;
	}

	printf("\n[*] Success.\n");

	return 0;
}
