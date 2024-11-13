// CryptoFolderMon.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "pch.h"

#include "..\CryptoFolder\CryptoFolderCommon.h"

#pragma comment(lib, "fltlib")


void HandleMessage(const BYTE* buffer) 
{
	auto msg = (CryptoFolderPortMessage*)buffer;
	std::wstring filename(msg->FileName, msg->FileNameLength);

	printf("Context created for filename: %ws\n", filename.c_str());
}

int main() 
{
	HANDLE hPort;
	auto hr = ::FilterConnectCommunicationPort(L"\\CryptoFolderPort", 0, nullptr, 0, nullptr, &hPort);
	
	if (FAILED(hr)) 
	{
		printf("Error connecting to port (HR=0x%08X)\n", hr);
		return 1;
	}

	BYTE buffer[1 << 12];	// 4 KB
	auto message = (FILTER_MESSAGE_HEADER*)buffer;


	commandMessage.Command = AvCmdCloseSectionForDataScan;
	hr = FilterSendMessage(Context->ConnectionPort,
		&commandMessage,
		sizeof(COMMAND_MESSAGE),
		NULL,
		0,
		&bytesReturned);

	if (FAILED(hr))
	{
		fprintf(stderr,
			"[UserScanHandleStartScanMsg]: Failed to close message SendMessageToCreateSection to the minifilter.\n");
		DisplayError(hr);
		return hr;
	}


	for (;;) 
	{
		hr = ::FilterGetMessage(hPort, message, sizeof(buffer), nullptr);
		if (FAILED(hr)) 
		{
			printf("Error receiving message (0x%08X)\n", hr);
			break;
		}
		HandleMessage(buffer + sizeof(FILTER_MESSAGE_HEADER));
	}

	::CloseHandle(hPort);

	return 0;
}

