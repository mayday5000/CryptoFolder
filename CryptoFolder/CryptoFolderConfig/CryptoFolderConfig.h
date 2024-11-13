#pragma once

constexpr int DeviceType = 0x8000;
constexpr auto DeviceName = L"\\\\.\\CryptoFolder";
constexpr auto FilterPort = L"\\CryptoFolderPort";


#define IOCTL_CRYPTOFOLDER_ADD_DIR      CTL_CODE(DeviceType, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CRYPTOFOLDER_REMOVE_DIR   CTL_CODE(DeviceType, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CRYPTOFOLDER_CLEAR        CTL_CODE(DeviceType, 0x802, METHOD_NEITHER,  FILE_ANY_ACCESS)

#define MAX_MESSAGE_BUFFER_LEN 255


enum class Ioctls 
{
	ConfigAddDirectory = CTL_CODE(DeviceType, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS),
	ConfigRemoveDirectory = CTL_CODE(DeviceType, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS),
	ConfigClearDirectory = CTL_CODE(DeviceType, 0x802, METHOD_NEITHER, FILE_ANY_ACCESS),
	ConfigListDirectory = CTL_CODE(DeviceType, 0x803, METHOD_NEITHER, FILE_ANY_ACCESS),
	ConfigAddProcess = CTL_CODE(DeviceType, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS),
	ConfigRemoveProcess = CTL_CODE(DeviceType, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS),
	ConfigClearProcess = CTL_CODE(DeviceType, 0x806, METHOD_NEITHER, FILE_ANY_ACCESS),
	ConfigListProcess = CTL_CODE(DeviceType, 0x807, METHOD_NEITHER, FILE_ANY_ACCESS)
};

struct CryptoFolderPortMessage
{
	USHORT FileNameLength;
	WCHAR FileName[1];
};

typedef enum _PortCommands
{
	ConfigAddDirectory = 1,
	ConfigRemoveDirectory = 2, 
	ConfigClearDirectory = 3, 
	ConfigListDirectory = 4, 
	ConfigAddProcess = 5,
	ConfigRemoveProcess = 6,
	ConfigClearProcess = 7,
	ConfigListProcess = 8, 
	LogMonitor = 9
} PortCommands;

typedef struct _COMMAND
{
	PortCommands Command;
	UCHAR BufferLength;
	WCHAR Buffer[MAX_MESSAGE_BUFFER_LEN + 1] = { 0 };
} COMMAND, *PCOMMAND;
