//#pragma once

//#include <fltKernel.h>


#ifndef __CRYPTOFOLDERCOMMON_H__
#define __CRYPTOFOLDERCOMMON_H__


#define IOCTL_CRYPTOFOLDER_ADD_DIR      CTL_CODE(0x8000, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CRYPTOFOLDER_REMOVE_DIR   CTL_CODE(0x8000, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CRYPTOFOLDER_CLEAR        CTL_CODE(0x8000, 0x802, METHOD_NEITHER,  FILE_ANY_ACCESS)

#define MAX_MESSAGE_BUFFER_LEN 255

typedef struct _FILTER_DATA 
{
    PDRIVER_OBJECT DriverObject;
    PFLT_FILTER Filter;
    PFLT_PORT ServerPort;
    PEPROCESS UserProcess;
    PFLT_PORT ClientPort;

} FILTER_DATA, *PFILTER_DATA;


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


#endif