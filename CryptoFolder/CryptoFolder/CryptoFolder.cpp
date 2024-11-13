/*++

Module Name:

	CryptoFolder.cpp

Abstract:

	This is the main module of the CryptoFolder miniFilter driver.

Environment:

	Kernel mode

--*/

#include <fltKernel.h>
#include <dontuse.h>
#include "AutoLock.h"
#include "FastMutex.h"
#include "Mutex.h"
#include "kstring.h"
#include <ntifs.h>
#include <ntstrsafe.h>
//#include <wdmsec.h>
#include <ntdef.h>
#include "FileNameInformation.h"
#include "CryptoFolderCommon.h"

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")

#define DRIVER_TAG 'ALU'
#define DRIVER_CONTEXT_TAG 'cALU'
#define PTDBG_TRACE_ROUTINES            0x00000001
#define PTDBG_TRACE_OPERATION_STATUS    0x00000002
#define SYMLINK L"\\DosDevices\\CryptoFolder"
#define DEVNAME L"\\Device\\CryptoFolder"

const PWSTR PortName = L"\\CryptoFolderPort";

PFLT_FILTER gFilterHandle;
PFLT_PORT FilterPort;
PFLT_PORT SendClientPort;
ULONG gTraceFlags = 0;
FILTER_DATA FilterData;


struct DirectoryEntry 
{
	UNICODE_STRING DosName;
	UNICODE_STRING NtName;

	void Free() 
	{
		if (DosName.Buffer) 
		{
			ExFreePool(DosName.Buffer);
			DosName.Buffer = nullptr;
		}

		if (NtName.Buffer) 
		{
			ExFreePool(NtName.Buffer);
			NtName.Buffer = nullptr;
		}
	}
};

struct FileContext
{
	Mutex Lock;
	UNICODE_STRING FileName;
	BOOLEAN Crypted;
	BOOLEAN CryptedDirectory;
};

// Necesito decriptarlo para leerlo?
struct StreamHandleContext
{
	BOOLEAN DeCrypt;
};


typedef struct _FILE_CONTEXT
{
	//
	// Lock to rundown threads that are dispatching I/Os on a file handle 
	// while the cleanup for that handle is in progress.
	//
	IO_REMOVE_LOCK  FileRundownLock;
} FILE_CONTEXT, * PFILE_CONTEXT;


const int MaxDirectories = 32;
static const UCHAR XorKey = 0xfe;

DirectoryEntry DirNames[MaxDirectories];
int DirNamesCount;
FastMutex DirNamesLock;


#define PT_DBG_PRINT( _dbgLevel, _string )          \
	(FlagOn(gTraceFlags,(_dbgLevel)) ?              \
		DbgPrint _string :                          \
		((int)0))

/*************************************************************************
	Prototypes
*************************************************************************/

void CryptoFolderUnloadDriver(PDRIVER_OBJECT DriverObject);
int FindCryptedDirectory(_In_ PCUNICODE_STRING name, bool dosName);
NTSTATUS ConvertDosNameToNtName(_In_ PCWSTR dosName, _Out_ PUNICODE_STRING ntName);
bool IsEncryptedDirectory(_In_ PCUNICODE_STRING name, _In_ bool dosName);
NTSTATUS EncryptDecryptFile(_In_ PUNICODE_STRING FileName, _In_ PCFLT_RELATED_OBJECTS FltObjects);
NTSTATUS PortConfigAddDirectory(_In_ PWSTR name, _In_ UCHAR nameLen);
void ClearAll();

EXTERN_C_START

DRIVER_DISPATCH CryptoFolderRead, CryptoFolderWrite, CryptoFolderDeviceControl;

DRIVER_INITIALIZE DriverEntry;
NTSTATUS
DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath
);

NTSTATUS
CryptoFolderInstanceSetup(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_SETUP_FLAGS Flags,
	_In_ DEVICE_TYPE VolumeDeviceType,
	_In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
);

NTSTATUS
CryptoFolderUnload(
	_In_ FLT_FILTER_UNLOAD_FLAGS Flags
);

FLT_PREOP_CALLBACK_STATUS
CryptoFolderPreOperation(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID* CompletionContext
);

VOID
CryptoFolderOperationStatusCallback(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ PFLT_IO_PARAMETER_BLOCK ParameterSnapshot,
	_In_ NTSTATUS OperationStatus,
	_In_ PVOID RequesterContext
);

NTSTATUS CloseCleanupDispatchRoutine(
	_In_ PDEVICE_OBJECT DeviceObject,
	_Inout_ PIRP Irp
);

FLT_POSTOP_CALLBACK_STATUS
CryptoFolderPostCreate(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
);

NTSTATUS PortConnectNotify(
	_In_ PFLT_PORT ClientPort,
	_In_opt_ PVOID ServerPortCookie,
	_In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
	_In_ ULONG SizeOfContext,
	_Outptr_result_maybenull_ PVOID* ConnectionPortCookie);

void PortDisconnectNotify(_In_opt_ PVOID ConnectionCookie);

NTSTATUS PortMessageNotify(
	_In_opt_ PVOID PortCookie,
	_In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
	_In_ ULONG InputBufferLength,
	_Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
	_In_ ULONG OutputBufferLength,
	_Out_ PULONG ReturnOutputBufferLength);

NTSTATUS
FilterPortConnect(
	_In_ PFLT_PORT ClientPort,
	_In_opt_ PVOID ServerPortCookie,
	_In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
	_In_ ULONG SizeOfContext,
	_Outptr_result_maybenull_ PVOID* ConnectionCookie
);

VOID
FilterPortDisconnect(
	_In_opt_ PVOID ConnectionCookie
);

NTSTATUS MessageCallback(
	__in PVOID ConnectionCookie,
	__in_bcount_opt(InputBufferSize) PVOID InputBuffer,
	__in ULONG InputBufferSize,
	__out_bcount_part_opt(OutputBufferSize, *ReturnOutputBufferLength) PVOID OutputBuffer,
	__in ULONG OutputBufferSize,
	__out PULONG ReturnOutputBufferLength
);

void FileContextCleanup(_In_ PFLT_CONTEXT Context, _In_ FLT_CONTEXT_TYPE /* ContextType */);
NTSTATUS CreateDispatchRoutine(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp);


EXTERN_C_END

//
//  Assign text sections for each routine.
//

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, CryptoFolderUnload)
#pragma alloc_text(PAGE, CryptoFolderInstanceSetup)
#pragma alloc_text(PAGE, FilterPortConnect)
#pragma alloc_text(PAGE, FilterPortDisconnect)
#pragma alloc_text(PAGE, MessageCallback)
#endif

//
//  operation registration
//

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
	{ IRP_MJ_CREATE, 0, nullptr, CryptoFolderPostCreate },
	//	{ IRP_MJ_READ, FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO, CryptoFolderRead },
	//	{ IRP_MJ_WRITE, FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO, CryptoFolderWrite },
	//	{ IRP_MJ_CLEANUP, 0, nullptr, CloseCleanupDispatchRoutine },

		{ IRP_MJ_OPERATION_END }
};

//
//  This defines what we want to filter with FltMgr
//

const FLT_CONTEXT_REGISTRATION Contexts[] = {
	{ FLT_FILE_CONTEXT, 0, FileContextCleanup, sizeof(FileContext), DRIVER_CONTEXT_TAG },
	{ FLT_STREAMHANDLE_CONTEXT, 0, nullptr, sizeof(FileContext), DRIVER_CONTEXT_TAG },
	{ FLT_CONTEXT_END }
};

CONST FLT_REGISTRATION FilterRegistration = {
	sizeof(FLT_REGISTRATION),         //  Size
	FLT_REGISTRATION_VERSION,         //  Version
	0,                                //  Flags

	Contexts,                         //  Context
	Callbacks,                        //  Operation callbacks
	CryptoFolderUnload,                 //  MiniFilterUnload
	CryptoFolderInstanceSetup,
	/*FileBackupInstanceQueryTeardown*/nullptr,
	/*FileBackupInstanceTeardownStart*/nullptr,
	/*FileBackupInstanceTeardownComplete*/nullptr,

	nullptr,    //  GenerateFileName
	nullptr,    //  GenerateDestinationFileName
	nullptr     //  NormalizeNameComponent
};


NTSTATUS
CryptoFolderInstanceSetup(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_SETUP_FLAGS Flags,
	_In_ DEVICE_TYPE VolumeDeviceType,
	_In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
)
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);
	UNREFERENCED_PARAMETER(VolumeDeviceType);
	UNREFERENCED_PARAMETER(VolumeFilesystemType);

	PAGED_CODE();

	if (VolumeFilesystemType != FLT_FSTYPE_NTFS) {
		KdPrint(("Not attaching to non-NTFS volume\n"));
		return STATUS_FLT_DO_NOT_ATTACH;
	}

	return STATUS_SUCCESS;
}


/*************************************************************************
	MiniFilter initialization and unload routines.
*************************************************************************/

NTSTATUS
DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath
)
{
	UNREFERENCED_PARAMETER(RegistryPath);

	NTSTATUS status;
	UNICODE_STRING uniString;
	PSECURITY_DESCRIPTOR sd;
	OBJECT_ATTRIBUTES oa;
	PDEVICE_OBJECT DeviceObject = nullptr;
	UNICODE_STRING devName = RTL_CONSTANT_STRING(DEVNAME);
	UNICODE_STRING symLink = RTL_CONSTANT_STRING(SYMLINK);
	auto symLinkCreated = false;

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("CryptoFolder!DriverEntry: Entered\n"));

	do {
		status = IoCreateDevice(DriverObject, 0, &devName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &DeviceObject);
		if (!NT_SUCCESS(status))
			break;

		RtlInitUnicodeString(&devName, DEVNAME);
/*		status = IoCreateDeviceSecure(DriverObject,
			0,
			&devName,
			FILE_DEVICE_UNKNOWN,
			0,
			TRUE,
			&SDDL_DEVOBJ_SYS_ALL_ADM_ALL,
			0,
			&DeviceObject);*/

		if (!NT_SUCCESS(status)) 
		{
			KdPrint((TL_CRITICAL, DBG_INIT, "DRIVER error creating control device, status:[0x%lX] ... unloading", status));
			return status;
		}
		if (!DeviceObject)
		{
			return STATUS_UNEXPECTED_IO_ERROR;
		}

		RtlInitUnicodeString(&symLink, SYMLINK);
		status = IoCreateSymbolicLink(&symLink, &devName);
		
		if (!NT_SUCCESS(status))
			break;
		
//		DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

		symLinkCreated = true;

		status = FltRegisterFilter(DriverObject, &FilterRegistration, &gFilterHandle);

		FLT_ASSERT(NT_SUCCESS(status));
		if (!NT_SUCCESS(status))
			break;

		DriverObject->MajorFunction[IRP_MJ_CREATE] = CreateDispatchRoutine;
		DriverObject->MajorFunction[IRP_MJ_CLOSE] = CloseCleanupDispatchRoutine;
		DriverObject->MajorFunction[IRP_MJ_CLEANUP] = CloseCleanupDispatchRoutine;
		DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = CryptoFolderDeviceControl;
		DriverObject->DriverUnload = CryptoFolderUnloadDriver;

		RtlInitUnicodeString(&uniString, PortName);
		status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);

		if (NT_SUCCESS(status))
		{
			InitializeObjectAttributes(&oa,
				&uniString,
				OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
				NULL,
				sd);

			status = FltCreateCommunicationPort(gFilterHandle,
				&FilterData.ServerPort,
				&oa,
				NULL,
				FilterPortConnect,
				FilterPortDisconnect,
				MessageCallback,
				1);

			FltFreeSecurityDescriptor(sd);

			if (NT_SUCCESS(status))
			{
				status = FltStartFiltering(gFilterHandle);

				if (NT_SUCCESS(status))
				{
					return STATUS_SUCCESS;
				}
				FltCloseCommunicationPort(FilterData.ServerPort);
			}
		}
	} while (false);

	if (!NT_SUCCESS(status))
	{
		if (gFilterHandle)
			FltUnregisterFilter(gFilterHandle);
		if (symLinkCreated)
			IoDeleteSymbolicLink(&symLink);
		if (DeviceObject)
			IoDeleteDevice(DeviceObject);
	}

	return status;
}


void CryptoFolderUnloadDriver(PDRIVER_OBJECT DriverObject)
{
	ClearAll();
	UNICODE_STRING symLink = RTL_CONSTANT_STRING(SYMLINK);
	IoDeleteSymbolicLink(&symLink);
	IoDeleteDevice(DriverObject->DeviceObject);
}


NTSTATUS CryptoFolderDeviceControl(PDEVICE_OBJECT, PIRP Irp)
{
	auto stack = IoGetCurrentIrpStackLocation(Irp);
	auto status = STATUS_SUCCESS;

	switch (stack->Parameters.DeviceIoControl.IoControlCode)
	{
	case IOCTL_CRYPTOFOLDER_ADD_DIR:
	{
		auto name = (WCHAR*)Irp->AssociatedIrp.SystemBuffer;
		if (!name)
		{
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		auto bufferLen = stack->Parameters.DeviceIoControl.InputBufferLength;
		if (bufferLen > 1024)
		{
			// just too long for a directory
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		// make sure there is a NULL terminator somewhere
		name[bufferLen / sizeof(WCHAR) - 1] = L'\0';
		auto dosNameLen = ::wcslen(name);

		if (dosNameLen < 3)
		{
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		//		AutoLock locker(DirNamesLock);
		UNICODE_STRING strName;
		RtlInitUnicodeString(&strName, name);

		// Break if current directory already exist
		if (FindCryptedDirectory(&strName, true) >= 0)
		{
			break;
		}

		// Break if too many directories 
		if (DirNamesCount == MaxDirectories)
		{
			status = STATUS_TOO_MANY_NAMES;
			break;
		}

		for (int i = 0; i < MaxDirectories; i++)
		{
			if (DirNames[i].DosName.Buffer == nullptr)
			{
				auto len = (dosNameLen + 2) * sizeof(WCHAR);
				auto buffer = (WCHAR*)ExAllocatePoolWithTag(PagedPool, len, DRIVER_TAG);

				if (!buffer)
				{
					status = STATUS_INSUFFICIENT_RESOURCES;
					break;
				}
				::wcscpy_s(buffer, len / sizeof(WCHAR), name);
				// append a backslash if it's missing
				if (name[dosNameLen - 1] != L'\\')
					::wcscat_s(buffer, dosNameLen + 2, L"\\");

				status = ConvertDosNameToNtName(buffer, &DirNames[i].NtName);
				if (!NT_SUCCESS(status))
				{
					ExFreePool(buffer);
					buffer = nullptr;
					break;
				}

				RtlInitUnicodeString(&DirNames[i].DosName, buffer);
				KdPrint(("Add: %wZ <=> %wZ\n", &DirNames[i].DosName, &DirNames[i].NtName));
				++DirNamesCount;
				break;
			}
		}
		break;
	}

	case IOCTL_CRYPTOFOLDER_REMOVE_DIR:
	{
		auto name = (WCHAR*)Irp->AssociatedIrp.SystemBuffer;
		if (!name)
		{
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		auto bufferLen = stack->Parameters.DeviceIoControl.InputBufferLength;
		if (bufferLen > 1024)
		{
			// just too long for a directory
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		// make sure there is a NULL terminator somewhere
		name[bufferLen / sizeof(WCHAR) - 1] = L'\0';

		auto dosNameLen = ::wcslen(name);
		if (dosNameLen < 3)
		{
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		//		AutoLock locker(DirNamesLock);
		UNICODE_STRING strName;
		RtlInitUnicodeString(&strName, name);
		int found = FindCryptedDirectory(&strName, true);

		if (found >= 0)
		{
			DirNames[found].Free();
			DirNamesCount--;
		}
		else
			status = STATUS_NOT_FOUND;
		break;
	}

	case IOCTL_CRYPTOFOLDER_CLEAR:
		ClearAll();
		break;

	default:
		status = STATUS_INVALID_DEVICE_REQUEST;
		break;
	}

	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}


NTSTATUS
CryptoFolderUnload(
	_In_ FLT_FILTER_UNLOAD_FLAGS Flags
)
{
	UNREFERENCED_PARAMETER(Flags);

	PAGED_CODE();

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("CryptoFolder!CryptoFolderUnload: Entered\n"));

	FltCloseCommunicationPort(FilterPort);

/*	UNICODE_STRING symLink = RTL_CONSTANT_STRING(SYMLINK);
	IoDeleteSymbolicLink(&symLink);*/

	FltUnregisterFilter(gFilterHandle);

	return STATUS_SUCCESS;
}


void ClearAll()
{
	//	AutoLock locker(DirNamesLock);
	for (int i = 0; i < MaxDirectories; i++)
	{
		if (DirNames[i].DosName.Buffer)
		{
			ExFreePool(DirNames[i].DosName.Buffer);
			DirNames[i].DosName.Buffer = nullptr;
		}
		if (DirNames[i].NtName.Buffer)
		{
			ExFreePool(DirNames[i].NtName.Buffer);
			DirNames[i].NtName.Buffer = nullptr;
		}
	}
	DirNamesCount = 0;
}


NTSTATUS ConvertDosNameToNtName(_In_ PCWSTR dosName, _Out_ PUNICODE_STRING ntName)
{
	ntName->Buffer = nullptr;
	auto dosNameLen = ::wcslen(dosName);

	if (dosNameLen < 3)
		return STATUS_BUFFER_TOO_SMALL;

	// make sure we have a driver letter
	if (dosName[2] != L'\\' || dosName[1] != L':')
		return STATUS_INVALID_PARAMETER;

	kstring dosSymLink(L"\\??\\", PagedPool, DRIVER_TAG);

	dosSymLink.Append(dosName, 2);		// driver letter and colon

	// prepare to open symbolic link

	UNICODE_STRING symLinkFull;
	dosSymLink.GetUnicodeString(&symLinkFull);
	OBJECT_ATTRIBUTES symLinkAttr;
	InitializeObjectAttributes(&symLinkAttr, &symLinkFull, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, nullptr, nullptr);

	HANDLE hSymLink = nullptr;
	auto status = STATUS_SUCCESS;
	do {
		// open symbolic link
		status = ZwOpenSymbolicLinkObject(&hSymLink, GENERIC_READ, &symLinkAttr);
		if (!NT_SUCCESS(status))
			break;

		USHORT maxLen = 1024;	// arbitrary
		ntName->Buffer = (WCHAR*)ExAllocatePool(PagedPool, maxLen);
		if (!ntName->Buffer)
		{
			status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}
		ntName->MaximumLength = maxLen;
		// read target of symbolic link
		status = ZwQuerySymbolicLinkObject(hSymLink, ntName, nullptr);
		if (!NT_SUCCESS(status))
			break;
	} while (false);

	if (!NT_SUCCESS(status))
	{
		if (ntName->Buffer)
		{
			ExFreePool(ntName->Buffer);
			ntName->Buffer = nullptr;
		}
	}
	else {
		RtlAppendUnicodeToString(ntName, dosName + 2);	// directory
	}
	if (hSymLink)
		ZwClose(hSymLink);

	return status;
}


int FindCryptedDirectory(PCUNICODE_STRING name, bool dosName)
{
	if (DirNamesCount == 0)
		return -1;

	for (int i = 0; i < MaxDirectories; i++)
	{
		const auto& dir = dosName ? DirNames[i].DosName : DirNames[i].NtName;
		if (dir.Buffer && RtlEqualUnicodeString(name, &dir, TRUE))
			return i;
	}
	return -1;
}


bool IsEncryptedDirectory(_In_ PCUNICODE_STRING name, _In_ bool dosName)
{
	if (DirNamesCount == 0)
		false;

	for (int i = 0; i < MaxDirectories; i++)
	{
		const auto& dir = dosName ? DirNames[i].DosName : DirNames[i].NtName;
		if (dir.Buffer && RtlEqualUnicodeString(name, &dir, TRUE))
			return true;
	}
	return false;
}


NTSTATUS EncryptDecryptFile(_In_ PUNICODE_STRING FileName, _In_ PCFLT_RELATED_OBJECTS FltObjects)
{
	HANDLE hSourceFile = nullptr;
	IO_STATUS_BLOCK ioStatus;
	auto status = STATUS_SUCCESS;
	void* buffer = nullptr;

	// get source file size
	LARGE_INTEGER fileSize;
	status = FsRtlGetFileSize(FltObjects->FileObject, &fileSize);
	if (!NT_SUCCESS(status) || fileSize.QuadPart == 0)
		return status;

	do {
		// open source file
		OBJECT_ATTRIBUTES sourceFileAttr;
		InitializeObjectAttributes(&sourceFileAttr, FileName,
			OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, nullptr, nullptr);

		status = FltCreateFile(
			FltObjects->Filter,		// filter object
			FltObjects->Instance,	// filter instance
			&hSourceFile,			// resulting handle
			FILE_READ_DATA | SYNCHRONIZE, // access mask
			&sourceFileAttr,		// object attributes
			&ioStatus,				// resulting status
			nullptr, FILE_ATTRIBUTE_NORMAL, 	// allocation size, file attributes
			FILE_SHARE_READ | FILE_SHARE_WRITE,		// share flags
			FILE_OPEN,		// create disposition
			FILE_SYNCHRONOUS_IO_NONALERT | FILE_SEQUENTIAL_ONLY, // create options (sync I/O)
			nullptr, 0,				// extended attributes, EA length
			IO_IGNORE_SHARE_ACCESS_CHECK);	// flags

		if (!NT_SUCCESS(status))
			break;

		// allocate buffer for copying purposes
		ULONG size = 1 << 21;	// 2 MB
		buffer = ExAllocatePoolWithTag(PagedPool, size, DRIVER_TAG);
		if (!buffer)
		{
			status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		// loop - read from source, write to target
		LARGE_INTEGER offset = { 0 };		// read
		LARGE_INTEGER writeOffset = { 0 };	// write

		ULONG bytes;
		auto saveSize = fileSize;
		while (fileSize.QuadPart > 0)
		{
			status = ZwReadFile(
				hSourceFile,
				nullptr,	// optional KEVENT
				nullptr, nullptr,	// no APC
				&ioStatus,
				buffer,
				(ULONG)min((LONGLONG)size, fileSize.QuadPart),	// # of bytes
				&offset,	// offset
				nullptr);	// optional key
			if (!NT_SUCCESS(status))
				break;

			bytes = (ULONG)ioStatus.Information;

			// Encrypt / Decrypt Buffer...
			UCHAR* ptr = reinterpret_cast<UCHAR*>(buffer);
			for (SIZE_T i = 0; i < bytes; ++i)
				ptr[i] ^= XorKey;

			// write encrypted buffer to file
			status = ZwWriteFile(
				hSourceFile,	// target handle
				nullptr,		// optional KEVENT
				nullptr, nullptr, // APC routine, APC context
				&ioStatus,		// I/O status result
				buffer,			// data to write
				bytes, // # bytes to write
				&writeOffset,	// offset
				nullptr);		// optional key

			if (!NT_SUCCESS(status))
				break;

			// update byte count and offsets
			offset.QuadPart += bytes;
			writeOffset.QuadPart += bytes;
			fileSize.QuadPart -= bytes;
		}

		FILE_END_OF_FILE_INFORMATION info;
		info.EndOfFile = saveSize;
		NT_VERIFY(NT_SUCCESS(ZwSetInformationFile(hSourceFile, &ioStatus, &info, sizeof(info), FileEndOfFileInformation)));

		KdPrint(("File encrypted: %wZ\n", &FileName));
	} while (false);

	if (buffer)
	{
		ExFreePool(buffer);
		buffer = nullptr;
	}
	if (hSourceFile)
		FltClose(hSourceFile);

	return status;
}

/*************************************************************************
	MiniFilter callback routines.
*************************************************************************/

NTSTATUS CreateDispatchRoutine(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	//	TRACE_INFO(CHANNEL, L"Exit %!STATUS!", Irp->IoStatus.Status);

	return Irp->IoStatus.Status;
}


void FileContextCleanup(_In_ PFLT_CONTEXT Context, _In_ FLT_CONTEXT_TYPE /* ContextType */)
{
	auto fileContext = (FileContext*)Context;

	if (fileContext->FileName.Buffer)
	{
		ExFreePool(fileContext->FileName.Buffer);
		fileContext->FileName.Buffer = nullptr;
	}
}


FLT_PREOP_CALLBACK_STATUS
CryptoFolderPreOperationNoPostOperation(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
/*++
Routine Description:
	This routine is a pre-operation dispatch routine for this miniFilter.
	This is non-pageable because it could be called on the paging path
Arguments:
	Data - Pointer to the filter callbackData that is passed to us.
	FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
		opaque handles to this filter, instance, its associated volume and
		file object.
	CompletionContext - The context for the completion routine for this
		operation.
Return Value:
	The return value is the status of the operation.
--*/
{
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("CryptoFolder!CryptoFolderPreOperationNoPostOperation: Entered\n"));

	// This template code does not do anything with the callbackData, but
	// rather returns FLT_PREOP_SUCCESS_NO_CALLBACK.
	// This passes the request down to the next miniFilter in the chain.

	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}


NTSTATUS CloseCleanupDispatchRoutine(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);

//	TRACE_INFO(CHANNEL, L"Exit %!STATUS!", Irp->IoStatus.Status);

	return STATUS_SUCCESS;
}


FLT_POSTOP_CALLBACK_STATUS CryptoFolderPostCreate(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID CompletionContext, FLT_POST_OPERATION_FLAGS Flags)
{
	UNREFERENCED_PARAMETER(CompletionContext);

	if (Flags & FLTFL_POST_OPERATION_DRAINING)
		return FLT_POSTOP_FINISHED_PROCESSING;

	const auto& params = Data->Iopb->Parameters.Create;
	if (Data->RequestorMode == KernelMode
		||  Data->IoStatus.Information == FILE_DOES_NOT_EXIST) 
	{
		// kernel caller, not write access or a new file - skip
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	// get file name
	FilterFileNameInformation fileNameInfo(Data);
	if (!fileNameInfo)
		return FLT_POSTOP_FINISHED_PROCESSING;

	if (!NT_SUCCESS(fileNameInfo.Parse()))
		return FLT_POSTOP_FINISHED_PROCESSING;

	// if it's not the default stream, we don't care
	if (fileNameInfo->Stream.Length > 0)
		return FLT_POSTOP_FINISHED_PROCESSING;

	// allocate and initialize a file context
	FileContext* context = nullptr;
	auto status = FltAllocateContext(FltObjects->Filter, FLT_FILE_CONTEXT, sizeof(FileContext), PagedPool, (PFLT_CONTEXT*)&context);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("Failed to allocate file context (0x%08X)\n", status));
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	do {
		context->CryptedDirectory = IsEncryptedDirectory(&fileNameInfo->ParentDir, false);
		context->Crypted = FALSE;
		context->FileName.MaximumLength = fileNameInfo->Name.Length;
		context->FileName.Buffer = (WCHAR*)ExAllocatePoolWithTag(PagedPool, fileNameInfo->Name.Length, DRIVER_TAG);
		if (!context->FileName.Buffer)
		{
			KdPrint(("Failed to set file context (0x%08X)\n", status));
			break;
		}

		RtlCopyUnicodeString(&context->FileName, &fileNameInfo->Name);
		//context->Lock.Init();
		status = FltSetFileContext(FltObjects->Instance, FltObjects->FileObject, FLT_SET_CONTEXT_KEEP_IF_EXISTS, context, nullptr);
		if (!NT_SUCCESS(status))
		{
			KdPrint(("Failed to set file context (0x%08X)\n", status));
			ExFreePoolWithTag(context->FileName.Buffer, DRIVER_TAG);
			context->FileName.Buffer = nullptr;
			break;
		}

		// send message to user mode
		if (SendClientPort)
		{
			USHORT nameLen = context->FileName.Length;
			USHORT len = sizeof(CryptoFolderPortMessage) + nameLen;
			auto msg = (CryptoFolderPortMessage*)ExAllocatePoolWithTag(PagedPool, len, DRIVER_TAG);
			
			if (msg) 
			{
				msg->FileNameLength = nameLen / sizeof(WCHAR);
				RtlCopyMemory(msg->FileName, context->FileName.Buffer, nameLen);
				LARGE_INTEGER timeout;
				timeout.QuadPart = -10000 * 100;	// 100msec

				FltSendMessage(gFilterHandle, &SendClientPort, msg, len, nullptr, nullptr, &timeout);
				ExFreePoolWithTag(msg, DRIVER_TAG);
			}
		}

	} while (false);

	FltReleaseContext(context);

	return FLT_POSTOP_FINISHED_PROCESSING;
}



#if 0
NTSTATUS CryptoFolderRead(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
{
	// Suppress W4 warning - C4100
	UNREFERENCED_PARAMETER(pDeviceObject);

	// Init some important stuff
	PIO_STACK_LOCATION pIoStackLocation = NULL;
	DWORD32 bufferLength = 0;
	NTSTATUS status = STATUS_SUCCESS;
	DWORD32 bytesTransferred = 0;
	PVOID pBuffer = NULL;

	// Get caller's I/O stack location in IRP
	pIoStackLocation = IoGetCurrentIrpStackLocation(pIrp);

	// Get length of read buffer
	bufferLength = pIoStackLocation->Parameters.Read.Length;
	if (bufferLength == 0)
	{
		status = STATUS_INVALID_BUFFER_SIZE;
		KdPrint(("Read buffer length error: %X\n", status));
		goto cleanup;
	}
	bytesTransferred = bufferLength;

	// Map locked user-mode buffer to system space and return its kernel-mode VA
	pBuffer = MmGetSystemAddressForMdlSafe(pIrp->MdlAddress, NormalPagePriority);
	if (pBuffer == NULL)
	{
		status = STATUS_INSUFFICIENT_RESOURCES;
		bytesTransferred = 0;
		KdPrint(("MmGetSystemAddressForMdlSafe error: %X\n", status));
		goto cleanup;
	}

	// Secure zero out read buffer
//	RtlSecureZeroMemory(pBuffer, bufferLength);


	// Cleanup
cleanup:
	// Set IRP status and information
	pIrp->IoStatus.Status = status;
	pIrp->IoStatus.Information = bytesTransferred;

	// Complete IRP
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return status;
}
#endif

//#if 0
NTSTATUS CryptoFolderWrite(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext)
{
	PIO_STACK_LOCATION pIoStackLocation = NULL;
	DWORD32 bufferLength = 0;
	NTSTATUS status = STATUS_SUCCESS;
	DWORD32 bytesTransferred = 0;

	// get the file context if exists
	FileContext* context;

	status = FltGetFileContext(FltObjects->Instance, FltObjects->FileObject, (PFLT_CONTEXT*)&context);
	if (!NT_SUCCESS(status) || context == nullptr)
	{
		// no context, continue normally
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	// Get current process
	//auto currentProcess = IoGetCurrentProcess();

	{
		// acquire the mutex in case of multiple writes
		AutoLock<Mutex> locker(context->Lock);

		if ((!context->Crypted)/* && (context->CryptedDirectory)*/)
		{
			status = EncryptDecryptFile(&context->FileName, FltObjects);
			if (!NT_SUCCESS(status))
			{
				KdPrint(("Failed encrypting file! (0x%X)\n", status));
			}
			else
			{
				KdPrint(("Ok encrypting file! (0x%X)\n", status));
				context->Crypted = TRUE;
			}
		}
	}
	FltReleaseContext(context);

	return status;
}

//#endif // 0


NTSTATUS
FilterPortConnect(
	_In_ PFLT_PORT ClientPort,
	_In_opt_ PVOID ServerPortCookie,
	_In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
	_In_ ULONG SizeOfContext,
	_Outptr_result_maybenull_ PVOID* ConnectionCookie
)
{
	PAGED_CODE();

	UNREFERENCED_PARAMETER(ServerPortCookie);
	UNREFERENCED_PARAMETER(ConnectionContext);
	UNREFERENCED_PARAMETER(SizeOfContext);
	UNREFERENCED_PARAMETER(ConnectionCookie = NULL);

	FLT_ASSERT(FilterData.ClientPort == NULL);
	FLT_ASSERT(FilterData.UserProcess == NULL);
	FilterData.UserProcess = PsGetCurrentProcess();
	FilterData.ClientPort = ClientPort;

	DbgPrint("CryptoFolder.sys --- connected, port=0x%p\n", ClientPort);
	return STATUS_SUCCESS;
}


VOID
FilterPortDisconnect(
	_In_opt_ PVOID ConnectionCookie
)
{
	UNREFERENCED_PARAMETER(ConnectionCookie);
	PAGED_CODE();

	DbgPrint("CryptoFolder.sys --- disconnected, port=0x%p\n", FilterData.ClientPort);

	FltCloseClientPort(gFilterHandle, &FilterData.ClientPort);
	FilterData.UserProcess = NULL;
}

NTSTATUS MessageCallback(
	__in PVOID ConnectionCookie,
	__in_bcount_opt(InputBufferSize) PVOID InputBuffer,
	__in ULONG InputBufferSize,
	__out_bcount_part_opt(OutputBufferSize, *ReturnOutputBufferLength) PVOID OutputBuffer,
	__in ULONG OutputBufferSize,
	__out PULONG ReturnOutputBufferLength
)
{
	PAGED_CODE();

	UNREFERENCED_PARAMETER(ReturnOutputBufferLength);
	UNREFERENCED_PARAMETER(OutputBuffer);
	UNREFERENCED_PARAMETER(OutputBufferSize);
	UNREFERENCED_PARAMETER(ConnectionCookie);

	NTSTATUS status;
	PWSTR buffer = nullptr;

	do {
		if ((InputBuffer != NULL) && (InputBufferSize >= sizeof(COMMAND)))
		{
			auto command = ((PCOMMAND)InputBuffer)->Command;
			if (!command)
			{
				status = STATUS_INVALID_PARAMETER;
				break;
			}

			buffer = ((PCOMMAND)InputBuffer)->Buffer;
			if (!buffer)
			{
				status = STATUS_INVALID_PARAMETER;
				break;
			}

			auto bufferLen = ((PCOMMAND)InputBuffer)->BufferLength;
			if (bufferLen > MAX_MESSAGE_BUFFER_LEN)
			{
				status = STATUS_INVALID_PARAMETER;
				break;
			}

			buffer[bufferLen] = '\0';
			auto messageLen = ::wcslen(buffer);

			if (messageLen < 1)
			{
				status = STATUS_BUFFER_TOO_SMALL;
				break;
			}

			switch (command)
			{
			case ConfigAddDirectory:
				PortConfigAddDirectory(buffer, bufferLen);
				status = STATUS_SUCCESS;
				break;
			case ConfigAddProcess:

				status = STATUS_SUCCESS;
				break;
			case LogMonitor:
			default:
				status = STATUS_INVALID_PARAMETER;
				break;
			}
		}
		else
		{
			status = STATUS_INVALID_PARAMETER;
		}
	}
	while (false);

	return status;
}


NTSTATUS PortConfigAddDirectory(_In_ PWSTR name, _In_ UCHAR nameLen)
{
	NTSTATUS status;

	do
	{
		if (!name)
		{
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		auto bufferLen = nameLen;
		if (bufferLen > 1024)
		{
			// just too long for a directory
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		// make sure there is a NULL terminator somewhere
		name[bufferLen / sizeof(WCHAR) - 1] = L'\0';
		auto dosNameLen = ::wcslen(name);

		if (dosNameLen < 3)
		{
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		//		AutoLock locker(DirNamesLock);
		UNICODE_STRING strName;
		RtlInitUnicodeString(&strName, name);

		// Break if current directory already exist
		if (FindCryptedDirectory(&strName, true) >= 0)
		{
			break;
		}

		// Break if too many directories 
		if (DirNamesCount == MaxDirectories)
		{
			status = STATUS_TOO_MANY_NAMES;
			break;
		}

		for (int i = 0; i < MaxDirectories; i++)
		{
			if (DirNames[i].DosName.Buffer == nullptr)
			{
				auto len = (dosNameLen + 2) * sizeof(WCHAR);
				auto buffer = (WCHAR*)ExAllocatePoolWithTag(PagedPool, len, DRIVER_TAG);

				if (!buffer)
				{
					status = STATUS_INSUFFICIENT_RESOURCES;
					break;
				}
				::wcscpy_s(buffer, len / sizeof(WCHAR), name);
				// append a backslash if it's missing
				if (name[dosNameLen - 1] != L'\\')
					::wcscat_s(buffer, dosNameLen + 2, L"\\");

				status = ConvertDosNameToNtName(buffer, &DirNames[i].NtName);
				if (!NT_SUCCESS(status))
				{
					ExFreePool(buffer);
					buffer = nullptr;
					break;
				}

				RtlInitUnicodeString(&DirNames[i].DosName, buffer);
				KdPrint(("Add: %wZ <=> %wZ\n", &DirNames[i].DosName, &DirNames[i].NtName));
				++DirNamesCount;
				break;
			}
		}
		break;
	} while (false);

	return status;
}

