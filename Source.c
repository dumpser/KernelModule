#include <ntifs.h>
#include <ntddk.h>
#include <windef.h>
#include <wdf.h>
#include <ntdef.h>
#include "raw.h"
#include "Source.h"



#define GET_MODULE_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x13, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define GET_MODULE_REQUEST_GAME CTL_CODE(FILE_DEVICE_UNKNOWN, 0x21, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

PDEVICE_OBJECT DeviceObject;
UNICODE_STRING dev, dos;
DWORD PID;
DWORD64 MainModule = NULL;
PEPROCESS Process;

NTSTATUS UnloadDriver(PDRIVER_OBJECT pDriverObject);
NTSTATUS CreateCall(PDEVICE_OBJECT DeviceObject, PIRP irp);
NTSTATUS CloseCall(PDEVICE_OBJECT DeviceObject, PIRP irp);



NTSTATUS RDrvGetModuleEntry(__in LPCWSTR ModuleName)
{
	if (!PID)
		return STATUS_UNSUCCESSFUL;
	
	KAPC_STATE pkApc;
	// Attach to target process
	KeStackAttachProcess(Process, &pkApc);

	if (!Process) return STATUS_INVALID_PARAMETER_1;
	//if(!ModuleName) return STATUS_INVALID_PARAMETER_2;

	BOOLEAN returnFirstModule = !ModuleName;
	INT waitCount = 0;

	PPEB peb = PsGetProcessPeb(Process);
	if (!peb) {
		return STATUS_UNSUCCESSFUL;
	}

	PPEB_LDR_DATA ldr = peb->Ldr;

	if (!ldr) {
		return STATUS_UNSUCCESSFUL;
	}

	if (!ldr->Initialized) {
		while (!ldr->Initialized && waitCount++ < 4)

		if (!ldr->Initialized) {
			return STATUS_UNSUCCESSFUL;
		}
	}

	for (PLIST_ENTRY listEntry = (PLIST_ENTRY)ldr->InLoadOrderModuleList.Flink;
		listEntry != &ldr->InLoadOrderModuleList;
		listEntry = (PLIST_ENTRY)listEntry->Flink) {

		PLDR_DATA_TABLE_ENTRY ldrEntry = CONTAINING_RECORD(listEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

		if (returnFirstModule) {
			return STATUS_SUCCESS;
		}
		else {
			if (RtlCompareMemory(ldrEntry->BaseDllName.Buffer, ModuleName, ldrEntry->BaseDllName.Length) == ldrEntry->BaseDllName.Length) {
#ifdef DEBUGPRINT
				DbgPrint("%p\n", ldrEntry->DllBase);
#endif
				MainModule = ldrEntry->DllBase;
				KeUnstackDetachProcess(&pkApc);
				return STATUS_SUCCESS;
			}
		}
	}
	return STATUS_NOT_FOUND;
}

NTSTATUS LSFindProcessIdByName(IN PCWSTR imagename)
{

	NTSTATUS durum = STATUS_UNSUCCESSFUL;
	ULONG qmemsize = 0x1024;
	PVOID qmemptr = 0;
	P_SYSTEM_PROCESS_INFO_L spi;
	UNICODE_STRING uimagename;
	RtlInitUnicodeString(&uimagename, imagename); // @RbMm
	do
	{
		qmemptr = ExAllocatePool(PagedPool, qmemsize); // alloc memory for spi
		if (qmemptr == NULL) // check memory is allocated or not.
		{
			return STATUS_UNSUCCESSFUL;
		}
		durum = ZwQuerySystemInformation(5, qmemptr, qmemsize, NULL);
		if (durum == STATUS_INFO_LENGTH_MISMATCH)
		{
			qmemsize = qmemsize * 2; // increase qmemsize for next memory alloc
			ExFreePool(qmemptr); // free memory
		}
	} while (durum == STATUS_INFO_LENGTH_MISMATCH); // resize memory
	spi = (P_SYSTEM_PROCESS_INFO_L)qmemptr;

	while (1)
	{

		if (RtlEqualUnicodeString(&uimagename, &spi->ImageName, TRUE)) // @RbMm
		{
#ifdef DEBUGPRINT
			DbgPrint("%d\n", spi->ProcessId);
#endif
			PID = spi->ProcessId;
			break;
		}

		if (spi->NextEntryOffset == 0)
			break;

		spi = (P_SYSTEM_PROCESS_INFO_L)((unsigned char*)spi + spi->NextEntryOffset); // next info 
	}

	if (!NT_SUCCESS(durum))
	{
		ExFreePool(qmemptr); // free memory
		return STATUS_UNSUCCESSFUL;
	}
	ExFreePool(qmemptr); // free memory 
	return STATUS_SUCCESS;
}


NTSTATUS IoControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	NTSTATUS Status;
	ULONG BytesIO = 0;

	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);

	// Code received from user space
	ULONG ControlCode = stack->Parameters.DeviceIoControl.IoControlCode;
	ULONG outBufferLength = stack->Parameters.DeviceIoControl.OutputBufferLength;


	if (ControlCode == GET_MODULE_REQUEST_GAME)
	{
		PDWORD64 OutPut = (PDWORD64)Irp->AssociatedIrp.SystemBuffer;

		LSFindProcessIdByName(L"Notepad.exe");
		NTSTATUS stat = PsLookupProcessByProcessId(PID, &Process);

		RDrvGetModuleEntry(L"WhatModuleYouWant.dll");

		*OutPut = MainModule;

		//DbgPrintEx(0, 0, "Module get %#010x", MainModule);
		Status = STATUS_SUCCESS;
		BytesIO = sizeof(*OutPut);
	}
	else
	{
		// if the code is unknown
		Status = STATUS_INVALID_PARAMETER;
		BytesIO = 0;
	}

	// Complete the request
	Irp->IoStatus.Status = Status;
	Irp->IoStatus.Information = BytesIO;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return Status;
}

NTSTATUS DriverInitialize(_In_  struct _DRIVER_OBJECT* DriverObject, _In_  PUNICODE_STRING RegistryPath)
{
	NTSTATUS        status;
	UNICODE_STRING  SymLink, DevName;
	PDEVICE_OBJECT  devobj;
	ULONG           t;

	//RegistryPath is NULL
	UNREFERENCED_PARAMETER(RegistryPath);


	RtlInitUnicodeString(&DevName, L"\\Device\\DeviceName");
	status = IoCreateDevice(DriverObject, 0, &DevName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, TRUE, &devobj);


	if (!NT_SUCCESS(status)) {
		return status;
	}

	RtlInitUnicodeString(&SymLink, L"\\DosDevices\\DeviceName");
	status = IoCreateSymbolicLink(&SymLink, &DevName);



	devobj->Flags |= DO_BUFFERED_IO;

	DriverObject->MajorFunction[IRP_MJ_CREATE] = CreateCall;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = CloseCall;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IoControl;
	DriverObject->DriverUnload = NULL; //nonstandard way of driver loading, no unload

	devobj->Flags &= ~DO_DEVICE_INITIALIZING;
	return status;
}

NTSTATUS DriverEntry(_In_  struct _DRIVER_OBJECT* DriverObject, _In_  PUNICODE_STRING RegistryPath)
{

	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);

	

	//PsSetLoadImageNotifyRoutine(ImageLoadCallback);
	// Our device and symbolic link names

	RtlInitUnicodeString(&dev, L"\\Driver\\DeviceName");

	IoCreateDriver(&dev, &DriverInitialize);

	return STATUS_SUCCESS;
}

NTSTATUS UnloadDriver(PDRIVER_OBJECT pDriverObject)
{
	return STATUS_SUCCESS;
}

NTSTATUS CreateCall(PDEVICE_OBJECT DeviceObject, PIRP irp)
{
	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;

	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS CloseCall(PDEVICE_OBJECT DeviceObject, PIRP irp)
{
	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;

	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}
