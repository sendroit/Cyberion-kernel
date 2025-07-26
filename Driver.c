/*
 * DRIVER.C
 *
 * Main source file for the Cyberion Kernel-Mode Driver.
 * This driver is responsible for intercepting process creation events
 * and communicating with a user-mode service for analysis and decision-making.
 */

#include <ntddk.h>
#include <wdm.h>
#include "Public.h"

//
// Globals
//
PDEVICE_OBJECT g_DeviceObject = NULL; // Global pointer to our device object
PIRP g_PendingIrp = NULL; // Stores the IRP from user-mode waiting for a notification
KSPIN_LOCK g_IrpQueueLock; // Spinlock to protect access to the pending IRP

//
// Forward Declarations
//
DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD CyberionUnload;
DRIVER_DISPATCH CyberionCreateClose;
DRIVER_DISPATCH CyberionDeviceControl;
VOID ProcessNotifyCallback(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo);

//
// DriverEntry: The entry point for the driver.
//
NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    NTSTATUS status;
    UNICODE_STRING devName = RTL_CONSTANT_STRING(CYBERION_DEVICE_NAME);
    UNICODE_STRING dosDeviceName = RTL_CONSTANT_STRING(CYBERION_DOS_DEVICE_NAME);

    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrint("CyberionDriver: DriverEntry - Loading.\n");

    // Create the device object
    status = IoCreateDevice(
        DriverObject,
        0,
        &devName,
        FILE_DEVICE_UNKNOWN,
        0,
        FALSE,
        &g_DeviceObject);

    if (!NT_SUCCESS(status)) {
        DbgPrint("CyberionDriver: Failed to create device object (0x%08X).\n", status);
        return status;
    }

    // Create a symbolic link for the user-mode application
    status = IoCreateSymbolicLink(&dosDeviceName, &devName);

    if (!NT_SUCCESS(status)) {
        DbgPrint("CyberionDriver: Failed to create symbolic link (0x%08X).\n", status);
        IoDeleteDevice(g_DeviceObject);
        return status;
    }

    // Set up driver dispatch routines
    DriverObject->DriverUnload = CyberionUnload;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = CyberionCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = CyberionCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = CyberionDeviceControl;

    // Register the process creation callback
    status = PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCallback, FALSE);

    if (!NT_SUCCESS(status)) {
        DbgPrint("CyberionDriver: Failed to register process notify routine (0x%08X).\n", status);
        IoDeleteSymbolicLink(&dosDeviceName);
        IoDeleteDevice(g_DeviceObject);
        return status;
    }

    KeInitializeSpinLock(&g_IrpQueueLock);

    DbgPrint("CyberionDriver: Driver loaded successfully.\n");

    return STATUS_SUCCESS;
}

//
// CyberionUnload: Called when the driver is being unloaded.
//
VOID CyberionUnload(
    _In_ PDRIVER_OBJECT DriverObject
)
{
    UNICODE_STRING dosDeviceName = RTL_CONSTANT_STRING(CYBERION_DOS_DEVICE_NAME);

    DbgPrint("CyberionDriver: Unloading driver.\n");

    // Unregister the callback routine
    PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCallback, TRUE);

    // If an IRP is pending, cancel it
    if (g_PendingIrp) {
        IoCancelIrp(g_PendingIrp);
        g_PendingIrp = NULL;
    }

    // Clean up resources
    IoDeleteSymbolicLink(&dosDeviceName);
    IoDeleteDevice(DriverObject->DeviceObject);
}

//
// CyberionCreateClose: Handles IRP_MJ_CREATE and IRP_MJ_CLOSE requests.
//
NTSTATUS CyberionCreateClose(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

//
// ProcessNotifyCallback: The core routine that gets called on every process creation/exit.
//
VOID ProcessNotifyCallback(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
)
{
    UNREFERENCED_PARAMETER(Process);
    
    if (CreateInfo) { // Process is being created
        DbgPrint("CyberionDriver: Process creation detected: PID %d, Name: %wZ\n", ProcessId, CreateInfo->ImageFileName);

        KLOCK_QUEUE_HANDLE lockHandle;
        KeAcquireInStackQueuedSpinLock(&g_IrpQueueLock, &lockHandle);

        if (g_PendingIrp) {
            PPROCESS_CREATION_INFO pInfo = (PPROCESS_CREATION_INFO)g_PendingIrp->AssociatedIrp.SystemBuffer;
            
            pInfo->ProcessId = ProcessId;
            pInfo->ParentProcessId = CreateInfo->ParentProcessId;
            
            // Safely copy the image file name
            if (CreateInfo->ImageFileName != NULL) {
                RtlCopyMemory(pInfo->ImageFileName, CreateInfo->ImageFileName->Buffer, min(CreateInfo->ImageFileName->Length, MAX_PATH_SIZE * sizeof(WCHAR)));
            }

            g_PendingIrp->IoStatus.Status = STATUS_SUCCESS;
            g_PendingIrp->IoStatus.Information = sizeof(PROCESS_CREATION_INFO);
            IoCompleteRequest(g_PendingIrp, IO_NO_INCREMENT);
            g_PendingIrp = NULL;
        }

        KeReleaseInStackQueuedSpinLock(&lockHandle);
    }
}

//
// CyberionDeviceControl: Handles IOCTL requests from the user-mode application.
//
NTSTATUS CyberionDeviceControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_SUCCESS;

    switch (stack->Parameters.DeviceIoControl.IoControlCode) {
        case IOCTL_CYBERION_GET_PROCESS_INFO:
        {
            DbgPrint("CyberionDriver: IOCTL_CYBERION_GET_PROCESS_INFO received.\n");
            
            KLOCK_QUEUE_HANDLE lockHandle;
            KeAcquireInStackQueuedSpinLock(&g_IrpQueueLock, &lockHandle);

            if (g_PendingIrp) {
                // Another request is already pending
                status = STATUS_DEVICE_BUSY;
            } else {
                // Mark the IRP as pending and store it
                g_PendingIrp = Irp;
                status = STATUS_PENDING;
                IoMarkIrpPending(Irp);
            }

            KeReleaseInStackQueuedSpinLock(&lockHandle);

            // If not pending, complete the request now
            if (status != STATUS_PENDING) {
                Irp->IoStatus.Status = status;
                Irp->IoStatus.Information = 0;
                IoCompleteRequest(Irp, IO_NO_INCREMENT);
            }
            break;
        }

        case IOCTL_CYBERION_SEND_RESPONSE:
        {
            // In a full implementation, you would handle the response here.
            // For example, terminate a process if the user chose to block it.
            // This part is left for future expansion.
            DbgPrint("CyberionDriver: IOCTL_CYBERION_SEND_RESPONSE received.\n");
            
            // For now, just complete the request successfully.
            Irp->IoStatus.Status = STATUS_SUCCESS;
            Irp->IoStatus.Information = 0;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);
            break;
        }

        default:
            status = STATUS_INVALID_DEVICE_REQUEST;
            Irp->IoStatus.Status = status;
            Irp->IoStatus.Information = 0;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);
            break;
    }

    return status;
} 