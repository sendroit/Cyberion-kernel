/*
 * PUBLIC.H
 *
 * This header file defines the public interface between the Cyberion
 * kernel-mode driver and the user-mode monitoring application.
 * It includes IOCTL codes, device information, and shared data structures.
 */

#pragma once

//
// Device and Interface GUIDs
//
#define CYBERION_DEVICE_NAME L"\\Device\\Cyberion"
#define CYBERION_DOS_DEVICE_NAME L"\\DosDevices\\Cyberion"

// {0E228C62-3651-4106-BEC4-824CC1F53C0A}
DEFINE_GUID(GUID_DEVINTERFACE_CYBERION,
    0xe228c62, 0x3651, 0x4106, 0xbe, 0xc4, 0x82, 0x4c, 0xc1, 0xf5, 0x3c, 0xa);


//
// Custom IOCTL Codes
//
// IOCTL_CYBERION_GET_PROCESS_INFO:
//   User-mode service calls this to wait for a new process notification.
//   This is a blocking (pending) IOCTL.
//
// IOCTL_CYBERION_SEND_RESPONSE:
//   User-mode service calls this to send the user's decision (allow/block)
//   for a specific process.
//
#define IOCTL_CYBERION_GET_PROCESS_INFO CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_READ_DATA)
#define IOCTL_CYBERION_SEND_RESPONSE    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_WRITE_DATA)


//
// Shared Data Structures
//

//
// Structure for passing process creation data from kernel to user mode.
// We use fixed-size arrays to simplify marshalling.
//
#define MAX_PATH_SIZE 260

typedef struct _PROCESS_CREATION_INFO {
    HANDLE ProcessId;       // PID of the new process
    HANDLE ParentProcessId; // PID of the parent process
    WCHAR ImageFileName[MAX_PATH_SIZE]; // Full path of the executable
} PROCESS_CREATION_INFO, *PPROCESS_CREATION_INFO;


//
// Structure for passing the user's response from user mode to kernel.
//
typedef enum _USER_RESPONSE_TYPE {
    UserResponseAllow,  // Whitelist this process hash
    UserResponseBlock   // Blacklist this process hash and terminate
} USER_RESPONSE_TYPE;

typedef struct _USER_RESPONSE {
    HANDLE ProcessId;
    USER_RESPONSE_TYPE Response;
} USER_RESPONSE, *PUSER_RESPONSE; 