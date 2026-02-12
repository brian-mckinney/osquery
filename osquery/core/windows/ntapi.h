/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <osquery/utils/system/system.h>
#include <winternl.h>

namespace osquery {

#define NTSTATUS ULONG
#define STATUS_SUCCESS 0L

//#define OBJ_CASE_INSENSITIVE 64L
#define DIRECTORY_QUERY 0x0001
#define SYMBOLIC_LINK_QUERY 0x0001

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
  PVOID Object = nullptr;
  ULONG_PTR UniqueProcessId = 0;
  ULONG_PTR HandleValue = 0;
  ULONG GrantedAccess = 0;
  USHORT CreatorBackTraceIndex = 0;
  USHORT ObjectTypeIndex = 0;
  ULONG HandleAttributes = 0;
  ULONG Reserved = 0;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX {
  ULONG_PTR NumberOfHandles = 0;
  ULONG_PTR Reserved = 0;
  SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1] = {0};
} SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;

typedef struct _OBJECT_BASIC_INFORMATION {
  ULONG Attributes = 0;
  ACCESS_MASK GrantedAccess = 0;
  ULONG HandleCount = 0;
  ULONG PointerCount = 0;
  ULONG PagedPoolCharge = 0;
  ULONG NonPagedPoolCharge = 0;
  ULONG Reserved[3] = {0};
  ULONG NameInfoSize = 0;
  ULONG TypeInfoSize = 0;
  ULONG SecurityDescriptorSize = 0;
  LARGE_INTEGER CreationTime = {0};
} OBJECT_BASIC_INFORMATION, *POBJECT_BASIC_INFORMATION;

typedef struct _OBJECT_TYPE_INFORMATION {
  UNICODE_STRING TypeName;
  ULONG TotalNumberOfObjects = 0;
  ULONG TotalNumberOfHandles = 0;
  ULONG TotalPagedPoolUsage = 0;
  ULONG TotalNonPagedPoolUsage = 0;
  ULONG TotalNamePoolUsage = 0;
  ULONG TotalHandleTableUsage = 0;
  ULONG HighWaterNumberOfObjects = 0;
  ULONG HighWaterNumberOfHandles = 0;
  ULONG HighWaterPagedPoolUsage = 0;
  ULONG HighWaterNonPagedPoolUsage = 0;
  ULONG HighWaterNamePoolUsage = 0;
  ULONG HighWaterHandleTableUsage = 0;
  ULONG InvalidAttributes = 0;
  GENERIC_MAPPING GenericMapping;
  ULONG ValidAccessMask = 0;
  BOOLEAN SecurityRequired = false;
  BOOLEAN MaintainHandleCount = false;
  UCHAR TypeIndex = 0; // Available > Win8, Empty otherwise
  CHAR ReservedByte = 0;
  ULONG PoolType = 0;
  ULONG DefaultPagedPoolCharge = 0;
  ULONG DefaultNonPagedPoolCharge = 0;
} OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION;

typedef struct _OBJECT_ALL_TYPES_INFORMATION {
  ULONG NumberOfTypes;
  OBJECT_TYPE_INFORMATION Types[1];
} OBJECT_ALL_TYPES_INFORMATION, *POBJECT_ALL_TYPES_INFORMATION;

// Avoid dynamic allocation for name buffer by using a buffer that
// can contain the largest possible UNICODE_STRING.
typedef struct _OBJECT_TYPE_INFORMATION_WITH_STORAGE {
  OBJECT_TYPE_INFORMATION TypeInfo = {0};
  uint8_t Storage[USHRT_MAX];
} OBJECT_TYPE_INFORMATION_WITH_STORAGE, *POBJECT_TYPE_INFORMATION_WITH_STORAGE;

// Avoid dynamic allocation for name buffer by using a buffer that
// can contain the largest possible UNICODE_STRING.
typedef struct _OBJECT_NAME_BUFFER_WITH_STORAGE {
  UNICODE_STRING usName = {0};
  uint8_t Storage[USHRT_MAX];
} OBJECT_NAME_BUFFER_WITH_STORAGE, *POBJECT_NAME_BUFFER_WITH_STORAGE;

struct QueryObjectNameParams {
  HANDLE hObject = INVALID_HANDLE_VALUE;
  OBJECT_NAME_BUFFER_WITH_STORAGE nameBuffer = {0};
  NTSTATUS ntStatus;
};

typedef NTSTATUS(WINAPI* ZwQueryObject)(HANDLE h,
                                        OBJECT_INFORMATION_CLASS oic,
                                        PVOID ObjectInformation,
                                        ULONG ObjectInformationLength,
                                        PULONG ReturnLength);

typedef NTSTATUS(WINAPI* ZwQuerySystemInformation)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength);

typedef NTSTATUS(WINAPI* NTCLOSE)(HANDLE Handle);

typedef NTSTATUS(WINAPI* NTOPENDIRECTORYOBJECT)(
    PHANDLE DirectoryHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes);

typedef NTSTATUS(WINAPI* NTQUERYDIRECTORYOBJECT)(HANDLE DirectoryHandle,
                                                 PVOID Buffer,
                                                 ULONG Length,
                                                 BOOLEAN ReturnSingleEntry,
                                                 BOOLEAN RestartScan,
                                                 PULONG Context,
                                                 PULONG ReturnLength);

typedef NTSTATUS(WINAPI* NTOPENSYMBOLICLINKOBJECT)(
    PHANDLE LinkHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes);

typedef NTSTATUS(WINAPI* NTQUERYSYMBOLICLINKOBJECT)(HANDLE LinkHandle,
                                                    PUNICODE_STRING LinkTarget,
                                                    PULONG ReturnedLength);

typedef struct _SYSTEM_HANDLE_INFORMATION {
  ULONG ProcessId;
  BYTE ObjectTypeNumber;
  BYTE Flags;
  USHORT Handle;
  PVOID Object;
  ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef struct _OBJDIR_INFORMATION {
  UNICODE_STRING ObjectName;
  UNICODE_STRING ObjectTypeName;
  BYTE Data[1];
} OBJDIR_INFORMATION, *POBJDIR_INFORMATION;

} // namespace osquery
