/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */
#include <windows.h>
#include <winternl.h>

#include <iomanip>
#include <iostream>
#include <map>
#include <set>
#include <sstream>
#include <stdio.h>
#include <string>
#include <unordered_map>
#include <vector>

#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>
#include <osquery/sql/dynamic_table_row.h>
#include <osquery/sql/sql.h>
#include <osquery/utils/conversions/windows/strings.h>

#pragma comment(lib, "ntdll.lib")

namespace osquery {
namespace tables {

namespace handles {

#ifndef ULONG
#define ULONG unsigned long
#endif

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS 0L
#endif

constexpr size_t INITIAL_ENUMERATION_BUFFER_SIZE = 1024 * 1024 * 4; // 4 MBs
constexpr size_t MAXIMUM_ENUMERATION_BUFFER_SIZE = 1024 * 1024 * 1024; // 1GB

#ifndef SystemExtendedHandleInformation
#define SystemExtendedHandleInformation ((SYSTEM_INFORMATION_CLASS)64)
#endif

#ifndef ObjectNameInformation
#define ObjectNameInformation ((OBJECT_INFORMATION_CLASS)1)
#endif

#ifndef ObjectTypeInformation
#define ObjectTypeInformation ((OBJECT_INFORMATION_CLASS)2)
#endif

#ifndef ObjectAllTypesInformation
#define ObjectAllTypesInformation ((OBJECT_INFORMATION_CLASS)3)
#endif

#ifndef STATUS_UNSUCCESSFUL
#define STATUS_UNSUCCESSFUL 0xC0000001L
#endif

#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004L
#endif

#ifndef STATUS_ACCESS_DENIED
#define STATUS_ACCESS_DENIED 0xC0000022L
#endif

#ifndef STATUS_BUFFER_TOO_SMALL
#define STATUS_BUFFER_TOO_SMALL 0xC0000023L
#endif

#ifndef STATUS_NOT_SUPPORTED
#define STATUS_NOT_SUPPORTED 0xC00000BBL
#endif

#ifndef STATUS_RETRY
#define STATUS_RETRY 0xC000022DL
#endif

constexpr size_t AlignUp(size_t value, size_t align) {
  return (value + (align - 1)) & ~(align - 1);
}

constexpr size_t AlignUpPtr(size_t value) {
  return AlignUp(value, sizeof(void*));
}

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
  PVOID Object;
  ULONG_PTR UniqueProcessId;
  ULONG_PTR HandleValue;
  ULONG GrantedAccess;
  USHORT CreatorBackTraceIndex;
  USHORT ObjectTypeIndex;
  ULONG HandleAttributes;
  ULONG Reserved;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX {
  ULONG_PTR NumberOfHandles;
  ULONG_PTR Reserved;
  SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;

typedef struct _OBJECT_BASIC_INFORMATION {
  ULONG Attributes;
  ACCESS_MASK GrantedAccess;
  ULONG HandleCount;
  ULONG PointerCount;
  ULONG PagedPoolCharge;
  ULONG NonPagedPoolCharge;
  ULONG Reserved[3];
  ULONG NameInfoSize;
  ULONG TypeInfoSize;
  ULONG SecurityDescriptorSize;
  LARGE_INTEGER CreationTime;
} OBJECT_BASIC_INFORMATION, *POBJECT_BASIC_INFORMATION;

typedef struct _OBJECT_TYPE_INFORMATION {
  UNICODE_STRING TypeName;
  ULONG TotalNumberOfObjects;
  ULONG TotalNumberOfHandles;
  ULONG TotalPagedPoolUsage;
  ULONG TotalNonPagedPoolUsage;
  ULONG TotalNamePoolUsage;
  ULONG TotalHandleTableUsage;
  ULONG HighWaterNumberOfObjects;
  ULONG HighWaterNumberOfHandles;
  ULONG HighWaterPagedPoolUsage;
  ULONG HighWaterNonPagedPoolUsage;
  ULONG HighWaterNamePoolUsage;
  ULONG HighWaterHandleTableUsage;
  ULONG InvalidAttributes;
  GENERIC_MAPPING GenericMapping;
  ULONG ValidAccessMask;
  BOOLEAN SecurityRequired;
  BOOLEAN MaintainHandleCount;
  UCHAR TypeIndex; // Available > Win8, Empty otherwise
  CHAR ReservedByte;
  ULONG PoolType;
  ULONG DefaultPagedPoolCharge;
  ULONG DefaultNonPagedPoolCharge;
} OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION;

typedef struct _OBJECT_ALL_TYPES_INFORMATION {
  ULONG NumberOfTypes;
  OBJECT_TYPE_INFORMATION Types[1];
} OBJECT_ALL_TYPES_INFORMATION, *POBJECT_ALL_TYPES_INFORMATION;

// Avoid dynamic allocation for name buffer by using a buffer that
// can contain the largest possible UNICODE_STRING.
typedef struct _OBJECT_TYPE_INFORMATION_WITH_STORAGE {
  OBJECT_TYPE_INFORMATION TypeInfo;
  BYTE Storage[USHRT_MAX];
} OBJECT_TYPE_INFORMATION_WITH_STORAGE, *POBJECT_TYPE_INFORMATION_WITH_STORAGE;

// Avoid dynamic allocation for name buffer by using a buffer that
// can contain the largest possible UNICODE_STRING.
typedef struct _OBJECT_NAME_BUFFER_WITH_STORAGE {
  UNICODE_STRING usName;
  BYTE Storage[USHRT_MAX];
} OBJECT_NAME_BUFFER_WITH_STORAGE, *POBJECT_NAME_BUFFER_WITH_STORAGE;

typedef struct _QUERY_OBJECT_NAME_PARAMS {
  HANDLE hObject;
  OBJECT_NAME_BUFFER_WITH_STORAGE nameBuffer;
  NTSTATUS ntStatus;
} QUERY_OBJECT_NAME_PARAMS, *PQUERY_OBJECT_NAME_PARAMS;

extern "C" NTSTATUS NTAPI NtDuplicateObject(HANDLE SourceProcessHandle,
                                            HANDLE SourceHandle,
                                            HANDLE TargetProcessHandle,
                                            PHANDLE TargetHandle,
                                            ACCESS_MASK DesiredAccess,
                                            ULONG HandleAttributes,
                                            ULONG Options);

extern "C" LONG NTAPI RtlCompareUnicodeString(PCUNICODE_STRING String1,
                                              PCUNICODE_STRING String2,
                                              BOOLEAN CaseInSensitive);

extern "C" NTSTATUS NTAPI RtlGetVersion(PRTL_OSVERSIONINFOW lpVersionInformation);

enum class ErrorStage {
  None = 0,
  ProcessOpening = 1,
  HandleDuplication = 2,
  ObjectBasicInfoQuerying = 3,
  ObjectTypeInfoQuerying = 4,
  ObjectNameQuerying = 5
};

std::string_view ErrorStageString(ErrorStage stage) {
  switch (stage) {
  case ErrorStage::None:
    return "None";
  case ErrorStage::ProcessOpening:
    return "ProcessOpening";
  case ErrorStage::HandleDuplication:
    return "HandleDuplication";
  case ErrorStage::ObjectBasicInfoQuerying:
    return "ObjectBasicInfoQuerying";
  case ErrorStage::ObjectTypeInfoQuerying:
    return "ObjectTypeInfoQuerying";
  case ErrorStage::ObjectNameQuerying:
    return "ObjectNameQuerying";
  default:
    return "Unknown";
  }
}

namespace mappings {
struct MappedValue {
  unsigned long mask;
  std::string_view name;
};

constexpr MappedValue Generic[] = {{GENERIC_READ, "GENERIC_READ"},
                                   {GENERIC_WRITE, "GENERIC_WRITE"},
                                   {GENERIC_EXECUTE, "GENERIC_EXECUTE"},
                                   {GENERIC_ALL, "GENERIC_ALL"}};

constexpr MappedValue Standard[] = {{DELETE, "DELETE"},
                                    {READ_CONTROL, "READ_CONTROL"},
                                    {WRITE_DAC, "WRITE_DAC"},
                                    {WRITE_OWNER, "WRITE_OWNER"},
                                    {SYNCHRONIZE, "SYNCHRONIZE"}};

constexpr MappedValue File[] = {{FILE_READ_DATA, "READ_DATA"},
                                {FILE_WRITE_DATA, "WRITE_DATA"},
                                {FILE_APPEND_DATA, "APPEND_DATA"},
                                {FILE_READ_EA, "READ_EA"},
                                {FILE_WRITE_EA, "WRITE_EA"},
                                {FILE_EXECUTE, "EXECUTE"},
                                {FILE_READ_ATTRIBUTES, "READ_ATTRIBUTES"},
                                {FILE_WRITE_ATTRIBUTES, "WRITE_ATTRIBUTES"}};

constexpr MappedValue Directory[] = {{FILE_READ_DATA, "LIST_DIRECTORY"},
                                     {FILE_WRITE_DATA, "ADD_FILE"},
                                     {FILE_APPEND_DATA, "ADD_SUBDIRECTORY"},
                                     {FILE_READ_EA, "READ_EA"},
                                     {FILE_WRITE_EA, "WRITE_EA"},
                                     {FILE_EXECUTE, "TRAVERSE"},
                                     {FILE_READ_ATTRIBUTES, "READ_ATTRIBUTES"},
                                     {FILE_WRITE_ATTRIBUTES, "WRITE_ATTRIBUTES"}};

constexpr MappedValue Key[] = {{KEY_QUERY_VALUE, "QUERY_VALUE"},
                               {KEY_SET_VALUE, "SET_VALUE"},
                               {KEY_CREATE_SUB_KEY, "CREATE_SUB_KEY"},
                               {KEY_ENUMERATE_SUB_KEYS, "ENUMERATE_SUB_KEYS"},
                               {KEY_NOTIFY, "NOTIFY"},
                               {KEY_CREATE_LINK, "CREATE_LINK"}};

constexpr MappedValue Attributes[] = {{OBJ_INHERIT, "INHERIT"},
                                      {OBJ_PERMANENT, "PERMANENT"},
                                      {OBJ_EXCLUSIVE, "EXCLUSIVE"},
                                      {OBJ_CASE_INSENSITIVE, "CASE_INSENSITIVE"},
                                      {OBJ_OPENIF, "OPENIF"},
                                      {OBJ_OPENLINK, "OPENLINK"},
                                      {OBJ_KERNEL_HANDLE, "KERNEL_HANDLE"},
                                      {OBJ_FORCE_ACCESS_CHECK, "FORCE_ACCESS_CHECK"},
                                      {OBJ_IGNORE_IMPERSONATED_DEVICEMAP, "IGNORE_IMPERSONATED_DEVICEMAP"},
                                      {OBJ_DONT_REPARSE, "DONT_REPARSE"}};
} // namespace mappings

struct KeyHash {
  size_t operator()(const std::pair<ULONG, std::string>& key) const {
    return std::hash<ULONG>()(key.first) ^ std::hash<std::string>()(key.second);
  }
};
using GrantedAccessCache = std::unordered_map<std::pair<ULONG, std::string>, std::string, KeyHash>;
using HandleAttributesCache = std::unordered_map<ULONG, std::string>;
using ObjectTypeNameCache = std::unordered_map<std::wstring, std::string>;
using ObjectNameCache = std::unordered_map<std::wstring, std::string>;
using HandleTypeMap = std::unordered_map<ULONG, std::wstring>;

// Cache for handle enumeration that allows us to avoid expensive operations like string
// conversions and access mask decoding when possible.  During enumeration we could possibly
// encounter larger numbers of handles, and would have serious performance issues if we did
// did not have this cache in place.
//
class HandleRecordCache {
 private:
  ObjectTypeNameCache m_objectTypeNameCache;
  GrantedAccessCache m_grantedAccessCache;
  HandleAttributesCache m_handleAttributesCache;
  ObjectNameCache m_objectNameCache;
  HandleTypeMap m_handleTypeMap;

  std::wstring FromPUnicodeString(PUNICODE_STRING us) {
    if (!us || !us->Buffer || us->Length == 0) {
      return L"";
    }
    return std::wstring(us->Buffer, us->Length / sizeof(WCHAR));
  }

 public:
  HandleRecordCache() {}

  // ObjectName comes in as a unicode string, but we will cache
  // it as an std::string for use in our final output.  The function
  // is overloaded to allow callers to pass in either a PUNICODE_STRING (default)
  // or a std::wstring in cases where we are storing special sentinel values like
  // "Unknown" for objects we failed to query the name of.
  //
  const std::string* GetObjectName(PUNICODE_STRING us) {
    return GetObjectName(this->FromPUnicodeString(us));
  }

  const std::string* GetObjectName(const std::wstring& lookup) {
    if (lookup.empty()) {
      return nullptr;
    }

    auto it = m_objectNameCache.find(lookup);
    if (it != m_objectNameCache.end()) {
      // Found!
      return &(it->second);
    }

    std::string converted = wstringToString(lookup.c_str());
    auto [insertIt, _] = m_objectNameCache.try_emplace(std::move(lookup), std::move(converted));
    return &(insertIt->second);
  }

  // ObjectTypeName comes in as a unicode string, but we will cache
  // it as an std::string for use in our final output.  The function
  // is overloaded to allow callers to pass in either a PUNICODE_STRING (default)
  // or a std::wstring in cases where we are storing special sentinel values like
  // "Unknown" for objects we failed to query the name of.
  //
  const std::string* GetObjectTypeName(PUNICODE_STRING us) {
    return GetObjectTypeName(this->FromPUnicodeString(us));
  }

  const std::string* GetObjectTypeName(const std::wstring& lookup) {
    if (lookup.empty()) {
      return nullptr;
    }

    auto it = m_objectTypeNameCache.find(lookup);
    if (it != m_objectTypeNameCache.end()) {
      // Found!
      return &(it->second);
    }

    // Not found. Insert the lookup string.
    std::string converted = wstringToString(lookup.c_str());
    auto [insertIt, _] = m_objectTypeNameCache.try_emplace(std::move(lookup), std::move(converted));
    return &(insertIt->second);
  }

  // During Enumeration we collect granted access as a raw mask, but we want to convert it
  // to a string for our final output.  This function is used to cache the results of
  // that conversion.  We are returning the result as an std::string instead of a pointer
  // because this function is only called at row generation time, and will be copied regardless
  //
  std::string GetGrantedAccessString(ULONG grantedAccess, const std::string& type) {
    auto it = m_grantedAccessCache.find({grantedAccess, type});
    if (it != m_grantedAccessCache.end()) {
      return it->second;
    } else {
      std::vector<std::string_view> rights;
      auto check_mask = [&](const mappings::MappedValue& mapping) {
        if (grantedAccess & mapping.mask)
          rights.push_back(mapping.name);
      };

      // Handle Generic Rights
      for (const auto& mapping : mappings::Generic) {
        check_mask(mapping);
      }

      // Handle Standard Rights (Common to most objects)
      for (const auto& mapping : mappings::Standard) {
        check_mask(mapping);
      }

      // Handle Type-Specific Rights
      if (type == "File") {
        for (const auto& mapping : mappings::File) {
          check_mask(mapping);
        }
      } else if (type == "Directory") {
        for (const auto& mapping : mappings::Directory) {
          check_mask(mapping);
        }
      } else if (type == "Key") {
        for (const auto& mapping : mappings::Key) {
          check_mask(mapping);
        }
      }

      // Combine results
      if (rights.empty()) {
        return "NO_ACCESS";
      }

      std::string accessRights;
      for (size_t i = 0; i < rights.size(); i++) {
        accessRights.append(rights[i]);
        if (i != rights.size() - 1) {
          accessRights.append("|");
        }
      }

      auto [it, _] = m_grantedAccessCache.try_emplace({grantedAccess, type}, std::move(accessRights));
      return it->second;
    }
  }

  // Similar to GetGrantedAccessString, we want to cache the results of
  // decoding handle attributes for use in our final output.
  //
  std::string GetHandleAttributesString(ULONG handleAttributes) {
    if (0 == handleAttributes) {
      return "None";
    }

    auto it = this->m_handleAttributesCache.find(handleAttributes);
    if (it != m_handleAttributesCache.end()) {
      return it->second;
    } else {
      std::vector<std::string_view> attributes;
      auto check_mask = [&](const mappings::MappedValue& mapping) {
        if (handleAttributes & mapping.mask)
          attributes.push_back(mapping.name);
      };
      for (const auto& mapping : mappings::Attributes) {
        check_mask(mapping);
      }

      if (attributes.empty()) {
        return std::to_string(handleAttributes);
      }

      std::string attributesStr;
      for (size_t i = 0; i < attributes.size(); i++) {
        attributesStr.append(attributes[i]);
        if (i != attributes.size() - 1) {
          attributesStr.append(",");
        }
      }

      auto [it, _] = this->m_handleAttributesCache.try_emplace(handleAttributes, std::move(attributesStr));
      return it->second;
    }
  }

  // We cache the mapping of ObjectTypeIndex to ObjectTypeName here as well
  // since we need to query the type name
  HandleTypeMap& GetHandleTypeMap() {
    return this->m_handleTypeMap;
  }
};

// Represents a single handle record for enumeration and eventual conversion to a Row for output.
// This class also contains an error state that allows us to capture and log errors that occur during enumeration
// while still returning partial results for handles that we were able to query successfully.
//
class HandleRecord {
 private:
  // the stage at which an error occurred for this handle, if any
  ErrorStage m_errorStage{ErrorStage::None};
  // the error code resulting from the error, if any
  DWORD m_errorStatus{0};
  // the name of the object type, if available
  const std::string* m_ObjectTypeName{nullptr};
  // the granted access mask for the handle
  ULONG m_GrantedAccess = 0;
  // the handle attributes
  ULONG m_HandleAttributes = 0;
  // the raw pointer count
  ULONG m_RawPointerCount = 0;
  // the handle count
  ULONG m_HandleCount = 0;
  // the name of the object, if available
  const std::string* m_ObjectName{nullptr};
  // the process ID associated with the handle
  ULONG_PTR ProcessId = 0;
  // reference to the handle record cache
  HandleRecordCache& m_cache;
  // the handle value
  ULONG_PTR HandleValue = 0;
  // the object type index
  USHORT ObjectTypeIndex = 0;

 public:
  HandleRecord(PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX entry, HandleRecordCache& cache) : m_cache(cache) {
    this->ProcessId = entry->UniqueProcessId;
    this->HandleValue = entry->HandleValue;
    this->m_GrantedAccess = entry->GrantedAccess;
    this->ObjectTypeIndex = entry->ObjectTypeIndex;
    this->m_HandleAttributes = entry->HandleAttributes;
  }

  // Setters and Getters optimized to use the cache where possible for
  // string conversions and lookups

  ULONG_PTR Handle() const {
    return this->HandleValue;
  }

  USHORT TypeIndex() const {
    return this->ObjectTypeIndex;
  }

  ULONG_PTR Pid() const {
    return this->ProcessId;
  }

  void SetObjectName(PUNICODE_STRING objectName) {
    this->m_ObjectName = this->m_cache.GetObjectName(objectName);
  }
  void SetObjectName(const std::wstring& objectName) {
    this->m_ObjectName = this->m_cache.GetObjectName(objectName);
  }

  void SetObjectTypeName(PUNICODE_STRING objectTypeName) {
    this->m_ObjectTypeName = this->m_cache.GetObjectTypeName(objectTypeName);
  }

  void SetGrantedAccess(ULONG grantedAccess) {
    this->m_GrantedAccess = grantedAccess;
  }

  void SetHandleAttributes(ULONG handleAttributes) {
    this->m_HandleAttributes = handleAttributes;
  }

  void SetRawPointerCount(ULONG rawPointerCount) {
    this->m_RawPointerCount = rawPointerCount;
  }

  void SetHandleCount(ULONG handleCount) {
    this->m_HandleCount = handleCount;
  }

  std::string Type() {
    // If we have a valid type, return it
    if (this->m_ObjectTypeName) {
      return *this->m_ObjectTypeName;
    }

    // If we don't have a valid type, attempt to look it up in the cache using the ObjectTypeIndex.
    // If we find a match, cache it and return it
    auto it = this->m_cache.GetHandleTypeMap().find(this->ObjectTypeIndex);
    if (it != this->m_cache.GetHandleTypeMap().end()) {
      const std::string* typeName = this->m_cache.GetObjectTypeName(it->second);
      if (typeName) {
        return *typeName;
      }
    }
    return "Unknown";
  }

  std::string Access() {
    const std::string type = this->Type();
    return this->m_cache.GetGrantedAccessString(this->m_GrantedAccess, type);
  }

  std::string Attributes() {
    return this->m_cache.GetHandleAttributesString(this->m_HandleAttributes);
  }

  std::string Name() const {
    return this->m_ObjectName ? *this->m_ObjectName : "Unknown";
  }

  ULONG RawPointerCount() const {
    return this->m_RawPointerCount;
  }

  ULONG HandleCount() const {
    return this->m_HandleCount;
  }

  void SetError(ErrorStage errorStage, DWORD errorStatus, bool logError = false) {
    this->m_errorStage = errorStage;
    this->m_errorStatus = errorStatus;

    if (!logError) {
      return;
    }

    std::stringstream errorStatusStream;
    switch (errorStage) {
    case ErrorStage::ProcessOpening:
      errorStatusStream << "Error opening process";
      break;
    case ErrorStage::HandleDuplication:
      errorStatusStream << "Error duplicating handle";
      break;
    case ErrorStage::ObjectBasicInfoQuerying:
      errorStatusStream << "Error querying object basic info";
      break;
    case ErrorStage::ObjectTypeInfoQuerying:
      errorStatusStream << "Error querying object type info";
      break;
    case ErrorStage::ObjectNameQuerying:
      errorStatusStream << "Error querying object name";
      break;
    default:
      errorStatusStream << "Unknown error";
      break;
    }
    errorStatusStream << " Pid: " << this->ProcessId << " Error Code: " << this->m_errorStatus << " Handle 0x"
                      << std::hex << this->HandleValue << std::dec;
    LOG(ERROR) << errorStatusStream.str();
  }

  ErrorStage GetErrorStage() const {
    return this->m_errorStage;
  }

  DWORD GetErrorCode() const {
    return this->m_errorStatus;
  }

  Row ToRow() {
    Row row;
    row["pid"] = INTEGER(this->Pid());
    row["handle_value"] = INTEGER(this->HandleValue);
    row["type"] = this->Type();
    row["access"] = this->Access();
    row["name"] = this->Name();
    row["attributes"] = this->Attributes();
    row["handle_count"] = INTEGER(this->HandleCount());
    row["raw_pointer_count"] = INTEGER(this->RawPointerCount());
    row["error_stage"] = ErrorStageString(this->GetErrorStage());
    row["error_code"] = INTEGER(this->GetErrorCode());
    return row;
  }
};
using HandleRecordPtr = std::unique_ptr<HandleRecord>;

// Parent class that holds the state of handle enumeration,
// including the cache, the list of PIDs to filter on, and the resulting handle
// records that will be converted to rows for output.
class HandleEnumeration {
 public:
  HandleRecordCache m_cache;
  std::set<int> m_pidlist;
  std::vector<HandleRecordPtr> handleRecords;

  HandleEnumeration(const std::set<int>& pidlist) : m_pidlist(pidlist) {}

  bool IsPidFiltered(DWORD pid) const {
    return !m_pidlist.empty() && m_pidlist.find(pid) == m_pidlist.end();
  }

  HandleRecordCache& Cache() {
    return m_cache;
  }

  QueryData ToRows() {
    QueryData rows;
    for (const auto& handle : this->handleRecords) {
      rows.push_back(handle->ToRow());
    }
    return rows;
  }
};

// Helper struct to query the os version, as certain operations we
// perform during handle enumeration are only supported on certain
// versions of Windows.
struct OSVersionInfo {
  bool isWin80OrGreater = false;

  OSVersionInfo() {
    RTL_OSVERSIONINFOW osvi = {sizeof(osvi)};

    // Win 8.0/2012 is 6.2, Win 8.1/2012R2 is 6.3
    if (RtlGetVersion(&osvi) == 0) {
      if (osvi.dwMajorVersion > 6) {
        isWin80OrGreater = true;
      } else if (osvi.dwMajorVersion == 6) {
        if (osvi.dwMinorVersion >= 2) {
          isWin80OrGreater = true;
        }
      }
    }
  }
};
static const OSVersionInfo gOSVersionInfo;

// Helper function to set the SeDebugPrivilege for the current process,
// which allows us to query handles from processes we don't own.
// We attempt to set this privilege at the start of enumeration,
// and if it fails we log the error but continue on with enumeration
// since we may still be able to query handles from some processes
//
DWORD
SetDebugTokenPrivilege() {
  DWORD dwStatus = ERROR_SUCCESS;
  HANDLE hToken = NULL;
  TOKEN_PRIVILEGES tp = {0};
  LUID val = {0};

  // This ensures the token handle is always closed when we exit this function, even in error cases
  struct HandleTokenCloser {
    HANDLE& handle;
    HandleTokenCloser(HANDLE& handle) : handle(handle) {}
    ~HandleTokenCloser() {
      if (handle != NULL && handle != INVALID_HANDLE_VALUE) {
        CloseHandle(handle);
      }
    };
  } handleTokenCloser{hToken};

  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
    return GetLastError();
  }

  if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &val)) {
    return GetLastError();
  }

  tp.PrivilegeCount = 1;
  tp.Privileges[0].Luid = val;
  tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

  if (!AdjustTokenPrivileges(hToken, FALSE, &tp, NULL, NULL, NULL)) {
    return GetLastError();
  }

  // AdjustTokenPrivileges can succeed but set LastError to
  // ERROR_NOT_ALL_ASSIGNED if our token doesn't have this privilege.
  if (ERROR_NOT_ALL_ASSIGNED == GetLastError()) {
    return ERROR_NOT_ALL_ASSIGNED;
  }

  return dwStatus;
}

// The thread executing this function may be terminated (likely) while hung in
DWORD
WINAPI
QueryObjectNameThreadFunc(LPVOID lpParam) {
  DWORD ntStatus = ERROR_SUCCESS;
  ULONG retLen = 0;
  PQUERY_OBJECT_NAME_PARAMS params = (PQUERY_OBJECT_NAME_PARAMS)lpParam;

  if (nullptr == params) {
    ntStatus = ERROR_INVALID_PARAMETER;
    goto Cleanup;
  }

  params->ntStatus =
      NtQueryObject(params->hObject, ObjectNameInformation, &params->nameBuffer, sizeof(params->nameBuffer), &retLen);

Cleanup:
  return ntStatus;
}

NTSTATUS
GetObjectTypeEnumeration(HandleRecordCache& cache) {
  NTSTATUS ntStatus = STATUS_SUCCESS;
  POBJECT_ALL_TYPES_INFORMATION pTypes = nullptr;
  ULONG retLen = 0;
  std::vector<uint8_t> localBuffer(INITIAL_ENUMERATION_BUFFER_SIZE);

  if (!gOSVersionInfo.isWin80OrGreater) {
    LOG(ERROR) << "Object type enumeration is only supported on Windows 8.0+";
    return STATUS_NOT_SUPPORTED;
  }

  ntStatus = NtQueryObject(
      nullptr, ObjectAllTypesInformation, localBuffer.data(), static_cast<ULONG>(localBuffer.size()), &retLen);

  if (STATUS_INFO_LENGTH_MISMATCH == ntStatus) {
    // We assume that even if an active system is creating/destroying object
    // types, it will not change so fast that the required buffer size doubles
    // between our calls. It's atypical for it to dynamically change at all
    // on most systems.
    size_t newSize = retLen * 2;
    if ((newSize > MAXIMUM_ENUMERATION_BUFFER_SIZE) || (newSize > ULONG_MAX)) {
      return STATUS_BUFFER_TOO_SMALL;
    }
    localBuffer.resize(newSize);
    ntStatus =
        NtQueryObject(nullptr, ObjectAllTypesInformation, localBuffer.data(), static_cast<ULONG>(newSize), &retLen);
  }

  if (!NT_SUCCESS(ntStatus)) {
    LOG(ERROR) << "Failed to query object all types information: 0x" << std::hex << ntStatus << std::dec;
    return ntStatus;
  }

  pTypes = reinterpret_cast<POBJECT_ALL_TYPES_INFORMATION>(localBuffer.data());
  if (pTypes->NumberOfTypes > USHRT_MAX) {
    LOG(ERROR) << "Too many object types (" << pTypes->NumberOfTypes
               << ") exceeds a uint16_t which is used for handle type indices";
    return STATUS_INTEGER_OVERFLOW;
  }

  // Initialize the iter
  POBJECT_TYPE_INFORMATION typeIter = &pTypes->Types[0];
  for (ULONG i = 0; i < pTypes->NumberOfTypes; i++) {
    cache.GetHandleTypeMap()[typeIter->TypeIndex] =
        std::wstring(typeIter->TypeName.Buffer, typeIter->TypeName.Length / sizeof(WCHAR));

    // advance our iterator, accounting for the trailing serialized string
    // buffer and alignment
    typeIter = (POBJECT_TYPE_INFORMATION)((PBYTE)typeIter + AlignUpPtr(sizeof(OBJECT_TYPE_INFORMATION) +
                                                                       typeIter->TypeName.MaximumLength));
  }

  return STATUS_SUCCESS;
}

// Get handle enumeration and a minimal type mapping. The mapping is constructed
// by calling ObjectAllTypesInformation before and after the handle enumeration
// and verifying the two snapshots match (number and names). If they match we
// construct a minimal map (index -> name) and return it in ppTypeMap.
// Caller must free both *ppHandleInfo and the type map and its internal name
// buffers.
DWORD
GetHandleAndTypeEnumeration(HandleEnumeration& handleEnum) {
  NTSTATUS ntStatus = STATUS_SUCCESS;
  PSYSTEM_HANDLE_INFORMATION_EX pHandleInfo = nullptr;
  ULONG retLen = 0;

  std::vector<uint8_t> localBuffer(INITIAL_ENUMERATION_BUFFER_SIZE);

  // 1. Acquire the type enumeration if supported.
  ntStatus = GetObjectTypeEnumeration(handleEnum.Cache());
  if (STATUS_SUCCESS != ntStatus && STATUS_NOT_SUPPORTED != ntStatus) {
    LOG(ERROR) << "Failed to query object type enumeration: 0x" << std::hex << ntStatus << std::dec;
    return ntStatus;
  }

  // 2. Query handles
  ntStatus =
      NtQuerySystemInformation(SystemExtendedHandleInformation, localBuffer.data(), (ULONG)localBuffer.size(), &retLen);

  if (STATUS_INFO_LENGTH_MISMATCH == ntStatus) {
    // We assume that the quantity of handles won't more than double between our
    // calls, on typical system we'll be expecting on the order of 10s of thousands
    // of handles
    size_t newSize = retLen * 2;
    if ((newSize > MAXIMUM_ENUMERATION_BUFFER_SIZE) || (newSize > ULONG_MAX)) {
      return STATUS_BUFFER_TOO_SMALL;
    }
    localBuffer.resize(newSize);
    ntStatus = NtQuerySystemInformation(SystemExtendedHandleInformation, localBuffer.data(), (ULONG)newSize, &retLen);
  }

  if (STATUS_SUCCESS != ntStatus) {
    LOG(ERROR) << "Failed to query system handle information: 0x" << std::hex << ntStatus << std::dec;
    return ntStatus;
  }

  // 3. Filter and process the basic enumeration into our record structure
  pHandleInfo = reinterpret_cast<PSYSTEM_HANDLE_INFORMATION_EX>(localBuffer.data());
  for (ULONG i = 0; i < pHandleInfo->NumberOfHandles; i++) {
    PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX entry = &pHandleInfo->Handles[i];

    if (!entry) {
      LOG(ERROR) << "Null entry found in handle enumeration at index " << i;
      continue;
    }

    if (handleEnum.IsPidFiltered((int)entry->UniqueProcessId)) {
      continue;
    }
    auto handleRecord = std::make_unique<HandleRecord>(entry, handleEnum.Cache());
    handleEnum.handleRecords.emplace_back(std::move(handleRecord));
  }

  return STATUS_SUCCESS;
}

DWORD
EnumerateAllHandles(const std::set<int>& pidlist, HandleEnumeration& handleEnumeration) {
  NTSTATUS ntStatus = STATUS_SUCCESS;
  UNICODE_STRING fileTypeName = {0};
  std::set<ULONG_PTR> accessDeniedPIDs;

  // cache process handles, so we don't call openprocess for every handle
  struct HandleCloser {
    using pointer = HANDLE;
    void operator()(HANDLE h) const {
      if (h != NULL && h != INVALID_HANDLE_VALUE) {
        CloseHandle(h);
      }
    }
  };
  using SmartHandle = std::unique_ptr<HANDLE, HandleCloser>;
  std::unordered_map<ULONG_PTR, SmartHandle> processHandleCache;

  // 1.  Acquire the enumerations.
  ntStatus = GetHandleAndTypeEnumeration(handleEnumeration);

  if (STATUS_SUCCESS != ntStatus) {
    DWORD dwStatus = RtlNtStatusToDosError(ntStatus);
    LOG(ERROR) << "Failed to query system handle information / type mapping: 0x" << std::hex << dwStatus << std::dec;
    return dwStatus;
  }

  RtlInitUnicodeString(&fileTypeName, L"File");

  // Allocate these outside of the loop to avoid unnecessary stack allocation on each iteration
  OBJECT_TYPE_INFORMATION_WITH_STORAGE objTypeInfo = {0};
  QUERY_OBJECT_NAME_PARAMS params = {0};
  OBJECT_BASIC_INFORMATION objBasicInfo = {0};

  // 2. Enrich Handle records
  for (auto& handleIter : handleEnumeration.handleRecords) {
    HANDLE duplicatedObjectHandle = INVALID_HANDLE_VALUE;
    HANDLE processHandle = INVALID_HANDLE_VALUE;

    // 2a. Open the source process
    auto accessDeniedIt = accessDeniedPIDs.find(handleIter->Pid());
    if (accessDeniedIt != accessDeniedPIDs.end()) {
      handleIter->SetError(ErrorStage::ProcessOpening, ERROR_ACCESS_DENIED);
      continue;
    }

    auto cachedHandleIt = processHandleCache.find(handleIter->Pid());
    if (cachedHandleIt != processHandleCache.end()) {
      processHandle = cachedHandleIt->second.get();
    } else {
      processHandle = OpenProcess(PROCESS_DUP_HANDLE, FALSE, (DWORD)handleIter->Pid());
      // cache the handle (including failures) to avoid repeated attempts on the same PID which can happen with many
      // handles from the same process
      processHandleCache.try_emplace(handleIter->Pid(), processHandle);
    }

    if (NULL == processHandle || INVALID_HANDLE_VALUE == processHandle) {
      DWORD lastError = GetLastError();
      handleIter->SetError(ErrorStage::ProcessOpening, lastError);
      if (lastError == ERROR_ACCESS_DENIED) {
        accessDeniedPIDs.insert(handleIter->Pid());
      }
      continue;
    }

    // 2b. Duplicate the handle into our process to query it
    ntStatus = NtDuplicateObject(
        processHandle, (HANDLE)handleIter->Handle(), GetCurrentProcess(), &duplicatedObjectHandle, GENERIC_READ, 0, 0);

    // 2c. if the request for GENERIC_READ failed, try again with no access
    // requested
    if (STATUS_ACCESS_DENIED == ntStatus) {
      ntStatus = NtDuplicateObject(
          processHandle, (HANDLE)handleIter->Handle(), GetCurrentProcess(), &duplicatedObjectHandle, 0, 0, 0);
    }

    // 2d. Query ObjectBasicInformation to get the raw PointerCount and handle
    // potential handle reuse between our enumeration and duplication.
    if (STATUS_SUCCESS == ntStatus) {
      ULONG retLen = 0;
      ZeroMemory(&objBasicInfo, sizeof(objBasicInfo));
      ntStatus =
          NtQueryObject(duplicatedObjectHandle, ObjectBasicInformation, &objBasicInfo, sizeof(objBasicInfo), &retLen);
      if (STATUS_SUCCESS != ntStatus) {
        handleIter->SetError(ErrorStage::ObjectBasicInfoQuerying, RtlNtStatusToDosError(ntStatus));
      } else {
        // The pointer count is new information we wanted.
        handleIter->SetRawPointerCount(objBasicInfo.PointerCount);

        // Other information came in the initial enumeration, but we have to
        // allow for the possibility that the handle value got reused between
        // that enumeration and now, so if we're able to get to the
        // ObjectBasicInformation query on the duplicated handle, we should
        // replace it.
        handleIter->SetGrantedAccess(objBasicInfo.GrantedAccess);
        handleIter->SetHandleAttributes(objBasicInfo.Attributes);
        handleIter->SetHandleCount(objBasicInfo.HandleCount);

        // We query the ObjectTypeInformation to accommodate the potential
        // handle reuse case, but also on pre-Win8 systems we would not have had
        // access to type information in the initial enumeration.
        ZeroMemory(&objTypeInfo, sizeof(objTypeInfo));
        ntStatus =
            NtQueryObject(duplicatedObjectHandle, ObjectTypeInformation, &objTypeInfo, sizeof(objTypeInfo), &retLen);

        if (!NT_SUCCESS(ntStatus)) {
          // If unsuccessful, log the error and move on, we will
          // have a chance to recover at row generation by checking the type index mapping
          // against the cache
          handleIter->SetError(ErrorStage::ObjectTypeInfoQuerying, RtlNtStatusToDosError(ntStatus));
        } else {
          bool bThreadWaitSatisfied = false;
          handleIter->SetObjectTypeName(&objTypeInfo.TypeInfo.TypeName);

          // Prepare params for querying the name
          // STATUS_UNSUCCESSFUL allows us to detect failure in the thread if it
          // doesn't get to the point of setting it.
          ZeroMemory(&params, sizeof(params));
          params.hObject = duplicatedObjectHandle;
          params.ntStatus = STATUS_UNSUCCESSFUL;

          // For File object types the NtQueryObject call could block
          // indefinitely (sync consoles, pipes, etc.) As such we make the call
          // in a thread and potentially time it out.
          if (0 == RtlCompareUnicodeString(&objTypeInfo.TypeInfo.TypeName, &fileTypeName, FALSE)) {
            HANDLE hThread = NULL;

            hThread = CreateThread(NULL, 0, QueryObjectNameThreadFunc, &params, 0, NULL);
            if (NULL == hThread) {
              handleIter->SetError(ErrorStage::ObjectNameQuerying, GetLastError());
            } else {
              switch (WaitForSingleObject(hThread, 500)) {
              case WAIT_OBJECT_0:
                // Thread completed, we check results below
                bThreadWaitSatisfied = true;
                break;
              case WAIT_TIMEOUT:
                handleIter->SetError(ErrorStage::ObjectNameQuerying, ERROR_TIMEOUT, true);
                LOG(ERROR) << "Querying object timed out for PID: " << handleIter->Pid() << " | Handle : 0x" << std::hex
                           << handleIter->Handle() << std::dec;
                break;
              default:
                DWORD lastError = GetLastError();
                handleIter->SetError(ErrorStage::ObjectNameQuerying, lastError, true);
                LOG(ERROR) << "Error waiting for thread for PID: " << handleIter->Pid() << " | Handle : 0x" << std::hex
                           << handleIter->Handle() << std::dec << " | Error: " << lastError;
                break;
              }

              if (!bThreadWaitSatisfied) {
                // Cancel the thread and guarantee it's terminated
                TerminateThread(hThread, ERROR_CANCELLED);
                WaitForSingleObject(hThread, INFINITE);
              }

              CloseHandle(hThread);
            }
          }
          // Not a File object, this query can't block and we don't need a
          // thread
          else {
            params.ntStatus = NtQueryObject(
                params.hObject, ObjectNameInformation, &params.nameBuffer, sizeof(params.nameBuffer), &retLen);
          }

          // Whether we called in the thread or called directly, store the error
          // if necessary
          if (STATUS_SUCCESS != params.ntStatus) {
            handleIter->SetError(ErrorStage::ObjectNameQuerying, RtlNtStatusToDosError(params.ntStatus));
          }

          // Store the name as appropriate
          switch (params.ntStatus) {
          case STATUS_SUCCESS:
            if (params.nameBuffer.usName.Length > 0) {
              handleIter->SetObjectName(&params.nameBuffer.usName);
            } else {
              handleIter->SetObjectName(L"None");
            }
            break;
          case STATUS_UNSUCCESSFUL:
            handleIter->SetObjectName(L"<query would block, synch file handle>");
            break;
          default:
            handleIter->SetObjectName(L"<failed resolving>");
            break;
          }
        }
      }
      if (INVALID_HANDLE_VALUE != duplicatedObjectHandle && NULL != duplicatedObjectHandle) {
        CloseHandle(duplicatedObjectHandle);
      }
    } else {
      handleIter->SetError(ErrorStage::HandleDuplication, RtlNtStatusToDosError(ntStatus));
      // STATUS_NOT_SUPPORTED is too common, it slows down execution to print it
      if (STATUS_NOT_SUPPORTED != ntStatus) {
        LOG(ERROR) << "Error (0x" << std::hex << ntStatus << std::dec
                   << ") duplicating handle for PID: " << handleIter->Pid() << " | Handle: 0x" << std::hex
                   << handleIter->Handle() << std::dec;
      }
    }
  }

  return ERROR_SUCCESS;
}

} // namespace handles

QueryData genHandles(QueryContext& context) {
  QueryData results;
  std::set<int> pidlist;

  if (context.constraints.count("pid") > 0 && context.constraints.at("pid").exists(EQUALS)) {
    for (const auto& pid : context.constraints.at("pid").getAll<int>(EQUALS)) {
      pidlist.insert(pid);
    }
  }

  if (pidlist.empty()) {
    LOG(INFO) << "No process ID constraint found, using current process ID: " << GetCurrentProcessId();
    pidlist.insert(GetCurrentProcessId());
  }

  handles::HandleEnumeration handleEnumeration(pidlist);
  if (ERROR_SUCCESS != handles::SetDebugTokenPrivilege()) {
    LOG(ERROR) << "Failed to set debug token privilege.";
    return results;
  }

  if (ERROR_SUCCESS != handles::EnumerateAllHandles(pidlist, handleEnumeration)) {
    LOG(ERROR) << "Failed to enumerate all handles.";
    return results;
  }

  results = handleEnumeration.ToRows();

  return results;
}
} // namespace tables
} // namespace osquery