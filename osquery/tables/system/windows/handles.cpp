/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <iomanip>
#include <iostream>
#include <map>
#include <osquery/core/tables.h>
#include <osquery/core/windows/ntapi.h>
#include <osquery/logger/logger.h>
#include <osquery/sql/dynamic_table_row.h>
#include <osquery/sql/sql.h>
#include <osquery/utils/conversions/windows/strings.h>
#include <set>
#include <sstream>
#include <stdio.h>
#include <string>
#include <unordered_map>
#include <vector>
#include <windows.h>

#pragma comment(lib, "ntdll.lib")

namespace osquery {
namespace tables {

namespace handles {

extern "C" NTSTATUS NTAPI NtDuplicateObject(HANDLE SourceProcessHandle,
                                            HANDLE SourceHandle,
                                            HANDLE TargetProcessHandle,
                                            PHANDLE TargetHandle,
                                            ACCESS_MASK DesiredAccess,
                                            ULONG HandleAttributes,
                                            ULONG Options);

extern "C" NTSTATUS NTAPI RtlCompareUnicodeString(PCUNICODE_STRING String1,
                                                  PCUNICODE_STRING String2,
                                                  BOOLEAN CaseInSensitive);

extern "C" NTSTATUS NTAPI
RtlGetVersion(PRTL_OSVERSIONINFOW lpVersionInformation);

// Specific definitions not in winternl.h
constexpr auto SystemExtendedHandleInformation =
    static_cast<SYSTEM_INFORMATION_CLASS>(64);
constexpr auto ObjectNameInformation = static_cast<OBJECT_INFORMATION_CLASS>(1);
constexpr auto ObjectTypeInformation = static_cast<OBJECT_INFORMATION_CLASS>(2);
constexpr auto ObjectAllTypesInformation =
    static_cast<OBJECT_INFORMATION_CLASS>(3);
// constexpr auto STATUS_SUCCESS = 0x00000000;
constexpr auto STATUS_UNSUCCESSFUL = 0xC0000001;
constexpr auto STATUS_INFO_LENGTH_MISMATCH = 0xC0000004;
constexpr auto STATUS_ACCESS_DENIED = 0xC0000022;
constexpr auto STATUS_BUFFER_TOO_SMALL = 0xC0000023;
constexpr auto STATUS_NOT_SUPPORTED = 0xC00000BB;
constexpr auto STATUS_RETRY = 0xC000022D;
constexpr auto INITAL_ENUMERATION_BUFFER_SIZE = 1024 * 1024 * 4; // 4 MBs
constexpr auto MAXIMUM_ENUMERATION_BUFFER_SIZE = 1024 * 1024 * 1024; // 1GB

constexpr size_t AlignUp(size_t value, size_t align) {
  return (value + (align - 1)) & ~(align - 1);
}

constexpr size_t AlignUpPtr(size_t value) {
  return AlignUp(value, sizeof(void*));
}

// Constants for the Windows 8.1+ reference counting logic
#ifdef _WIN64
constexpr ULONG OBJECT_REF_BIAS = 0x7FFF;
#else
constexpr ULONG OBJECT_REF_BIAS = 0x1F;
#endif

enum class ErrorStage {
  None = 0,
  ProcessOpening = 1,
  HandleDuplication = 2,
  ObjectBasicInfoQuerying = 3,
  ObjectTypeInfoQuerying = 4,
  ObjectNameQuerying = 5
};

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

constexpr MappedValue Directory[] = {
    {FILE_READ_DATA, "LIST_DIRECTORY"},
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

constexpr MappedValue Attributes[] = {{0x00000002L, "Inherit"},
                                      {0x00000010L, "Permanent"},
                                      {0x00000020L, "Exclusive"},
                                      {0x00000040L, "CaseInsensitive"},
                                      {0x00000080L, "OpenIf"},
                                      {0x00000100L, "OpenLink"},
                                      {0x00000200L, "KernelHandle"},
                                      {0x00000400L, "ForceAccessCheck"}};
} // namespace mappings

struct KeyHash {
  size_t operator()(const std::pair<ULONG, std::string>& key) const {
    return std::hash<ULONG>()(key.first) ^ std::hash<std::string>()(key.second);
  }
};
using GrantedAccessCache =
    std::unordered_map<std::pair<ULONG, std::string>, std::string, KeyHash>;
using HandleAttributesCache = std::unordered_map<ULONG, std::string>;
using ObjectTypeNameCache = std::unordered_map<std::wstring, std::string>;

class HandleRecordCache {
 private:
  ObjectTypeNameCache m_objectTypeNameCache;
  GrantedAccessCache m_grantedAccessCache;
  HandleAttributesCache m_handleAttributesCache;

 public:
  HandleRecordCache() {
    m_grantedAccessCache = GrantedAccessCache();
    m_handleAttributesCache = HandleAttributesCache();
    m_objectTypeNameCache = ObjectTypeNameCache();
  }

  // This is returning a pointer, because we have to store this value
  // during enumeration and we want to avoid unnecessary copying of strings
  // in the case of large amounts of handles.  The cache will ensure that we
  // only have one copy of each unique object type name.
  const std::string* GetObjectTypeName(PUNICODE_STRING us) {
    if (!us || !us->Buffer || us->Length == 0) {
      return nullptr;
    }

    std::wstring lookup(us->Buffer, us->Length / sizeof(WCHAR));
    auto it = m_objectTypeNameCache.find(lookup);

    if (it != m_objectTypeNameCache.end()) {
      // Found!
      return &(it->second);
    }

    // Not found. Insert the lookup string.
    auto [insertIt, _] = m_objectTypeNameCache.try_emplace(
        std::move(lookup), wstringToString(lookup.c_str()));
    return &(insertIt->second);
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
    auto [insertIt, _] = m_objectTypeNameCache.try_emplace(
        lookup, wstringToString(lookup.c_str()));
    return &(insertIt->second);
  }

  // This function is responsible for converting a granted access mask into a
  // human readable string. This is called at row creation time
  std::string GetGrantedAccessString(ULONG grantedAccess,
                                     const std::string& type) {
    auto it = m_grantedAccessCache.find({grantedAccess, type});
    if (it != m_grantedAccessCache.end()) {
      return it->second;
    } else {
      std::vector<std::string_view> rights;
      auto check_mask = [&](const mappings::MappedValue& mapping) {
        if (grantedAccess & mapping.mask)
          rights.push_back(mapping.name);
      };

      // 1. Handle Generic Rights
      for (const auto& mapping : mappings::Generic) {
        check_mask(mapping);
      }

      // 2. Handle Standard Rights (Common to most objects)
      for (const auto& mapping : mappings::Standard) {
        check_mask(mapping);
      }

      // 3. Handle Type-Specific Rights
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

      std::ostringstream oss;
      for (size_t i = 0; i < rights.size(); i++) {
        oss << rights[i] << (i == rights.size() - 1 ? "" : "|");
      }

      auto [it, _] = m_grantedAccessCache.try_emplace({grantedAccess, type},
                                                      std::move(oss.str()));
      return it->second;
    }
  }

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
      for (const auto& mapping : mappings::Key) {
        check_mask(mapping);
      }

      std::ostringstream oss;
      for (size_t i = 0; i < attributes.size(); i++) {
        oss << attributes[i] << (i == attributes.size() - 1 ? "" : ",");
      }

      auto [it, _] = this->m_handleAttributesCache.try_emplace(
          handleAttributes, std::move(oss.str()));
      return it->second;
    }
  }
};

class HandleRecord {
 private:
  ErrorStage m_errorStage = ErrorStage::None;
  DWORD m_errorStatus = 0;
  const std::string* m_ObjectTypeName = nullptr;
  ULONG m_GrantedAccess = 0;
  ULONG m_HandleAttributes = 0;
  ULONG m_RawPointerCount = 0;
  ULONG m_HandleCount = 0;
  const std::string* m_ObjectName = nullptr;

 public:
  ULONG_PTR ProcessId = 0;
  ULONG_PTR HandleValue = 0;
  USHORT ObjectTypeIndex = 0;

  void SetObjectName(const std::string* objectName) {
    this->m_ObjectName = objectName;
  }

  void SetObjectTypeName(const std::string* objectTypeName) {
    this->m_ObjectTypeName = objectTypeName;
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

  std::string Type() const {
    return this->m_ObjectTypeName ? *this->m_ObjectTypeName : "Unknown";
  }

  std::string Access(HandleRecordCache& cache) const {
    return cache.GetGrantedAccessString(this->m_GrantedAccess, this->Type());
  }

  std::string Attributes(HandleRecordCache& cache) const {
    return cache.GetHandleAttributesString(this->m_HandleAttributes);
  }

  std::string Name() const {
    return this->m_ObjectName ? *this->m_ObjectName : "Unknown";
  }

  HandleRecord(PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX entry) {
    if (!entry) {
      throw std::invalid_argument(
          "HandleRecord constructor: Invalid Handle Record entry");
    }
    this->ProcessId = entry->UniqueProcessId;
    this->HandleValue = entry->HandleValue;
    this->m_GrantedAccess = entry->GrantedAccess;
    this->ObjectTypeIndex = entry->ObjectTypeIndex;
    this->m_HandleAttributes = entry->HandleAttributes;
  }

  void SetError(ErrorStage errorStage, DWORD errorStatus) {
    this->m_errorStage = errorStage;
    this->m_errorStatus = errorStatus;
  }

  ErrorStage GetErrorStage() const {
    return this->m_errorStage;
  }

  DWORD GetErrorStatus() const {
    return this->m_errorStatus;
  }

  Row ToRow(HandleRecordCache& cache) const;
};
using HandleRecordPtr = std::unique_ptr<HandleRecord>;
using HandleTypeMap = std::unordered_map<USHORT, std::wstring>;

class HandleEnumeration {
 public:
  HandleRecordCache m_cache;
  HandleTypeMap handleTypeMap;
  std::set<int> m_pidlist;
  std::vector<HandleRecordPtr> handleRecords;

  HandleEnumeration(const std::set<int>& pidlist) : m_pidlist(pidlist) {}

  bool IsPidFiltered(int pid) const {
    return !m_pidlist.empty() && m_pidlist.find(pid) == m_pidlist.end();
  }

  HandleRecordCache& Cache() {
    return m_cache;
  }

  QueryData ToRows() {
    QueryData rows;
    for (const auto& handle : this->handleRecords) {
      rows.push_back(handle->ToRow(this->m_cache));
    }
    return rows;
  }
};

bool isWin80OrGreater() {
  static int major = 0;
  static int minor = 0;
  static bool initialized = false;

  if (!initialized) {
    auto os_version = SQL::selectAllFrom("os_version");
    if (os_version.size() != 1) {
      LOG(ERROR) << "Could not determine OS version";
      return false;
    }
    major = std::stoi(os_version.front().at("major"));
    minor = std::stoi(os_version.front().at("minor"));
    LOG(INFO) << "Detected Windows version: " << major << "." << minor;
    initialized = true;
  }
  return (major > 6) || (major == 6 && minor >= 2);
}

DWORD
SetDebugTokenPrivilege() {
  DWORD dwStatus = ERROR_SUCCESS;
  HANDLE hToken = NULL;
  TOKEN_PRIVILEGES tp = {0};
  LUID val = {0};

  if (!OpenProcessToken(GetCurrentProcess(),
                        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                        &hToken)) {
    dwStatus = GetLastError();
    fprintf(
        stderr, "Failed to obtain process token handle. Error: %d\n", dwStatus);
    goto Cleanup;
  }

  if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &val)) {
    dwStatus = GetLastError();
    fprintf(stderr, "LookupPrivilegeValue failed. Error: %d\n", dwStatus);
    goto Cleanup;
  }

  tp.PrivilegeCount = 1;
  tp.Privileges[0].Luid = val;
  tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

  if (!AdjustTokenPrivileges(hToken, FALSE, &tp, NULL, NULL, NULL)) {
    dwStatus = GetLastError();
    fprintf(stderr, "AdjustTokenPrivileges failed. Error: %d\n", dwStatus);
    goto Cleanup;
  }

  // AdjustTokenPrivileges can succeed but set LastError to
  // ERROR_NOT_ALL_ASSIGNED if our token doesn't have this privilege.
  if (ERROR_NOT_ALL_ASSIGNED == GetLastError()) {
    dwStatus = ERROR_NOT_ALL_ASSIGNED;
    fprintf(stderr,
            "The token does not have the specified privilege. Error: %d\n",
            dwStatus);
    goto Cleanup;
  }

Cleanup:

  if (NULL != hToken) {
    CloseHandle(hToken);
  }

  return dwStatus;
}

DWORD
WINAPI
QueryObjectNameThreadFunc(LPVOID lpParam) {
  DWORD ntStatus = ERROR_SUCCESS;
  ULONG retLen = 0;
  QueryObjectNameParams* params = (QueryObjectNameParams*)lpParam;

  if (nullptr == params) {
    ntStatus = ERROR_INVALID_PARAMETER;
    goto Cleanup;
  }

  params->ntStatus = NtQueryObject(params->hObject,
                                   ObjectNameInformation,
                                   &params->nameBuffer,
                                   sizeof(params->nameBuffer),
                                   &retLen);

Cleanup:
  return ntStatus;
}

NTSTATUS
GetObjectTypeEnumeration(HandleTypeMap& handleTypeMap) {
  NTSTATUS ntStatus = STATUS_SUCCESS;
  POBJECT_ALL_TYPES_INFORMATION pTypes = nullptr;
  ULONG retLen = 0;
  std::vector<uint8_t> localBuffer(INITAL_ENUMERATION_BUFFER_SIZE);

  if (!isWin80OrGreater()) {
    LOG(ERROR) << "Object type enumeration is only supported on Windows 8.0+";
    return STATUS_NOT_SUPPORTED;
  }

  ntStatus = NtQueryObject(nullptr,
                           ObjectAllTypesInformation,
                           localBuffer.data(),
                           static_cast<ULONG>(localBuffer.size()),
                           &retLen);

  if (STATUS_INFO_LENGTH_MISMATCH == ntStatus) {
    // We assume that even if an active system is creating/destroying object
    // types, it will not change so fast that the required buffer size doubles
    // between our calls.
    size_t newSize = retLen * 2;
    if ((newSize > MAXIMUM_ENUMERATION_BUFFER_SIZE) || (newSize > ULONG_MAX)) {
      return STATUS_BUFFER_TOO_SMALL;
    }
    localBuffer.resize(newSize);
    std::fill(localBuffer.begin(), localBuffer.end(), 0);
    ntStatus = NtQueryObject(nullptr,
                             ObjectAllTypesInformation,
                             localBuffer.data(),
                             static_cast<ULONG>(newSize),
                             &retLen);
  }

  if (STATUS_SUCCESS != ntStatus) {
    LOG(ERROR) << "Failed to query object all types information: 0x" << std::hex
               << ntStatus << std::dec << std::endl;
    return ntStatus;
  }

  pTypes = reinterpret_cast<POBJECT_ALL_TYPES_INFORMATION>(localBuffer.data());
  if (pTypes->NumberOfTypes > USHRT_MAX) {
    LOG(ERROR) << "Too many object types (" << pTypes->NumberOfTypes
               << ") exceeds a uint16_t which is used for handle type indices"
               << std::endl;
    return STATUS_INTEGER_OVERFLOW;
  }

  // Initialize the iter
  POBJECT_TYPE_INFORMATION typeIter = &pTypes->Types[0];
  for (ULONG i = 0; i < pTypes->NumberOfTypes; i++) {
    handleTypeMap[typeIter->TypeIndex] = std::wstring(
        typeIter->TypeName.Buffer, typeIter->TypeName.Length / sizeof(WCHAR));

    // advance our iterator, accounting for the trailing serialized string
    // buffer and alignment
    typeIter =
        (POBJECT_TYPE_INFORMATION)((PBYTE)typeIter +
                                   AlignUpPtr(
                                       sizeof(OBJECT_TYPE_INFORMATION) +
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

  std::vector<uint8_t> localBuffer(INITAL_ENUMERATION_BUFFER_SIZE);

  ntStatus = GetObjectTypeEnumeration(handleEnum.handleTypeMap);
  if (STATUS_SUCCESS != ntStatus && STATUS_NOT_SUPPORTED != ntStatus) {
    throw std::runtime_error("Failed to query object type enumeration");
  }

  // 2. Query handles
  ntStatus = NtQuerySystemInformation(SystemExtendedHandleInformation,
                                      localBuffer.data(),
                                      (ULONG)localBuffer.size(),
                                      &retLen);

  if (STATUS_INFO_LENGTH_MISMATCH == ntStatus) {
    // We assume that the quantity of handles won't more than double between our
    // calls,
    size_t newSize = retLen * 2;
    if ((newSize > MAXIMUM_ENUMERATION_BUFFER_SIZE) || (newSize > ULONG_MAX)) {
      return STATUS_BUFFER_TOO_SMALL;
    }
    localBuffer.resize(newSize);
    std::fill(localBuffer.begin(), localBuffer.end(), 0);
    ntStatus = NtQuerySystemInformation(SystemExtendedHandleInformation,
                                        localBuffer.data(),
                                        (ULONG)newSize,
                                        &retLen);
  }

  if (STATUS_SUCCESS != ntStatus) {
    LOG(ERROR) << "Failed to query system handle information: 0x" << std::hex
               << ntStatus << std::dec << std::endl;
    throw std::runtime_error("Failed to query system handle information");
  }

  // 5. Process the basic enumeration into our record structure
  pHandleInfo =
      reinterpret_cast<PSYSTEM_HANDLE_INFORMATION_EX>(localBuffer.data());
  for (ULONG i = 0; i < pHandleInfo->NumberOfHandles; i++) {
    PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX entry = &pHandleInfo->Handles[i];
    if (handleEnum.IsPidFiltered((int)entry->UniqueProcessId)) {
      continue;
    }
    try {
      handleEnum.handleRecords.push_back(std::make_unique<HandleRecord>(entry));
    } catch (const std::invalid_argument& e) {
      LOG(ERROR) << "Error creating HandleRecord: " << e.what();
      continue;
    } catch (const std::bad_alloc& e) {
      LOG(ERROR) << "Error allocating memory for HandleRecord: " << e.what();
      continue;
    }
  }

  return STATUS_SUCCESS;
}

DWORD
EnumerateAllHandles(const std::set<int>& pidlist,
                    HandleEnumeration& handleEnumeration) {
  NTSTATUS ntStatus = STATUS_SUCCESS;
  UNICODE_STRING fileTypeName = {0};
  std::set<ULONG_PTR> accessDeniedPIDs;
  // We'll retry up to 5 times on type registration activity.  Retries
  // are unlikely to ever be necessary.
  ULONG retryCount = 5;

  std::vector<std::wstring> handleTypeMapVector;

  auto closeHandle = [](HANDLE h) {
    if (h && h != INVALID_HANDLE_VALUE) {
      CloseHandle(h);
    }
  };

  for (size_t i = 0; i < retryCount; i++) {
    ntStatus = GetHandleAndTypeEnumeration(handleEnumeration);
    if (STATUS_RETRY == ntStatus) {
      LOG(ERROR) << "Retrying handle and type enumeration";
      continue;
    }
    break;
  }

  if (STATUS_SUCCESS != ntStatus) {
    LOG(ERROR) << "Failed to query system handle information / type mapping: 0x"
               << std::hex << ntStatus << std::dec;
    return ERROR_RETRY;
  }

  RtlInitUnicodeString(&fileTypeName, L"File");

  // 2. Enrich Handle records
  for (auto& handleIter : handleEnumeration.handleRecords) {
    HANDLE duplicatedObjectHandle = INVALID_HANDLE_VALUE;
    HANDLE processHandle = INVALID_HANDLE_VALUE;

    // 3a. Open the source process
    auto accessDeniedIt = accessDeniedPIDs.find(handleIter->ProcessId);
    if (accessDeniedIt != accessDeniedPIDs.end()) {
      handleIter->SetError(ErrorStage::ProcessOpening, ERROR_ACCESS_DENIED);
      continue;
    }

    processHandle =
        OpenProcess(PROCESS_DUP_HANDLE, FALSE, (DWORD)handleIter->ProcessId);

    if (NULL == processHandle || INVALID_HANDLE_VALUE == processHandle) {
      handleIter->SetError(ErrorStage::ProcessOpening, GetLastError());
      if (GetLastError() == ERROR_ACCESS_DENIED) {
        accessDeniedPIDs.insert(handleIter->ProcessId);
      } else {
        LOG(ERROR) << "Error opening process ("
                   << "(PID: " << GetLastError() << ", "
                   << "(ERROR: " << GetLastError() << ")";
      }
      continue;
    }

    // 2b. Duplicate the handle into our process to query it
    ntStatus = NtDuplicateObject(processHandle,
                                 (HANDLE)handleIter->HandleValue,
                                 GetCurrentProcess(),
                                 &duplicatedObjectHandle,
                                 GENERIC_READ,
                                 0,
                                 0);

    // if the request for GENERIC_READ failed, try again with no access
    // requested
    if (STATUS_ACCESS_DENIED == ntStatus) {
      ntStatus = NtDuplicateObject(processHandle,
                                   (HANDLE)handleIter->HandleValue,
                                   GetCurrentProcess(),
                                   &duplicatedObjectHandle,
                                   0,
                                   0,
                                   0);
    }

    if (STATUS_SUCCESS == ntStatus) {
      ULONG retLen = 0;
      OBJECT_BASIC_INFORMATION objBasicInfo = {0};

      ntStatus = NtQueryObject(duplicatedObjectHandle,
                               ObjectBasicInformation,
                               &objBasicInfo,
                               sizeof(objBasicInfo),
                               &retLen);
      if (STATUS_SUCCESS != ntStatus) {
        handleIter->SetError(ErrorStage::ObjectBasicInfoQuerying,
                             RtlNtStatusToDosError(ntStatus));
        LOG(ERROR) << "Error (" << std::hex << ntStatus
                   << ") querying object basic info for PID: "
                   << handleIter->ProcessId << " | Hand: 0x" << std::hex
                   << handleIter->HandleValue << std::dec;
      } else {
        OBJECT_TYPE_INFORMATION_WITH_STORAGE objTypeInfo = {0};

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

        ntStatus = NtQueryObject(duplicatedObjectHandle,
                                 ObjectTypeInformation,
                                 &objTypeInfo,
                                 sizeof(objTypeInfo),
                                 &retLen);
        if (STATUS_SUCCESS != ntStatus) {
          handleIter->SetError(ErrorStage::ObjectTypeInfoQuerying,
                               RtlNtStatusToDosError(ntStatus));
          LOG(ERROR) << "Error (" << std::hex << ntStatus << std::dec
                     << ") querying object type info for PID: "
                     << handleIter->ProcessId << " | Hand: 0x" << std::hex
                     << handleIter->HandleValue << std::dec;
        } else {
          QueryObjectNameParams params;
          bool bThreadWaitSatisfied = false;

          handleIter->SetObjectTypeName(
              handleEnumeration.Cache().GetObjectTypeName(
                  &objTypeInfo.TypeInfo.TypeName));

          // Prepare params for querying the name
          params.hObject = duplicatedObjectHandle;
          // STATUS_UNSUCCESSFUL allows us to detect failure in the thread if it
          // doesn't get to the point of setting it.
          params.ntStatus = STATUS_UNSUCCESSFUL;

          // For File object types the NtQueryObject call could block
          // indefinitely (sync consoles, pipes, etc.) As such we make the call
          // in a thread and potentially time it out.
          if (0 == RtlCompareUnicodeString(
                       &objTypeInfo.TypeInfo.TypeName, &fileTypeName, FALSE)) {
            HANDLE hThread = NULL;

            hThread = CreateThread(
                NULL, 0, QueryObjectNameThreadFunc, &params, 0, NULL);
            if (NULL == hThread) {
              handleIter->SetError(ErrorStage::ObjectNameQuerying,
                                   GetLastError());
            } else {
              switch (WaitForSingleObject(hThread, 500)) {
              case WAIT_OBJECT_0:
                // Thread completed, we check results below
                bThreadWaitSatisfied = true;
                break;
              case WAIT_TIMEOUT:
                handleIter->SetError(ErrorStage::ObjectNameQuerying,
                                     ERROR_TIMEOUT);
                LOG(ERROR) << "Querying object timed out for PID: "
                           << handleIter->ProcessId << " | Handle : 0x"
                           << std::hex << handleIter->HandleValue << std::dec;
                TerminateThread(hThread, ERROR_CANCELLED);
                break;
              default:
                handleIter->SetError(ErrorStage::ObjectNameQuerying,
                                     GetLastError());
                LOG(ERROR) << "Error waiting for thread for PID: "
                           << handleIter->ProcessId << " | Handle : 0x"
                           << std::hex << handleIter->HandleValue << std::dec
                           << " | Error: " << GetLastError();
                TerminateThread(hThread, ERROR_CANCELLED);
                break;
              }

              if (!bThreadWaitSatisfied) {
                // Cancel the thread and guarantee it's terminated
                TerminateThread(hThread, ERROR_CANCELLED);
                WaitForSingleObject(hThread, INFINITE);
              }

              closeHandle(hThread);
            }
          }
          // Not a File object, this query can't block and we don't need a
          // thread
          else {
            params.ntStatus = NtQueryObject(params.hObject,
                                            ObjectNameInformation,
                                            &params.nameBuffer,
                                            sizeof(params.nameBuffer),
                                            &retLen);
          }

          // Whether we called in the thread or called directly, store the error
          // if necessary
          if (STATUS_SUCCESS != params.ntStatus) {
            handleIter->SetError(ErrorStage::ObjectNameQuerying,
                                 RtlNtStatusToDosError(params.ntStatus));
          }

          // Store the name as appropriate
          switch (params.ntStatus) {
          case STATUS_SUCCESS:
            if (params.nameBuffer.usName.Length > 0) {
              handleIter->SetObjectName(
                  handleEnumeration.Cache().GetObjectTypeName(
                      &params.nameBuffer.usName));
            } else {
              handleIter->SetObjectName(
                  handleEnumeration.Cache().GetObjectTypeName(L"None"));
            }
            break;
          case STATUS_UNSUCCESSFUL:
            handleIter->SetObjectName(
                handleEnumeration.Cache().GetObjectTypeName(
                    L"<query would block, synch file handle>"));
            break;
          default:
            handleIter->SetObjectName(
                handleEnumeration.Cache().GetObjectTypeName(
                    L"<failed resolving>"));
            break;
          }
        }
      }
      closeHandle(duplicatedObjectHandle);
    } else {
      handleIter->SetError(ErrorStage::HandleDuplication,
                           RtlNtStatusToDosError(ntStatus));
      // STATUS_NOT_SUPPORTED is too common, it slows down execution to print it
      if (STATUS_NOT_SUPPORTED != ntStatus) {
        LOG(ERROR) << "Error (0x" << std::hex << ntStatus << std::dec
                   << ") duplicating handle for PID: " << handleIter->ProcessId
                   << " | Hand: 0x" << std::hex << handleIter->HandleValue
                   << std::dec;
      }
    }
    closeHandle(processHandle);
  }

  return ERROR_SUCCESS;
}

Row HandleRecord::ToRow(HandleRecordCache& cache) const {
  Row row;
  row["pid"] = INTEGER(this->ProcessId);
  row["type"] = this->Type();
  row["access"] = this->Access(cache);
  row["name"] = this->Name();
  row["attributes"] = this->Attributes(cache);
  return row;
}

} // namespace handles

QueryData genHandles(QueryContext& context) {
  QueryData results;
  std::set<int> pidlist;

  if (context.constraints.count("pid") > 0 &&
      context.constraints.at("pid").exists(EQUALS)) {
    for (const auto& pid : context.constraints.at("pid").getAll<int>(EQUALS)) {
      pidlist.insert(pid);
    }
  }

  if (pidlist.empty()) {
    LOG(INFO) << "No process ID constraint found, using current process ID: "
              << GetCurrentProcessId();
    pidlist.insert(GetCurrentProcessId());
  }

  try {
    handles::HandleEnumeration handleEnumeration(pidlist);
    (void)handles::SetDebugTokenPrivilege();
    handles::EnumerateAllHandles(pidlist, handleEnumeration);
    results = handleEnumeration.ToRows();
  } catch (const std::exception& e) {
    LOG(ERROR) << "Exception during handle enumeration: " << e.what();
    return results;
  }

  return results;
}

} // namespace tables
} // namespace osquery