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
#include <osquery/logger/logger.h>
#include <osquery/utils/conversions/windows/strings.h>
#include <set>
#include <sstream>
#include <stdio.h>
#include <string>
#include <vector>
#include <windows.h>
#include <winternl.h>

#pragma comment(lib, "ntdll.lib")

namespace osquery {
namespace tables {

namespace handles {

// Specific definitions not in winternl.h
constexpr auto SystemExtendedHandleInformation =
    static_cast<SYSTEM_INFORMATION_CLASS>(64);
constexpr auto ObjectNameInformation = static_cast<OBJECT_INFORMATION_CLASS>(1);
constexpr auto ObjectTypeInformation = static_cast<OBJECT_INFORMATION_CLASS>(2);
constexpr auto ObjectAllTypesInformation =
    static_cast<OBJECT_INFORMATION_CLASS>(3);
constexpr auto STATUS_SUCCESS = 0x00000000;
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

struct SystemHandleTableEntryInfoEx {
  PVOID Object = nullptr;
  ULONG_PTR UniqueProcessId = 0;
  ULONG_PTR HandleValue = 0;
  ULONG GrantedAccess = 0;
  USHORT CreatorBackTraceIndex = 0;
  USHORT ObjectTypeIndex = 0;
  ULONG HandleAttributes = 0;
  ULONG Reserved = 0;
};

struct SystemHandleInformationEx {
  ULONG_PTR NumberOfHandles = 0;
  ULONG_PTR Reserved = 0;
  SystemHandleTableEntryInfoEx Handles[1] = {0};
};

struct ObjectBasicInfo {
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
};

struct ObjectTypeInfo {
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
  UCHAR TypeIndex = 0; // Available in newer Windows versions
  CHAR ReservedByte = 0;
  ULONG PoolType = 0;
  ULONG DefaultPagedPoolCharge = 0;
  ULONG DefaultNonPagedPoolCharge = 0;
};

struct ObjectAllTypesInfo {
  ULONG NumberOfTypes = 0;
  ULONG Reserved = 0;
  ObjectTypeInfo Types[1] = {0};
};

// Minimal mapping entry to return to caller
struct HandleTypeMapEntry {
  USHORT Index = 0; // index in the types array (this is what
                    // handle.ObjectTypeIndex refers to)
  PWSTR Name = nullptr; // nul-terminated wide char buffer (allocated)
};

struct HandleTypeMap {
  ULONG Count = 0;
  HandleTypeMapEntry Entries[1] = {0};
};

// Avoid dynamic allocation for name buffer by using a buffer that
// can contain the largest possible UNICODE_STRING.
struct ObjectTypeInfoWithStorage {
  ObjectTypeInfo TypeInfo = {0};
  uint8_t Storage[USHRT_MAX];
};

// Avoid dynamic allocation for name buffer by using a buffer that
// can contain the largest possible UNICODE_STRING.
struct ObjectNameBufferWithStorage {
  UNICODE_STRING usName = {0};
  uint8_t Storage[USHRT_MAX];
};

struct QueryObjectNameParams {
  HANDLE hObject = INVALID_HANDLE_VALUE;
  ObjectNameBufferWithStorage nameBuffer = {0};
  NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
};

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

  HandleRecord(SystemHandleTableEntryInfoEx* entry) {
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

// We tie the lifespan of the handleRecords vector to the lifespan of
// a string pool by throwing them together here.  Could make this more
// robust by arbitrating acess to the vector.
struct Collector {
  HandleRecordCache cache;
  std::vector<HandleRecordPtr> handleRecords;
};

bool isWin81OrGreater() {
  static bool initialized = false;
  static bool isWin81OrGreater = false;
  if (!initialized) {
    RTL_OSVERSIONINFOW osvi = {sizeof(osvi)};
    if (RtlGetVersion(&osvi) == 0) {
      isWin81OrGreater = (osvi.dwMajorVersion > 6) ||
                         (osvi.dwMajorVersion == 6 && osvi.dwMinorVersion >= 3);
    }
  }
  return isWin81OrGreater;
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

ULONG
UnduplicatedPointerCount(ULONG ulDuplicatedPointerCount) {
  // Uses the new bias system
  if (isWin81OrGreater()) {
    // NtQueryObject will have referenced the handle, which decrements the BIAS
    // by 1. So our total impact in the result from the query is
    // (OBJECT_REF_BIAS - 1).
    return (ulDuplicatedPointerCount > (OBJECT_REF_BIAS - 1))
               ? (ulDuplicatedPointerCount - (OBJECT_REF_BIAS)-1)
               : 0;
  } else {
    // Here we need to accont for the handle and the query references.
    return (ulDuplicatedPointerCount > 2) ? (ulDuplicatedPointerCount - 2) : 0;
  }
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
GetObjectTypeEnumeration(std::vector<std::wstring>& handleTypeMap) {
  NTSTATUS ntStatus = STATUS_SUCCESS;
  ObjectAllTypesInfo* pTypes = nullptr;
  ULONG retLen = 0;

  std::vector<uint8_t> localBuffer(INITAL_ENUMERATION_BUFFER_SIZE);

  ntStatus = NtQueryObject(nullptr,
                           ObjectAllTypesInformation,
                           localBuffer.data(),
                           (ULONG)localBuffer.size(),
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
                             (ULONG)newSize,
                             &retLen);
  }

  if (STATUS_SUCCESS != ntStatus) {
    std::cerr << "Failed to query object all types information: 0x" << std::hex
              << ntStatus << std::dec << std::endl;
    return ntStatus;
  }

  pTypes = (ObjectAllTypesInfo*)(localBuffer.data());
  if (pTypes->NumberOfTypes > USHRT_MAX) {
    std::cerr << "Too many object types (" << pTypes->NumberOfTypes
              << ") exceeds a uint16_t which is used for handle type indices"
              << std::endl;
    return STATUS_INTEGER_OVERFLOW;
  }

  // Initialize the iter
  ObjectTypeInfo* typeIter = &pTypes->Types[0];
  for (ULONG i = 0; i < pTypes->NumberOfTypes; i++) {
    handleTypeMap.push_back(std::wstring(
        typeIter->TypeName.Buffer, typeIter->TypeName.Length / sizeof(WCHAR)));

    // advance our iterator, accounting for the trailing serialized string
    // buffer and alignment
    typeIter = (ObjectTypeInfo*)((uint8_t*)typeIter +
                                 AlignUpPtr(sizeof(ObjectTypeInfo) +
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
NTSTATUS
GetHandleAndTypeEnumeration(const std::set<int>& pidlist,
                            std::vector<HandleRecordPtr>& handleRecords,
                            std::vector<std::wstring>& handleTypeMap) {
  NTSTATUS ntStatus = STATUS_SUCCESS;
  SystemHandleInformationEx* pHandleInfo = nullptr;
  std::vector<std::wstring> beforeTypeMap;
  std::vector<std::wstring> afterTypeMap;
  ULONG retLen = 0;

  std::vector<uint8_t> localBuffer(INITAL_ENUMERATION_BUFFER_SIZE);

  if (STATUS_SUCCESS != GetObjectTypeEnumeration(beforeTypeMap)) {
    goto Cleanup;
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
    std::cerr << "Failed to query system handle information: 0x" << std::hex
              << ntStatus << std::dec << std::endl;
    goto Cleanup;
  }

  // 3. Query types snapshot #2
  ntStatus = GetObjectTypeEnumeration(afterTypeMap);
  if (STATUS_SUCCESS != ntStatus) {
    goto Cleanup;
  }

  // 4. Verify the two type snapshots match
  if (beforeTypeMap != afterTypeMap) {
    std::cerr << "Type map snapshot mismatch.  Likely contemporaneous "
                 "enumeration relative to type registration.  Try again."
              << std::endl;
    ntStatus = STATUS_RETRY;
    goto Cleanup;
  }

  // 5. Process the basic enumeration into our record structure
  pHandleInfo = (SystemHandleInformationEx*)(localBuffer.data());
  for (ULONG i = 0; i < pHandleInfo->NumberOfHandles; i++) {
    SystemHandleTableEntryInfoEx* entry = &pHandleInfo->Handles[i];
    if (pidlist.end() == pidlist.find((int)entry->UniqueProcessId)) {
      continue;
    }
    try {
      handleRecords.push_back(std::make_unique<HandleRecord>(entry));
    } catch (const std::invalid_argument& e) {
      LOG(ERROR) << "Error creating HandleRecord: " << e.what();
      continue;
    } catch (const std::bad_alloc& e) {
      LOG(ERROR) << "Error allocating memory for HandleRecord: " << e.what();
      continue;
    }
  }

  handleTypeMap = std::move(beforeTypeMap);

Cleanup:

  return ntStatus;
}

DWORD
EnumerateAllHandles(const std::set<int>& pidlist,
                    Collector& handleEnumeration) {
  NTSTATUS ntStatus = STATUS_SUCCESS;
  UNICODE_STRING fileTypeName = {0};
  std::set<ULONG_PTR> accessDeniedPIDs;
  ULONG ulRetryCount =
      5; // We'll retry up to 5 times on type registration activity.  Retries
         // are unlikely to ever be necessary.

  std::vector<std::wstring> handleTypeMaVector;

  // 1. Gather the handle enumeration and a stable type mapping
  while (
      ulRetryCount-- &&
      (STATUS_RETRY ==
       (ntStatus = GetHandleAndTypeEnumeration(
            pidlist, handleEnumeration.handleRecords, handleTypeMaVector)))) {
    std::cerr << "Retrying handle and type enumeration likely due to type "
                 "registration activity..."
              << std::endl;
  }
  if (STATUS_SUCCESS != ntStatus) {
    std::cerr << "Failed to query system handle information / type mapping: 0x"
              << std::hex << ntStatus << std::dec << std::endl;
    return ERROR_RETRY;
  }

  RtlInitUnicodeString(&fileTypeName, L"File");

  // 2. Enrich Handle records
  for (auto& handleIter : handleEnumeration.handleRecords) {
    HANDLE duplicatedObjectHandle = INVALID_HANDLE_VALUE;
    HANDLE processHandle = INVALID_HANDLE_VALUE;

    // 3a. Open the source process
    if (accessDeniedPIDs.end() ==
        accessDeniedPIDs.find(handleIter->ProcessId)) {
      processHandle =
          OpenProcess(PROCESS_DUP_HANDLE, FALSE, (DWORD)handleIter->ProcessId);
      if (NULL == processHandle || INVALID_HANDLE_VALUE == processHandle) {
        handleIter->SetError(ErrorStage::ProcessOpening, GetLastError());
        if (GetLastError() == ERROR_ACCESS_DENIED) {
          accessDeniedPIDs.insert(handleIter->ProcessId);
        } else {
          LOG(ERROR) << "Error (" << GetLastError()
                     << ") opening process (PID: " << handleIter->ProcessId
                     << ")";
        }
        continue;
      }
    } else {
      handleIter->SetError(ErrorStage::ProcessOpening, ERROR_ACCESS_DENIED);
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
      ObjectBasicInfo objBasicInfo = {0};

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
        ObjectTypeInfoWithStorage objTypeInfo = {0};

        // The pointer count is new information we wanted.
        handleIter->SetRawPointerCount(
            UnduplicatedPointerCount(objBasicInfo.PointerCount));

        // Other information came in the initial enumeration, but we have to
        // allow for the possibility that the handle value got reused between
        // that enumeration and now, so if we're able to get to the
        // ObjectBasicInformation query on the duplicated handle, we should
        // replace it.
        handleIter->SetGrantedAccess(objBasicInfo.GrantedAccess);
        handleIter->SetHandleAttributes(objBasicInfo.Attributes);
        // We duplicated the handle, so we subtract one to account for that.
        handleIter->SetHandleCount(objBasicInfo.HandleCount - 1);

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

          handleIter->SetObjectTypeName(
              handleEnumeration.cache.GetObjectTypeName(
                  &objTypeInfo.TypeInfo.TypeName));

          // Prepare params for querying the name
          params.hObject = duplicatedObjectHandle;
          // STATUS_UNSUCCESSFUL allows us to detect failure in the thread if it
          // doesn't get to the point of setting it.
          params.ntStatus = STATUS_UNSUCCESSFUL;

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

              CloseHandle(hThread);
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
                  handleEnumeration.cache.GetObjectTypeName(
                      &params.nameBuffer.usName));
            } else {
              handleIter->SetObjectName(
                  handleEnumeration.cache.GetObjectTypeName(L"<none>"));
            }
            break;
          case STATUS_UNSUCCESSFUL:
            handleIter->SetObjectName(handleEnumeration.cache.GetObjectTypeName(
                L"<query would block, synch file handle>"));
            break;
          default:
            handleIter->SetObjectName(handleEnumeration.cache.GetObjectTypeName(
                L"<failed resolving>"));
            break;
          }
        }
      }
      CloseHandle(duplicatedObjectHandle);
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
    CloseHandle(processHandle);
  }

  return ERROR_SUCCESS;
}

std::string DecodeHandleAttributes(ULONG Attributes) {
  std::string result;

  if (0 == Attributes) {
    return "None";
  }

  struct FlagMapping {
    ULONG flag;
    const char* name;
  };

  static const FlagMapping mappings[] = {{0x00000002L, "Inherit"},
                                         {0x00000010L, "Permanent"},
                                         {0x00000020L, "Exclusive"},
                                         {0x00000040L, "CaseInsensitive"},
                                         {0x00000080L, "OpenIf"},
                                         {0x00000100L, "OpenLink"},
                                         {0x00000200L, "KernelHandle"},
                                         {0x00000400L, "ForceAccessCheck"}};

  for (const auto& m : mappings) {
    if (Attributes & m.flag) {
      if (!result.empty())
        result += ", ";
      result += m.name;
    }
  }

  return (result.empty() ? "Unknown (" + std::to_string(Attributes) + ")"
                         : result);
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

  DWORD dwStatus = ERROR_SUCCESS;
  handles::Collector handleEnumeration;
  handles::HandleRecordCache cache;

  (void)handles::SetDebugTokenPrivilege();

  dwStatus = handles::EnumerateAllHandles(pidlist, handleEnumeration);
  if (ERROR_SUCCESS != dwStatus) {
    LOG(ERROR) << "Failed to enumerate handles with Win32 error: " << dwStatus;
  } else {
    LOG(ERROR) << "Enumerated " << handleEnumeration.handleRecords.size()
               << " handles";
    // handles::OutputEnumeratedHandles(handleEnumeration);
  }
  for (const auto& handle : handleEnumeration.handleRecords) {
    results.push_back(handle->ToRow(cache));
  }
  return results;
}
} // namespace tables
} // namespace osquery