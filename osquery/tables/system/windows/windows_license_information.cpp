/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

//#include <sstream>

#include "osquery/core/windows/wmi.h"
#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/conversions/windows/windows_time.h>

namespace osquery {
namespace tables {

// Map of license status codes to their string representations
// See:
// https://learn.microsoft.com/en-us/previous-versions/windows/desktop/sppwmi/softwarelicensingproduct
constexpr std::array<std::string_view, 7> license_statuses = {"Unlicensed",
                                                              "Licensed",
                                                              "OOBGrace",
                                                              "OOTGrace",
                                                              "NonGenuineGrace",
                                                              "Notification",
                                                              "ExtendedGrace"};

std::string_view licenseStatusToString(long status) {
  if (status >= 0 && status < static_cast<long>(license_statuses.size())) {
    return license_statuses[status];
  }
  return "Unknown";
}

QueryData genWindowsLicenseInformation(QueryContext& context) {
  QueryData results_data;
  std::string query =
      "SELECT * FROM SoftwareLicensingProduct WHERE PartialProductKey IS NOT "
      "NULL";

  // Make a WMI request to get all the software licensing product information
  const auto request = WmiRequest::CreateWmiRequest(query);
  if (!request || !request->getStatus().ok()) {
    VLOG(1) << "Failed to create WmiRequest for windows_license_information: "
            << (request ? request->getStatus().toString() : "Unknown error");
    return results_data;
  }

  // Iterate through the results and populate the query data
  const auto& results = request->results();
  for (const auto& result : results) {
    Row row;

    auto getLong = [&result](const std::string& wmi_name) -> long {
      long value = -1;
      auto status = result.GetLong(wmi_name, value);
      if (!status.ok()) {
        VLOG(1) << "Failed to get long value for " << wmi_name << ": "
                << status.getMessage();
      }
      return value;
    };

    auto getString = [&result](const std::string& wmi_name) -> std::string {
      std::string value;
      auto status = result.GetString(wmi_name, value);
      if (!status.ok()) {
        VLOG(1) << "Failed to get string value for " << wmi_name << ": "
                << status.getMessage();
      }
      return std::move(value);
    };

    auto getTimestamp = [&result](const std::string& wmi_name) -> uint64_t {
      FILETIME value{};
      auto status = result.GetDateTime(wmi_name, false, value);
      if (!status.ok()) {
        VLOG(1) << "Failed to get datetime value for " << wmi_name << ": "
                << status.getMessage();
        return static_cast<std::uint64_t>(0);
      }
      return static_cast<std::uint64_t>(filetimeToUnixtime(value));
    };

    row["application_id"] = getString("ApplicationID");
    row["name"] = getString("Name");
    row["description"] = getString("Description");
    row["license_family"] = getString("LicenseFamily");
    row["grace_period_remaining"] = INTEGER(getLong("GracePeriodRemaining"));
    row["partial_product_key"] = getString("PartialProductKey");
    row["product_key_channel"] = getString("ProductKeyChannel");
    row["trusted_time"] = BIGINT(getTimestamp("TrustedTime"));
    row["license_id"] = getString("ID");
    row["ad_activation_object_name"] = getString("ADActivationObjectName");
    row["ad_activation_object_dn"] = getString("ADActivationObjectDN");
    row["genuine_status"] = INTEGER(getLong("GenuineStatus"));

    long license_status_raw = getLong("LicenseStatus");
    row["license_status_raw"] = INTEGER(license_status_raw);
    row["license_status"] = licenseStatusToString(license_status_raw);

    results_data.push_back(row);
  }
  return results_data;
}
} // namespace tables
} // namespace osquery
