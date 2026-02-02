/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>

namespace osquery {
namespace tables {

QueryData genHandles(QueryContext& context) {
  QueryData results;

  LOG(INFO) << "Generating handles table";

  for (auto i = 0; i < 10; ++i) {
    Row r;
    r["handle_id"] = INTEGER(i);
    r["type"] = "ExampleType";
    r["pid"] = INTEGER(1234);
    r["name"] = "ExampleHandleName";
    results.push_back(r);
  }
  return results;
}
}
}
