// path: RankGateInsane/client/src/crypto/base64.hpp
//
// Standard RFC 4648 base64 (with '=' padding), matching Python's
// base64.b64encode/b64decode used by the HTTP transport.
#pragma once

#include <string>

#include "../common.hpp"

namespace rg::crypto {

std::string b64encode(const Bytes& data);
Bytes b64decode(const std::string& text);

}  // namespace rg::crypto
