// path: RankGateInsane/client/src/net/http_client.hpp
//
// Minimal localhost HTTP client over WinHTTP. The application protocol is
// binary; this transport only carries base64 of binary frames in the body and
// returns the server's (base64 or JSON) response text verbatim.
#pragma once

#include <string>

#include "../common.hpp"

namespace rg::net {

class HttpClient {
public:
    // Parses a base URL like "http://127.0.0.1:31337".
    explicit HttpClient(const std::string& base_url);

    // POST body to <base>/<path>; returns the raw response body text.
    std::string post(const std::string& path, const std::string& body) const;
    // GET <base>/<path>; returns the raw response body text.
    std::string get(const std::string& path) const;

    const std::string& host() const { return host_; }
    int port() const { return port_; }

private:
    std::string request(const std::wstring& verb, const std::string& path,
                        const std::string& body) const;

    std::string host_ = "127.0.0.1";
    int port_ = 31337;
};

}  // namespace rg::net
