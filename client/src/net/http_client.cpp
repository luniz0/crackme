// path: RankGateInsane/client/src/net/http_client.cpp
#include "http_client.hpp"

#include <windows.h>
#include <winhttp.h>

#include <stdexcept>

namespace rg::net {

namespace {

std::wstring widen(const std::string& s) {
    return std::wstring(s.begin(), s.end());  // ASCII-only (localhost URLs)
}

struct Handle {
    HINTERNET h = nullptr;
    explicit Handle(HINTERNET x) : h(x) {}
    ~Handle() { if (h) WinHttpCloseHandle(h); }
    operator HINTERNET() const { return h; }
};

}  // namespace

HttpClient::HttpClient(const std::string& base_url) {
    std::string u = base_url;
    const std::string scheme = "http://";
    if (u.rfind(scheme, 0) == 0) u = u.substr(scheme.size());
    // strip any trailing path/slash
    size_t slash = u.find('/');
    if (slash != std::string::npos) u = u.substr(0, slash);
    size_t colon = u.find(':');
    if (colon != std::string::npos) {
        host_ = u.substr(0, colon);
        port_ = std::stoi(u.substr(colon + 1));
    } else {
        host_ = u;
        port_ = 80;
    }
}

std::string HttpClient::request(const std::wstring& verb, const std::string& path,
                                const std::string& body) const {
    Handle session(WinHttpOpen(L"RankGate/6", WINHTTP_ACCESS_TYPE_NO_PROXY,
                               WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0));
    if (!session) throw std::runtime_error("WinHttpOpen failed");

    Handle connect(WinHttpConnect(session, widen(host_).c_str(),
                                  static_cast<INTERNET_PORT>(port_), 0));
    if (!connect) throw std::runtime_error("WinHttpConnect failed (is the server running?)");

    Handle request(WinHttpOpenRequest(connect, verb.c_str(), widen(path).c_str(),
                                      nullptr, WINHTTP_NO_REFERER,
                                      WINHTTP_DEFAULT_ACCEPT_TYPES, 0));
    if (!request) throw std::runtime_error("WinHttpOpenRequest failed");

    const wchar_t* headers = L"Content-Type: application/octet-stream\r\n";
    if (!WinHttpSendRequest(request, headers, -1L,
                            body.empty() ? WINHTTP_NO_REQUEST_DATA
                                         : const_cast<char*>(body.data()),
                            static_cast<DWORD>(body.size()),
                            static_cast<DWORD>(body.size()), 0))
        throw std::runtime_error("WinHttpSendRequest failed (is the server running?)");

    if (!WinHttpReceiveResponse(request, nullptr))
        throw std::runtime_error("WinHttpReceiveResponse failed");

    std::string out;
    for (;;) {
        DWORD avail = 0;
        if (!WinHttpQueryDataAvailable(request, &avail))
            throw std::runtime_error("WinHttpQueryDataAvailable failed");
        if (avail == 0) break;
        std::string chunk(avail, '\0');
        DWORD read = 0;
        if (!WinHttpReadData(request, chunk.data(), avail, &read))
            throw std::runtime_error("WinHttpReadData failed");
        out.append(chunk.data(), read);
    }
    return out;
}

std::string HttpClient::post(const std::string& path, const std::string& body) const {
    return request(L"POST", path, body);
}

std::string HttpClient::get(const std::string& path) const {
    return request(L"GET", path, std::string());
}

}  // namespace rg::net
