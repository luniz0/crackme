// path: RankGateInsane/client/src/app.cpp
#include "app.hpp"

#include <cstdio>
#include <iostream>
#include <string>

#include "challenge/license_format.hpp"
#include "crypto/crypto.hpp"
#include "net/protocol.hpp"
#include "protection/anti_debug.hpp"
#include "protection/decoys.hpp"

namespace rg {

namespace {

struct Args {
    std::string server = "http://127.0.0.1:31337";
    std::string username;
    std::string license;
    bool have_username = false;
    bool have_license = false;
    bool no_protection = false;
    bool verbose = false;
    bool help = false;
};

Args parse_args(int argc, char** argv) {
    Args a;
    for (int i = 1; i < argc; ++i) {
        std::string s = argv[i];
        auto next = [&](const char* what) -> std::string {
            if (i + 1 >= argc) throw std::runtime_error(std::string("missing value for ") + what);
            return argv[++i];
        };
        if (s == "--server") a.server = next("--server");
        else if (s == "--username" || s == "-u") { a.username = next("--username"); a.have_username = true; }
        else if (s == "--license" || s == "-l") { a.license = next("--license"); a.have_license = true; }
        else if (s == "--no-protection") a.no_protection = true;
        else if (s == "--verbose" || s == "-v") a.verbose = true;
        else if (s == "--help" || s == "-h") a.help = true;
        else throw std::runtime_error("unknown argument: " + s);
    }
    return a;
}

void print_help() {
    std::printf(
        "RankGate License Portal\n"
        "Usage: rankgate [options]\n"
        "  --server URL        license server (default http://127.0.0.1:31337)\n"
        "  -u, --username U     username (prompted if omitted)\n"
        "  -l, --license  K     license key (prompted if omitted)\n"
        "  --no-protection      disable challenge-only anti-analysis checks\n"
        "  -v, --verbose        print protocol progress\n"
        "  -h, --help           show this help\n");
}

std::string prompt(const char* label) {
    std::printf("%s", label);
    std::fflush(stdout);
    std::string line;
    std::getline(std::cin, line);
    return line;
}

}  // namespace

int run_app(int argc, char** argv) {
    Args args;
    try {
        args = parse_args(argc, argv);
    } catch (const std::exception& e) {
        std::printf("error: %s\n", e.what());
        print_help();
        return 2;
    }
    if (args.help) {
        print_help();
        return 0;
    }

    std::printf("==============================\n");
    std::printf("   RankGate License Portal\n");
    std::printf("==============================\n");

    crypto::init();
    if (!args.no_protection) protection::run_guards(args.verbose);
    else if (args.verbose) std::printf("[*] protection disabled (--no-protection)\n");

    std::string username = args.have_username ? args.username : prompt("Username   : ");
    std::string license = args.have_license ? args.license : prompt("License key: ");

    try {
        // Harmless local "preflight" -- looks meaningful, gates nothing. The
        // real validation happens server-side over the protocol below.
        protection::decoy_preflight(username, license, args.verbose);

        Bytes uname = challenge::normalize_username(username);
        Bytes lic = challenge::decode_license(license);

        net::ProtocolOptions opt;
        opt.server_url = args.server;
        opt.verbose = args.verbose;
        Bytes flag = net::run_session(opt, uname, lic);

        std::printf("\nACCESS GRANTED\n");
        std::printf("%s\n", std::string(flag.begin(), flag.end()).c_str());
        return 0;
    } catch (const std::exception& e) {
        if (args.verbose) std::printf("[-] %s\n", e.what());
        std::printf("\nACCESS DENIED\n");
        std::printf("invalid username or license\n");
        return 1;
    }
}

}  // namespace rg
