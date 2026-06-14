// path: RankGateInsane/client/src/main.cpp
//
// RankGate Insane challenge client entry point. The interesting logic lives in
// app.cpp and the net/crypto/vm/challenge modules; main only forwards argv.
#include "app.hpp"

int main(int argc, char** argv) {
    return rg::run_app(argc, argv);
}
