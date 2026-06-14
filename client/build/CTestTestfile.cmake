# CMake generated Testfile for 
# Source directory: C:/Users/Jawood/source/repos/crackme/RankGateInsane/client
# Build directory: C:/Users/Jawood/source/repos/crackme/RankGateInsane/client/build
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test([=[crypto_selftest]=] "C:/Users/Jawood/source/repos/crackme/RankGateInsane/client/build/rg_selftest.exe")
set_tests_properties([=[crypto_selftest]=] PROPERTIES  _BACKTRACE_TRIPLES "C:/Users/Jawood/source/repos/crackme/RankGateInsane/client/CMakeLists.txt;78;add_test;C:/Users/Jawood/source/repos/crackme/RankGateInsane/client/CMakeLists.txt;0;")
add_test([=[vm_selftest]=] "C:/Users/Jawood/source/repos/crackme/RankGateInsane/client/build/rg_selftest_vm.exe")
set_tests_properties([=[vm_selftest]=] PROPERTIES  _BACKTRACE_TRIPLES "C:/Users/Jawood/source/repos/crackme/RankGateInsane/client/CMakeLists.txt;82;add_test;C:/Users/Jawood/source/repos/crackme/RankGateInsane/client/CMakeLists.txt;0;")
