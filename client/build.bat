@echo off
REM Local build helper (not for distribution). Sets up MSVC + builds with Ninja.
call "C:\Program Files\Microsoft Visual Studio\18\Insiders\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
set "CM=C:\Program Files\Microsoft Visual Studio\18\Insiders\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"
set "NINJA=C:\Program Files\Microsoft Visual Studio\18\Insiders\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja"
set "PATH=%NINJA%;%PATH%"
cd /d C:\Users\Jawood\source\repos\crackme\RankGateInsane
"%CM%" -S client -B client/build -G Ninja -DCMAKE_BUILD_TYPE=Release -DSODIUM_ROOT=C:/Users/Jawood/vcpkg-work/installed/x64-windows-static || exit /b 1
"%CM%" --build client/build || exit /b 1
