@echo off
echo === Building curl for ARM64, x64, x86 (Release + Debug) ===
set COMMON=-DBUILD_SHARED_LIBS=OFF -DCURL_STATIC_CRT=ON -DBUILD_CURL_EXE=OFF -DCURL_USE_SCHANNEL=ON -DCURL_USE_OPENSSL=OFF -DBUILD_TESTING=OFF -DUSE_LIBPSL=OFF -DCURL_USE_LIBPSL=OFF -DUSE_NGHTTP2=OFF -DUSE_LIBIDN2=OFF
set RELEASE=-DCMAKE_BUILD_TYPE=Release
set DEBUG=-DCMAKE_BUILD_TYPE=Debug

echo [1/6] Configuring ARM64...
cmake curl -B curl\build\ARM64 -A ARM64 -T v143 %COMMON% %RELEASE%
echo [2/6] Building ARM64 Release...
cmake --build curl\build\ARM64 --config Release
echo [3/6] Building ARM64 Debug...
cmake --build curl\build\ARM64 --config Debug

echo [4/6] Configuring x64...
cmake curl -B curl\build\x64 -A x64 %COMMON% %RELEASE%
echo [5/6] Building x64 Release...
cmake --build curl\build\x64 --config Release
echo [6/6] Building x64 Debug...
cmake --build curl\build\x64 --config Debug

echo [7/6] Configuring x86...
cmake curl -B curl\build\x86 -A Win32 %COMMON% %RELEASE%
echo [8/6] Building x86 Release...
cmake --build curl\build\x86 --config Release
echo [9/6] Building x86 Debug...
cmake --build curl\build\x86 --config Debug

echo === Done! ===
echo ARM64 Release: curl\build\ARM64\lib\Release\libcurl.lib
echo ARM64 Debug:   curl\build\ARM64\lib\Debug\libcurl-d.lib
echo x64   Release: curl\build\x64\lib\Release\libcurl.lib
echo x64   Debug:   curl\build\x64\lib\Debug\libcurl-d.lib
echo x86   Release: curl\build\x86\lib\Release\libcurl.lib
echo x86   Debug:   curl\build\x86\lib\Debug\libcurl-d.lib