@echo off

c:\lazarus\lazbuild netdump.lpi --build-all --build-mode=Win64-Release
c:\lazarus\lazbuild netdump.lpi --build-all --build-mode=Win32-Release
c:\lazarus\lazbuild netlimit.lpi --build-all --build-mode=Win64-Release
c:\lazarus\lazbuild netlimit.lpi --build-all --build-mode=Win32-Release
c:\lazarus\lazbuild passthru.lpi --build-all --build-mode=Win64-Release
c:\lazarus\lazbuild passthru.lpi --build-all --build-mode=Win32-Release
c:\lazarus\lazbuild webfilter.lpi --build-all --build-mode=Win64-Release
c:\lazarus\lazbuild webfilter.lpi --build-all --build-mode=Win32-Release

call compress.bat
