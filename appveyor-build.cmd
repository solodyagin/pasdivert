@echo off
set lazbuild=c:\lazarus\lazbuild.exe
for /F "tokens=*" %%i in ('dir /A:-D /B /S "*.lpi"') do (
	"%lazbuild%" "%%i" --build-all --build-mode=Win32-Release
	"%lazbuild%" "%%i" --build-all --build-mode=Win64-Release
)
