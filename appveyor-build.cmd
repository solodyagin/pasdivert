@echo off
set lazbuild=c:\lazarus\lazbuild.exe
for /F "tokens=*" %%i in ('dir /A:-D /B /S "*.lpi"') do (
	"%lazbuild%" "%%i" --build-all --build-mode=Win32-Release
	"%lazbuild%" "%%i" --build-all --build-mode=Win64-Release
)
copy x86\WinDivert.dll fpc\Win32\Release
copy x86\WinDivert32.sys fpc\Win32\Release
copy amd64\WinDivert.dll fpc\Win64\Release
copy amd64\WinDivert64.sys fpc\Win64\Release
