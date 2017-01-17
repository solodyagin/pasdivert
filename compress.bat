@echo off

copy README.md fpc\Win32\Release
copy LICENSE fpc\Win32\Release
copy README.md fpc\Win64\Release
copy LICENSE fpc\Win64\Release

if exist pasdivert-win32.zip del pasdivert-win32.zip
cd fpc\Win32\Release
"%PROGRAMFILES%\7-Zip\7z.exe" a -tzip ..\..\..\pasdivert-win32.zip *.exe *.dll *.sys README.md LICENSE
cd ..\..\..

if exist pasdivert-win64.zip del pasdivert-win64.zip
cd fpc\Win64\Release
"%PROGRAMFILES%\7-Zip\7z.exe" a -tzip ..\..\..\pasdivert-win64.zip *.exe *.dll *.sys README.md LICENSE
cd ..\..\..
