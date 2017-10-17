@echo off

if exist c:\lazarus goto :installed

echo Downloading Lazarus 1.6.4 for Windows 32 bit
rem curl -fsSL -o laz-setup.exe "https://downloads.sourceforge.net/project/lazarus/Lazarus Windows 32 bits/Lazarus 1.6.4/lazarus-1.6.4-fpc-3.0.2-win32.exe?r=&ts=1507852966&use_mirror=netix"
curl -fsSL -o laz-setup.exe "https://www.dropbox.com/s/xe0l2wldh4pfofu/lazarus-1.6.4-fpc-3.0.2-win32.exe?dl=1"

echo Installing Lazarus 1.6.4 for Windows 32 bit
laz-setup.exe /verysilent

echo Downloading Lazarus Add-On for building 64 bit Windows applications
rem curl -fsSL -o laz-cross-setup.exe "https://downloads.sourceforge.net/project/lazarus/Lazarus Windows 32 bits/Lazarus 1.6.4/lazarus-1.6.4-fpc-3.0.2-cross-x86_64-win64-win32.exe?r=&ts=1507863403&use_mirror=10gbps-io"
curl -fsSL -o laz-cross-setup.exe "https://www.dropbox.com/s/0ic204mdq4ty8dz/lazarus-1.6.4-fpc-3.0.2-cross-x86_64-win64-win32.exe?dl=1"

echo Installing Lazarus Add-On for building 64 bit Windows applications
laz-cross-setup.exe /verysilent

rmdir /S /Q c:\lazarus\docs
rmdir /S /Q c:\lazarus\examples

:installed
