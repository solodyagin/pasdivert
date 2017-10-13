if exist c:\lazarus goto :installed

curl -fsSL -o laz-setup.exe "https://downloads.sourceforge.net/project/lazarus/Lazarus Windows 32 bits/Lazarus 1.6.4/lazarus-1.6.4-fpc-3.0.2-win32.exe?r=&ts=1507852966&use_mirror=netix"
laz-setup.exe /verysilent

curl -fsSL -o laz-cross-setup.exe "https://downloads.sourceforge.net/project/lazarus/Lazarus Windows 32 bits/Lazarus 1.6.4/lazarus-1.6.4-fpc-3.0.2-cross-x86_64-win64-win32.exe?r=&ts=1507863403&use_mirror=10gbps-io"
laz-cross-setup.exe /verysilent

rd /s /q c:\lazarus\docs
rd /s /q c:\lazarus\examples

:installed
