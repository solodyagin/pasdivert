pasdivert
=========

Pascal binding for [WinDivert](http://reqrypt.org/windivert.html).

Requirements
------------

You need the binary distribution from the WinDivert homepage. Since we use it
with Pascal/Delphi you can use any distribtution (VS, DDK or MinGW), this does 
not matter because we do not need the lib files for linking.

On Windows 64 put `amd64\WinDivert64.sys` and `amd64\WinDivert.dll` in the 
program directory.

On Windows 32 put `x86\WinDivert32.sys` and `x86\WinDivert.dll` in the 
program directory.

Examples
--------

Please run the examples as Adminsitrator.

* passthru
* netdump
