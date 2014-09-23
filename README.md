pasdivert
=========

Pascal binding for [WinDivert](http://reqrypt.org/windivert.html).

WinDivert
---------

Copied from the Website: WinDivert is a user-mode packet capture-and-divert 
package for Windows Vista, Windows 2008, Windows 7, Windows 8.

WinDivert allows user-mode applications to capture/modify/drop network packets 
sent to/from the Windows network stack.

WinDivert can be used to implement user-mode packet filters, packet sniffers, 
firewalls, NAT, VPNs, tunneling applications, etc. 

GitHub repository of WinDivert: https://github.com/basil00/Divert

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

Please run these examples as Adminsitrator. To debug them with Delphi run Delphi
as Adminsitrator.

* `passthru` This program does nothing except divert packets and re-inject them.
* `netdump` This is a simple traffic monitor.  It uses a WinDivert handle in SNIFF 
  mode. The SNIFF mode copies packets and does not block the original.
