# pasdivert
[![Release](https://img.shields.io/github/release/stievie/pasdivert.svg)](https://github.com/stievie/pasdivert/releases/latest)
[![Downloads](https://img.shields.io/github/downloads/stievie/pasdivert/latest/total.svg?maxAge=3600)](https://github.com/stievie/pasdivert/releases)

Pascal binding for [WinDivert](http://reqrypt.org/windivert.html).

This Unit can be used with Delphi and Free Pascal.

## WinDivert

Copied from the Website: WinDivert is a user-mode packet capture-and-divert 
package for Windows Vista, Windows 2008, Windows 7, Windows 8 and Windows 10.

WinDivert allows user-mode applications to capture/modify/drop network packets 
sent to/from the Windows network stack.

WinDivert can be used to implement user-mode packet filters, packet sniffers, 
firewalls, NAT, VPNs, tunneling applications, etc. 

GitHub repository of WinDivert: https://github.com/basil00/Divert

## Requirements

You need the binary distribution from the WinDivert homepage. Since we use it
with Pascal/Delphi you can use any distribution (VS, DDK or MinGW), this does 
not matter because we do not need the lib files for linking.

On Windows 64 put `amd64\WinDivert64.sys` and `amd64\WinDivert.dll` in the 
program directory.

On Windows 32 put `x86\WinDivert32.sys` and `x86\WinDivert.dll` in the 
program directory.

## Examples

Please run these examples as Administrator. To debug them with Delphi run Delphi
as Administrator.

* `passthru` This program does nothing except divert packets and re-inject them.
* `netdump` This is a simple traffic monitor.  It uses a WinDivert handle in SNIFF 
  mode. The SNIFF mode copies packets and does not block the original.
* `webfilter` This is a simple web (HTTP) filter using WinDivert.
* `netlimit` Simulates bad networks.

## webfilter

Is a simple web (HTTP) filter using WinDivert.

It works by intercepting outbound HTTP GET/POST requests and matching
the URL against a blacklist.  If the URL is matched, we hijack the TCP
connection, reseting the connection at the server end, and sending a
blockpage to the browser.

### Example

~~~
webfilter blacklist.txt [blacklist2.txt ...]
~~~

This `blacklist.txt` will block all HTTP requests to Google and Facebook domains.

~~~
google.com
facebook.com
~~~

## netlimit

A Program to simulate bad networks. Can add latency and drop packets.

This program can be useful when you have to test client/server programs (such as online games) 
which must be able to deal with bad/unreliable networks (e.g. the Internet). For
example, you can't test *lag compensation*, *server/client prediction* when you have
an almost perfect network (localhost, LAN).

### Example

~~~
netlimit -f "outbound and udp.DstPort == 3337" -t 1 -l 1000 -d 20
~~~

1. Filter outbound UDP traffic on port 3337
2. Use 1 worker thread
3. Simulate an average ping of ~1000 ms (between 500 ms and 1500 ms)
4. Drop 20 % packets

## Compiling

To compile the examples on Windows 64 with Free Pascal, download the latest 
*32-Bit* [Lazarus](http://lazarus.freepascal.org/) distribution (at the moment of
this writing, it's Lazarus 1.4.2 and FPC 2.6.4) and the `cross-x86_64-win64-win32` 
crosscompile add on and install both.
Open the project file (*.lpi), select the configuration (Win64-Debug, Win64-Release, 
Win32-Debug or Win32-Release) and click Start -> Compile.
