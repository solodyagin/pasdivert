{*
 * windivert.pas
 * (C) 2014, all rights reserved,
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *}

{
  Translation of windivert.h
}

unit windivert;

interface

uses
	SysUtils, Windows;

type
  BOOL = LongBool;
  INT8 = Byte;
  UINT8 = Byte;
  INT16 = ShortInt;
  UINT16 = ShortInt;
  INT32 = Integer;
  UINT32 = Cardinal;
  PUINT32 = ^UINT32;
  UINT64 = Int64;
  UINT = Cardinal;
  PUINT = ^UINT;
  
type
  WINDIVERT_ADDRESS = record
    IfIdx: UINT32;
    SubIfIdx: UINT32;
    Direction: UINT8;
  end;
  TWinDivertAddress = WINDIVERT_ADDRESS;
  PWinDivertAddress = ^TWinDivertAddress;
  
const
  WINDIVERT_DIRECTION_OUTBOUND = 0;
  WINDIVERT_DIRECTION_INBOUND = 1;
  
type
  WINDIVERT_LAYER = (
    WINDIVERT_LAYER_NETWORK,
    WINDIVERT_LAYER_NETWORK_FORWARD
  );
  TWinDivertLayer = WINDIVERT_LAYER;
  
const
  WINDIVERT_FLAG_SNIFF = 1;
  WINDIVERT_FLAG_DROP = 2;
  WINDIVERT_FLAG_NO_CHECKSUM = 1024;
  
type
  WINDIVERT_PARAM = (
    WINDIVERT_PARAM_QUEUE_LEN,
    WINDIVERT_PARAM_QUEUE_TIME
  );
  TWinDivertParam = WINDIVERT_PARAM;
  
const
  WINDIVERT_PARAM_MAX = WINDIVERT_PARAM_QUEUE_TIME;
  
{*
 * Open a WinDivert handle.
 *}
function WinDivertOpen(
  const filter: PAnsiChar;
  layer: TWinDivertLayer;
  priority: INT16;
  flags: UINT64
): THandle; cdecl; external 'windivert.dll';

{*
 * Receive (read) a packet from a WinDivert handle.
 *}
function WinDivertRecv(
  handle: THandle;
  pPacket: Pointer;
  packetLen: UINT;
  pAdd: PWinDivertAddress;
  var readLen: UINT
): BOOL; cdecl; external 'windivert.dll';
  
{*
 * Receive (read) a packet from a WinDivert handle.
 *}
function WinDivertRecvEx(
  handle: THandle;
  pPacket: Pointer;
  packetLen: UINT;
  flags: UINT64;
  pAdd: PWinDivertAddress;
  readLen: UINT;
  var lpOverlapped: POverlapped
): BOOL; cdecl; external 'windivert.dll';

{*
 * Send (write/inject) a packet to a WinDivert handle.
 *}
function WinDivertSend(
  handle: THandle;
  pPacket: Pointer;
  packetLen: UINT;
  pAdd: PWinDivertAddress;
  var writeLen: UINT
): BOOL; cdecl; external 'windivert.dll';

{*
 * Send (write/inject) a packet to a WinDivert handle.
 *}
function WinDivertSendEx(
  handle: THandle;
  pPacket: Pointer;
  packetLen: UINT;
  flags: UINT64;
  pAdd: PWinDivertAddress;
  var writeLen: UINT;
  var lpOverlapped: POverlapped  
): BOOL; cdecl; external 'windivert.dll';

{*
 * Close a WinDivert handle.
 *}
function WinDivertClose(
  handle: THandle
): BOOL; cdecl; external 'windivert.dll';

{*
 * Set a WinDivert handle parameter.
 *}
function WinDivertSetParam(
  handle: THandle;
  param: TWinDivertParam;
  value: UINT64
): BOOL; cdecl; external 'windivert.dll';

{*
 * Get a WinDivert handle parameter.
 *}
function WinDivertGetParam(
  handle: THandle;
  param: TWinDivertParam;
  var pValue: UINT64
): BOOL; cdecl; external 'windivert.dll';

{****************************************************************************}
{* WINDIVERT HELPER API                                                     *}
{****************************************************************************}

{*
 * IPv4/IPv6/ICMP/ICMPv6/TCP/UDP header definitions.
 *}
type
  WINDIVERT_IPHDR = record
    HdrLength: UINT8;
    Version: UINT8;
    TOS: UINT8;
    Length: UINT16;
    Id: UINT16;
    FragOff0: UINT16;
    TTL: UINT8;
    Protocol: UINT8;
    Checksum: UINT16;
    SrcAddr: UINT32;
    DstAddr: UINT32;
  end;
  TWinDivertIpHdr = WINDIVERT_IPHDR;
  PWinDivertIpHdr = ^TWinDivertIpHdr;
  PPWinDivertIpHdr = ^PWinDivertIpHdr;

// Macros
function WINDIVERT_IPHDR_GET_FRAGOFF(hdr: PWinDivertIpHdr): UINT16;
function WINDIVERT_IPHDR_GET_MF(hdr: PWinDivertIpHdr): UINT16;
function WINDIVERT_IPHDR_GET_DF(hdr: PWinDivertIpHdr): UINT16;
function WINDIVERT_IPHDR_GET_RESERVED(hdr: PWinDivertIpHdr): UINT16;

type  
  WINDIVERT_IPV6HDR = record
    TrafficClass0: UINT8;
    Version: UINT8;
    FlowLabel0: UINT8;
    TrafficClass1: UINT8;
    FlowLabel1: UINT16;
    Length: UINT16;
    NextHdr: UINT8;
    HopLimit: UINT8;
    SrcAddr: array[0..3] of UINT32;
    DstAddr: array[0..3] of UINT32;
  end;
  TWinDivertIpv6Hdr = WINDIVERT_IPV6HDR;
  PWinDivertIpv6Hdr = ^TWinDivertIpv6Hdr;
  PPWinDivertIpv6Hdr = ^PWinDivertIpv6Hdr;
  
// Macros
function WINDIVERT_IPV6HDR_GET_TRAFFICCLASS(hdr: PWinDivertIpv6Hdr): UINT8;
function WINDIVERT_IPV6HDR_GET_FLOWLABEL(hdr: PWinDivertIpv6Hdr): UINT32;

type
  WINDIVERT_ICMPHDR = record
    _Type: UINT8;
    Code: UINT8;
    Checksum: UINT16;
    Body: UINT32;
  end;
  TWinDivertIcmpHdr = WINDIVERT_ICMPHDR;
  PWinDivertIcmpHdr = ^TWinDivertIcmpHdr;
  PPWinDivertIcmpHdr = ^PWinDivertIcmpHdr;
  
  WINDIVERT_ICMPV6HDR = record
    _Type: UINT8;
    Code: UINT8;
    Checksum: UINT16;
    Body: UINT32;
  end;
  TWinDivertIcmpv6Hdr = WINDIVERT_ICMPV6HDR;
  PWinDivertIcmpv6Hdr = ^TWinDivertIcmpv6Hdr;
  PPWinDivertIcmpv6Hdr = ^PWinDivertIcmpv6Hdr;
  
  WINDIVERT_TCPHDR = record
    SrcPort: UINT16;
    DstPort: UINT16;
    SeqNum: UINT32;
    AckNum: UINT32;
    Reserved: UINT16;
    HdrLength: UINT16;
    Fin: UINT16;
    Syn: UINT16;
    Rst: UINT16;
    Psh: UINT16;
    Ack: UINT16;
    Urg: UINT16;
    Reserved2: UINT16;
    Window: UINT16;
    Checksum: UINT16;
    UrgPtr: UINT16;
  end;
  TWinDivertTcpHdr = WINDIVERT_TCPHDR;
  PWinDivertTcpHdr = ^TWinDivertTcpHdr;
  PPWinDivertTcpHdr = ^PWinDivertTcpHdr;
  
  WINDIVERT_UDPHDR = record
    SrcPort: UINT16;
    DstPort: UINT16;
    Length: UINT16;
    Checksum: UINT16;
  end;
  TWinDivertUdpHdr = WINDIVERT_UDPHDR;
  PWinDivertUdpHdr = ^TWinDivertUdpHdr;
  PPWinDivertUdpHdr = ^PWinDivertUdpHdr;
  
{*
 * Flags for DivertHelperCalcChecksums()
 *}
const
  WINDIVERT_HELPER_NO_IP_CHECKSUM     =  1;
  WINDIVERT_HELPER_NO_ICMP_CHECKSUM   =  2;
  WINDIVERT_HELPER_NO_ICMPV6_CHECKSUM =  4;
  WINDIVERT_HELPER_NO_TCP_CHECKSUM    =  8;
  WINDIVERT_HELPER_NO_UDP_CHECKSUM    = 16;

{*
 * Parse IPv4/IPv6/ICMP/ICMPv6/TCP/UDP headers from a raw packet.
 *}
function WinDivertHelperParsePacket(
  pPacket: Pointer;
  packetLen: UINT;
  ppIpHdr: PPWinDivertIpHdr;
  ppIpv6Hdr: PPWinDivertIpv6Hdr;
  ppIcmpHdr: PPWinDivertIcmpHdr;
  ppIcmpv6Hdr: PPWinDivertIcmpv6Hdr;
  ppTcpHdr: PPWinDivertTcpHdr;
  ppUdpHdr: PPWinDivertUdpHdr;
  ppData: PPointer;
  pDataLen: PUINT
): BOOL; cdecl; external 'windivert.dll';

{*
 * Parse an IPv4 address.
 *}
function WinDivertHelperParseIPv4Address(
  const addrStr: PAnsiChar;
  var pAddr: UINT32
): BOOL; cdecl; external 'windivert.dll';

{*
 * Parse an IPv6 address.
 *}
function WinDivertHelperParseIPv6Address(
  const addrStr: PAnsiChar;
  var pAddr: UINT32
): BOOL; cdecl; external 'windivert.dll';

{*
 * Calculate IPv4/IPv6/ICMP/ICMPv6/TCP/UDP checksums.
 *}
function WinDivertHelperCalcChecksums(
  var pPacket: Pointer;
  packetLen: UINT;
  flags: UINT64
): UINT; cdecl; external 'windivert.dll';

implementation

function WINDIVERT_IPHDR_GET_FRAGOFF(hdr: PWinDivertIpHdr): UINT16;
begin
  Result := hdr^.FragOff0 and $FF1F;
end;

function WINDIVERT_IPHDR_GET_MF(hdr: PWinDivertIpHdr): UINT16;
begin
  if (hdr^.FragOff0 and $0020) <> 0 then
  	Result := 1
  else
  	Result := 0;
end;

function WINDIVERT_IPHDR_GET_DF(hdr: PWinDivertIpHdr): UINT16;
begin
  if (hdr^.FragOff0 and $0040) <> 0 then
  	Result := 1
  else
  	Result := 0;
end;

function WINDIVERT_IPHDR_GET_RESERVED(hdr: PWinDivertIpHdr): UINT16;
begin
  if (hdr^.FragOff0 and $0080) <> 0 then
  	Result := 1
  else
  	Result := 0;
end;

function WINDIVERT_IPV6HDR_GET_TRAFFICCLASS(hdr: PWinDivertIpv6Hdr): UINT8;
begin
  Result := (hdr^.TrafficClass0 shl 4) or hdr^.TrafficClass1;
end;

function WINDIVERT_IPV6HDR_GET_FLOWLABEL(hdr: PWinDivertIpv6Hdr): UINT32;
begin
  Result := (UINT32(hdr^.FlowLabel0) shl 16) or (UINT32(hdr^.FlowLabel1));
end;

end.