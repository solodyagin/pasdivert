{*
 * netdump
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

program netdump;

{$APPTYPE CONSOLE}

{$R *.res}

uses
  System.SysUtils,
  Windows,
  Winsock,
  windivert in 'windivert.pas';

const
  MAXBUF = $FFFF;

type
  TIpv4Addr = packed array[0..3] of UINT8;
  TIpv6Addr = packed array[0..7] of UINT16;

resourcestring
  SIpv4Hdr = 'IPv4 [Version=%d HdrLength=%d TOS=%d Length=%d Id=0x%.4x ' +
    'Reserved=%d DF=%d MF=%d FragOff=%d TTL=%u Protocol=%d ' +
    'Checksum=0x%.4x SrcAddr=%d.%d.%d.%d DstAddr=%d.%d.%d.%d]';
  SIpv6Hdr = 'IPv6 [Version=%u TrafficClass=%u FlowLabel=%u Length=%u ' +
    'NextHdr=%u HopLimit=%u ';
  STcpHdr = 'TCP [SrcPort=%u DstPort=%u SeqNum=%u AckNum=%u ' +
    'HdrLength=%u Reserved1=%u Reserved2=%u Urg=%u Ack=%u ' +
    'Psh=%u Rst=%u Syn=%u Fin=%u Window=%u Checksum=0x%.4X ' +
    'UrgPtr=%u]';

function isprint(const AC: AnsiChar): boolean;
begin
  Result := (Ord(AC) > $1F) and (Ord(AC) <> $7F);
end;

var
  priority: INT16;
  handle, console: THandle;
  filter: string;
  packet: array[0..MAXBUF-1] of Byte;
  addr: TWinDivertAddress;
  packet_len: UINT;
  ip_header: PWinDivertIpHdr;
  ipv6_header: PWinDivertIpv6Hdr;
  icmp_header: PWinDivertIcmpHdr;
  icmpv6_header: PWinDivertIcmpv6Hdr;
  tcp_header: PWinDivertTcpHdr;
  udp_header: PWinDivertUdpHdr;
  src_v4addr: TIpv4Addr;
  dst_v4addr: TIpv4Addr;
  src_v6addr: TIpv6Addr;
  dst_v6addr: TIpv6Addr;
  i: integer;
  nil1: Pointer;
  dummy_uint: UINT;
  uVersion, uHdrLength, uTrafficClass0, uReserved1, uReserved2: UINT8;
begin
  try
    priority := 0;
    case ParamCount of
      1: ;
      2:
        begin
          priority := StrToInt(ParamStr(2));
        end;
      else
        begin
          WriteLn('usage: netdump windivert-filter [priority]');
          WriteLn('examples:');
          WriteLn('  netdump true');
          WriteLn('  netdump "outbound and tcp.DstPort == 80" 1000');
          WriteLn('  netdump "inbound and tcp.Syn" -4000');
          Halt(1);
        end;
    end;

    // Get console for pretty colors.
    console := GetStdHandle(STD_OUTPUT_HANDLE);

    // Divert traffic matching the filter:
    filter := ParamStr(1);
    handle := WinDivertOpen(PAnsiChar(AnsiString(filter)), WINDIVERT_LAYER_NETWORK,
      priority, WINDIVERT_FLAG_SNIFF);
    if handle = INVALID_HANDLE_VALUE then begin
      if GetLastError = ERROR_INVALID_PARAMETER then
        WriteLn('error: filter syntax error')
      else
        WriteLn(Format('error: failed to open the WinDivert device (%d)', [GetLastError]));
      Halt(1);
    end;

    // Max-out the packet queue:
    if not WinDivertSetParam(handle, WINDIVERT_PARAM_QUEUE_LEN, 8192) then begin
      WriteLn(Format('error: failed to set packet queue length (%d)', [GetLastError]));
      Halt(1);
    end;
    if not WinDivertSetParam(handle, WINDIVERT_PARAM_QUEUE_TIME, 2048) then begin
      WriteLn(Format('error: failed to set packet queue time (%d)', [GetLastError]));
      Halt(1);
    end;

    // Main loop:
    while (true) do begin
      // Read a matching packet.
      if not WinDivertRecv(handle, @packet, SizeOf(packet), addr, packet_len) then begin
        WriteLn(Format('warning: failed to read packet (%d)', [GetLastError]));
        Continue;
      end;

      // Print info about the matching packet.
      nil1 := nil;
      WinDivertHelperParsePacket(@packet, packet_len,
        ip_header, ipv6_header, icmp_header, icmpv6_header, tcp_header,
        udp_header, nil1, dummy_uint);
      if (ip_header = nil) and (ipv6_header = nil) then
        WriteLn('warning: junk packet');

      // Dump packet info:
      WriteLn;
      SetConsoleTextAttribute(console, FOREGROUND_RED);
      WriteLn(Format('Packet [Direction=%d IfIdx=%d SubIfIdx=%d]', [addr.Direction, addr.IfIdx, addr.SubIfIdx]));

      if (ip_header <> nil) then begin
        SetConsoleTextAttribute(console, FOREGROUND_GREEN or FOREGROUND_RED);
        src_v4addr := TIpv4Addr(ip_header^.SrcAddr);
        dst_v4addr := TIpv4Addr(ip_header^.DstAddr);

        Get4Bits(ip_header^.HdrLength_Version, uHdrLength, uVersion);
        WriteLn(Format(SIpv4Hdr, [
          uVersion, uHdrLength,
          ntohs(ip_header^.TOS), ntohs(ip_header^.Length),
          ntohs(ip_header^.Id), WINDIVERT_IPHDR_GET_RESERVED(ip_header),
          WINDIVERT_IPHDR_GET_DF(ip_header),
          WINDIVERT_IPHDR_GET_MF(ip_header),
          ntohs(WINDIVERT_IPHDR_GET_FRAGOFF(ip_header)), ip_header^.TTL,
          ip_header^.Protocol, ntohs(ip_header^.Checksum),
          src_v4addr[0], src_v4addr[1], src_v4addr[2], src_v4addr[3],
          dst_v4addr[0], dst_v4addr[1], dst_v4addr[2], dst_v4addr[3]
        ]));
      end;

      if (ipv6_header <> nil) then begin
        SetConsoleTextAttribute(console, FOREGROUND_GREEN or FOREGROUND_RED);
        // Ugly cast xD: ipv6_header^.SrcAddr -> untyped pointer -> TIpv6Addr.
        src_v6addr := TIpv6Addr((@ipv6_header^.SrcAddr)^);
        dst_v6addr := TIpv6Addr((@ipv6_header^.DstAddr)^);
        Get4Bits(ipv6_header^.TrafficClass0_Version, uTrafficClass0, uVersion);
        Write(Format(SIpv6Hdr, [
          uVersion,
          WINDIVERT_IPV6HDR_GET_TRAFFICCLASS(ipv6_header),
          ntohl(WINDIVERT_IPV6HDR_GET_FLOWLABEL(ipv6_header)),
          ntohs(ipv6_header^.Length), ipv6_header^.NextHdr,
          ipv6_header^.HopLimit
        ]));
        for i := 0 to 7 do begin
          Write(Format('%x', [ntohs(src_v6addr[i])]));
          if (i <> 7) then
            Write(':')
          else
            Write(' ');
        end;
        Write('DstAddr=');
        for i := 0 to 7 do begin
          Write(Format('%x', [ntohs(dst_v6addr[i])]));
          if (i <> 7) then
            Write(':');
        end;

        WriteLn(']');
      end;

      if (icmp_header <> nil) then begin
        SetConsoleTextAttribute(console, FOREGROUND_RED);
        WriteLn(Format('ICMP [Type=%d Code=%d Checksum=0x%.4x Body=0x%.8x]', [
          icmp_header^._Type, icmp_header^.Code,
          ntohs(icmp_header^.Checksum), ntohl(icmp_header^.Body)
        ]));
      end;

      if (icmpv6_header <> nil) then begin
        SetConsoleTextAttribute(console, FOREGROUND_RED);
        WriteLn(Format('ICMPV6 [Type=%d Code=%d Checksum=0x%.4x Body=0x%.8x]', [
          icmpv6_header^._Type, icmpv6_header^.Code,
          ntohs(icmpv6_header^.Checksum), ntohl(icmpv6_header^.Body)
        ]));
      end;

      if (tcp_header <> nil) then begin
        SetConsoleTextAttribute(console, FOREGROUND_GREEN);
        Get4Bits(tcp_header^.Reserved1_HdrLength, uReserved1, uHdrLength);
        uReserved2 := uReserved2;
        if (fReserved20 in tcp_header^.Flags) then
					Inc(uReserved2);
        if (fReserved21 in tcp_header^.Flags) then
					Inc(uReserved2, 2);
        WriteLn(Format(STcpHdr, [
          ntohs(tcp_header^.SrcPort), ntohs(tcp_header^.DstPort),
          ntohl(tcp_header^.SeqNum), ntohl(tcp_header^.AckNum),
          uHdrLength, uReserved1,
          uReserved2,
          Ord(fUrg in tcp_header^.Flags), Ord(fAck in tcp_header^.Flags),
          Ord(fPsh in tcp_header^.Flags), Ord(fRst in tcp_header^.Flags),
          Ord(fSyn in tcp_header^.Flags), Ord(fFin in tcp_header^.Flags),
          ntohs(tcp_header^.Window),
          ntohs(tcp_header^.Checksum), ntohs(tcp_header^.UrgPtr)
        ]));
      end;

      if (udp_header <> nil) then begin
        SetConsoleTextAttribute(console, FOREGROUND_GREEN);
        WriteLn(Format('UDP [SrcPort=%d DstPort=%d Length=%d Checksum=0x%.4x]', [
          ntohs(udp_header^.SrcPort), ntohs(udp_header^.DstPort),
          ntohs(udp_header^.Length), ntohs(udp_header^.Checksum)
        ]));
      end;

      SetConsoleTextAttribute(console, FOREGROUND_GREEN or FOREGROUND_BLUE);
      for i := 0 to packet_len - 1 do begin
        if (i mod 20 = 0) then begin
          WriteLn;
          Write(#9);
        end;
        Write(Format('%.2x', [packet[i]]));
      end;

      SetConsoleTextAttribute(console, FOREGROUND_RED or FOREGROUND_BLUE);
      for i := 0 to packet_len - 1 do begin
        if (i mod 40 = 0) then begin
          WriteLn;
          Write(#9);
        end;
        if isprint(AnsiChar(packet[i])) then
          Write(AnsiChar(packet[i]))
        else
          Write('.');
      end;

      WriteLn;
      SetConsoleTextAttribute(console, FOREGROUND_RED or FOREGROUND_GREEN or FOREGROUND_BLUE);
    end;
  except
    on E: Exception do
      Writeln(E.ClassName, ': ', E.Message);
  end;
end.
