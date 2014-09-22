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
	TAddr = packed array[0..3] of UINT8;

resourcestring
	SIpv4Hdr = 'IPv4 [Version=%d HdrLength=%d TOS=%d Length=%d Id=0x%.4x ' +
  	'Reserved=%d DF=%d MF=%d FragOff=%d TTL=%u Protocol=%d ' +
    'Checksum=0x%.4x SrcAddr=%d.%d.%d.%d DstAddr=%d.%d.%d.%d]';

var
	priority: INT16;
  handle, console: THandle;
  filter: string;
  packet: array[0..MAXBUF] of Byte;
  addr: TWinDivertAddress;
  packet_len: UINT;
  ip_header: PWinDivertIpHdr;
  ipv6_header: PWinDivertIpv6Hdr;
  icmp_header: PWinDivertIcmpHdr;
  icmpv6_header: PWinDivertIcmpv6Hdr;
  tcp_header: PWinDivertTcpHdr;
  udp_header: PWinDivertUdpHdr;
  src_addr: TAddr;
  dst_addr: TAddr;
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
      if not WinDivertRecv(handle, @packet, SizeOf(packet), @addr, packet_len) then begin
        WriteLn(Format('warning: failed to read packet (%d)', [GetLastError]));
        Continue;
      end;

      // Print info about the matching packet.
      WinDivertHelperParsePacket(@packet, packet_len,
      	@ip_header, @ipv6_header, @icmp_header, @icmpv6_header, @tcp_header,
        @udp_header, nil, nil);
      if (ip_header = nil) and (ipv6_header = nil) then
      	WriteLn('warning: junk packet');

      // Dump packet info:
      WriteLn;
      SetConsoleTextAttribute(console, FOREGROUND_RED);
      WriteLn(Format('Packet [Direction=%d IfIdx=%d SubIfIdx=%d]', [addr.Direction, addr.IfIdx, addr.SubIfIdx]));

      if (ip_header <> nil) then begin
        SetConsoleTextAttribute(console, FOREGROUND_GREEN or FOREGROUND_RED);
        src_addr := TAddr(ip_header^.SrcAddr);
        dst_addr := TAddr(ip_header^.DstAddr);

        WriteLn(Format(SIpv4Hdr, [
        	ip_header^.Version, ip_header^.HdrLength,
          ntohs(ip_header^.TOS), ntohs(ip_header^.Length),
          ntohs(ip_header^.Id), WINDIVERT_IPHDR_GET_RESERVED(ip_header),
          WINDIVERT_IPHDR_GET_DF(ip_header),
          WINDIVERT_IPHDR_GET_MF(ip_header),
          ntohs(WINDIVERT_IPHDR_GET_FRAGOFF(ip_header)), ip_header^.TTL,
          ip_header^.Protocol, ntohs(ip_header^.Checksum),
          src_addr[0], src_addr[1], src_addr[2], src_addr[3],
          dst_addr[0], dst_addr[1], dst_addr[2], dst_addr[3]
        ]));
      end;

      // More to come...
    end;
  except
    on E: Exception do
      Writeln(E.ClassName, ': ', E.Message);
  end;
end.
