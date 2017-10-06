{*
 * webfilter
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

{*
 * DESCRIPTION:
 * This is a simple web (HTTP) filter using WinDivert.
 *
 * It works by intercepting outbound HTTP GET/POST requests and matching
 * the URL against a blacklist.  If the URL is matched, we hijack the TCP
 * connection, reseting the connection at the server end, and sending a
 * blockpage to the browser.
 *}

program webfilter;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

{$APPTYPE CONSOLE}

uses
  SysUtils,
  Windows,
  Winsock,
  Classes, regexpr,
  windivert in 'windivert.pas',
  elevate in 'elevate.pas';

procedure SetBit(var Value: Byte; Index: Byte);
begin
  Value := Value or (1 shl Index);
end;

const
  MAXBUF = $FFFF;

{*
 * Pre-fabricated packets.
 *}
type
  TPacket = record
    ip: TWinDivertIpHdr;
    tcp: TWinDivertTcpHdr;
  end;
  PPacket = ^TPacket;

{*
 * The block page contents.
 *}
const
  block_data: AnsiString =
    'HTTP/1.1 200 OK' + #13#10 +
    'Connection: close' + #13#10 +
    'Content-Type: text/html' + #13#10 +
    #13#10 +
    '<!doctype html>' + #13#10 +
    '<html>' + #13#10 +
    '<head>' + #13#10 +
    '<title>BLOCKED!</title>' + #13#10 +
    '</head>' + #13#10 +
    '<body>' + #13#10 +
    '<h1>BLOCKED!</h1>' + #13#10 +
    '<hr>' + #13#10 +
    '<p>This URL has been blocked!</p>' + #13#10 +
    '</body>' + #13#10 +
    '</html>';

var
  console: THandle;
  handle: THandle;
  blacklist: TStringList;

{*
 * Prototypes
 *}
procedure PacketInit(var packet: TPacket);
begin
  FillByte(packet, SizeOf(TPacket), 0);
  //packet.ip.HdrLength = SizeOf(TWinDivertIpHdr) / SizeOf(UINT32);
  //packet.ip.Version = 4;
  packet.ip.HdrLength_Version := 69;
  packet.ip.Length := htons(SizeOf(TPacket));
  packet.ip.TTL := 64;
  packet.ip.Protocol := IPPROTO_TCP;
  //packet.tcp.HdrLength := SizeOf(TWinDivertTcpHdr) / SizeOf(UINT32);
  packet.tcp.Reserved1_HdrLength := 80;
end;

function BlackListPayloadMatch(blacklist: TStringList; data: PChar; len: UINT16): Boolean;
var
  SL: TStringList;
  S: AnsiString;
  I: Integer;
  RE: TRegExpr;
  domain: AnsiString;
  uri: AnsiString;
  URL: AnsiString;
begin
  Result := False;

  SL := TStringList.Create;
  try
    SL.Text := StrPas(data);
    if (SL.Count = 0) then Exit;

    S := SL.Strings[0];

    RE := TRegExpr.Create;
    try
      RE.Expression := '^(GET|POST|HEAD) (.*) HTTP/\d\.\d$';
      if RE.Exec(S) then
      begin
        uri := RE.Match[2];
        if (uri = '/') then uri := '';

        for I := 0 to SL.Count - 1 do
        begin
          S := SL.Strings[I];
          if (Pos('Host:', S) = 1) then
          begin
            Delete(S, 1, 5);
            domain := SysUtils.Trim(S);
            Break;
          end;
        end;

        URL := domain + uri;

        SetConsoleTextAttribute(console, FOREGROUND_RED or FOREGROUND_GREEN or FOREGROUND_BLUE);
        Write(Format('URL %s: ', [URL]));

        for I := 0 to blacklist.Count - 1 do
        begin
          if (AnsiPos(blacklist.Strings[I], URL) = 1) then
          begin
            Result := True;
            Break;
          end;
        end;

        if (Result) then
        begin
          SetConsoleTextAttribute(console, FOREGROUND_RED);
          Writeln('BLOCKED!');
        end
        else
        begin
          SetConsoleTextAttribute(console, FOREGROUND_GREEN);
          Writeln('allowed');
        end;
      end;
    finally
      RE.Free;
    end;
  finally
    SL.Free;
  end;
end;

{*
 * Thread function
 *}
function passthr(arg: Pointer): DWORD; stdcall;
var
  addr: WINDIVERT_ADDRESS;
  packet: array[0..MAXBUF - 1] of UINT8;
  packet_len: UINT;
  ip_header: PWinDivertIpHdr;
  tcp_header: PWinDivertTcpHdr;
  payload: Pointer;
  payload_len: UINT;
  reset: TPacket;
  finish: TPacket;
  blockpage: array of UINT8;
  blockpage_hdr: TPacket;
  blockpage_len: UINT16;
  writeLen: UINT;
begin
  // Initialize the pre-frabricated packets:
  blockpage_len := SizeOf(TPacket) + Length(block_data);
  SetLength(blockpage, blockpage_len);
  PacketInit(blockpage_hdr);
  blockpage_hdr.ip.Length := htons(blockpage_len);
  blockpage_hdr.tcp.SrcPort := htons(80);
  SetBit(blockpage_hdr.tcp.Flags, 3); // Psh
  SetBit(blockpage_hdr.tcp.Flags, 4); // Ack
  Move(blockpage_hdr, blockpage[0], SizeOf(TPacket));
  Move(block_data[1], blockpage[SizeOf(TPacket)], Length(block_data));
  PacketInit(reset);
  SetBit(reset.tcp.Flags, 3); // Psh
  SetBit(reset.tcp.Flags, 4); // Ack
  PacketInit(finish);
  SetBit(finish.tcp.Flags, 0); // Fin
  SetBit(finish.tcp.Flags, 4); // Ack

{$IFDEF FPC}
  Initialize(packet);
{$ENDIF}

  while True do
  begin
    if (not WinDivertRecv(handle, packet, SizeOf(packet), addr, packet_len)) then
    begin
      SetConsoleTextAttribute(console, FOREGROUND_GREEN or FOREGROUND_RED);
      Writeln(Format('Warning: failed to read packet (%u)', [GetLastError()]));
      Continue;
    end;

    if ((not WinDivertHelperParsePacket(packet, packet_len, @ip_header, nil,
           nil, nil, @tcp_header, nil, @payload, @payload_len)) or
        (not BlackListPayloadMatch(blacklist, payload, payload_len))) then
    begin
      // Packet does not match the blacklist; simply reinject it.
      if (not WinDivertSend(handle, packet, packet_len, @addr, writeLen)) then
      begin
        SetConsoleTextAttribute(console, FOREGROUND_GREEN or FOREGROUND_RED);
        Writeln(Format('Warning: failed to reinject packet (%u)', [GetLastError()]));
      end;
      Continue;
    end;

    // The URL matched the blacklist; we block it by hijacking the TCP
    // connection.

    // (1) Send a TCP RST to the server; immediately closing the
    //     connection at the server's end.
    reset.ip.SrcAddr := ip_header.SrcAddr;
    reset.ip.DstAddr := ip_header.DstAddr;
    reset.tcp.SrcPort := tcp_header.SrcPort;
    reset.tcp.DstPort := htons(80);
    reset.tcp.SeqNum := tcp_header.SeqNum;
    reset.tcp.AckNum := tcp_header.AckNum;
    WinDivertHelperCalcChecksums(reset, SizeOf(TPacket), 0);
    if (not WinDivertSend(handle, reset, SizeOf(TPacket), @addr, writeLen)) then
    begin
      SetConsoleTextAttribute(console, FOREGROUND_GREEN or FOREGROUND_RED);
      Writeln(Format('Warning: failed to send reset packet (%u)', [GetLastError()]));
    end;

    // (2) Send the blockpage to the browser:
    blockpage_hdr.ip.SrcAddr := ip_header.DstAddr;
    blockpage_hdr.ip.DstAddr := ip_header.SrcAddr;
    blockpage_hdr.tcp.DstPort := tcp_header.SrcPort;
    blockpage_hdr.tcp.SeqNum := tcp_header.AckNum;
    blockpage_hdr.tcp.AckNum := htonl(ntohl(tcp_header.SeqNum) + payload_len);
    Move(blockpage_hdr, blockpage[0], SizeOf(TPacket));
    WinDivertHelperCalcChecksums(blockpage[0], blockpage_len, 0);
    addr.Direction := UINT8(not (Boolean(addr.Direction)));     // Reverse direction.
    if (not WinDivertSend(handle, blockpage[0], blockpage_len, @addr, writeLen)) then
    begin
      SetConsoleTextAttribute(console, FOREGROUND_GREEN or FOREGROUND_RED);
      Writeln(Format('Warning: failed to send block page packet (%u)', [GetLastError()]));
    end;

    // (3) Send a TCP FIN to the browser; closing the connection at the
    //     browser's end.
    finish.ip.SrcAddr := ip_header.DstAddr;
    finish.ip.DstAddr := ip_header.SrcAddr;
    finish.tcp.SrcPort := htons(80);
    finish.tcp.DstPort := tcp_header.SrcPort;
    finish.tcp.SeqNum := htonl(ntohl(tcp_header.AckNum) + Length(block_data));
    finish.tcp.AckNum := htonl(ntohl(tcp_header.SeqNum) + payload_len);
    WinDivertHelperCalcChecksums(finish, SizeOf(TPacket), 0);
    if (not WinDivertSend(handle, finish, SizeOf(TPacket), @addr, writeLen)) then
    begin
      SetConsoleTextAttribute(console, FOREGROUND_GREEN or FOREGROUND_RED);
      Writeln(Format('Warning: failed to send finish packet (%u)', [GetLastError()]));
    end;
  end; { while }

  Result := 0;
end;

{*
 * Waits until a key was pressed and returns the VK_ code.
 *}
function KeyPressed: Word;
var
  Read: Cardinal;
  Hdl: THandle;
  Rec: _INPUT_RECORD;
begin
  Hdl := GetStdHandle(STD_INPUT_HANDLE);
  Read := 0;
  repeat
    Rec.EventType := KEY_EVENT;
    ReadConsoleInput(Hdl, Rec, 1, Read);
  until (Read = 1) and (Rec.Event.KeyEvent.bKeyDown);
  Result := Rec.Event.KeyEvent.wVirtualKeyCode;
end;

{*
 * Entry.
 *}
var
  SL: TStringList;
  I, J: Integer;
  S: String;
  priority: INT16 = 404; // Arbitrary.
  ThHandle: THandle;
  ThId: DWORD;
  key: Word;
  exit_code: DWORD;
begin
  RunElevated;

  // Read the blacklists.
  if (ParamCount = 0) then
  begin
    Writeln(Format('Usage: %s blacklist.txt [blacklist2.txt ...]', [ParamStr(0)]));
    Halt(1);
  end;

  try
    blacklist := TStringList.Create;
    try

      // Load blacklist
      for I := 1 to ParamCount do
      begin
        SL := TStringList.Create;
        SL.LoadFromFile(ParamStr(I));
        for J := 0 to SL.Count - 1 do
        begin
          S := Trim(SL.Strings[J]);
          if (S <> '') then
          begin
            blacklist.Add(S);
            Writeln('ADD ' + S);
          end;
        end;
        SL.Free;
      end;
      blacklist.Sort;

      // Get console for pretty colors.
      console := GetStdHandle(STD_OUTPUT_HANDLE);

      // Open the Divert device:
      handle := WinDivertOpen(
              'outbound && ' +             // Outbound traffic only
              'ip && ' +                   // Only IPv4 supported
              'tcp.DstPort == 80 && ' +    // HTTP (port 80) only
              'tcp.PayloadLength > 0',     // TCP data packets only
              WINDIVERT_LAYER_NETWORK, priority, 0
          );
      if (handle = INVALID_HANDLE_VALUE) then
      begin
        SetConsoleTextAttribute(console, FOREGROUND_RED);
        Writeln(Format('Error: failed to open the WinDivert device (%u)', [GetLastError()]));
        Halt(1);
      end;

      SetConsoleTextAttribute(console, FOREGROUND_GREEN);
      Writeln('OPENED WinDivert');

      // Create thread
      ThHandle := CreateThread(nil, 0, @passthr, nil, 0, ThId);
      if (ThHandle = 0) then
      begin
        SetConsoleTextAttribute(console, FOREGROUND_RED);
        WriteLn(Format('Error: failed to start thread (%u)', [GetLastError]));
        Halt(1);
      end;
      SetConsoleTextAttribute(console, FOREGROUND_GREEN);
      WriteLn('Running. Press `q` to terminate, `h` for help.');

      while (True) do
      begin
        key := KeyPressed;
        case key of
          Ord('Q'):
          begin
            // Quit
            SetConsoleTextAttribute(console, FOREGROUND_RED or FOREGROUND_GREEN or FOREGROUND_BLUE);
            Write('Really? [y/n]: ');
            key := KeyPressed;
            if (key = Ord('Y')) then
            begin
              WriteLn('Yesss');
              Break;
            end
            else
              WriteLn('Noooo!');
          end;
          Ord('H'):
          begin
            SetConsoleTextAttribute(console, FOREGROUND_RED or FOREGROUND_GREEN or FOREGROUND_BLUE);
            WriteLn('q: Quit');
            WriteLn('h: Show this help');
          end;
        end;
        Sleep(10);
      end; { while }

      SetConsoleTextAttribute(console, FOREGROUND_GREEN);
      WriteLn('Stopping...');
      exit_code := 0;
      GetExitCodeThread(ThHandle, exit_code);
      // The thread doesn't have to clean up stuff, so I think it's safe to call
      // just TerminateThread()
      TerminateThread(ThHandle, exit_code);
      // Wait for thread
      WaitForSingleObject(ThHandle, 5000);

    finally
      blacklist.Free;
    end;

    WinDivertClose(handle);
    SetConsoleTextAttribute(console, FOREGROUND_RED);
    WriteLn('Hasta la vista, baby');
    SetConsoleTextAttribute(console, FOREGROUND_RED or FOREGROUND_GREEN or FOREGROUND_BLUE);

  except
    on E: Exception do
    begin
      SetConsoleTextAttribute(console, FOREGROUND_RED);
      Writeln(E.ClassName, ': ', E.Message);
    end;
  end;
end.
