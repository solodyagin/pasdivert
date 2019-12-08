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
  Classes,
  regexpr,
  windivert in '..\..\windivert.pas',
  elevate in '..\..\elevate.pas';

const
  MAXBUF = $FFFF;

{*
 * Pre-fabricated packets.
 *}
type
  TPacket = record
    ipHdr: TWinDivertIpHdr;
    tcpHdr: TWinDivertTcpHdr;
  end;

{*
 * The block page contents.
 *}
const
  BlockpageData: AnsiString =
    'HTTP/1.1 200 OK' + #13#10 +
    'Connection: close' + #13#10 +
    'Content-Type: text/html' + #13#10 +
    #13#10 +
    '<!DOCTYPE HTML>' + #13#10 +
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
  hConsole: THandle;
  hWinDivert: THandle;
  Blacklist: TStringList;

 {*
  * Prototypes
  *}
  procedure PacketInit(var packet: TPacket);
  begin
    FillByte(packet, SizeOf(TPacket), 0);
    //packet.ipHdr.HdrLength = SizeOf(TWinDivertIpHdr) / SizeOf(UINT32);
    //packet.ipHdr.Version = 4;
    packet.ipHdr.HdrLength_Version := 69;
    packet.ipHdr.Length := htons(SizeOf(TPacket));
    packet.ipHdr.TTL := 64;
    packet.ipHdr.Protocol := IPPROTO_TCP;
    //packet.tcpHdr.HdrLength := SizeOf(TWinDivertTcpHdr) / SizeOf(UINT32);
    packet.tcpHdr.Reserved1_HdrLength := 80;
  end;

  function BlacklistPayloadMatch(blacklist: TStringList; data: PChar; len: UINT16): Boolean;
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
      if SL.Count = 0 then
        Exit;

      S := SL.Strings[0];

      RE := TRegExpr.Create;
      try
        RE.Expression := '^(GET|POST|HEAD) (.*) HTTP/\d\.\d$';
        if RE.Exec(S) then
        begin
          uri := RE.Match[2];
          if uri = '/' then
            uri := '';

          for I := 0 to SL.Count - 1 do
          begin
            S := SL.Strings[I];
            if Pos('Host:', S) = 1 then
            begin
              Delete(S, 1, 5);
              domain := SysUtils.Trim(S);
              Break;
            end;
          end;

          URL := domain + uri;

          SetConsoleTextAttribute(hConsole, FOREGROUND_RED or FOREGROUND_GREEN or FOREGROUND_BLUE);
          Write(Format('URL %s: ', [URL]));

          for I := 0 to blacklist.Count - 1 do
          begin
            if AnsiPos(blacklist.Strings[I], URL) = 1 then
            begin
              Result := True;
              Break;
            end;
          end;

          if Result then
          begin
            SetConsoleTextAttribute(hConsole, FOREGROUND_RED);
            Writeln('BLOCKED!');
          end
          else
          begin
            SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN);
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
  function Capture(arg: Pointer): DWORD; stdcall;
  var
    addr: TWinDivertAddress;
    packet: array[0..MAXBUF - 1] of UINT8;
    packetLen: UINT;
    pIpHdr: PWinDivertIpHdr;
    pTcpHdr: PWinDivertTcpHdr;
    payload: Pointer;
    payloadLen: UINT;
    reset: TPacket;
    finish: TPacket;
    blockpage: array of UINT8;
    blockpageHdr: TPacket;
    blockpageLen: UINT16;
    writeLen: UINT;
  begin
    // Initialize the pre-frabricated packets:
    blockpageLen := SizeOf(TPacket) + Length(BlockPageData);
    SetLength(blockpage, blockpageLen);
    PacketInit(blockpageHdr);
    blockpageHdr.ipHdr.Length := htons(blockpageLen);
    blockpageHdr.tcpHdr.SrcPort := htons(80);
    SetBit(blockpageHdr.tcpHdr.Flags, 3); // Psh
    SetBit(blockpageHdr.tcpHdr.Flags, 4); // Ack
    Move(blockpageHdr, blockpage[0], SizeOf(TPacket));
    Move(BlockPageData[1], blockpage[SizeOf(TPacket)], Length(BlockPageData));
    PacketInit(reset);
    SetBit(reset.tcpHdr.Flags, 3); // Psh
    SetBit(reset.tcpHdr.Flags, 4); // Ack
    PacketInit(finish);
    SetBit(finish.tcpHdr.Flags, 0); // Fin
    SetBit(finish.tcpHdr.Flags, 4); // Ack

{$IFDEF FPC}
    Initialize(packet);
{$ENDIF}

    while True do
    begin
      if not WinDivertRecv(hWinDivert, packet, SizeOf(packet), addr, packetLen) then
      begin
        SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN or FOREGROUND_RED);
        Writeln(Format('Warning: failed to read packet (%u)', [GetLastError()]));
        Continue;
      end;

      if (not WinDivertHelperParsePacket(packet, packetLen, @pIpHdr, nil, nil, nil, @pTcpHdr,
        nil, @payload, @payloadLen)) or (not BlacklistPayloadMatch(Blacklist, payload, payloadLen)) then
      begin
        // Packet does not match the blacklist; simply reinject it.
        if not WinDivertSend(hWinDivert, packet, packetLen, @addr, writeLen) then
        begin
          SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN or FOREGROUND_RED);
          Writeln(Format('Warning: failed to reinject packet (%u)', [GetLastError()]));
        end;
        Continue;
      end;

      // The URL matched the blacklist; we block it by hijacking the TCP
      // connection.

      // (1) Send a TCP RST to the server; immediately closing the
      //     connection at the server's end.
      reset.ipHdr.SrcAddr := pIpHdr^.SrcAddr;
      reset.ipHdr.DstAddr := pIpHdr^.DstAddr;
      reset.tcpHdr.SrcPort := pTcpHdr^.SrcPort;
      reset.tcpHdr.DstPort := htons(80);
      reset.tcpHdr.SeqNum := pTcpHdr^.SeqNum;
      reset.tcpHdr.AckNum := pTcpHdr^.AckNum;
      WinDivertHelperCalcChecksums(reset, SizeOf(TPacket), @addr, 0);
      if not WinDivertSend(hWinDivert, reset, SizeOf(TPacket), @addr, writeLen) then
      begin
        SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN or FOREGROUND_RED);
        Writeln(Format('Warning: failed to send reset packet (%u)', [GetLastError()]));
      end;

      // (2) Send the blockpage to the browser:
      blockpageHdr.ipHdr.SrcAddr := pIpHdr^.DstAddr;
      blockpageHdr.ipHdr.DstAddr := pIpHdr^.SrcAddr;
      blockpageHdr.tcpHdr.DstPort := pTcpHdr^.SrcPort;
      blockpageHdr.tcpHdr.SeqNum := pTcpHdr^.AckNum;
      blockpageHdr.tcpHdr.AckNum := htonl(ntohl(pTcpHdr^.SeqNum) + payloadLen);
      Move(blockpageHdr, blockpage[0], SizeOf(TPacket));
      WinDivertHelperCalcChecksums(blockpage[0], blockpageLen, @addr, 0);
      // Reverse direction.
      //addr.Direction := UINT8(not (Boolean(addr.Direction)));
      if GetBit(addr.Direction_Reserved, 0) = 0 then
        SetBit(addr.Direction_Reserved, 0)
      else
        ClearBit(addr.Direction_Reserved, 0);
      if not WinDivertSend(hWinDivert, blockpage[0], blockpageLen, @addr, writeLen) then
      begin
        SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN or FOREGROUND_RED);
        Writeln(Format('Warning: failed to send block page packet (%u)', [GetLastError()]));
      end;

      // (3) Send a TCP FIN to the browser; closing the connection at the
      //     browser's end.
      finish.ipHdr.SrcAddr := pIpHdr^.DstAddr;
      finish.ipHdr.DstAddr := pIpHdr^.SrcAddr;
      finish.tcpHdr.SrcPort := htons(80);
      finish.tcpHdr.DstPort := pTcpHdr^.SrcPort;
      finish.tcpHdr.SeqNum := htonl(ntohl(pTcpHdr^.AckNum) + Length(BlockPageData));
      finish.tcpHdr.AckNum := htonl(ntohl(pTcpHdr^.SeqNum) + payloadLen);
      WinDivertHelperCalcChecksums(finish, SizeOf(TPacket), @addr, 0);
      if not WinDivertSend(hWinDivert, finish, SizeOf(TPacket), @addr, writeLen) then
      begin
        SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN or FOREGROUND_RED);
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
  thHandle: THandle;
  thId: DWORD;
  key: Word;
  exitCode: DWORD;
begin
  RunElevated;

  // Read the blacklists.
  if ParamCount = 0 then
  begin
    Writeln(Format('Usage: %s blacklist.txt [blacklist2.txt ...]', [ParamStr(0)]));
    Halt(1);
  end;

  try
    Blacklist := TStringList.Create;
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
            Blacklist.Add(S);
            Writeln('ADD ' + S);
          end;
        end;
        SL.Free;
      end;
      Blacklist.Sort;

      // Get console for pretty colors.
      hConsole := GetStdHandle(STD_OUTPUT_HANDLE);

      // Open the Divert device:
      hWinDivert := WinDivertOpen(
        'outbound && ' +             // Outbound traffic only
        'ip && ' +                   // Only IPv4 supported
        'tcp.DstPort == 80 && ' +    // HTTP (port 80) only
        'tcp.PayloadLength > 0',     // TCP data packets only
        WINDIVERT_LAYER_NETWORK, priority, 0);
      if hWinDivert = INVALID_HANDLE_VALUE then
      begin
        SetConsoleTextAttribute(hConsole, FOREGROUND_RED);
        Writeln(Format('Error: failed to open the WinDivert device (%u)', [GetLastError()]));
        Halt(1);
      end;

      SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN);
      Writeln('OPENED WinDivert');

      // Create thread
      thHandle := CreateThread(nil, 0, @Capture, nil, 0, thId);
      if thHandle = 0 then
      begin
        SetConsoleTextAttribute(hConsole, FOREGROUND_RED);
        Writeln(Format('Error: failed to start thread (%u)', [GetLastError]));
        Halt(1);
      end;
      SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN);
      Writeln('Running. Press `q` to terminate, `h` for help.');

      while True do
      begin
        key := KeyPressed;
        case key of
          Ord('Q'):
          begin
            // Quit
            SetConsoleTextAttribute(hConsole, FOREGROUND_RED or FOREGROUND_GREEN or FOREGROUND_BLUE);
            Write('Really? [y/n]: ');
            key := KeyPressed;
            if key = Ord('Y') then
            begin
              Writeln('Yesss');
              Break;
            end
            else
              Writeln('Noooo!');
          end;
          Ord('H'):
          begin
            SetConsoleTextAttribute(hConsole, FOREGROUND_RED or FOREGROUND_GREEN or FOREGROUND_BLUE);
            Writeln('q: Quit');
            Writeln('h: Show this help');
          end;
        end;
        Sleep(10);
      end; { while }

      SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN);
      Writeln('Stopping...');
      exitCode := 0;
      GetExitCodeThread(thHandle, exitCode);
      // The thread doesn't have to clean up stuff, so I think it's safe to call
      // just TerminateThread()
      TerminateThread(thHandle, exitCode);
      // Wait for thread
      WaitForSingleObject(thHandle, 5000);

    finally
      Blacklist.Free;
    end;

    WinDivertClose(hWinDivert);
    SetConsoleTextAttribute(hConsole, FOREGROUND_RED);
    Writeln('Hasta la vista, baby');
    SetConsoleTextAttribute(hConsole, FOREGROUND_RED or FOREGROUND_GREEN or FOREGROUND_BLUE);

  except
    on E: Exception do
    begin
      SetConsoleTextAttribute(hConsole, FOREGROUND_RED);
      Writeln(E.ClassName, ': ', E.Message);
    end;
  end;
end.
