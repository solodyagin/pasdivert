{*
 * This is a simple DNS traffic monitor using WinDivert.
 *
 * It uses a WinDivert handle in SNIFF mode.
 * The SNIFF mode copies packets and does not block the original.
 *}
program dnsdump;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

{$APPTYPE CONSOLE}

uses
  SysUtils,
  Windows,
  Classes,
  WinSock,
  windivert in '..\..\windivert.pas',
  elevate in '..\..\elevate.pas',
  dnshelper in 'dnshelper.pas';

  function IsPrint(const C: AnsiChar): Boolean;
  begin
    Result := (C >= ' ') and (C <= '~') and (Ord(C) <> $7F);
  end;

var
  hConsole: THandle;
  hWinDivert: THandle;

  {*
   * Thread function
   *}
  function Capture(arg: Pointer): DWORD; stdcall;
  var
    addr: TWinDivertAddress;
    packet: TByteArray;
    packetLen: UINT;
    ipHdr: PWinDivertIpHdr;
    udpHdr: PWinDivertUdpHdr;
    payload: PByteArray;
    payloadLen: UINT;
    writeLen: UINT;
    data: AnsiString;
    DH: TDnsHelper;
    SL: TStringList;
    i: Integer;
    b: Byte;
    h: Integer;
    t: Integer;
  begin
{$IFDEF FPC}
    Initialize(packet);
{$ENDIF}

    while True do
    begin
      // Read a matching packet.
      if not WinDivertRecv(hWinDivert, packet, SizeOf(packet), addr, packetLen) then
      begin
        SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN or FOREGROUND_RED);
        Writeln(Format('Warning: failed to read packet (%u)', [GetLastError()]));
        Continue;
      end;

      // Print info about the matching packet.
      if WinDivertHelperParsePacket(packet, packetLen, @ipHdr, nil, nil, nil, nil, @udpHdr,
        @payload, @payloadLen) then
      begin
        SetConsoleTextAttribute(hConsole, FOREGROUND_RED);
        Writeln(Format('Packet [Direction=%d IfIdx=%d SubIfIdx=%d]', [GetAddrDirection(@addr),
          addr.IfIdx, addr.SubIfIdx]));

        SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN);
        Writeln(Format('UDP [SrcPort=%d DstPort=%d Length=%d Checksum=0x%.4x]',
          [ntohs(udpHdr^.SrcPort), ntohs(udpHdr^.DstPort), ntohs(udpHdr^.Length),
          ntohs(udpHdr^.Checksum)]));

        SetConsoleTextAttribute(hConsole, FOREGROUND_RED or FOREGROUND_GREEN);
        SetLength(data, payloadLen);
        Move(payload^[0], data[1], payloadLen);

        DH := TDnsHelper.Create(data);
        try
          if DH.DecodeData then
          begin
            Writeln(Format('ID: 0x%0:0.4x', [DH.ID]));
            Writeln(Format('Flags: 0x%0:0.4x', [DH.Flags.Raw]));
            Writeln(#9 + Format('QR: %u', [DH.Flags.QR]));
            Writeln(#9 + Format('OPCODE: %u', [DH.Flags.OPCODE]));
            Writeln(#9 + Format('AA (Authoritative Answer): %u', [DH.Flags.AA]));
            Writeln(#9 + Format('TC (Truncated Response): %u', [DH.Flags.TC]));
            Writeln(#9 + Format('RD (Recursion Desired): %u', [DH.Flags.RD]));
            Writeln(#9 + Format('RA (Recursion Available): %u', [DH.Flags.RA]));
            Writeln(#9 + Format('RCODE: %u', [DH.Flags.RCODE]));
            Writeln('Questions (QDCOUNT): ', DH.QDCOUNT);
            Writeln(DH.QuestionInfo.Text);
            Writeln('Answer Resource Records (ANCOUNT): ', DH.ANCOUNT);
            Writeln(DH.AnswerInfo.Text);
            Writeln('Authority Resource Records (NSCOUNT): ', DH.NSCOUNT);
            Writeln(DH.AuthorityInfo.Text);
            Writeln('Additional Resource Records (ARCOUNT): ', DH.ARCOUNT);
            Writeln(DH.AdditionalInfo.Text);
          end;
        finally
          DH.Free;
        end;
        SetLength(data, 0);

        // Dump packet
        SL := TStringList.Create;
        try
          h := 0;
          t := 1;
          for i := 0 to packetLen do
          begin
          if (i mod 32 = 0) then
            begin
              h := SL.Add(Format('0x%0:0.4x:', [i]));
              t := SL.Add(Format('%7s', [' ']));
            end;
            b := packet[i];

            // Hex line
            SL.Strings[h] := SL.Strings[h] + Format('%3.2x', [b]);

            // Text line
            if IsPrint(AnsiChar(b)) then
              SL.Strings[t] := SL.Strings[t] + Format('%0:3s', [AnsiChar(b)])
            else
              SL.Strings[t] := SL.Strings[t] + Format('%0:3s', ['.']);
          end;
          for i := 0 to SL.Count - 1 do
          begin
            if (i mod 2 = 0) then
              SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN or FOREGROUND_BLUE)
            else
              SetConsoleTextAttribute(hConsole, FOREGROUND_RED or FOREGROUND_BLUE);
            Writeln(SL.Strings[i]);
          end;
        finally
          SL.Free;
        end;
      end;

      // Reinject
      if not WinDivertSend(hWinDivert, packet, packetLen, @addr, writeLen) then
      begin
        SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN or FOREGROUND_RED);
        Writeln(Format('Warning: failed to reinject packet (%u)', [GetLastError()]));
      end;

      SetConsoleTextAttribute(hConsole, FOREGROUND_RED or FOREGROUND_GREEN or FOREGROUND_BLUE);
      Writeln('------------------------------');

    end; { while }

{$IFDEF FPC}
    Finalize(packet);
{$ENDIF}

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
  priority: INT16 = 404; // Arbitrary.
  thHandle: THandle;
  thId: DWORD = 0;
  key: Word;
  exitCode: DWORD;
begin
  RunElevated;

  try
    // Get console for pretty colors.
    hConsole := GetStdHandle(STD_OUTPUT_HANDLE);

    // Open the Divert device:
    hWinDivert := WinDivertOpen(
      //'outbound and ' +    // Outbound traffic only
      //'ip and ' +          // Only IPv4 supported
      //'udp.DstPort == 53', // DNS (port 53) only
      'ip and udp.DstPort == 53 or udp.SrcPort == 53',
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
    if (thHandle = 0) then
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
