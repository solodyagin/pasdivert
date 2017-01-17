{*
 * netlimit
 * (C) 2017, all rights reserved,
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

program netlimit;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

{$APPTYPE CONSOLE}

uses
  SysUtils,
  Windows,
  windivert in 'windivert.pas';

const
  MAXBUF = $FFFF;

var
  latency: integer;
  drops: integer;
  console: THandle;
  handle: THandle;
  drop_all: boolean = false;

function passthr(arg: Pointer): DWORD;
var
  packet: array[0..MAXBUF-1] of Byte;
  packetLen, writeLen: UINT;
  addr: TWinDivertAddress;
  sleep_ms: integer;
  per: integer;
begin
  while (true) do begin
    // Read a matching packet.
    if not WinDivertRecv(handle, packet, SizeOf(packet), addr, packetLen) then begin
      SetConsoleTextAttribute(console, FOREGROUND_RED);
      WriteLn(Format('Warning: failed to read packet (%d)', [GetLastError]));
      Continue;
    end;

    // Sleep for (latency * 0.5) - (latency * 1.5)
    sleep_ms := Trunc(latency * (Random + 0.5));
    if (sleep_ms > 0) then
      Sleep(sleep_ms);
    per := Random(100);

    if ((drops > 0) and (per <= drops)) or drop_all then begin
      // Drop it
      if not drop_all then begin
        SetConsoleTextAttribute(console, FOREGROUND_GREEN or FOREGROUND_RED);
        WriteLn(Format('Info: dropped packet (%d%%)', [per]));
      end;
      Continue;
    end;

    // Re-inject the matching packet.
    if not WinDivertSend(handle, packet, packetLen, @addr, writeLen) then begin
      SetConsoleTextAttribute(console, FOREGROUND_RED);
      WriteLn(Format('Warning: failed to reinject packet (%d)', [GetLastError]));
    end;

  end;
  Result := 0;
end;

var
  filter: string;
  num_threads: integer;

procedure ParseCommandline;
var
  i: integer;
  str: string;
begin
  if ParamCount < 2 then begin
    WriteLn('Usage: netlimit -f <filter> -t <worker threads> -l <latency> -d <drop chance>');
    WriteLn('Example: netlimit -f "outbound and udp.DstPort == 3337" -t 1 -l 200 -d 10');
    Halt(1);
  end;

  i := 1;
  while (i < ParamCount) do begin
    str := ParamStr(i);
    if (str[1] = '-') then begin
      Delete(str, 1, 1);
      if (str = 'f') then begin
        Inc(i);
        filter := ParamStr(i);
      end else if (str = 't') then begin
        Inc(i);
        num_threads := StrToInt(ParamStr(i));
      end else if (str = 'l') then begin
        Inc(i);
        latency := StrToInt(ParamStr(i));
      end else if (str = 'd') then begin
        Inc(i);
        drops := StrToInt(ParamStr(i));
      end;
    end;
    Inc(i);
  end;

  if (num_threads < 1) and (num_threads > 64) then begin
    WriteLn('Error: invalid number of worker threads');
    Halt(1);
  end;
end;

{
  Waits until a key was pressed and returns the VK_ code.
}
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

var
  hThreads: array[0..63] of THandle;
  i: integer;
  thread_id: DWORD;
  key: Word;
  cs: TRTLCriticalSection;
begin
  WriteLn('netlimit, (c) 2017 sa');
  WriteLn('Simulate bad network');
  WriteLn;
  try
    num_threads := 1;
    latency := 200;   // ms
    drops := 0;       // %
    ParseCommandline;
    Randomize;

    // Get console for pretty colors.
    console := GetStdHandle(STD_OUTPUT_HANDLE);

    handle := WinDivertOpen(PAnsiChar(AnsiString(filter)), WINDIVERT_LAYER_NETWORK, 0, 0);
    if handle = INVALID_HANDLE_VALUE then begin
      if GetLastError = ERROR_INVALID_PARAMETER then begin
        SetConsoleTextAttribute(console, FOREGROUND_RED);
        WriteLn('Error: filter syntax error');
        Halt(1);
      end;
      SetConsoleTextAttribute(console, FOREGROUND_RED);
      WriteLn(Format('Error: failed to open the WinDivert device (%d)', [GetLastError]));
      WriteLn('Run this program as Administrator.');
      Halt(1);
    end;

    InitializeCriticalSection(cs);
    for i := 1 to num_threads do begin
      hThreads[i-1] := CreateThread(nil, 1, @passthr, nil, 0, thread_id);
      if (hThreads[i-1] = 0) then begin
        SetConsoleTextAttribute(console, FOREGROUND_RED);
        WriteLn(Format('Error: failed to start thread (%u)', [GetLastError]));
        Halt(1);
      end;
    end;
    SetConsoleTextAttribute(console, FOREGROUND_GREEN);
    WriteLn('Running. Press `q` to terminate, `h` for help.');

    while (true) do begin
      key := KeyPressed;
      case key of
        Ord('Q'):
          begin
            // Quit
            SetConsoleTextAttribute(console, FOREGROUND_GREEN or FOREGROUND_RED);
            Write('Really? [y/n]: ');
            key := KeyPressed;
            WriteLn(Char(key));
            if (key = Ord('Y')) then
              Break;
          end;
        Ord('D'):
          begin
            // Disconnect -> Drop all
            EnterCriticalsection(cs);
            try
              drop_all := not drop_all;
              if drop_all then begin
                SetConsoleTextAttribute(console, FOREGROUND_RED);
                WriteLn('Disconnected, packet loss = 100%');
              end else begin
                SetConsoleTextAttribute(console, FOREGROUND_GREEN);
                WriteLn(Format('Connected, packet loss = %d%%', [drops]));
              end;
            finally
              LeaveCriticalsection(cs);
            end;
          end;
        Ord('H'):
          begin
            SetConsoleTextAttribute(console, FOREGROUND_RED or FOREGROUND_GREEN or FOREGROUND_BLUE);
            WriteLn('q: Quit');
            WriteLn('d: Toggle drop all packets');
            WriteLn('h: Show this help');
          end;
      end;
      Sleep(10);
    end;

    SetConsoleTextAttribute(console, FOREGROUND_GREEN);
    WriteLn('Stopping...');
    for i := 1 to num_threads do begin
      TerminateThread(hThreads[i-1], 0);
    end;

    DeleteCriticalSection(cs);
    WinDivertClose(handle);
    SetConsoleTextAttribute(console, FOREGROUND_RED);
    WriteLn('Hasta la vista, baby');
    SetConsoleTextAttribute(console, FOREGROUND_RED or FOREGROUND_GREEN or FOREGROUND_BLUE);
  except
    on E: Exception do begin
      SetConsoleTextAttribute(console, FOREGROUND_RED);
      Writeln(E.ClassName, ': ', E.Message);
    end;
  end;
end.

