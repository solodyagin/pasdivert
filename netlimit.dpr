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

function passthr(arg: Pointer): DWORD;
var
  packet: array[0..MAXBUF-1] of Byte;
  packetLen, writeLen: UINT;
  addr: TWinDivertAddress;
  handle: THandle;
  sleep_ms: integer;
  per: integer;
begin
  handle := THandle(arg);
  while (true) do begin
    // Read a matching packet.
    if not WinDivertRecv(handle, packet, SizeOf(packet), addr, packetLen) then begin
      SetConsoleTextAttribute(console, FOREGROUND_RED);
      WriteLn(Format('Warning: failed to read packet (%d)', [GetLastError]));
      Continue;
    end;

    sleep_ms := Trunc(latency * (Random + 1));
    Sleep(sleep_ms);
    per := Random(100);
    if (per <= drops) then begin
      // Drop it
      SetConsoleTextAttribute(console, FOREGROUND_GREEN or FOREGROUND_RED);
      WriteLn(Format('Info: dropped packet (%d %%)', [per]));
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
    WriteLn('Usage: netlimit -f <filter> -t <num-threads> -l <latency> -d <drop chance>');
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
    WriteLn('Error: invalid number of threads');
    Halt(1);
  end;
end;

var
  handle, thread: THandle;
  i: integer;
  thread_id: DWORD;
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

    for i := 1 to num_threads do begin
      thread := CreateThread(nil, 1, @passthr, Pointer(handle), 0, thread_id);
      if (thread = 0) then begin
        SetConsoleTextAttribute(console, FOREGROUND_RED);
        WriteLn(Format('Error: failed to start passthru thread (%u)', [GetLastError]));
        Halt(1);
      end;
    end;
    SetConsoleTextAttribute(console, FOREGROUND_GREEN);
    WriteLn('Running. Press Ctrl+C to terminate.');

    passthr(Pointer(handle));
  except
    on E: Exception do begin
      SetConsoleTextAttribute(console, FOREGROUND_RED);
      Writeln(E.ClassName, ': ', E.Message);
    end;
  end;
end.
