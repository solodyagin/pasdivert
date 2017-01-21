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
  DateUtils,
  windivert in 'windivert.pas';

const
  MAXBUF = $FFFF;

type
  TThreadRec = record
    Handle: THandle;
    Id: DWORD;
    Start: TDateTime;
    Recv: DWORD;
    Sent: DWORD;
  end;
  PThreadRec = ^TThreadRec;

var
  latency: integer;
  drops: integer;
  console: THandle;
  handle: THandle;
  drop_all: boolean = false;
  pass_all: boolean = false;

function passthr(arg: Pointer): DWORD; stdcall;
var
  packet: array[0..MAXBUF-1] of Byte;
  packetLen, writeLen: UINT;
  addr: TWinDivertAddress;
  sleep_ms: integer;
  per: integer;
  tr: PThreadRec;
begin
  tr := PThreadRec(arg);
  WriteLn(Format('Starting thread %d', [tr^.Id]));
  tr^.Start := Now;
{$IFDEF FPC}
  Initialize(packet);
{$ENDIF}
  while (true) do begin
    // Read a matching packet.
    if not WinDivertRecv(handle, packet, SizeOf(packet), addr, packetLen) then begin
      SetConsoleTextAttribute(console, FOREGROUND_RED);
      WriteLn(Format('Warning: failed to read packet (%d)', [GetLastError]));
      Continue;
    end;
    Inc(tr^.Recv, packetLen);

    if not pass_all then begin
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
    end;

    // Re-inject the matching packet.
    if WinDivertSend(handle, packet, packetLen, @addr, writeLen) then begin
      Inc(tr^.Sent, writeLen);
    end else begin
      SetConsoleTextAttribute(console, FOREGROUND_RED);
      WriteLn(Format('Warning: failed to reinject packet (%d)', [GetLastError]));
    end;

    if (tr^.Recv > (MAXDWORD - 1024)) or (tr^.Sent > (MAXDWORD - 1024)) then begin
      tr^.Start := Now;
      tr^.Sent := 0;
      tr^.Recv := 0;
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
  hThreads: array[0..63] of PThreadRec;
  pThread: PThreadRec;
  i: integer;
  key: Word;
  cs: TRTLCriticalSection;
  exit_code: DWORD;
  measure_time_sec: Int64;
  sent_byte_per_sec, recv_byte_per_sec: Cardinal;
  sum_recv, sum_sent: UInt64;
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
      WriteLn(Format('Error: failed to open the WinDivert device (%u)', [GetLastError]));
      WriteLn('Run this program as Administrator.');
      Halt(1);
    end;

{$IFDEF FPC}
    Initialize(cs);
{$ENDIF}
    InitializeCriticalSection(cs);
    for i := 1 to num_threads do begin
      New(pThread);
      pThread^ := Default(TThreadRec);
      pThread^.Handle := CreateThread(nil, 0, @passthr, pThread, 0, pThread^.Id);
      if (pThread^.Handle = 0) then begin
        SetConsoleTextAttribute(console, FOREGROUND_RED);
        WriteLn(Format('Error: failed to start thread (%u)', [GetLastError]));
        Halt(1);
      end;
      hThreads[i-1] := pThread;
    end;
    SetConsoleTextAttribute(console, FOREGROUND_GREEN);
    WriteLn('Running. Press `q` to terminate, `h` for help.');

    while (true) do begin
      key := KeyPressed;
      case key of
        Ord('Q'):
          begin
            // Quit
            SetConsoleTextAttribute(console, FOREGROUND_RED or FOREGROUND_GREEN or FOREGROUND_BLUE);
            Write('Really? [y/n]: ');
            key := KeyPressed;
            if (key = Ord('Y')) then begin
              WriteLn('Yesss');
              Break;
            end else
              WriteLn('Noooo!');
          end;
        Ord('D'):
          begin
            // Disconnect -> Drop all
            EnterCriticalsection(cs);
            try
              if pass_all then begin
                SetConsoleTextAttribute(console, FOREGROUND_GREEN or FOREGROUND_RED);
                WriteLn('Disabling passing all');
                pass_all := false;
              end;
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
        Ord('P'):
          begin
            // Pass all
            EnterCriticalsection(cs);
            try
              if drop_all then begin
                SetConsoleTextAttribute(console, FOREGROUND_GREEN or FOREGROUND_RED);
                WriteLn('Disabling drop all');
                drop_all := false;
              end;
              pass_all := not pass_all;
              if pass_all then begin
                SetConsoleTextAttribute(console, FOREGROUND_GREEN);
                WriteLn('Disabled, no latency and drops');
              end else begin
                SetConsoleTextAttribute(console, FOREGROUND_RED);
                WriteLn(Format('Enabled, latency = %d, packet loss = %d%%', [latency, drops]));
              end;
            finally
              LeaveCriticalsection(cs);
            end;
          end;
        Ord('S'):
          begin
            EnterCriticalsection(cs);
            try
              SetConsoleTextAttribute(console, FOREGROUND_RED or FOREGROUND_GREEN or FOREGROUND_BLUE);
              sum_recv := 0; sum_sent := 0;
              measure_time_sec := 0;
              for i := 1 to num_threads do begin
                pThread := hThreads[i-1];
                if (measure_time_sec = 0) then
                  measure_time_sec := MilliSecondsBetween(Now, pThread^.Start) div 1000;
                sent_byte_per_sec := 0; recv_byte_per_sec := 0;
                if measure_time_sec > 0 then begin
                  sent_byte_per_sec := pThread^.Sent div measure_time_sec;
                  recv_byte_per_sec := pThread^.Recv div measure_time_sec;
                end;
                WriteLn(Format('%u: Recv = %u (%u B/s), Sent = %u (%u B/s)',
                  [pThread^.Id, pThread^.Recv, recv_byte_per_sec, pThread^.Sent, sent_byte_per_sec]));
                Inc(sum_recv, pThread^.Recv);
                Inc(sum_sent, pThread^.Sent);
              end;
              if measure_time_sec > 0 then begin
                sent_byte_per_sec := sum_sent div measure_time_sec;
                recv_byte_per_sec := sum_recv div measure_time_sec;
              end else begin
                sent_byte_per_sec := 0;
                recv_byte_per_sec := 0;
              end;
              WriteLn(Format('Sum: Recv = %u (%u B/s), Sent = %u (%u B/s)',
                [sum_recv, recv_byte_per_sec, sum_sent, sent_byte_per_sec]));
            finally
              LeaveCriticalsection(cs);
            end;
          end;
        Ord('H'):
          begin
            SetConsoleTextAttribute(console, FOREGROUND_RED or FOREGROUND_GREEN or FOREGROUND_BLUE);
            WriteLn('q: Quit');
            WriteLn('d: Toggle drop all packets');
            WriteLn('p: Toggle pass all');
            WriteLn('   d and p are mutually exclusive');
            WriteLn('s: Show statistics');
            WriteLn('h: Show this help');
          end;
      end;
      Sleep(10);
    end;

    SetConsoleTextAttribute(console, FOREGROUND_GREEN);
    WriteLn('Stopping...');
    for i := 1 to num_threads do begin
      exit_code := 0;
      GetExitCodeThread(hThreads[i-1]^.Handle, exit_code);
      // The thread doesn't have to clean up stuff, so I think it's safe to call
      // just TerminateThread()
      TerminateThread(hThreads[i-1]^.Handle, exit_code);
      // Wait for thread
      WaitForSingleObject(hThreads[i-1]^.Handle, 2000);
      Dispose(hThreads[i-1]);
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

