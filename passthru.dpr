{*
 * passthru
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

program passthru;

{$APPTYPE CONSOLE}

{$R *.res}

uses
  SysUtils,
  Windows,
  windivert in 'windivert.pas';

const
  MAXBUF = $FFFF;

function passthr(arg: Pointer): DWORD;
var
  packet: array[0..MAXBUF-1] of Byte;
  packetLen, writeLen: UINT;
  addr: TWinDivertAddress;
  handle: THandle;
begin
  handle := THandle(arg);
  while (true) do begin
    // Read a matching packet.
    if not WinDivertRecv(handle, @packet, SizeOf(packet), addr, packetLen) then begin
      WriteLn(Format('warning: failed to read packet (%d)', [GetLastError]));
      Continue;
    end;

    // Re-inject the matching packet.
    if not WinDivertSend(handle, @packet, packetLen, @addr, writeLen) then begin
      WriteLn(Format('warning: failed to reinject packet (%d)', [GetLastError]));
    end;

  end;
  Result := 0;
end;

var
  handle, thread: THandle;
  filter: string;
  num_threads, i: integer;
  thread_id: DWORD;
begin
  try
    if ParamCount <> 2 then begin
      WriteLn('usage: passthru filter num-threads');
      WriteLn('example: passthru "outbound and tcp.PayloadLength > 0 and tcp.DstPort == 80" 3');
      Halt(1);
    end;
    filter := ParamStr(1);
    num_threads := StrToInt(ParamStr(2));
    if (num_threads < 1) and (num_threads > 64) then begin
      WriteLn('error: invalid number of threads');
      Halt(1);
    end;

    handle := WinDivertOpen(PAnsiChar(AnsiString(filter)), WINDIVERT_LAYER_NETWORK, 0, 0);
    if handle = INVALID_HANDLE_VALUE then begin
      if GetLastError = ERROR_INVALID_PARAMETER then begin
        WriteLn('error: filter syntax error');
        Halt(1);
      end;
      WriteLn(Format('error: failed to open the WinDivert device (%d)', [GetLastError]));
      Halt(1);
    end;

    for i := 1 to num_threads do begin
      thread := CreateThread(nil, 1, @passthr, Pointer(handle), 0, thread_id);
      if (thread = 0) then begin
        WriteLn(Format('error: failed to start passthru thread (%u)', [GetLastError]));
        Halt(1);
      end;
    end;

    passthr(Pointer(handle));
  except
    on E: Exception do
      Writeln(E.ClassName, ': ', E.Message);
  end;
end.
