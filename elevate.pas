{*
 * pasdivert
 * (C) 2017, sa
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

unit Elevate;

interface

uses
  SysUtils, Windows, ShellAPI, ComObj;

procedure RunElevated;

implementation

function CheckTokenMembership(TokenHandle: THANDLE; SidToCheck: Pointer; var IsMember: BOOL): BOOL; stdcall; external advapi32 name 'CheckTokenMembership';

const
  SECURITY_NT_AUTHORITY: TSidIdentifierAuthority = (Value: (0, 0, 0, 0, 0, 5));
  SECURITY_BUILTIN_DOMAIN_RID  = $00000020;
  DOMAIN_ALIAS_RID_ADMINS      = $00000220;

function IsRunningAsAdmin: boolean;
var
  dwError: DWORD;
  pAdministratorsGroup: Pointer;
  NtAuthority: TSIDIdentifierAuthority;
  b: BOOL;
begin
  Result := false;
  dwError := ERROR_SUCCESS;
  pAdministratorsGroup := nil;
  NtAuthority := SECURITY_NT_AUTHORITY;

  try
    if (AllocateAndInitializeSid(
      @NtAuthority,
      2,
      SECURITY_BUILTIN_DOMAIN_RID,
      DOMAIN_ALIAS_RID_ADMINS,
      0, 0, 0, 0, 0, 0,
      pAdministratorsGroup))
    then begin
      b := false;
      if (CheckTokenMembership(0, pAdministratorsGroup, b)) then begin
        Result := b;
      end else begin
        dwError := GetLastError;
      end;
    end else begin
      dwError := GetLastError;
    end;
  finally
    if (pAdministratorsGroup <> nil) then begin
      FreeSid(pAdministratorsGroup);
    end;
  end;
  if (dwError <> ERROR_SUCCESS) then
    raise Exception.Create(SysErrorMessage(dwError));
end;

procedure RunElevated;
{$IFDEF FPC}
type
  PShellExecuteInfo = ^TShellExecuteInfo;
{$ENDIF}
var
  SEI: TShellExecuteInfo;
  Host: string;
  Args: string;
  i: integer;
begin
  if not IsRunningAsAdmin then begin
    Host := ParamStr(0);
    Args := '';
    for i := 1 to ParamCount do begin
      Args := Args + ' "' + ParamStr(i) + '"';
    end;
    Args := Trim(Args);

    SEI := Default(TShellExecuteInfo);
    SEI.cbSize := SizeOf(SEI);
    SEI.fMask := SEE_MASK_NOCLOSEPROCESS;
{$IFDEF UNICODE}
    SEI.fMask := SEI.fMask or SEE_MASK_UNICODE;
{$ENDIF}
    SEI.Wnd := 0;
    SEI.lpVerb := 'runas';
    SEI.lpFile := PChar(Host);
    SEI.lpParameters := PChar(Args);
    SEI.nShow := SW_NORMAL;
    if not ShellExecuteEx({$IFDEF FPC}PShellExecuteInfo{$ENDIF}(@SEI)) then
      RaiseLastOSError;
    Halt(0);
  end;
end;

end.
