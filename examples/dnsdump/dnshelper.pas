unit dnshelper;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface

uses
  Classes, SysUtils;

{ TFlags }
type
  TFlags = record
  private
    FRaw: Word;
    function GetBits(const Index: Integer): Integer; inline;
  public
    property Raw: Word read FRaw;
    // High byte of index - offset, low byte of index - bit count
    property QR:     Integer index $0F01 read GetBits; // 1 bit  at offset 15
    property OPCODE: Integer index $0B04 read GetBits; // 4 bits at offset 11
    property AA:     Integer index $0A01 read GetBits; // 1 bit  at offset 10
    property TC:     Integer index $0901 read GetBits; // 1 bit  at offset 9
    property RD:     Integer index $0801 read GetBits; // 1 bit  at offset 8
    property RA:     Integer index $0701 read GetBits; // 1 bit  at offset 7
    property Z:      Integer index $0403 read GetBits; // 3 bits at offset 4
    property RCODE:  Integer index $0004 read GetBits; // 4 bits at offset 0
  end;

{ TDnsHelper }
type
  TDnsHelper = class
  private
    FData: AnsiString;
    FID: Word;
    FFlags: TFlags;
    FQDCOUNT: Word;
    FANCOUNT: Word;
    FNSCOUNT: Word;
    FARCOUNT: Word;
    FQuestionInfo: TStringList;
    FAnswerInfo: TStringList;
    FAuthorityInfo: TStringList;
    FAdditionalInfo: TStringList;
    function DecodeWord(P: Integer): Word;
    function DecodeString(var P: Integer): AnsiString;
    function DecodeLabels(var P: Integer): AnsiString;
    function DecodeResource(var P: Integer; const SL: TStringList): AnsiString;
  public
    constructor Create(const AData: AnsiString);
    destructor Destroy; override;
  public
    function DecodeData: Boolean;
  public
    property ID: Word read FID;           // ID
    property Flags: TFlags read FFlags;   // QR, OPCODE, AA, TC, RD, RA, Z, RCODE
    property QDCOUNT: Word read FQDCOUNT; // No. of items in Question Section
    property ANCOUNT: Word read FANCOUNT; // No. of items in Answer Section
    property NSCOUNT: Word read FNSCOUNT; // No. of items in Authority Section
    property ARCOUNT: Word read FARCOUNT; // No. of items in Additional Section
    property QuestionInfo: TStringList read FQuestionInfo;
    property AnswerInfo: TStringList read FAnswerInfo;
    property AuthorityInfo: TStringList read FAuthorityInfo;
    property AdditionalInfo: TStringList read FAdditionalInfo;
  end;

implementation

type
  TIP6Bytes = array[0..15] of Byte;
  TIP6Words = array[0..7] of Word;

function IP6ToStr(Value: TIP6Bytes): String;
var
  i, x: Byte;
  zr1, zr2: set of Byte;
  zc1, zc2: Byte;
  haveSkipped: Boolean;
  ip6w: TIP6Words;
begin
  zr1 := [];
  zr2 := [];
  zc1 := 0;
  zc2 := 0;
  for i := 0 to 7 do
  begin
    x := i * 2;
    ip6w[i] := Value[x] * 256 + Value[x + 1];
    if (ip6w[i] = 0) then
    begin
      Include(zr2, i);
      Inc(zc2);
    end
    else
    begin
      if (zc1 < zc2) then
      begin
        zc1 := zc2;
        zr1 := zr2;
        zc2 := 0;
        zr2 := [];
      end;
    end;
  end;
  if (zc1 < zc2) then
    zr1 := zr2;
  SetLength(Result, 8 * 5 - 1);
  SetLength(Result, 0);
  haveSkipped := False;
  for i := 0 to 7 do
  begin
    if not (i in zr1) then
    begin
      if haveSkipped then
      begin
        if (Result = '') then
          Result := '::'
        else
          Result := Result + ':';
        haveSkipped := False;
      end;
      Result := Result + IntToHex(ip6w[i], 1) + ':';
    end
    else
      haveSkipped := True;
  end;

  if haveSkipped then
  begin
    if (Result = '') then
      Result := '::0'
    else
      Result := Result + ':';
  end;

  if (Result = '') then
    Result := '::0';

  if not (7 in zr1) then
    SetLength(Result, Length(Result) - 1);

  Result := LowerCase(result);
end;

const
  QTYPE_A     = 1;
  QTYPE_NS    = 2;
  QTYPE_CNAME = 5;
  QTYPE_SOA   = 6;
  //QTYPE_WKS   = 11;
  QTYPE_PTR   = 12;
  QTYPE_MX    = 15;
  QTYPE_TXT   = 16;
  QTYPE_AAAA  = 28;
  QTYPE_SRV   = 33;
  //QTYPE_ANY   = 255;

{ TFlags }

function TFlags.GetBits(const Index: Integer): Integer;
var
  offset: Integer;
  bitCount: Integer;
  mask: Integer;
begin
  offset := Index shr 8;
  bitCount := Index and $FF;
  mask := (1 shl bitCount) - 1;
  Result := (FRaw shr offset) and mask;
end;

{ TDnsHelper }

constructor TDnsHelper.Create(const AData: AnsiString);
begin
  inherited Create;
  FData := AData;
  FQuestionInfo := TStringList.Create;
  FAnswerInfo := TStringList.Create;
  FAuthorityInfo := TStringList.Create;
  FAdditionalInfo := TStringList.Create;
end;

destructor TDnsHelper.Destroy;
begin
  FQuestionInfo.Free;
  FAnswerInfo.Free;
  FAuthorityInfo.Free;
  FAdditionalInfo.Free;
  inherited Destroy;
end;

function TDnsHelper.DecodeWord(P: Integer): Word;
var
  len: Integer;
  x, y: Byte;
begin
  len := Length(FData);
  if (len > P) then
    x := Ord(FData[P])
  else
    x := 0;
  if (len >= (P + 1)) then
    y := Ord(FData[P + 1])
  else
    y := 0;
  Result := x * 256 + y;
end;

function TDnsHelper.DecodeString(var P: Integer): AnsiString;
var
  len: Integer;
begin
  len := Ord(FData[P]);
  Inc(P);
  Result := Copy(FData, P, len);
  Inc(P, len);
end;

function TDnsHelper.DecodeLabels(var P: Integer): AnsiString;
var
  l, f: Integer;
begin
  Result := '';
  while (P < Length(FData)) do
  begin
    l := Ord(FData[P]);
    Inc(P);
    if (l = 0) then
      Break;
    if (Result <> '') then
      Result := Result + '.';
    if ((l and $C0) = $C0) then
    begin
      f := l and $3F;
      f := f * 256 + Ord(FData[P]) + 1;
      Inc(P);
      Result := Result + DecodeLabels(f);
      Break;
    end
    else
    begin
      Result := Result + Copy(FData, P, l);
      Inc(P, l);
    end;
  end;
end;

function TDnsHelper.DecodeResource(var P: Integer; const SL: TStringList): AnsiString;
var
  RName: AnsiString;
  RType: Integer;
  RData: AnsiString;
  len: Integer;
  i: Integer;
  n: Integer;
  x, y, z: Int64;
  t1, t2, ttl: Integer;
  ip6: TIP6Bytes;
begin
  Result := '';
  RData := '';
  RName := DecodeLabels(P);
  RType := DecodeWord(P);
  Inc(P, 4);
  t1 := DecodeWord(P);
  Inc(P, 2);
  t2 := DecodeWord(P);
  Inc(P, 2);
  ttl := t1 * 65536 + t2;
  len := DecodeWord(P);
  Inc(P, 2); // P point to begin of data
  i := P;
  P := P + len; // P point to next record
  if (Length(FData) >= (P - 1)) then
  begin
    case RType of
      QTYPE_A:
        begin
          RData := IntToStr(Ord(FData[i]));
          Inc(i);
          RData := RData + '.' + IntToStr(Ord(FData[i]));
          Inc(i);
          RData := RData + '.' + IntToStr(Ord(FData[i]));
          Inc(i);
          RData := RData + '.' + IntToStr(Ord(FData[i]));
        end;
      QTYPE_AAAA:
        begin
          for n := 0 to 15 do
            ip6[n] := Ord(FData[i + n]);
          RData := IP6ToStr(ip6);
        end;
      QTYPE_NS, QTYPE_CNAME, QTYPE_PTR:
        RData := DecodeLabels(i);
      QTYPE_SOA:
        begin
          RData := DecodeLabels(i);
          RData := RData + ',' + DecodeLabels(i);
          for n := 1 to 5 do
          begin
            x := DecodeWord(i) * 65536 + DecodeWord(i + 2);
            Inc(i, 4);
            RData := RData + ',' + IntToStr(x);
          end;
        end;
      QTYPE_MX:
        begin
          x := DecodeWord(i);
          Inc(i, 2);
          RData := IntToStr(x);
          RData := RData + ',' + DecodeLabels(i);
        end;
      QTYPE_TXT:
        begin
          RData := '';
          while (i < P) do
            RData := RData + DecodeString(i);
        end;
      QTYPE_SRV:
        begin
          x := DecodeWord(i); // Priority
          Inc(i, 2);
          y := DecodeWord(i); // Weight
          Inc(i, 2);
          z := DecodeWord(i); // Port
          Inc(i, 2);
          RData := IntToStr(x);
          RData := RData + ',' + IntToStr(y);
          RData := RData + ',' + IntToStr(z);
          RData := RData + ',' + DecodeLabels(i); // Server DNS Name
        end;
    end;
  end;

  if (RData <> '') then
    SL.Add(#9 + Format('name: %s, type: %u, ttl: %u, rdata: %s', [RName, RType, ttl, RData]));

  Result := RData;
end;

function TDnsHelper.DecodeData: Boolean;
var
  n, p: Integer;
  r: AnsiString;
  x, y: Word;
begin
  Result := False;
  FQuestionInfo.Clear;
  FAnswerInfo.Clear;
  FAuthorityInfo.Clear;
  FAdditionalInfo.Clear;
  if (Length(FData) < 14) then Exit;

  FID := DecodeWord(1);
  FFlags.FRaw := DecodeWord(3);
  if (FFlags.RCODE = 0) then
  begin
    FQDCOUNT := DecodeWord(5);
    FANCOUNT := DecodeWord(7);
    FNSCOUNT := DecodeWord(9);
    FARCOUNT := DecodeWord(11);

    p := 13; // begin of body

    // Decode Question Section
    if (QDCOUNT > 0) and (Length(FData) > p) then
    begin
      for n := 1 to QDCOUNT do
      begin
        r := DecodeLabels(p); // QNAME
        x := DecodeWord(p);   // QTYPE
        Inc(p, 2);
        y := DecodeWord(p);   // QCLASS
        Inc(p, 2);
        FQuestionInfo.Add(#9 + Format('name: %s, type: %u, class: %u', [r, x, y]));
      end;
    end;

    // Decode Answer Section
    if (ANCOUNT > 0) and (Length(FData) > p) then
    begin
      for n := 1 to ANCOUNT do
        DecodeResource(p, FAnswerInfo);
    end;

    // Decode Authority Section
    if (NSCOUNT > 0) and (Length(FData) > p) then
    begin
      for n := 1 to NSCOUNT do
        DecodeResource(p, FAuthorityInfo);
    end;

    // Decode Additional Section
    if (ARCOUNT > 0) and (Length(FData) > p) then
    begin
      for n := 1 to ARCOUNT do
        DecodeResource(p, FAdditionalInfo);
    end;
  end;

  Result := True;
end;

end.

