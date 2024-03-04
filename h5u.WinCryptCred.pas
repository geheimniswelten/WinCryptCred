/// <summary>Windows Credentials &amp; Cryptography</summary>
/// <remarks>Version: 1.0 2024-03-04<br />Copyright 2024 himitsu @ geheimniswelten<br />License: MPL v1.1 , GPL v3.0 or LGPL v3.0</remarks>
/// <seealso cref="http://geheimniswelten.de">Geheimniswelten</seealso>
/// <seealso cref="http://geheimniswelten.de/kontakt/#licenses">License Text</seealso>
/// <seealso cref="https://github.com/geheimniswelten/WinCryptCred">GitHub</seealso>
unit h5u.WinCryptCred;

interface

{$MINENUMSIZE 4}
{$POINTERMATH ON}
{$WARN SYMBOL_PLATFORM      OFF}  // [DCC Warnung] W1002 Symbol 'DELAYED' ist plattformspezifisch
{$WARN IMPLICIT_STRING_CAST OFF}  // [DCC Warnung] W1057 Implizite String-Umwandlung von 'ShortString' zu 'string'

uses
  //{Winapi.}Ole2,  // nicht eingebunden, nur wegen dem einen CoTaskMemFree (siehe unten)
  {$IFDEF WithWinMD}
  Windows.Foundation, Windows.Security.Credentials, Windows.Security.Cryptography,  // path see USES in CryptDemo.dpr
  {$ENDIF}
  //
  Windows, Messages, SysConst, SysUtils, StrUtils, Variants, Classes, Graphics, Forms, Math,
  {System.}Generics.Collections, {Winapi.}ShellAPI;

{$IF Declared(CredWrite)}
  {$DEFINE UseWinMD}
{$IFEND}

{$IFnDEF UseWinMD}

const
  CRYPTPROTECTMEMORY_BLOCK_SIZE        = 16;
  CRYPTPROTECTMEMORY_SAME_PROCESS      = $00;
  CRYPTPROTECTMEMORY_CROSS_PROCESS     = $01;
  CRYPTPROTECTMEMORY_SAME_LOGON        = $02;

  CRYPTPROTECT_UI_FORBIDDEN            = $1;
  CRYPTPROTECT_LOCAL_MACHINE           = $4;
  CRYPTPROTECT_CRED_SYNC               = $8;

  CRYPTPROTECT_PROMPT_ON_UNPROTECT     = $01;
  CRYPTPROTECT_PROMPT_ON_PROTECT       = $02;
  CRYPTPROTECT_PROMPT_RESERVED         = $04;
  CRYPTPROTECT_PROMPT_STRONG           = $08;

  CRED_MAX_STRING_LENGTH               = 256;        // Maximum length of the various credential string fields (in characters)
  CRED_MAX_USERNAME_LENGTH             = 256+1+256;  // Maximum length of the UserName field.  The worst case is <User>@<DnsDomain>
  CRED_MAX_GENERIC_TARGET_NAME_LENGTH  = 32767;      // Maximum length of the TargetName field for CRED_TYPE_GENERIC (in characters)
  CRED_MAX_DOMAIN_TARGET_NAME_LENGTH   = 256+1+80;   // Maximum length of the TargetName field for CRED_TYPE_DOMAIN_* (in characters), Largest one is <DfsRoot>\<DfsShare>
  CRED_MAX_TARGETNAME_NAMESPACE_LENGTH = 256;        // Maximum length of a target namespace
  CRED_MAX_TARGETNAME_ATTRIBUTE_LENGTH = 256;        // Maximum length of a target attribute
  CRED_MAX_VALUE_SIZE                  = 256;        // Maximum size of the Credential Attribute Value field (in bytes)
  CRED_MAX_ATTRIBUTES                  = 64;         // Maximum number of attributes per credential
  CRED_MAX_CREDENTIAL_BLOB_SIZE        = 5*512;      // Maximum size of the CredBlob field (in bytes)

  CRED_FLAGS_PASSWORD_FOR_CERT         = $0001;
  CRED_FLAGS_PROMPT_NOW                = $0002;
  CRED_FLAGS_USERNAME_TARGET           = $0004;
  CRED_FLAGS_OWF_CRED_BLOB             = $0008;
  CRED_FLAGS_REQUIRE_CONFIRMATION      = $0010;
  CRED_FLAGS_WILDCARD_MATCH            = $0020;
  CRED_FLAGS_VSM_PROTECTED             = $0040;
  CRED_FLAGS_NGC_CERT                  = $0080;
  CRED_FLAGS_VALID_FLAGS               = $F0FF;
  CRED_FLAGS_VALID_INPUT_FLAGS         = $F09F;

  CRED_TYPE_GENERIC                    = 1;
  CRED_TYPE_DOMAIN_PASSWORD            = 2;
  CRED_TYPE_DOMAIN_CERTIFICATE         = 3;
  CRED_TYPE_DOMAIN_VISIBLE_PASSWORD    = 4;
  CRED_TYPE_GENERIC_CERTIFICATE        = 5;
  CRED_TYPE_DOMAIN_EXTENDED            = 6;
  CRED_TYPE_MAXIMUM                    = 7;

  CRED_PERSIST_NONE                    = 0;
  CRED_PERSIST_SESSION                 = 1;
  CRED_PERSIST_LOCAL_MACHINE           = 2;
  CRED_PERSIST_ENTERPRISE              = 3;

  CRED_PACK_PROTECTED_CREDENTIALS      = $1;
  CRED_PACK_WOW_BUFFER                 = $2;
  CRED_PACK_GENERIC_CREDENTIALS        = $4;
  CRED_PACK_ID_PROVIDER_CREDENTIALS    = $8;

  CREDUIWIN_GENERIC                    = $00000001;  // Plain text username/password is being requested
  CREDUIWIN_CHECKBOX                   = $00000002;  // Show the Save Credential checkbox
  CREDUIWIN_AUTHPACKAGE_ONLY           = $00000010;  // Only Cred Providers that support the input auth package should enumerate
  CREDUIWIN_IN_CRED_ONLY               = $00000020;  // Only the incoming cred for the specific auth package should be enumerated
  CREDUIWIN_ENUMERATE_ADMINS           = $00000100;  // Cred Providers should enumerate administrators only
  CREDUIWIN_ENUMERATE_CURRENT_USER     = $00000200;  // Only the incoming cred for the specific auth package should be enumerated
  CREDUIWIN_SECURE_PROMPT              = $00001000;  // The CredUI prompt should be displayed on the secure desktop
  CREDUIWIN_PREPROMPTING               = $00002000;  // CredUI is invoked by  SspiPromptForCredentials and the client is prompting before a prior handshake
  CREDUIWIN_PACK_32_WOW                = $10000000;  // Tell the credential provider it should be packing its Auth Blob 32 bit even though it is running 64 native

  CREDUI_MAX_USERNAME_LENGTH           = CRED_MAX_USERNAME_LENGTH;
  CREDUI_MAX_PASSWORD_LENGTH           = 256;
  CREDUI_MAX_DOMAIN_TARGET_LENGTH      = CRED_MAX_DOMAIN_TARGET_NAME_LENGTH;

  {$IF not Declared(ERROR_NOT_FOUND)}
  ERROR_NOT_FOUND                      = 1168;
  {$IFEND}

  crypt32 = 'crypt32.dll';
  credui  = 'credui.dll';

type
  PCRYPT_DATA_BLOB = ^CRYPT_DATA_BLOB;
  CRYPT_DATA_BLOB  = record
    cbData: DWORD;
    pbData: PBYTE;
  end;
  CRYPT_INTEGER_BLOB  = CRYPT_DATA_BLOB;
  PCRYPT_INTEGER_BLOB = PCRYPT_DATA_BLOB;

  PCRYPTPROTECT_PROMPTSTRUCT = ^CRYPTPROTECT_PROMPTSTRUCT;
  CRYPTPROTECT_PROMPTSTRUCT  = record
    cbSize:        DWORD;
    dwPromptFlags: DWORD;
    hwndApp:       HWND;
    szPrompt:      LPCWSTR;
  end;

  PCREDENTIAL_ATTRIBUTE   = ^CREDENTIAL_ATTRIBUTE;
  CREDENTIAL_ATTRIBUTE{W} = record
    Keyword:   LPWSTR;
    Flags:     DWORD;
    ValueSize: DWORD;
    Value:     LPBYTE;
  end;

  PPCREDENTIAL  = ^PCREDENTIAL;
  PCREDENTIAL   = ^CREDENTIAL;
  CREDENTIAL{W} = record
    Flags:              DWORD;
    &Type:              DWORD;
    TargetName:         LPWSTR;
    Comment:            LPWSTR;
    LastWritten:        FILETIME;
    CredentialBlobSize: DWORD;
    CredentialBlob:     LPBYTE;
    Persist:            DWORD;
    AttributeCount:     DWORD;
    Attributes:         PCREDENTIAL_ATTRIBUTE;
    TargetAlias:        LPWSTR;
    UserName:           LPWSTR;
  end;

  PCREDUI_INFO   = ^CREDUI_INFO;
  CREDUI_INFO{W} = record
    cbSize:         DWORD;
    hwndParent:     HWND;
    pszMessageText: LPCWSTR;
    pszCaptionText: LPCWSTR;
    hbmBanner:      HBITMAP;
  end;

  CRED_PROTECTION_TYPE = (CredUnprotected, CredUserProtection, CredTrustedProtection, CredForSystemProtection);

// ab Vista
function CryptProtectMemory  (pDataIn: Pointer; cbDataIn, dwFlags: DWORD): BOOL; stdcall; external crypt32;
function CryptUnprotectMemory(pDataIn: Pointer; cbDataIn, dwFlags: DWORD): BOOL; stdcall; external crypt32;
function CryptProtectData  ({const} pDataIn: PCRYPT_INTEGER_BLOB;   szDataDescr: PWideChar;  pOptionalEntropy: PCRYPT_INTEGER_BLOB; pvReserved: PVOID; pPromptStruct: PCRYPTPROTECT_PROMPTSTRUCT; dwFlags: DWORD; out pDataOut: CRYPT_INTEGER_BLOB): BOOL; stdcall; external crypt32;
function CryptUnprotectData({const} pDataIn: PCRYPT_INTEGER_BLOB; ppszDataDescr: PPWideChar; pOptionalEntropy: PCRYPT_INTEGER_BLOB; pvReserved: PVOID; pPromptStruct: PCRYPTPROTECT_PROMPTSTRUCT; dwFlags: DWORD; out pDataOut: CRYPT_INTEGER_BLOB): BOOL; stdcall; external crypt32;

// ab WinXP
function CredWrite (Credential: PCREDENTIAL;    Flags: DWORD): BOOL; stdcall; external advapi32 name 'CredWriteW';
function CredDelete(TargetName: LPCWSTR; &Type, Flags: DWORD): BOOL; stdcall; external advapi32 name 'CredDeleteW';
function CredRead  (TargetName: LPCWSTR; &Type, Flags: DWORD; out Credential: PCREDENTIAL): BOOL; stdcall; external advapi32 name 'CredReadW';
function CredEnumerate (Filter: LPCWSTR;        Flags: DWORD; out Count: DWORD; out Credential: PPCREDENTIAL): BOOL; stdcall; external advapi32 name 'CredEnumerateW';
procedure CredFree(Buffer: PVOID); stdcall; external advapi32;

// ab Vista
function CredUIPromptForWindowsCredentials(pUiInfo: PCREDUI_INFO; dwAuthError: DWORD; var ulAuthPackage: ULONG; pvInAuthBuffer: LPCVOID; ulInAuthBufferSize: ULONG; out ppvOutAuthBuffer: LPVOID; out pulOutAuthBufferSize: ULONG; pfSave: PBOOL; dwFlags: DWORD): DWORD; stdcall; external 'credui.dll' name 'CredUIPromptForWindowsCredentialsW' delayed;
function CredUnPackAuthenticationBuffer(dwFlags: DWORD; pAuthBuffer: PVOID; cbAuthBuffer: DWORD; pszUserName: LPWSTR; pcchMaxUserName: PDWORD; pszDomainName: LPWSTR; pcchMaxDomainName: PDWORD; pszPassword: LPWSTR; pcchMaxPassword: PDWORD): BOOL; stdcall; external 'credui.dll' name 'CredUnPackAuthenticationBufferW' delayed;
function CredPackAuthenticationBuffer(dwFlags: DWORD; pszUserName, pszPassword: LPWSTR; pPackedCredentials: PBYTE; var cbPackedCredentials: DWORD): BOOL; stdcall; external 'credui.dll' name 'CredPackAuthenticationBufferW' delayed;

// ab Vista
function CredProtectA  (fAsSelf: BOOL; pszCredentials: LPSTR;           cchCredentials: DWORD;          pszProtectedCredentials: LPSTR;  var pcchMaxChars: DWORD; out ProtectionType: CRED_PROTECTION_TYPE): BOOL; stdcall; external advapi32 name 'CredProtectA';
function CredProtectW  (fAsSelf: BOOL; pszCredentials: LPWSTR;          cchCredentials: DWORD;          pszProtectedCredentials: LPWSTR; var pcchMaxChars: DWORD; out ProtectionType: CRED_PROTECTION_TYPE): BOOL; stdcall; external advapi32 name 'CredProtectW';
function CredUnprotectA(fAsSelf: BOOL; pszProtectedCredentials: LPSTR;  cchProtectedCredentials: DWORD; pszCredentials: LPSTR;           var pcchMaxChars: DWORD):                                           BOOL; stdcall; external advapi32 name 'CredUnprotectA';
function CredUnprotectW(fAsSelf: BOOL; pszProtectedCredentials: LPWSTR; cchProtectedCredentials: DWORD; pszCredentials: LPWSTR;          var pcchMaxChars: DWORD):                                           BOOL; stdcall; external advapi32 name 'CredUnprotectW';
function CredIsProtectedA(             pszProtectedCredentials: LPSTR;                                                                                            out ProtectionType: CRED_PROTECTION_TYPE): BOOL; stdcall; external advapi32 name 'CredIsProtectedA';
function CredIsProtectedW(             pszProtectedCredentials: LPWSTR;                                                                                           out ProtectionType: CRED_PROTECTION_TYPE): BOOL; stdcall; external advapi32 name 'CredIsProtectedW';

{$ELSE}

  // Bugfixe, weil die Idioten im WinMD überall einfach nur Mist gemaut haben.

  const CREDUI_MAX_PASSWORD_LENGTH = 256;

  { Wer kommt bitte auf die saublöde IDEE $IF innerhalb inaktiver Blöcke auszuwerten? }
  {.$IF TypeInfo(Windows.BOOL) <> TypeInfo(Windows.Foundation.BOOL)}
    type  BOOL  = Windows.BOOL;
    const True  = System.True;
    const False = System.False;

    function Win32Check(RetVal: Windows.Foundation.BOOL): BOOL;
  {.$ENDIF}


  // Bugfixe, weil die von emba einfach zu dämlich sind
  type PSTR         = PAnsiChar;
  type PCREDENTIAL  = PCREDENTIALW;
  type PPCREDENTIAL = ^PCREDENTIALW;
  function CredRead(TargetName: LPCWSTR; &Type, Flags: DWORD; out Credential: PCREDENTIAL): BOOL; stdcall; external advapi32 name 'CredReadW';
  function CredEnumerate(Filter: LPCWSTR; Flags: DWORD; out Count: DWORD; out Credential: PPCREDENTIAL): BOOL; stdcall; external advapi32 name 'CredEnumerateW';
  function CredUnPackAuthenticationBuffer(dwFlags: DWORD; pAuthBuffer: PVOID; cbAuthBuffer: DWORD; pszUserName: LPWSTR; pcchMaxUserName: PDWORD; pszDomainName: LPWSTR; pcchMaxDomainName: PDWORD; pszPassword: LPWSTR; pcchMaxPassword: PDWORD): Windows.Foundation.BOOL; stdcall; external 'credui.dll' name 'CredUnPackAuthenticationBufferW' delayed;
  function CredUnprotectA(fAsSelf: BOOL; pszProtectedCredentials: LPSTR;  cchProtectedCredentials: DWORD; pszCredentials: LPSTR; var pcchMaxChars: DWORD): BOOL; stdcall; external advapi32;
  function CredUnprotectW(fAsSelf: BOOL; pszProtectedCredentials: LPWSTR; cchProtectedCredentials: DWORD; pszCredentials: LPWSTR; var pcchMaxChars: DWORD): BOOL; stdcall; external advapi32;

{$ENDIF}

type
  TCryptAttribute = record
    Key:   string;
    Value: TBytes;

    class operator Implicit(const Data: TPair<string,TBytes>): TCryptAttribute; inline;
    class operator Implicit(const Data: TCryptAttribute): TPair<string,TBytes>; inline;
    constructor Create(const Key: string; const Value: TBytes);  overload;
    constructor Create(const Key: string; const Value: string);  overload;
    constructor Create(const Key: string;       Value: Integer); overload;
    constructor Create(const Key: string;       Value: Boolean); overload;
    function AsString:  string; inline;
    function AsInteger: Integer;
    function AsBoolean: Boolean; inline;

    class function Create    (Keys: array of string; Values: array of TBytes):  TArray<TCryptAttribute>; overload; static;
    class function CreateStr (Keys: array of string; Values: array of string):  TArray<TCryptAttribute>; static;
    class function CreateInt (Keys: array of string; Values: array of Integer): TArray<TCryptAttribute>; static;
    class function CreateBool(Keys: array of string; Values: array of Boolean): TArray<TCryptAttribute>; static;
    class function CreateMix (Keys: array of string; Values: array of const):   TArray<TCryptAttribute>; static;
    class function CreateEmpty:                                                 TArray<TCryptAttribute>; static; inline;

    // TCryptAttribute.Find(Attr, 'Key').AsBoolean
    class function Find(const Attributes: TArray<TCryptAttribute>; const Key: string):                         TCryptAttribute; overload; static; inline;
    class function Find(const Attributes: TArray<TCryptAttribute>; const Key: string; const Default: TBytes):  TCryptAttribute; overload; static;
    class function Find(const Attributes: TArray<TCryptAttribute>; const Key: string; const Default: string):  string;          overload; static;
    class function Find(const Attributes: TArray<TCryptAttribute>; const Key: string;       Default: Integer): Integer;         overload; static;
    class function Find(const Attributes: TArray<TCryptAttribute>; const Key: string;       Default: Boolean): Boolean;         overload; static; inline;
  end;
  PCryptAttributes = ^TCryptAttributes;
  TCryptAttributes = TArray<TCryptAttribute>;

  TCryptCredFlag    = (ccf0{ccfPasswordForCert}, ccfPromptNow{=1}, ccfUsernameTarget{=2} {, ccfOwfCredBlob, ccfRequireConfirm, ccfWildcardMatch, ccfVsmProtected, ccfNgcCert}, ccf3, ccf4, ccf5, ccf6, ccf7, ccf8, ccf9, ccf10, ccf11, ccf12, ccf13, ccf14, ccf15, ccf16, ccf17 {, ccf31=31});
  TCryptCredFlags   = set of TCryptCredFlag;
  TCryptCredCType   = (cct0, cctGeneric{=1}, cctDomainPassword, cctDomainCertificate, cctDomainVisiblePassword, cctGenericCertificate, cctDomainExtended, cct7, cct8, cct9, cct10, cct11, cct12, cct13, cct14, cct15, cct16, cct17, {...} cct31{=31});
  TCryptCredPersist = (ccpNone, ccpSession, ccpLocalMachine, ccpEnterprise, ccp4, ccp5, ccp6, ccp7, ccp8, ccp9, ccp10, ccp11, ccp12, ccp13, ccp14, ccp15, ccp16, ccp17 {, ccp31=31});

  TCryptCredential = record
    Target:  string;
    Name:    string;
    RawData: TBytes;                // CredentialBlob (ReadOnly, not for WriteToCredentialsStore)
    Data:    TBytes;                // CredentialBlob + optional CredProtect/CredUnprotect
    Passw:   string;                // CredentialBlob + optional CredProtect/CredUnprotect
    Protect: CRED_PROTECTION_TYPE;  // CredentialBlob = CredIsProtected/CredProtect
    Age:     TDateTime;             // LastWritten
    Attr:    TCryptAttributes;
    Flags:   TCryptCredFlags;       // see NextFlags
    CType:   TCryptCredCType;       // see DefaultCType
    Persist: TCryptCredPersist;     // see DefaultPersist
    Comment: string;
    Alias:   string;
  private
    class var FNextFlags:  TCryptCredFlags;
    class var FDefCType:   TCryptCredCType;
    class var FDefPersist: TCryptCredPersist;
  public
    class constructor Create;
    class operator Initialize(out Dest: TCryptCredential);
    class property NextFlags:      TCryptCredFlags   read FNextFlags  write FNextFlags  {default []};
    class property DefaultCType:   TCryptCredCType   read FDefCType   write FDefCType   {default cctGeneric};       // CRED_TYPE_GENERIC
    class property DefaultPersist: TCryptCredPersist read FDefPersist write FDefPersist {default ccpLocalMachine};  // CRED_PERSIST_LOCAL_MACHINE
  end;

  TCryptFlag = (
    OnlyThisProcess,      // CRYPTPROTECTMEMORY_SAME_PROCESS   Encrypt and decrypt memory in the same process. An application running in a different process will not be able to decrypt the data.
    SameLoginSession,     // CRYPTPROTECTMEMORY_SAME_LOGON     Use the same logon credentials to encrypt and decrypt memory in different processes. An application running in a different process will be able to decrypt the data. However, the process must run as the same user that encrypted the data and in the same logon session.
    CrossProcess          // CRYPTPROTECTMEMORY_CROSS_PROCESS  Encrypt and decrypt memory in different processes. An application running in a different process will be able to decrypt the data.
  );

  WinCrypt = class
  private const
    cCryptFlags: array[TCryptFlag] of DWORD = (CRYPTPROTECTMEMORY_SAME_PROCESS, CRYPTPROTECTMEMORY_SAME_LOGON, CRYPTPROTECTMEMORY_CROSS_PROCESS);
  private
    class function  GetParentWindow(ParentForm: TCustomForm=nil): HWND;
    class procedure BuildPrompt(out Prompt: CRYPTPROTECT_PROMPTSTRUCT; Encrypt: Boolean; ParentForm: TCustomForm; Caption: string; WithPassword: Boolean);
    class function  CryptData(var Data: TBytes; Encrypt: Boolean; Flags: DWORD; Prompt: PCRYPTPROTECT_PROMPTSTRUCT=nil; const Desription: string=''): Boolean;
  public
    class var EntropyForEncrypt: RawByteString;
    class constructor Create;

    /// <summary> Arbeitsspeicher verschlüsseln </summary>
    /// <param name="Len"> Vielfaches von 16 </param>
    /// <remarks> wird auch von DevExpress (dxCryptoAPI) und EurekaLog (EWinCrypt/EEncrypt) verwendet </remarks>
    class procedure EncryptProcessMemory(Data: Pointer; Len: Integer; Flag: TCryptFlag=OnlyThisProcess);
    class procedure DecryptProcessMemory(Data: Pointer; Len: Integer; Flag: TCryptFlag=OnlyThisProcess);

    /// <summary> Daten mit User-/Computer-Key verschlüsseln </summary>
    class procedure EncryptUserData    (var Data: TBytes); inline;
    class procedure DecryptUserData    (var Data: TBytes); inline;
    class procedure EncryptComputerData(var Data: TBytes); inline;
    class procedure DecryptComputerData(var Data: TBytes); inline;
    class function  EncryptWithPrompt  (var Data: TBytes; ParentForm: TCustomForm=nil; Caption: string='';   Desription: string='';  WithPassword: Boolean=False):  Boolean;
    class function  DecryptWithPrompt  (var Data: TBytes; ParentForm: TCustomForm=nil; Caption: string='' {; out Desription: string; WithPassword: Boolean=False}): Boolean;

    /// <summary> Schlüsselspeicher / Credentials </summary>
    /// <remarks> auch im UniGUI zu finden </remarks>
    class procedure  WriteToCredentialsStore(const Target: string; const Username, Password: string;                                   doProtect: Boolean=False); overload;
    class procedure  WriteToCredentialsStore(const Target: string; const Username, Password: string; Attrib: array of TCryptAttribute; doProtect: Boolean=False); overload;
    class function  ReadFromCredentialsStore(const Target: string; var   Username, Password: string; Attrib: PCryptAttributes=nil): Boolean; overload;

    class procedure  WriteToCredentialsStore(const Target: string; const Name: string; const Data: TBytes; doProtect: Boolean=False); overload;
    class procedure  WriteToCredentialsStore(const Target: string; const Name: string; const Data: TBytes; Attrib: array of TCryptAttribute; doProtect: Boolean=False); overload;
    class function  ReadFromCredentialsStore(const Target: string; var   Name: string; var   Data: TBytes; Attrib: PCryptAttributes=nil): Boolean; overload;
    class function  ReadFromCredentialsStore(const Target: string; var   Cred: TCryptCredential): Boolean; overload;
    class procedure  WriteToCredentialsStore(const Target: string; const Cred: TCryptCredential); overload;

    class procedure DeleteInCredentialsStore(const Target: string);
    class function  ExistsInCredentialsStore(const TargetFilter: string): Boolean;
    class function    FindInCredentialsStore(const TargetFilter: string): TArray<TCryptCredential>;
    class procedure OpenCredentialManager;

    class function  WindowsCredentialDialog(var Username, Password: string; SaveCheckBox: PBOOL=nil; ParentForm: TCustomForm=nil; Caption: string=''; Desription: string=''; AuthError: DWORD=NO_ERROR; Flags: DWORD=0; Banner: TBitmap=nil): Boolean;
  end;

implementation

{$IF not Declared(CoTaskMemFree)}
  // [DCC Warnung] SysVCL.Extern.dpk(87): W1033 Die Unit 'Ole2' wurde implizit in Package 'SysVCL.Extern' importiert
  // Nicht rausgefunden, in welchem Package die Unit ole2 drin steckt, daher die eine Funktion hier direkt deklariert.
  procedure CoTaskMemFree(pv: Pointer); stdcall; external 'ole32.dll';
{$IFEND}

{$IFDEF UseWinMD}
  {.$IF TypeInfo(Windows.BOOL) <> TypeInfo(Windows.Foundation.BOOL)}

  function Win32Check(RetVal: Windows.Foundation.BOOL): BOOL;
  begin
    if not BOOL(RetVal) then RaiseLastOSError;
    Result := BOOL(RetVal);
  end;

  {.$ENDIF}
{$ENDIF}

function FileTimeToDateTime(const FT: FILETIME): TDateTime;
var
  LT: FILETIME;
  ST: SYSTEMTIME;
begin
  FileTimeToLocalFileTime(FT, LT);
  FileTimeToSystemTime(LT, ST);
  Result := SystemTimeToDateTime(ST);
end;

class operator TCryptAttribute.Implicit(const Data: TPair<string,TBytes>): TCryptAttribute;
begin
  Result := TCryptAttribute(Data);
end;

class operator TCryptAttribute.Implicit(const Data: TCryptAttribute): TPair<string,TBytes>;
begin
  Result := TPair<string,TBytes>(Data);
end;

constructor TCryptAttribute.Create(const Key: string; const Value: TBytes);
begin
  Self.Key   := Key;
  Self.Value := Value;
end;

constructor TCryptAttribute.Create(const Key, Value: string);
begin
  Self.Key   := Key;
  Self.Value := TEncoding.UTF8.GetBytes(Value);
end;

constructor TCryptAttribute.Create(const Key: string; Value: Integer);
begin
  Self.Key              := Key;
  SetLength(Self.Value, SizeOf(Integer));
  PInteger(Self.Value)^ := Value;
end;

constructor TCryptAttribute.Create(const Key: string; Value: Boolean);
begin
  Create(Key, Ord(Value));
end;

function TCryptAttribute.AsString: string;
begin
  Result := TEncoding.UTF8.GetString(Value);
end;

function TCryptAttribute.AsInteger: Integer;
begin
  case Length(Value) of
    0: Result := 0;
    1: Result := PByte(Value)^;
    2: Result := PWord(Value)^;
    4: Result := PInteger(Value)^;
    else raise EInvalidCast.CreateRes(@SInvalidCast);
  end;
end;

function TCryptAttribute.AsBoolean: Boolean;
begin
  Result := AsInteger <> 0;
end;

class function TCryptAttribute.Create(Keys: array of string; Values: array of TBytes): TArray<TCryptAttribute>;
var
  i: Integer;
begin
  Assert(Length(Keys) = Length(Values));
  SetLength(Result, Length(Keys));
  for i := High(Keys) downto 0 do
    Result[i] := TCryptAttribute.Create(Keys[i], Values[i]);
end;

class function TCryptAttribute.CreateStr(Keys, Values: array of string): TArray<TCryptAttribute>;
var
  Data: array of TBytes;
  i:    Integer;
begin
  SetLength(Data, Length(Values));
  for i := High(Data) downto 0 do
    Data[i] := TEncoding.UTF8.GetBytes(Values[i]);
  Result := TCryptAttribute.Create(Keys, Data);
end;

class function TCryptAttribute.CreateInt(Keys: array of string; Values: array of Integer): TArray<TCryptAttribute>;
var
  Data: array of TBytes;
  i:    Integer;
begin
  SetLength(Data, Length(Values), SizeOf(Integer));
  for i := High(Data) downto 0 do
    PInteger(Data[i])^ := Values[i];
  Result := TCryptAttribute.Create(Keys, Data);
end;

class function TCryptAttribute.CreateBool(Keys: array of string; Values: array of Boolean): TArray<TCryptAttribute>;
var
  Data: array of Integer;
  i:    Integer;
begin
  SetLength(Data, Length(Values));
  for i := High(Data) downto 0 do
    Data[i] := Ord(Values[i]);
  Result := TCryptAttribute.CreateInt(Keys, Data);
end;

class function TCryptAttribute.CreateMix(Keys: array of string; Values: array of const): TArray<TCryptAttribute>;
var
  Data: array of TBytes;
  i:    Integer;
begin
  SetLength(Data, Length(Values));
  for i := High(Data) downto 0 do
    case Values[i].VType of
      vtString:        Data[I] := TEncoding.UTF8.GetBytes(Values[i].VString^);
      vtAnsiString:    Data[I] := TEncoding.UTF8.GetBytes(AnsiString(Values[i].VAnsiString));
      vtWideString:    Data[I] := TEncoding.UTF8.GetBytes(WideString(Values[i].VWideString));
      vtUnicodeString: Data[I] := TEncoding.UTF8.GetBytes(UnicodeString(Values[i].VUnicodeString));
      vtPChar:         Data[I] := TEncoding.UTF8.GetBytes(Values[i].VPChar);
      vtPWideChar:     Data[I] := TEncoding.UTF8.GetBytes(Values[i].VPWideChar);
      vtChar:          Data[I] := TEncoding.UTF8.GetBytes(AnsiString(Values[i].VChar));
      vtWideChar:      Data[I] := TEncoding.UTF8.GetBytes(UnicodeString(Values[i].VWideChar));
      vtBoolean:       begin  SetLength(Data, 4);  PInteger(Data[i])^ := Ord(Values[i].VBoolean);  end;
      vtInteger:       begin  SetLength(Data, 4);  PInteger(Data[i])^ :=     Values[i].VInteger;   end;
      //vtInt64:       ;
      else             raise EInvalidCast.CreateRes(@SInvalidCast);
    end;
  Result := TCryptAttribute.Create(Keys, Data);
end;

class function TCryptAttribute.CreateEmpty: TArray<TCryptAttribute>;
begin
  Result := nil;
end;

class function TCryptAttribute.Find(const Attributes: TArray<TCryptAttribute>; const Key: string; const Default: TBytes): TCryptAttribute;
var
  i: Integer;
begin
  Result.Key   := '';
  Result.Value := Default;
  for i := High(Attributes) downto 0 do
    if SameText(Attributes[i].Key, Key) then
      Exit(Attributes[i]);
end;

class function TCryptAttribute.Find(const Attributes: TArray<TCryptAttribute>; const Key: string): TCryptAttribute;
begin
  Result := Find(Attributes, Key, nil);
end;

class function TCryptAttribute.Find(const Attributes: TArray<TCryptAttribute>; const Key, Default: string): string;
begin
  Result := Find(Attributes, Key, TEncoding.UTF8.GetBytes(Default)).AsString;
end;

class function TCryptAttribute.Find(const Attributes: TArray<TCryptAttribute>; const Key: string; Default: Integer): Integer;
var
  Data: TBytes;
begin
  SetLength(Data, SizeOf(Integer));
  PInteger(Data)^ := Default;
  Result := Find(Attributes, Key, Data).AsInteger;
end;

class function TCryptAttribute.Find(const Attributes: TArray<TCryptAttribute>; const Key: string; Default: Boolean): Boolean;
begin
  Result := Find(Attributes, Key, Ord(Default)) <> 0;
end;

class constructor TCryptCredential.Create;
begin
  FNextFlags  := [];
  FDefCType   := cctGeneric;
  FDefPersist := ccpLocalMachine;
end;

class operator TCryptCredential.Initialize(out Dest: TCryptCredential);
begin
  //Finalize(Dest);
  ZeroMemory(@Dest, SizeOf(Dest));
  //Dest.Target  := ;
  //Dest.Name    := ;
  //Dest.RawData := nil;
  //Dest.Data    := nil;
  //Dest.Passw   := '';
  //Dest.Protect := CredUnprotected;
  //Dest.Age     := 0;
  //Dest.Attr    := [];
  Dest.Flags     := FNextFlags;
  Dest.CType     := FDefCType;
  Dest.Persist   := FDefPersist;
  //Dest.Comment := '';
  //Dest.Alias   := '';
end;

class constructor WinCrypt.Create;
begin
  EntropyForEncrypt := '4A6DA84D-0897-4087-ABB2-3DB75B0932C7';
end;

class procedure WinCrypt.EncryptProcessMemory(Data: Pointer; Len: Integer; Flag: TCryptFlag);
begin
  if Len = 0 then
    Exit;
  Assert(Len mod CRYPTPROTECTMEMORY_BLOCK_SIZE = 0);
  Win32Check(CryptProtectMemory(Data, DWORD(Len), cCryptFlags[Flag]));
end;

class procedure WinCrypt.DecryptProcessMemory(Data: Pointer; Len: Integer; Flag: TCryptFlag);
begin
  if Len = 0 then
    Exit;
  Assert(Len mod CRYPTPROTECTMEMORY_BLOCK_SIZE = 0);
  Win32Check(CryptUnprotectMemory(Data, DWORD(Len), cCryptFlags[Flag]));
end;

class function WinCrypt.GetParentWindow(ParentForm: TCustomForm): HWND;
begin
  if not Assigned(ParentForm) or not ParentForm.HandleAllocated or not IsWindowVisible(ParentForm.Handle) then
    ParentForm := Screen.ActiveCustomForm;
  if not Assigned(ParentForm) or not ParentForm.HandleAllocated or not IsWindowVisible(ParentForm.Handle) then
    ParentForm := Application.MainForm;

  if Assigned(ParentForm) and ParentForm.HandleAllocated and IsWindowVisible(ParentForm.Handle) then
    Result := ParentForm.Handle
  else
    Result := GetActiveWindow;
end;

class procedure WinCrypt.BuildPrompt(out Prompt: CRYPTPROTECT_PROMPTSTRUCT; Encrypt: Boolean; ParentForm: TCustomForm; Caption: string; WithPassword: Boolean);
begin
  if Caption = '' then
    if Encrypt then
      Caption  := 'Daten verschlüsseln'  // hier nur echte Konstanten verwenden, wergen des PChar am Ende
    else
      Caption  := 'Daten entschlüsseln';

  Prompt.cbSize          := SizeOf(Prompt);
  if Encrypt then
    Prompt.dwPromptFlags := CRYPTPROTECT_PROMPT_ON_PROTECT
  else
    Prompt.dwPromptFlags := CRYPTPROTECT_PROMPT_ON_PROTECT or CRYPTPROTECT_PROMPT_ON_UNPROTECT;
  if WithPassword then
    Prompt.dwPromptFlags := Prompt.dwPromptFlags or CRYPTPROTECT_PROMPT_STRONG;
  Prompt.hwndApp         := GetParentWindow(ParentForm);
  Prompt.szPrompt        := PChar(Caption);
end;

class function WinCrypt.CryptData(var Data: TBytes; Encrypt: Boolean; Flags: DWORD; Prompt: PCRYPTPROTECT_PROMPTSTRUCT; const Desription: string): Boolean;
var
  CurData, NewData, Entropy: {$IFDEF UseWinMD}Windows.Foundation.{$IFEND}CRYPT_INTEGER_BLOB;
  ReadDesription: PWideChar;
  State: {$IFDEF UseWinMD}Windows.Foundation.{$IFEND}BOOL;
begin
  if not Assigned(Data) then
    Exit(True);
  Data := Copy(Data);  // UniqueArray(Data);
  CurData.pbData := @Data[0];
  CurData.cbData := Length(Data);
  Entropy.pbData := Pointer(EntropyForEncrypt);
  Entropy.cbData := Length(EntropyForEncrypt);

  if Encrypt then
    State := CryptProtectData(@CurData, Pointer(Desription), @Entropy, nil, Prompt, Flags, NewData)
  else
    State := CryptUnprotectData(@CurData, @ReadDesription, @Entropy, nil, Prompt, Flags, NewData);

  if Assigned(Prompt) and not {$IFDEF UseWinMD}BOOL{$IFEND}(State) and (GetLastError = ERROR_CANCELLED) then
    Exit(False)
  else
    Win32Check(State);

  try
    SetLength(Data, NewData.cbData);
    Move(NewData.pbData^, Data[0], NewData.cbData);
    ZeroMemory(CurData.pbData, CurData.cbData);
    ZeroMemory(NewData.pbData, NewData.cbData);
  finally
    if not Encrypt then
      LocalFree(HLOCAL(ReadDesription));
    LocalFree(HLOCAL(NewData.pbData));
  end;
  Result := True;
end;

class procedure WinCrypt.EncryptUserData(var Data: TBytes);
begin
  CryptData(Data, True, CRYPTPROTECT_UI_FORBIDDEN);
end;

class procedure WinCrypt.DecryptUserData(var Data: TBytes);
begin
  CryptData(Data, False, CRYPTPROTECT_UI_FORBIDDEN);
end;

class procedure WinCrypt.EncryptComputerData(var Data: TBytes);
begin
  CryptData(Data, True, CRYPTPROTECT_LOCAL_MACHINE or CRYPTPROTECT_UI_FORBIDDEN);
end;

class procedure WinCrypt.DecryptComputerData(var Data: TBytes);
begin
  CryptData(Data, False, CRYPTPROTECT_LOCAL_MACHINE or CRYPTPROTECT_UI_FORBIDDEN);
end;

class function WinCrypt.EncryptWithPrompt(var Data: TBytes; ParentForm: TCustomForm; Caption, Desription: string; WithPassword: Boolean): Boolean;
var
  Prompt: CRYPTPROTECT_PROMPTSTRUCT;
begin
  BuildPrompt(Prompt, True, ParentForm, Caption, WithPassword);
  Result := CryptData(Data, True, CRYPTPROTECT_LOCAL_MACHINE, @Prompt, Desription);
end;

class function WinCrypt.DecryptWithPrompt(var Data: TBytes; ParentForm: TCustomForm; Caption: string): Boolean;
var
  Prompt: CRYPTPROTECT_PROMPTSTRUCT;
begin
  BuildPrompt(Prompt, False, ParentForm, Caption, False{WithPassword});
  Result := CryptData(Data, False, CRYPTPROTECT_LOCAL_MACHINE, @Prompt, ''{Desription});
end;

class procedure WinCrypt.WriteToCredentialsStore(const Target, Username, Password: string; doProtect: Boolean);
begin
  WriteToCredentialsStore(Target, Username, TEncoding.Unicode.GetBytes(Password), [], doProtect);
end;

class procedure WinCrypt.WriteToCredentialsStore(const Target, Username, Password: string; Attrib: array of TCryptAttribute; doProtect: Boolean);
begin
  WriteToCredentialsStore(Target, Username, TEncoding.Unicode.GetBytes(Password), Attrib, doProtect);
end;

class function WinCrypt.ReadFromCredentialsStore(const Target: string; var Username, Password: string; Attrib: PCryptAttributes): Boolean;
var
  Data: TBytes;
begin
  Result   := ReadFromCredentialsStore(Target, Username, Data, Attrib);
  Password := TEncoding.Unicode.GetString(Data);
end;

class procedure WinCrypt.WriteToCredentialsStore(const Target, Name: string; const Data: TBytes; doProtect: Boolean);
begin
  WriteToCredentialsStore(Target, Name, Data, [], doProtect);
end;

class procedure WinCrypt.WriteToCredentialsStore(const Target, Name: string; const Data: TBytes; Attrib: array of TCryptAttribute; doProtect: Boolean);
var
  Cred: TCryptCredential;
  i:    Integer;
begin
  Cred           := Default(TCryptCredential);
  Cred.Target    := Target;
  Cred.Name      := Name;
  //Cred.RawData := nil;
  Cred.Data      := Data;
  //Cred.Passw   := nil;
  Cred.Protect   := CRED_PROTECTION_TYPE(IfThen(doProtect, Ord(CredUserProtection), Ord(CredUnprotected)));
  //Cred.Age     := 0;
  //Cred.Flags   := Default [];
  //Cred.CType   := Default cctGeneric;
  //Cred.Persist := Default ccpLocalMachine;
  //Cred.Comment := '';
  //Cred.Alias   := '';
  SetLength(Cred.Attr, Length(Attrib));
  for i := High(Cred.Attr) downto 0 do
    Cred.Attr[i] := Attrib[i];

  WriteToCredentialsStore(Target, Cred);
end;

class function WinCrypt.ReadFromCredentialsStore(const Target: string; var Name: string; var Data: TBytes; Attrib: PCryptAttributes): Boolean;
var
  Cred: TCryptCredential;
begin
  Result := ReadFromCredentialsStore(Target, Cred);
  if Result then begin
    Name := Cred.Name;
    Data := Cred.Data;
    if Assigned(Attrib) then
      Attrib^ := Cred.Attr;
  end else begin
    Name := '';
    Data := nil;
  end;
end;

class function WinCrypt.ReadFromCredentialsStore(const Target: string; var Cred: TCryptCredential): Boolean;
var
  PCred: PCREDENTIAL;
  CProt: CRED_PROTECTION_TYPE;
  i:     Integer;
begin
  Cred   := Default(TCryptCredential);
  Result := CredRead(PChar(Target), CRED_TYPE_GENERIC, 0, PCred);
  if Result then
    try
      Cred.Target  := Target;
      Cred.Name    := PCred.UserName;
      Cred.Age     := FileTimeToDateTime({$IFDEF UseWinMD}FILETIME{$ENDIF}(PCred.LastWritten));
      Cred.Flags   := TCryptCredFlags(PCred.Flags);
      Cred.CType   := TCryptCredCType(PCred.&Type);
      Cred.Persist := TCryptCredPersist(PCred.Persist);
      Cred.Comment := PCred.Comment;
      Cred.Alias   := PCred.TargetAlias;

      SetLength(Cred.RawData, PCred.CredentialBlobSize);
      if Assigned(Cred.RawData) then
        Move(PCred.CredentialBlob^, Cred.RawData[0], PCred.CredentialBlobSize);

      SetLength(Cred.Data, PCred.CredentialBlobSize + 2);
      Move(PCred.CredentialBlob^, Cred.Data[0], PCred.CredentialBlobSize);
      PWideChar(@Cred.Data[PCred.CredentialBlobSize])^ := #0;
      if (PCred.CredentialBlobSize mod 2 = 0) and CredIsProtectedW(PWideChar(Cred.Data), CProt) and (CProt <> CredUnprotected) then begin
        i := 0;
        if not CredUnprotectW(False, PWideChar(PCred.CredentialBlob), PCred.CredentialBlobSize div 2, nil, DWORD(i)) and (GetLastError <> ERROR_INSUFFICIENT_BUFFER) then
          RaiseLastOSError;
        SetLength(Cred.Data, i * 2);
        if not CredUnprotectW(False, PWideChar(PCred.CredentialBlob), PCred.CredentialBlobSize div 2, PWideChar(Cred.Data), DWORD(i)) then
          RaiseLastOSError;
        Cred.Protect := CProt;
      end else if CredIsProtectedA(PAnsiChar(Cred.Data), CProt) and (CProt <> CredUnprotected) then begin
        i := 0;
        if not CredUnprotectA(False, PAnsiChar(PCred.CredentialBlob), PCred.CredentialBlobSize, nil, DWORD(i)) and (GetLastError <> ERROR_INSUFFICIENT_BUFFER) then
          RaiseLastOSError;
        SetLength(Cred.Data, i);
        if not CredUnprotectA(False, PAnsiChar(PCred.CredentialBlob), PCred.CredentialBlobSize, PAnsiChar(Cred.Data), DWORD(i)) then
          RaiseLastOSError;
        Cred.Protect := CProt;
      end else
        SetLength(Cred.Data, PCred.CredentialBlobSize);

      SetString(Cred.Passw, PChar(Cred.Data), Length(Cred.Data) div 2); //Cred.Passw := TEncoding.Unicode.GetString(Cred.Data);

      SetLength(Cred.Attr, PCred.AttributeCount);
      for i := High(Cred.Attr) downto 0 do begin
        Cred.Attr[i].Key := PCred.Attributes[i].Keyword;
        SetLength(Cred.Attr[i].Value, PCred.Attributes[i].ValueSize);
        if PCred.Attributes[i].ValueSize > 0 then
          Move(PCred.Attributes[i].Value^, Cred.Attr[i].Value[0], PCred.Attributes[i].ValueSize);
      end;
    finally
      CredFree(PCred);
    end;
end;

class procedure WinCrypt.WriteToCredentialsStore(const Target: string; const Cred: TCryptCredential);
var
  PCred: CREDENTIAL;
  CAttr: TArray<CREDENTIAL_ATTRIBUTE>;
  CProt: CRED_PROTECTION_TYPE;
  Prot:  TBytes;
  i:     Integer;
begin
  Assert(Length(Cred.Target)  <= CRED_MAX_DOMAIN_TARGET_NAME_LENGTH);  // Min(CRED_MAX_GENERIC_TARGET_NAME_LENGTH, CRED_MAX_DOMAIN_TARGET_NAME_LENGTH)
  Assert(Length(Cred.Name)    <= CRED_MAX_USERNAME_LENGTH);
  Assert(Length(Cred.Data)    <= CRED_MAX_CREDENTIAL_BLOB_SIZE);
  Assert(Length(Cred.Attr)    <= CRED_MAX_ATTRIBUTES);
  Assert(Length(Cred.Comment) <= CRED_MAX_STRING_LENGTH);
  Assert(Length(Cred.Alias)   <= CRED_MAX_STRING_LENGTH);
  Assert(Cred.Flags - [ccfPromptNow, ccfUsernameTarget] = []);
  Assert(Cred.CType   in [cctGeneric..{cctDomainExtended}cct31]);
  Assert(Cred.Persist in [ccpSession, ccpLocalMachine, ccpEnterprise]);
  for i := High(CAttr) downto 0 do begin
    Assert(Length(Cred.Attr[i].Key)   <= CRED_MAX_TARGETNAME_ATTRIBUTE_LENGTH);
    Assert(Length(Cred.Attr[i].Value) <= CRED_MAX_VALUE_SIZE);
  end;

  ZeroMemory(@PCred, SizeOf(PCred));
  PCred.TargetName         := PChar(Cred.Target);
  PCred.UserName           := PChar(Cred.Name);
  // ignored                  Cred.RawData;
  PCred.CredentialBlob     := Pointer(Cred.Data);  // Cred.Data corresponds to Cred.Passw
  PCred.CredentialBlobSize := Length(Cred.Data);
  // ignored                  Cred.Passw;
  Int64(PCred.LastWritten) := 0; //DateTimeToFileTime(Cred.Age);
  PCred.Flags              := DWORD(Cred.Flags);
  PCred.&Type              := DWORD(Cred.CType);
  PCred.Persist            := DWORD(Cred.Persist);
  PCred.Comment            := Pointer(Cred.Comment);
  PCred.TargetAlias        := Pointer(Cred.Alias);

  TCryptCredential.FNextFlags := [];

  if (Cred.Protect <> CredUnprotected) and Assigned(Cred.Data) then begin
    if Length(Cred.Data) mod 2 <> 0 then
      RaiseLastOSError(ERROR_BAD_LENGTH);
    i := 0;
    if not CredProtectW(False, PWideChar(Cred.Data), Length(Cred.Data) div 2, nil, DWORD(i), CProt) and (GetLastError <> ERROR_INSUFFICIENT_BUFFER) then
      RaiseLastOSError;
    SetLength(Prot, i * 2);
    if not CredProtectW(False, PWideChar(Cred.Data), Length(Cred.Data) div 2, PWideChar(Prot), DWORD(i), CProt) then
      RaiseLastOSError;
    PCred.CredentialBlob     := Pointer(Prot);
    PCred.CredentialBlobSize := DWORD(i) * 2;
  end;

  if Assigned(Cred.Attr) then begin
    SetLength(CAttr, Length(Cred.Attr));
    for i := High(CAttr) downto 0 do begin
      CAttr[i].Keyword     := PChar(Cred.Attr[i].Key);
      CAttr[i].Flags       := 0;
      CAttr[i].ValueSize   := Length(Cred.Attr[i].Value);
      CAttr[i].Value       := Pointer(Cred.Attr[i].Value);
    end;
    PCred.AttributeCount   := Length(Cred.Attr);
    PCred.Attributes       := @CAttr[0];
  end;

  Win32Check(CredWrite(@PCred, 0));
end;

class procedure WinCrypt.DeleteInCredentialsStore(const Target: string);
begin
  if not {$IFDEF UseWinMD}BOOL{$IFEND}(CredDelete(PChar(Target), CRED_TYPE_GENERIC, 0)) and (GetLastError <> {ERROR_NOT_FOUND}1168) then
    RaiseLastOSError;
end;

class function WinCrypt.ExistsInCredentialsStore(const TargetFilter: string): Boolean;
var
  Count: DWORD;
  Creds: PPCREDENTIAL;
begin
  if not CredEnumerate(PChar(TargetFilter), 0, Count, Creds) then begin
    //if (GetLastError <> ERROR_NOT_FOUND) and (GetLastError <> $80070490) then
    //  RaiseLastOSError;
    Result := False;
  end else begin
    Result := Count > 0;
    CredFree(Creds);
  end;
end;

class function WinCrypt.FindInCredentialsStore(const TargetFilter: string): TArray<TCryptCredential>;
var
  i, i2: Integer;
  Count: DWORD;
  Creds: PPCREDENTIAL;
  PCred: PCREDENTIAL;
  CProt: CRED_PROTECTION_TYPE;
begin
  if not CredEnumerate(PChar(TargetFilter), 0, Count, Creds) then begin
    if (GetLastError <> ERROR_NOT_FOUND) and (GetLastError <> $80070490) then
      RaiseLastOSError;
    Count := 0;
  end;
  try
    SetLength(Result, Count);
    for i := 0 to Integer(Count) - 1 do begin
      PCred := (Creds + i)^;
      Result[i].Target  := PCred.TargetName;
      Result[i].Name    := PCred.UserName;
      Result[i].Age     := FileTimeToDateTime({$IFDEF UseWinMD}FILETIME{$ENDIF}(PCred.LastWritten));
      Result[i].Flags   := TCryptCredFlags(PCred.Flags);
      Result[i].CType   := TCryptCredCType(PCred.&Type);
      Result[i].Persist := TCryptCredPersist(PCred.Persist);
      Result[i].Comment := PCred.Comment;
      Result[i].Alias   := PCred.TargetAlias;

      SetLength(Result[i].RawData, PCred.CredentialBlobSize);
      if Assigned(Result[i].RawData) then
        Move(PCred.CredentialBlob^, Result[i].RawData[0], PCred.CredentialBlobSize);

      SetLength(Result[i].Data, PCred.CredentialBlobSize + 2);
      Move(PCred.CredentialBlob^, Result[i].Data[0], PCred.CredentialBlobSize);
      PWideChar(@Result[i].Data[PCred.CredentialBlobSize])^ := #0;
      if (PCred.CredentialBlobSize mod 2 = 0) and CredIsProtectedW(PWideChar(Result[i].Data), CProt) and (CProt <> CredUnprotected) then begin
        i2 := 0;
        if not CredUnprotectW(False, PWideChar(PCred.CredentialBlob), PCred.CredentialBlobSize div 2, nil, DWORD(i2)) and (GetLastError <> ERROR_INSUFFICIENT_BUFFER) then
          RaiseLastOSError;
        SetLength(Result[i].Data, i2 * 2);
        if not CredUnprotectW(False, PWideChar(PCred.CredentialBlob), PCred.CredentialBlobSize div 2, PWideChar(Result[i].Data), DWORD(i2)) then
          RaiseLastOSError;
        Result[i].Protect := CProt;
      end else if CredIsProtectedA(PAnsiChar(Result[i].Data), CProt) and (CProt <> CredUnprotected) then begin
        i2 := 0;
        if not CredUnprotectA(False, PAnsiChar(PCred.CredentialBlob), PCred.CredentialBlobSize, nil, DWORD(i2)) and (GetLastError <> ERROR_INSUFFICIENT_BUFFER) then
          RaiseLastOSError;
        SetLength(Result[i].Data, i2);
        if not CredUnprotectA(False, PAnsiChar(PCred.CredentialBlob), PCred.CredentialBlobSize, PAnsiChar(Result[i].Data), DWORD(i2)) then
          RaiseLastOSError;
        Result[i].Protect := CProt;
      end else
        SetLength(Result[i].Data, PCred.CredentialBlobSize);

      SetString(Result[i].Passw, PChar(Result[i].Data), Length(Result[i].Data) div 2); //Cred.Passw := TEncoding.Unicode.GetString(Cred.Data);

      SetLength(Result[i].Attr, PCred.AttributeCount);
      for i2 := High(Result[i].Attr) downto 0 do begin
        Result[i].Attr[i2].Key := PCred.Attributes[i2].Keyword;
        SetLength(Result[i].Attr[i2].Value, PCred.Attributes[i2].ValueSize);
        if PCred.Attributes[i2].ValueSize > 0 then
          Move(PCred.Attributes[i2].Value^, Result[i].Attr[i2].Value[0], PCred.Attributes[i2].ValueSize);
      end;
    end;
  finally
    CredFree(Creds);
  end;
end;

class procedure WinCrypt.OpenCredentialManager;
begin
  ShellExecute(0, nil, 'control.exe', '/name Microsoft.CredentialManager', nil, 0);
end;

class function WinCrypt.WindowsCredentialDialog(var Username, Password: string; SaveCheckBox: PBOOL; ParentForm: TCustomForm; Caption, Desription: string; AuthError, Flags: DWORD; Banner: TBitmap): Boolean;
var
  UIInfo:   CREDUI_INFO;
  Size:     ULONG;
  AuthPack: ULONG;
  InitAuth: TBytes;
  AuthBuff: LPVOID;
  AuthSize: ULONG;
  State:    DWORD;
  Name:     array[0..CREDUI_MAX_USERNAME_LENGTH] of Char;
  Pass:     array[0..CREDUI_MAX_PASSWORD_LENGTH] of Char;
  LenName:  DWORD;
  LenPass:  DWORD;
begin
  UIInfo.cbSize         := SizeOf(UIInfo);
  UIInfo.hwndParent     := GetParentWindow(ParentForm);
  UIInfo.pszMessageText := Pointer(Desription);
  UIInfo.pszCaptionText := Pointer(Caption);  // "ApplicationName.exe" if empty
  UIInfo.hbmBanner      := 0;
  if Assigned(Banner) then
    UIInfo.hbmBanner    := Banner.Handle;

  if Username <> '' then begin
    Size := 0;                                                                                                    //Pointer(Password) : aktuelle Windows10 hätten liebendgern bei einem LeerString ein NIL, aber WindowsServer2008 knallt, wenn es NIL ist
    if not {$IFDEF UseWinMD}BOOL{$IFEND}(CredPackAuthenticationBuffer(CRED_PACK_GENERIC_CREDENTIALS, PChar(Username), PChar(Password), nil, Size)) and (GetLastError <> ERROR_INSUFFICIENT_BUFFER) then
      RaiseLastOSError;
    SetLength(InitAuth, Size);
    Win32Check(CredPackAuthenticationBuffer(CRED_PACK_GENERIC_CREDENTIALS, PChar(Username), PChar(Password), @InitAuth[0], Size));
  end;

  if Flags and (CREDUIWIN_AUTHPACKAGE_ONLY or CREDUIWIN_ENUMERATE_ADMINS or CREDUIWIN_ENUMERATE_CURRENT_USER) = 0 then
    Flags := Flags or CREDUIWIN_GENERIC;
  if Assigned(SaveCheckBox) then
    Flags := Flags or CREDUIWIN_CHECKBOX;

  AuthPack := 0;
  State    := CredUIPromptForWindowsCredentials(@UIInfo, AuthError, AuthPack, Pointer(InitAuth), Length(InitAuth), AuthBuff, AuthSize, @SaveCheckBox, Flags);
  Result   := State = ERROR_SUCCESS;
  if Result then
    try
      LenName   := Length(Name);
      LenPass   := Length(Pass);
      Win32Check(CredUnPackAuthenticationBuffer(0, AuthBuff, AuthSize, @Name, @LenName, nil, nil, @Pass, @LenPass));
      Username  := Name;
      Password  := Pass;
      ZeroMemory(@Name, SizeOf(Name));
      ZeroMemory(@Pass, SizeOf(Pass));
      ZeroMemory(AuthBuff, AuthSize);
    finally
      CoTaskMemFree(AuthBuff);
    end
  else if State <> ERROR_CANCELLED then
    RaiseLastOSError(HRESULT(State));
end;

end.

