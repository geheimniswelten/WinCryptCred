unit CryptDemoMain;

interface

uses
  {$IFDEF WithWinMD} Windows.Security.Cryptography, Windows.Security.Credentials, {$ENDIF}
  Windows, Messages, SysUtils, StrUtils, Variants, Classes, Graphics, Controls, Math, TypInfo,
  Forms, Dialogs, StdCtrls, ExtCtrls, Grids, ValEdit, ComCtrls, ImgList, System.ImageList,
  //
  Generics.Collections, System.NetEncoding, h5u.WinCryptCred;

type
  TButton = class(StdCtrls.TButton)
  protected
    procedure CreateParams(var Params: TCreateParams); override;
  end;

  TWinCryptDemoForm = class(TForm)
    {$REGION 'Components'}
    Label1: TLabel;
    edInput: TButtonedEdit;
    edBinary: TEdit;
    btProcMem: TButton;
    rgProcMemFlags: TRadioGroup;
    edBlockFill: TEdit;
    edEncrypted: TMemo;
    edDecrypted: TEdit;
    edOutput: TEdit;
    edEntropy: TButtonedEdit;
    btUserData: TButton;
    btComputerData: TButton;
    btWithPrompt: TButton;
    cbWithPromptCaption: TCheckBox;
    cbWithPromptPassword: TCheckBox;
    pcCredStore: TPageControl;
    tsCredStore1: TTabSheet;
    tcCredStore2: TTabSheet;
    edCredInputTarget1: TButtonedEdit;
    edCredInputName1: TButtonedEdit;
    edCredInputPass1: TButtonedEdit;
    cbCredInputPassBase1: TCheckBox;
    cbCredInputProtect1: TCheckBox;
    liCredInputAttrib1: TValueListEditor;
    edCredInputTarget2: TButtonedEdit;
    edCredInputName2: TButtonedEdit;
    edCredInputPass2: TButtonedEdit;
    cbCredInputPassBase2: TCheckBox;
    cbCredInputProtect2: TCheckBox;
    liCredInputAttrib2: TValueListEditor;
    btCredStoreWrite: TButton;
    cbCredReadTarget: TRadioButton;
    edCredFindTarget: TButtonedEdit;
    cbCredReadFilter: TRadioButton;
    edCredFindFilter: TButtonedEdit;
    btCredStoreRead: TButton;
    btCredStoreDelete: TButton;
    btCredStoreExists: TButton;
    btCredStoreFind: TButton;
    tsCredReadTargets: TTabControl;
    edCredReadTarget: TEdit;
    edCredReadName: TEdit;
    lbCredReadRAW: TLabel;
    edCredReadRAW: TEdit;
    lbCredReadANSI: TLabel;
    edCredReadANSI: TEdit;
    lbCredReadWide: TLabel;
    edCredReadWide: TEdit;
    lbCredReadBase: TLabel;
    edCredReadBase: TEdit;
    edCredReadDate: TEdit;
    meCredReadInfo: TMemo;
    cbCredReadProtect: TCheckBox;
    liCredReadAttrib: TValueListEditor;
    btCredStoreOpen: TButton;
    btCredDialog: TButton;
    cbCredDialogPrefill: TCheckBox;
    cbCredDialogSave: TCheckBox;
    cbCredDialogTrue: TCheckBox;
    cbCredDialogCaption: TCheckBox;
    cbCredDialogError: TCheckBox;
    cbCredDialogBanner: TCheckBox;
    cbCredDialogSecure: TCheckBox;
    btCredReadPrev: TButton;
    btCredReadNext: TButton;
    ImageList: TImageList;
    imgBanner: TImage;
    BalloonHint: TBalloonHint;
    Panel1: TPanel;
    {$ENDREGION}
    {$REGION 'Events'}
    procedure FormCreate(Sender: TObject);
    procedure btProcMemClick(Sender: TObject);
    procedure btUserDataClick(Sender: TObject);
    procedure edInputChange(Sender: TObject);
    procedure btComputerDataClick(Sender: TObject);
    procedure btWithPromptClick(Sender: TObject);
    procedure edCredInputTargetChange(Sender: TObject);
    procedure btCredStoreWriteClick(Sender: TObject);
    procedure btCredStoreReadClick(Sender: TObject);
    procedure btCredStoreDeleteClick(Sender: TObject);
    procedure btCredStoreExistsClick(Sender: TObject);
    procedure btCredStoreOpenClick(Sender: TObject);
    procedure btCredDialogClick(Sender: TObject);
    procedure RightButtonClick(Sender: TObject);
    procedure cbCredReadTargetClick(Sender: TObject);
    procedure tsCredReadTargetsChange(Sender: TObject);
    procedure tsCredReadTargetsEnter(Sender: TObject);
    {$ENDREGION}
  private
    FCredential: TArray<TCryptCredential>;
  end;

var
  WinCryptDemoForm: TWinCryptDemoForm;

implementation

{$R *.dfm}

{$REGION 'Global'}

procedure TButton.CreateParams(var Params: TCreateParams);
begin
  inherited CreateParams(Params);
  Params.Style := Params.Style or BS_MULTILINE;
end;

function BinärToString(P: PAnsiChar; Len: Integer): string;
var
  i: Integer;
begin
  SetLength(Result, Len);
  for i := 0 to Len-1 do
    if P[i] < ' ' then
      Result[i + 1] := Char(Ord(P[i]) or $2400)
    else
      Result[i + 1] := Char(Ord(P[i]));
end;

function Binär2ToString(P: PWideChar; Len: Integer): string;
var
  i: Integer;
begin
  SetLength(Result, Len);
  for i := 0 to Len-1 do
    if P[i] < ' ' then
      Result[i + 1] := Char(Ord(P[i]) or $2400)
    else
      Result[i + 1] := Char(Ord(P[i]));
end;

procedure TWinCryptDemoForm.FormCreate(Sender: TObject);
var
  C: TComponent;
begin
  edEntropy.Text := UTF8ToString(WinCrypt.EntropyForEncrypt);

  edInputChange(Self);
  edCredInputTargetChange(Self);
  cbCredReadTargetClick(Self);
  tsCredReadTargetsChange(Self);

  for C in Self do
    if C is TButtonedEdit then begin
      TButtonedEdit(C).Hint                   := TButtonedEdit(C).Text;
      TButtonedEdit(C).Images                 := ImageList;
      TButtonedEdit(C).RightButton.Visible    := True;
      TButtonedEdit(C).RightButton.ImageIndex := 0;
      TButtonedEdit(C).OnRightButtonClick     := RightButtonClick;
    end;
end;

procedure TWinCryptDemoForm.RightButtonClick(Sender: TObject);
begin
  TCustomEdit(Sender).Text := (Sender as TCustomEdit).Hint;
end;

{$ENDREGION}
{$REGION 'Encrypt/Decrypt'}

procedure TWinCryptDemoForm.edInputChange(Sender: TObject);
begin
  edBinary.Clear;
  edBlockFill.Clear;
  edEncrypted.Clear;
  edDecrypted.Clear;
  edOutput.Clear;

  if not Assigned(Sender) then begin
    //Application.ProcessMessages;
    edBinary.Repaint;
    edBlockFill.Repaint;
    edEncrypted.Repaint;
    edDecrypted.Repaint;
    edOutput.Repaint;
    Sleep(10);
  end;
end;

procedure TWinCryptDemoForm.btProcMemClick(Sender: TObject);
var
  F: TCryptFlag;
  A: UTF8String;
  L, Z: Integer;
begin
  // OnlyThisProcess  : Daten im RAM verschlüsseln, für den aktuellen Prozess
  // SameLoginSession : für ein Sharing zwischen Programmen in der aktuellen Login-Session
  // CrossProcess     : für ein Sharing zwischen Programmen (auch unter einem anderen Nutzer-Login)
  edInputChange(nil);  // clear Edits

  A := UTF8Encode(edInput.Text);
  F := TCryptFlag(rgProcMemFlags.ItemIndex);
  edBinary.Text    := BinärToString(@A[1], Length(A));

  Z :=  Length(A);
  L := (Length(A) + CRYPTPROTECTMEMORY_BLOCK_SIZE - 1) and not (CRYPTPROTECTMEMORY_BLOCK_SIZE - 1);
  SetLength(A, L);  // Blöcke zu je 16 Bytes
  FillChar(A[Z+1], L - Z, 0);

  edBlockFill.Text := BinärToString(@A[1], Length(A));

  WinCrypt.EncryptProcessMemory(@A[1], L, F);
  edEncrypted.Text := BinärToString(@A[1], Length(A));

  WinCrypt.DecryptProcessMemory(@A[1], L, F);
  edDecrypted.Text := BinärToString(@A[1], Length(A));
  edOutput.Text    := UTF8ToString(A);
end;

procedure TWinCryptDemoForm.btUserDataClick(Sender: TObject);
var
  B: TBytes;
begin
  // Daten verschlüsselt speichern, für das aktuelle Nutzerlogin
  edInputChange(nil);  // clear Edits

  B := TEncoding.UTF8.GetBytes(edInput.Text);
  edBinary.Text    := BinärToString(@B[0], Length(B));

  WinCrypt.EntropyForEncrypt := UTF8Encode(edEntropy.Text);
  WinCrypt.EncryptUserData(B);
  edEncrypted.Text := BinärToString(@B[0], Length(B));

  WinCrypt.DecryptUserData(B);
  edDecrypted.Text := BinärToString(@B[0], Length(B));
  edOutput.Text    := TEncoding.UTF8.GetString(B);
end;

procedure TWinCryptDemoForm.btComputerDataClick(Sender: TObject);
var
  B: TBytes;
begin
  // Daten verschlüsselt speichern, für diesen Computer
  edInputChange(nil);  // clear Edits

  B := TEncoding.UTF8.GetBytes(edInput.Text);
  edBinary.Text    := BinärToString(@B[0], Length(B));

  WinCrypt.EntropyForEncrypt := UTF8Encode(edEntropy.Text);
  WinCrypt.EncryptComputerData(B);
  edEncrypted.Text := BinärToString(@B[0], Length(B));

  WinCrypt.DecryptComputerData(B);
  edDecrypted.Text := BinärToString(@B[0], Length(B));
  edOutput.Text    := TEncoding.UTF8.GetString(B);
end;

procedure TWinCryptDemoForm.btWithPromptClick(Sender: TObject);
var
  B: TBytes;
  Password: Boolean;
  Caption, Descr: string;
begin
  // Daten verschlüsselt speichern, für diesen Computer mit Passwort
  edInputChange(nil);  // clear Edits

  B := TEncoding.UTF8.GetBytes(edInput.Text);
  edBinary.Text      := BinärToString(@B[0], Length(B));

  if cbWithPromptCaption.Checked then begin
    Caption := 'The Caption';
    Descr   := 'The Description ...';  // only one Line
  end;
  Password  := cbWithPromptPassword.Checked;


  WinCrypt.EntropyForEncrypt := UTF8Encode(edEntropy.Text);
  if not WinCrypt.EncryptWithPrompt(B, Self, Caption, Descr, Password) then begin
    edEncrypted.Text := 'CANCEL';
    Exit;
  end;
  edEncrypted.Text   := BinärToString(@B[0], Length(B));

  if not WinCrypt.DecryptWithPrompt(B, Self, Caption) then begin
    edDecrypted.Text := 'CANCEL';
    Exit;
  end;
  edDecrypted.Text   := BinärToString(@B[0], Length(B));
  edOutput.Text      := TEncoding.UTF8.GetString(B);
end;

{$ENDREGION}
{$REGION 'Credentials'}

procedure TWinCryptDemoForm.edCredInputTargetChange(Sender: TObject);
var
  TabSheet: TTabSheet;
  TabEdit:  TControl;
  Target:   string;
  Idx:      string;
begin
  if Sender is TCustomEdit then begin
    TabSheet := (TCustomEdit(Sender).Parent as TTabSheet);
    Target   := TCustomEdit(Sender).Text;

    TabSheet.Caption        := LeftStr(ExtractFileName(Target), 15);
    edCredFindTarget.Text   := Target;
    if ExtractFilePath(Target) <> '' then
      edCredFindFilter.Text := ExtractFilePath(Target) + '*'
    else
      edCredFindFilter.Text := '*';

  end else begin  // FormCreate and OnEnter
    Idx       := IntToStr(pcCredStore.ActivePageIndex + 1);
    TabSheet  := pcCredStore.ActivePage;
    TabEdit   := TabSheet.FindChildControl('edCredInputTarget' + Idx);
    Target    := TCustomEdit(TabEdit).Text;

    edCredFindTarget.Text     := Target;
    if ExtractFilePath(Target) <> '' then
      edCredFindFilter.Text := ExtractFilePath(Target) + '*'
    else
      edCredFindFilter.Text := '*';
  end;
end;

procedure TWinCryptDemoForm.cbCredReadTargetClick(Sender: TObject);
begin
  edCredFindTarget.Enabled  :=     cbCredReadTarget.Checked;
  edCredFindFilter.Enabled  := not cbCredReadTarget.Checked;
  btCredStoreRead.Enabled   :=     cbCredReadTarget.Checked;
  btCredStoreDelete.Enabled :=     cbCredReadTarget.Checked;
  btCredStoreExists.Enabled :=     True;
  btCredStoreFind.Enabled   := not cbCredReadTarget.Checked;

  cbCredDialogTrue.Enabled  :=     cbCredDialogSave.Checked;
end;

procedure TWinCryptDemoForm.btCredStoreWriteClick(Sender: TObject);
var
  Idx: string;
  _edCredInputTarget, _edCredInputName, _edCredInputPass: TCustomEdit;
  _cbCredInputPassBase, _cbCredInputProtect: TCheckBox;
  _liCredInputAttrib: TValueListEditor;
  Attributes: TArray<TCryptAttribute>;
  i: Integer;
begin
  Idx                  := IntToStr(pcCredStore.ActivePageIndex + 1);
  _edCredInputTarget   := TCustomEdit(FindComponent('edCredInputTarget'   + Idx));
  _edCredInputName     := TCustomEdit(FindComponent('edCredInputName'     + Idx));
  _edCredInputPass     := TCustomEdit(FindComponent('edCredInputPass'     + Idx));
  _cbCredInputPassBase :=   TCheckBox(FindComponent('cbCredInputPassBase' + Idx));
  _cbCredInputProtect  :=   TCheckBox(FindComponent('cbCredInputProtect'  + Idx));
  _liCredInputAttrib   := TValueListEditor(FindComponent('liCredInputAttrib' + Idx));

  if _liCredInputAttrib.Strings.Count > 0 then begin
    SetLength(Attributes, _liCredInputAttrib.Strings.Count);
    for i := 0 to High(Attributes) do begin
      Attributes[i].Key   := _liCredInputAttrib.Strings.Names[i];
      Attributes[i].Value := TEncoding.Default.GetBytes(_liCredInputAttrib.Strings.ValueFromIndex[i]);
    end;
    //WinCrypt.WriteToCredentialsStore('WinCrypt', 'Username', 'Password', [WinCrypt.Attr('abc', [1, 2, 3])]);
    if _cbCredInputPassBase.Checked then
      WinCrypt.WriteToCredentialsStore(_edCredInputTarget.Text, _edCredInputName.Text, TNetEncoding.Base64.DecodeStringToBytes(_edCredInputPass.Text), Attributes, _cbCredInputProtect.Checked)
    else
      WinCrypt.WriteToCredentialsStore(_edCredInputTarget.Text, _edCredInputName.Text, _edCredInputPass.Text, Attributes, _cbCredInputProtect.Checked);
  end else
    if _cbCredInputPassBase.Checked then
      WinCrypt.WriteToCredentialsStore(_edCredInputTarget.Text, _edCredInputName.Text, TNetEncoding.Base64.DecodeStringToBytes(_edCredInputPass.Text), _cbCredInputProtect.Checked)
    else
      WinCrypt.WriteToCredentialsStore(_edCredInputTarget.Text, _edCredInputName.Text, _edCredInputPass.Text, _cbCredInputProtect.Checked);
end;

procedure TWinCryptDemoForm.btCredStoreReadClick(Sender: TObject);
var
  i: Integer;
begin
  if Sender = btCredStoreRead then begin

    //FCredential := WinCrypt.FindInCredentialsStore(edCredFindTarget.Text);

    SetLength(FCredential, 1);
    {if WinCrypt.ReadFromCredentialsStore(edCredFindTarget.Text, FCredential[0].Name, FCredential[0].Passw, @FCredential[0].Attr) then begin
      FCredential[0].Target  := edCredFindTarget.Text;
      FCredential[0].Name    <- see ReadFromCredentialsStore parameters
      FCredential[0].RawData := nil;
      FCredential[0].Data    := TEncoding.Unicode.GetBytes(FCredential[0].Passw);
      FCredential[0].Passw   <- see ReadFromCredentialsStore parameters
      FCredential[0].Attr    <- see ReadFromCredentialsStore parameters
    end else
      FCredential := nil;}
    if not WinCrypt.ReadFromCredentialsStore(edCredFindTarget.Text, FCredential[0]) then
      FCredential := nil;

  end else {btCredStoreFind}
    FCredential := WinCrypt.FindInCredentialsStore(edCredFindFilter.Text);

  tsCredReadTargets.Tabs.Clear;
  if Assigned(FCredential) then
    for i := 0 to High(FCredential) do
      tsCredReadTargets.Tabs.Add(LeftStr(ExtractFileName(FCredential[i].Target), 15))
  else
    tsCredReadTargets.Tabs.Add('EMPTY');
  tsCredReadTargets.TabIndex := 0;
  tsCredReadTargetsChange(Sender);  // Refresh

  if Assigned(FCredential) then
    BalloonHint.Title := 'exists'
  else
    BalloonHint.Title := 'not found';
  BalloonHint.ShowHint(Sender as TButton);
end;

procedure TWinCryptDemoForm.btCredStoreDeleteClick(Sender: TObject);
begin
  if MessageDlg('Really delete "' + edCredFindTarget.Text + '"?', mtConfirmation, mbYesNo, 0, mbNo) = mrYes then
    WinCrypt.DeleteInCredentialsStore(edCredFindTarget.Text);
end;

procedure TWinCryptDemoForm.btCredStoreExistsClick(Sender: TObject);
var
  Target: string;
begin
  if cbCredReadTarget.Checked then
    Target := edCredFindTarget.Text
  else
    Target := edCredFindFilter.Text;

  if WinCrypt.ExistsInCredentialsStore(Target) then
    BalloonHint.Title := 'exists'
  else
    BalloonHint.Title := 'not found';
  BalloonHint.ShowHint(Sender as TButton);
end;

procedure TWinCryptDemoForm.btCredStoreOpenClick(Sender: TObject);
begin
  WinCrypt.OpenCredentialManager;
end;

procedure TWinCryptDemoForm.btCredDialogClick(Sender: TObject);
var
  Idx, Result:         string;
  Username, Password:  string;
  SaveCheckBox:        BOOL;
  pSaveCheckBox:       PBOOL;
  Caption, Desription: string;
  AuthError:           DWORD;
  Flags:               DWORD;
  Banner:              TBitmap;
begin
  Idx             := IntToStr(pcCredStore.ActivePageIndex + 1);
  pSaveCheckBox   := nil;
  AuthError       := NO_ERROR;
  Banner          := nil;
  Flags           := 0;

  if cbCredDialogPrefill.Checked then begin
    if TCheckBox(FindComponent('cbCredInputPassBase' + Idx)).Checked then
      raise Exception.Create('Passwort nur als Unicode (kein Base64)');
    Username      := TCustomEdit(FindComponent('edCredInputName' + Idx)).Text;
    Password      := TCustomEdit(FindComponent('edCredInputPass' + Idx)).Text;
  end;
  if cbCredDialogSave.Checked then begin
    SaveCheckBox  := cbCredDialogTrue.Checked;
    pSaveCheckBox := @SaveCheckBox;
  end;
  if cbCredDialogCaption.Checked then begin
    Caption       := 'The Caption';
    Desription    := 'The Description ...'; ;
  end;
  if cbCredDialogError.Checked then
    AuthError     := ERROR_FILE_NOT_FOUND;
  if cbCredDialogSecure.Checked then
    Flags         := CREDUIWIN_SECURE_PROMPT;  // CREDUIWIN_AUTHPACKAGE_ONLY CREDUIWIN_IN_CRED_ONLY CREDUIWIN_ENUMERATE_ADMINS CREDUIWIN_ENUMERATE_CURRENT_USER CREDUIWIN_PREPROMPTING CREDUIWIN_PACK_32_WOW
  if cbCredDialogBanner.Checked then
    Banner        := imgBanner.Picture.Bitmap;

  //if WinCrypt.WindowsCredentialDialog(Username, Password {, nil, Self}) then
  //if WinCrypt.WindowsCredentialDialog(Username, Password, pSaveCheckBox, Self, Caption, Desription) then
  if WinCrypt.WindowsCredentialDialog(Username, Password, pSaveCheckBox, Self, Caption, Desription, AuthError, Flags, Banner) then begin
    Result := 'Username = ' + Username
      + #13#10'Password = ' + Password
      + #13#10'Save = ' + BoolToStr(SaveCheckBox, True);
    ShowMessage(Result);
  end;
end;

procedure TWinCryptDemoForm.tsCredReadTargetsChange(Sender: TObject);
var
  i, a: Integer;
begin
  if (Sender = btCredReadPrev) or (Sender = btCredReadNext) then begin
    tsCredReadTargets.TabIndex := tsCredReadTargets.TabIndex + TButton(Sender).Tag;
    tsCredReadTargetsChange(nil);
    if not TButton(Sender).Enabled then begin
      if btCredReadPrev.CanFocus then btCredReadPrev.SetFocus;
      if btCredReadNext.CanFocus then btCredReadNext.SetFocus;
    end;
    Exit;
  end;

  i := tsCredReadTargets.TabIndex;
  btCredReadPrev.Enabled := i > 0;
  btCredReadNext.Enabled := i < High(FCredential);
  if (i < 0) or (i > High(FCredential)) then begin
    edCredReadTarget.Clear;
    edCredReadName.Clear;
    edCredReadRAW.Clear;
    edCredReadANSI.Clear;
    edCredReadWide.Clear;
    edCredReadBase.Clear;
    edCredReadDate.Clear;
    meCredReadInfo.Clear;
    lbCredReadRAW.Caption  := '';
    lbCredReadANSI.Caption := '';
    lbCredReadWide.Caption := '';
    lbCredReadBase.Caption := '';
    liCredReadAttrib.Strings.Clear;
    Exit;
  end;

  edCredReadTarget.Text   := FCredential[i].Target;
  edCredReadName.Text     := FCredential[i].Name;
  edCredReadRAW.Text      := BinärToString (PAnsiChar(FCredential[i].RawData), Length(FCredential[i].RawData));
  edCredReadANSI.Text     := BinärToString (PAnsiChar(FCredential[i].Data),    Length(FCredential[i].Data));
  edCredReadWide.Text     := Binär2ToString(PWideChar(FCredential[i].Data),   (Length(FCredential[i].Data) + 1) div 2) + IfThen(Length(FCredential[i].Data) mod 2 <> 0, '░'); //:= FCredential[i].Passw;
  edCredReadBase.Text     := TNetEncoding.Base64.EncodeBytesToString(FCredential[i].Data);
  lbCredReadRAW.Caption   := Length(edCredReadRAW.Text).ToString;
  lbCredReadANSI.Caption  := Length(edCredReadANSI.Text).ToString;
  lbCredReadWide.Caption  := Length(edCredReadWide.Text).ToString;
  lbCredReadBase.Caption  := Length(edCredReadBase.Text).ToString;
  cbCredReadProtect.State := TCheckBoxState(Min(Ord(FCredential[i].Protect), Ord(High(TCheckBoxState))));
  edCredReadDate.Text     := DateTimeToStr(FCredential[i].Age);
  meCredReadInfo.Text     := 'Flags       = ' + SetToString(PTypeInfo(TypeInfo(TCryptCredFlags)), Integer(FCredential[i].Flags), True) + sLineBreak
                           + 'CType     = ' + GetEnumName(TypeInfo(TCryptCredCType), Ord(FCredential[i].CType)) + sLineBreak
                           + 'Persist     = ' + GetEnumName(TypeInfo(TCryptCredPersist), Ord(FCredential[i].Persist)) + sLineBreak
                           + 'Alias        = ' + FCredential[i].Alias + sLineBreak
                           + 'Comment = ' + FCredential[i].Comment;

  liCredReadAttrib.Strings.Clear;
  for a := 0 to High(FCredential[i].Attr) do
    liCredReadAttrib.Strings.Add(FCredential[i].Attr[a].Key + '=' + TEncoding.Default.GetString(FCredential[i].Attr[a].Value));

  if (Sender <> btCredStoreExists) and (Sender <> btCredStoreFind) and (Sender <> btCredStoreDelete) then
    tsCredReadTargetsEnter(Sender);  // Filter aktualisieren
end;

procedure TWinCryptDemoForm.tsCredReadTargetsEnter(Sender: TObject);
var
  Target: string;
begin
  Target := edCredReadTarget.Text;

  edCredFindTarget.Text   := Target;
  if ExtractFilePath(Target) <> '' then
    edCredFindFilter.Text := ExtractFilePath(Target) + '*'
  else
    edCredFindFilter.Text := '*';
end;

{$ENDREGION}

end.

