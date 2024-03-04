program CryptDemo;

// C:\Users\%USERNAME%\Documents\Embarcadero\Studio\23.0\CatalogRepository\WindowsAPIfromWinMD-1.0\
// $(BDSCatalogRepository)\WindowsAPIfromWinMD-1.0\
uses
  Forms,
  {$IFDEF WithWinMD}
  Windows.Foundation in 'C:\Users\Besitzer\Documents\Embarcadero\Studio\23.0\CatalogRepository\WindowsAPIfromWinMD-1.0\Windows.Foundation.pas',
  Windows.Graphics.Gdi in 'C:\Users\Besitzer\Documents\Embarcadero\Studio\23.0\CatalogRepository\WindowsAPIfromWinMD-1.0\Windows.Graphics.Gdi.pas',
  Windows.Security in 'C:\Users\Besitzer\Documents\Embarcadero\Studio\23.0\CatalogRepository\WindowsAPIfromWinMD-1.0\Windows.Security.pas',
  Windows.Security.Credentials in 'C:\Users\Besitzer\Documents\Embarcadero\Studio\23.0\CatalogRepository\WindowsAPIfromWinMD-1.0\Windows.Security.Credentials.pas',
  Windows.Security.Cryptography in 'C:\Users\Besitzer\Documents\Embarcadero\Studio\23.0\CatalogRepository\WindowsAPIfromWinMD-1.0\Windows.Security.Cryptography.pas',
  Windows.System.Registry in 'C:\Users\Besitzer\Documents\Embarcadero\Studio\23.0\CatalogRepository\WindowsAPIfromWinMD-1.0\Windows.System.Registry.pas',
  Windows.UI.WindowsAndMessaging in 'C:\Users\Besitzer\Documents\Embarcadero\Studio\23.0\CatalogRepository\WindowsAPIfromWinMD-1.0\Windows.UI.WindowsAndMessaging.pas',
  {$ENDIF}
  h5u.WinCryptCred in 'h5u.WinCryptCred.pas',
  CryptDemoMain in 'CryptDemoMain.pas' {WinCryptDemoForm};

{$R *.res}

begin
  Application.Initialize;
  Application.MainFormOnTaskbar := True;
  Application.CreateForm(TWinCryptDemoForm, WinCryptDemoForm);
  Application.Run;
end.

