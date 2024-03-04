# Windows Credentials & Cryptography

Daten ohne Passwort verschl�sseln, mit Keys des aktuellen Prozesses, Benuters oder der Windows-Installation.

Passw�rter und Schl�ssel im Anmeldeinformationsspeicher des Windows hinterlegen.

![Screenshot](Screenshot.png)

---

Passw�rter, Schl�ssel und �hnliches in der Anmeldeinformationsverwaltung des aktuellen Nutzers speichern.

    Name := 'username';
    Pass := 'password';
    WinCrypt.WriteToCredentialsStore('TheTarget', Name, Pass);

    if WinCrypt.ReadFromCredentialsStore('TheTarget', Credential) then
      ShowMessage(Credential.Name + ' : ' + Credential.Passw);

    CredentialArr := WinCrypt.FindInCredentialsStore('TheTarget*');
    for var Cred in CredentialArr do
      ShowMessage(Cred.Name + ' : ' + Cred.Passw);

    // [WIN] Anmeldeinformationsverwaltung > Windows-Anmeldeinformation
    // control.exe /name Microsoft.CredentialManager
    WinCrypt.OpenCredentialManager;

Passwort-Dialog des Betriebssystems benutzen.

    var Username, Password: string;
    if WinCrypt.WindowsCredentialDialog(Username, Password {, nil, Self}) then
      ShowMessage(Username + ' / ' + Password);

    var Username: string := 'name';
    var Password: string := 'pass';
    var Save: LongBool   := False;
    if WinCrypt.WindowsCredentialDialog(Username, Password, @Save, Self, 'Caption', 'The Desription') then
      ShowMessage('Save=' + Save.ToString + ': ' + Username + ' / ' + Password);

---

Daten mit einem Kontext der aktuellen Prozess ver-/entschl�sseln.
Nur innerhalb der aktuellen Prozess-Intsanz entschl�sselbar, oder w�hrend der aktuellen Login-Session, oder
z.B. um ein Passwort w�hrend der Laufzeit zu sch�tzen, damit es nicht in der Auslagerungsdatei, bei einem ReadProcessMemory oder �ber ein Prozess-Abbild lesbar ist. (nur ganz kurz w�hrend der Verwendung)

    var Data: TBytes = TEncoding.UTF8.GetBytes('1234567890123456');  // Length = Multiple of 16 bytes
    WinCrypt.EncryptProcessMemory(Pointer(Data), Length(Data {, OnlyThisProcess});

    WinCrypt.DecryptProcessMemory(Pointer(Data), Length(Data {, OnlyThisProcess});
    ShowMessage(TEncoding.UTF8.GetString(Data));

Daten mit dem Schl�ssel des Benutzers ver-/entschl�sseln.
Nur f�r Programme im Kontext des aktuell angemeldeten Windows-Benutzers.

    var Data: TBytes = TEncoding.UTF8.GetBytes('abc123');
    WinCrypt.EncryptUserData(Data);

    WinCrypt.DecryptUserData(Data);
    ShowMessage(TEncoding.UTF8.GetString(Data));

Daten mit dem Schl�ssel des Computers ver-/entschl�sseln.
Nur f�r Programme, welche in dieser Windows-Installation laufen.

    var Data: TBytes = TEncoding.UTF8.GetBytes('abc123');
    WinCrypt.EncryptComputerData(Data);

    WinCrypt.DecryptComputerData(Data);
    ShowMessage(TEncoding.UTF8.GetString(Data));

