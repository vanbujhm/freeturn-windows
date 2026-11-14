; Установщик FreeTurn. Собирается из build.ps1:
;   ISCC.exe /DAppVersion=0.11.0 /DRepoDir=<корень репозитория> installer\freeturn.iss
; Данные службы лежат в {app}\Data. Их создаёт и удаляет FreeTurnService.exe install и
; uninstall, а служба считает путь от Program Files, поэтому каталог установки не выбирается.
; Сам установщик {app}\Data не трогает.

#ifndef AppVersion
  #error Нужен ключ /DAppVersion=1.2.3
#endif
#ifndef RepoDir
  #error Нужен ключ /DRepoDir=<корень репозитория>
#endif

#define AppName "FreeTurn"
#define WebView2Setup "MicrosoftEdgeWebview2Setup.exe"
; Раздел реестра, куда окно пишет автозапуск текущего пользователя.
#define RunKey "Software\Microsoft\Windows\CurrentVersion\Run"

[Setup]
AppId={{B3D1A6C4-2F5E-4C7A-8E19-6A0F4D2C9E31}
AppName={#AppName}
AppVersion={#AppVersion}
VersionInfoVersion={#AppVersion}.0
DefaultDirName={autopf}\FreeTurn
DefaultGroupName=FreeTurn
DisableDirPage=yes
DisableProgramGroupPage=yes
PrivilegesRequired=admin
SetupArchitecture=x64
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0.17763
CloseApplications=force
UninstallDisplayIcon={app}\FreeTurn.exe
; Иконку рисует build.ps1 (internal/logo) до компиляции установщика.
SetupIconFile=build\freeturn.ico
; После установки и удаления Проводник сбрасывает кэш значков. Без этого ярлыки поверх
; прежней версии показывают старую иконку, пока кэш не обновится сам.
ChangesAssociations=yes
SourceDir={#RepoDir}
OutputDir={#RepoDir}\dist
OutputBaseFilename=FreeTurnSetup-{#AppVersion}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern

[Languages]
Name: "russian"; MessagesFile: "compiler:Languages\Russian.isl"

[Files]
Source: "build\FreeTurn.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "build\FreeTurnService.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "build\wintun.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "LICENSES\*"; DestDir: "{app}\LICENSES"; Flags: ignoreversion recursesubdirs
; Загрузчик нужен, только если WebView2 нет, и после установки не остаётся.
Source: "third_party\webview2\{#WebView2Setup}"; DestDir: "{app}"; Flags: deleteafterinstall; Check: not CheckWebView2

[Registry]
; Схема freeturn:// для всех пользователей. Windows подставляет в %1 ссылку целиком.
Root: HKCR; Subkey: "freeturn"; ValueType: string; ValueName: ""; ValueData: "URL:FreeTurn"; Flags: uninsdeletekey
Root: HKCR; Subkey: "freeturn"; ValueType: string; ValueName: "URL Protocol"; ValueData: ""
Root: HKCR; Subkey: "freeturn\shell\open\command"; ValueType: string; ValueName: ""; ValueData: """{app}\FreeTurn.exe"" ""%1"""

[Icons]
Name: "{group}\FreeTurn"; Filename: "{app}\FreeTurn.exe"
Name: "{autodesktop}\FreeTurn"; Filename: "{app}\FreeTurn.exe"

[Run]
Filename: "{app}\FreeTurn.exe"; Description: "Запустить FreeTurn"; Flags: nowait postinstall skipifsilent runasoriginaluser

[UninstallDelete]
; Папка могла существовать до установки, например после сбоя прошлого удаления: Inno удаляет
; только созданные им папки. Пустую убираем всегда.
Type: dirifempty; Name: "{app}"

[Code]
const
  // Клиент WebView2 Runtime в EdgeUpdate. Данные для всех пользователей на 64-разрядной
  // системе лежат в WOW6432Node.
  WebView2ClientHKLM = 'SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}';
  WebView2ClientHKCU = 'Software\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}';

// CheckWebView2 сообщает, что WebView2 Runtime уже стоит: у него есть версия pv в разделе
// EdgeUpdate, для всех пользователей или для текущего.
function CheckWebView2: Boolean;
var
  Version: String;
begin
  Result :=
    (RegQueryStringValue(HKLM, WebView2ClientHKLM, 'pv', Version) and
     (Version <> '') and (Version <> '0.0.0.0')) or
    (RegQueryStringValue(HKCU, WebView2ClientHKCU, 'pv', Version) and
     (Version <> '') and (Version <> '0.0.0.0'));
end;

// ServiceStopped сообщает, что службы FreeTurnService нет или она остановлена. Вывод sc query
// Exec не отдаёт, поэтому он идёт во временный файл. Код 1060 значит, что службы нет.
function ServiceStopped: Boolean;
var
  ResultCode: Integer;
  OutFile: String;
  Output: AnsiString;
begin
  Result := False;
  OutFile := ExpandConstant('{tmp}\freeturn-sc.txt');
  DeleteFile(OutFile);
  if not Exec(ExpandConstant('{cmd}'), '/c sc query FreeTurnService > "' + OutFile + '" 2>&1', '',
              SW_HIDE, ewWaitUntilTerminated, ResultCode) then
    Exit;
  if ResultCode = 1060 then
  begin
    Result := True;
    Exit;
  end;
  if LoadStringFromFile(OutFile, Output) then
    Result := Pos('STOPPED', Output) > 0;
end;

// StopFreeTurn закрывает окно и останавливает службу. Остановка службы снимает туннель,
// адаптер и правила брандмауэра. Окна может и не быть, а вот служба должна остановиться: иначе
// её файлы заняты. Ждём до 35 секунд, столько служба сама отводит на остановку.
function StopFreeTurn: Boolean;
var
  ResultCode, I: Integer;
begin
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM FreeTurn.exe', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(ExpandConstant('{sys}\net.exe'), 'stop FreeTurnService', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Result := ServiceStopped;
  for I := 1 to 70 do
  begin
    if Result then
      Break;
    Sleep(500);
    Result := ServiceStopped;
  end;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  Result := '';
  if not StopFreeTurn then
  begin
    Log('Служба FreeTurnService не остановилась за 35 секунд');
    Result := 'Не удалось остановить службу FreeTurn. Закройте программу, подождите минуту и запустите установку ещё раз. ' +
      'Если не помогло, перезагрузите компьютер.';
  end;
end;

// RunWebView2 ставит WebView2 Runtime загрузчиком Microsoft. Он берёт файлы из интернета.
procedure RunWebView2;
var
  ResultCode: Integer;
begin
  if CheckWebView2 then
    Exit;
  WizardForm.StatusLabel.Caption := 'Установка WebView2...';
  if not Exec(ExpandConstant('{app}\{#WebView2Setup}'), '/silent /install', '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
    Log('Загрузчик WebView2 не запустился')
  else
    Log('Загрузчик WebView2 завершился с кодом ' + IntToStr(ResultCode));
  if not CheckWebView2 then
    SuppressibleMsgBox(
      'Для окна FreeTurn нужен Microsoft Edge WebView2 Runtime, а установить его не удалось: ' +
      'загрузчику нужен доступ в интернет. Подключитесь к интернету и запустите установку ещё раз.',
      mbError, MB_OK, IDOK);
end;

// Регистрацию службы нельзя отдать разделу [Run]: он не проверяет код выхода, и неудавшаяся
// установка службы осталась бы незамеченной. WebView2 здесь же по той же причине.
procedure CurStepChanged(CurStep: TSetupStep);
var
  ResultCode: Integer;
begin
  if CurStep = ssPostInstall then
  begin
    if not Exec(ExpandConstant('{app}\FreeTurnService.exe'), 'install', '', SW_HIDE, ewWaitUntilTerminated, ResultCode)
       or (ResultCode <> 0) then
    begin
      Log('FreeTurnService.exe install не удался, код ' + IntToStr(ResultCode));
      SuppressibleMsgBox(
        'Не удалось установить и запустить службу FreeTurn. Подробности в журнале событий Windows ' +
        '(источник FreeTurnService). Запустите установщик ещё раз.',
        mbError, MB_OK, IDOK);
    end;
    RunWebView2;
  end;
end;

// Службу снимаем до любых изменений: если она не удалилась, удаление отменяется целиком, иначе
// Inno стёр бы файлы и запись об установке, а служба, адаптер и маршруты остались бы без
// способа повторить. Служба снимает туннель, удаляет себя, адаптер, маршруты и {app}\Data.
// Вызывается на шаге удаления, а не в InitializeUninstall: там окно удаления ещё может
// получить «Отмена», и программа осталась бы без службы.
function RemoveService: Boolean;
var
  ResultCode: Integer;
  ServiceExe: String;
begin
  Result := True;
  // Окно закрывается раньше службы, иначе оно переподключится к ней.
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM FreeTurn.exe', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  ServiceExe := ExpandConstant('{app}\FreeTurnService.exe');
  if FileExists(ServiceExe) then
    Result := ExecAndLogOutput(ServiceExe, 'uninstall', '', SW_HIDE, ewWaitUntilTerminated, ResultCode, nil) and (ResultCode = 0)
  else
  begin
    // Файла нет, например его убрал антивирус. Удалению это мешать не должно: службу снимаем
    // средствами системы. Адаптер и маршруты в таком случае уберёт следующий запуск Windows
    // или ручная очистка, а код 1060 значит, что службы уже нет.
    Log('Нет файла ' + ServiceExe + ', службу снимаем через sc');
    Exec(ExpandConstant('{sys}\sc.exe'), 'stop FreeTurnService', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec(ExpandConstant('{sys}\sc.exe'), 'delete FreeTurnService', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  end;
  if not Result then
    Log('FreeTurnService.exe uninstall не удался, код ' + IntToStr(ResultCode));
end;

// CmdLineHas сообщает, что в командной строке есть ключ Name.
function CmdLineHas(const Name: String): Boolean;
var
  I: Integer;
begin
  Result := False;
  for I := 1 to ParamCount do
    if CompareText(ParamStr(I), Name) = 0 then
    begin
      Result := True;
      Exit;
    end;
end;

// FromUninstallForm: удаление запущено из окна удаления, см. InitializeUninstall.
function FromUninstallForm: Boolean;
begin
  Result := CmdLineHas('/DELETEDATA') or CmdLineHas('/KEEPDATA');
end;

// AskUninstall показывает окно удаления с галочкой «Удалить данные приложения». True: человек
// нажал «Удалить», WithData - отмечена ли галочка.
function AskUninstall(var WithData: Boolean): Boolean;
var
  Form: TSetupForm;
  Header: TPanel;
  Title, Subtitle, Info, DirLabel, DataHint, Footer: TNewStaticText;
  DirEdit: TNewEdit;
  DataBox: TNewCheckBox;
  TopLine, BottomLine: TBevel;
  RemoveButton, CancelButton: TNewButton;
  W: Integer;
begin
  Form := CreateCustomForm(480, 300, False, False);
  try
    Form.Caption := 'Удаление {#AppName}';

    Header := TPanel.Create(Form);
    Header.Parent := Form;
    Header.Left := 0;
    Header.Top := 0;
    Header.Width := Form.ClientWidth;
    Header.Height := ScaleY(58);
    Header.BevelOuter := bvNone;
    Header.ParentBackground := False;
    Header.Color := clWindow;

    Title := TNewStaticText.Create(Form);
    Title.Parent := Header;
    Title.Left := ScaleX(16);
    Title.Top := ScaleY(12);
    Title.Caption := 'Удаление {#AppName}';
    Title.Font.Style := [fsBold];

    Subtitle := TNewStaticText.Create(Form);
    Subtitle.Parent := Header;
    Subtitle.Left := ScaleX(28);
    Subtitle.Top := Title.Top + Title.Height + ScaleY(4);
    Subtitle.Caption := 'Удаление {#AppName} из компьютера.';

    TopLine := TBevel.Create(Form);
    TopLine.Parent := Form;
    TopLine.Left := 0;
    TopLine.Top := Header.Height;
    TopLine.Width := Form.ClientWidth;
    TopLine.Height := ScaleY(2);
    TopLine.Shape := bsTopLine;

    Info := TNewStaticText.Create(Form);
    Info.Parent := Form;
    Info.Left := ScaleX(16);
    Info.Top := Header.Height + ScaleY(16);
    Info.AutoSize := False;
    Info.WordWrap := True;
    Info.Width := Form.ClientWidth - ScaleX(32);
    Info.Height := ScaleY(32);
    Info.Caption := 'Программа {#AppName} будет удалена с компьютера вместе со службой и сетевым адаптером. ' +
      'Нажмите «Удалить», чтобы продолжить.';

    DirLabel := TNewStaticText.Create(Form);
    DirLabel.Parent := Form;
    DirLabel.Left := ScaleX(16);
    DirLabel.Caption := 'Удаление из:';

    DirEdit := TNewEdit.Create(Form);
    DirEdit.Parent := Form;
    DirEdit.Left := ScaleX(110);
    DirEdit.Top := Info.Top + Info.Height + ScaleY(14);
    DirEdit.Width := Form.ClientWidth - DirEdit.Left - ScaleX(16);
    DirEdit.ReadOnly := True;
    DirEdit.Color := clBtnFace;
    DirEdit.TabStop := False;
    DirEdit.Text := ExpandConstant('{app}');
    DirLabel.Top := DirEdit.Top + (DirEdit.Height - DirLabel.Height) div 2;

    DataBox := TNewCheckBox.Create(Form);
    DataBox.Parent := Form;
    DataBox.Left := ScaleX(16);
    DataBox.Top := DirEdit.Top + DirEdit.Height + ScaleY(18);
    DataBox.Width := Form.ClientWidth - ScaleX(32);
    DataBox.Height := ScaleY(17);
    DataBox.Caption := 'Удалить данные приложения';
    DataBox.Checked := False;

    DataHint := TNewStaticText.Create(Form);
    DataHint.Parent := Form;
    DataHint.Left := ScaleX(34);
    DataHint.Top := DataBox.Top + DataBox.Height + ScaleY(2);
    DataHint.AutoSize := False;
    DataHint.WordWrap := True;
    DataHint.Width := Form.ClientWidth - DataHint.Left - ScaleX(16);
    DataHint.Height := ScaleY(30);
    DataHint.Font.Color := clGrayText;
    DataHint.Caption := 'Профили с ключами и настройки. Оставьте их, если собираетесь установить программу снова.';

    RemoveButton := TNewButton.Create(Form);
    RemoveButton.Parent := Form;
    RemoveButton.Caption := 'Удалить';
    RemoveButton.ModalResult := mrOk;
    RemoveButton.Default := True;

    CancelButton := TNewButton.Create(Form);
    CancelButton.Parent := Form;
    CancelButton.Caption := 'Отмена';
    CancelButton.ModalResult := mrCancel;
    CancelButton.Cancel := True;

    W := Form.CalculateButtonWidth([RemoveButton.Caption, CancelButton.Caption]);
    RemoveButton.Width := W;
    CancelButton.Width := W;
    RemoveButton.Height := ScaleY(23);
    CancelButton.Height := ScaleY(23);
    CancelButton.Left := Form.ClientWidth - ScaleX(16) - W;
    RemoveButton.Left := CancelButton.Left - ScaleX(8) - W;
    CancelButton.Top := Form.ClientHeight - ScaleY(12) - CancelButton.Height;
    RemoveButton.Top := CancelButton.Top;

    BottomLine := TBevel.Create(Form);
    BottomLine.Parent := Form;
    BottomLine.Left := 0;
    BottomLine.Top := CancelButton.Top - ScaleY(12);
    BottomLine.Width := Form.ClientWidth;
    BottomLine.Height := ScaleY(2);
    BottomLine.Shape := bsTopLine;

    Footer := TNewStaticText.Create(Form);
    Footer.Parent := Form;
    Footer.Left := ScaleX(16);
    Footer.Caption := '{#AppName} {#AppVersion}';
    Footer.Font.Color := clGrayText;
    Footer.Top := CancelButton.Top + (CancelButton.Height - Footer.Height) div 2;

    Form.ActiveControl := RemoveButton;
    Result := Form.ShowModal = mrOk;
    WithData := DataBox.Checked;
  finally
    Form.Free;
  end;
end;

// Стандартный вопрос «Удалить программу?» Inno задаёт после InitializeUninstall, и места для
// галочки в нём нет. Поэтому вопрос заменяет окно удаления, а само удаление запускается заново
// в режиме /SILENT: он показывает ход удаления, но не спрашивает. Выбор передаётся ключом
// /DELETEDATA или /KEEPDATA, а этот запуск завершается, ничего не тронув. Новый запуск ждёт
// пару секунд, пока этот процесс выйдет и отпустит файл журнала удаления.
function InitializeUninstall: Boolean;
var
  WithData: Boolean;
  Params: String;
  ResultCode: Integer;
begin
  Result := True;
  if UninstallSilent then
    Exit;
  Result := False;
  if not AskUninstall(WithData) then
    Exit;
  if WithData then
    Params := '/SILENT /DELETEDATA'
  else
    Params := '/SILENT /KEEPDATA';
  if not Exec(ExpandConstant('{cmd}'),
              '/c ping -n 3 127.0.0.1 >nul & start "" "' + ExpandConstant('{uninstallexe}') + '" ' + Params,
              '', SW_HIDE, ewNoWait, ResultCode) then
    MsgBox('Не удалось запустить удаление: ' + SysErrorMessage(ResultCode), mbError, MB_OK);
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  ProfilesDir: String;
begin
  // Тихое удаление не сообщает об успехе, а запущенное из окна удаления видит человек.
  if (CurUninstallStep = usDone) and FromUninstallForm then
    MsgBox('Программа {#AppName} удалена с компьютера.', mbInformation, MB_OK);

  if CurUninstallStep = usUninstall then
  begin
    if not RemoveService then
    begin
      SuppressibleMsgBox(
        'Не удалось удалить службу FreeTurn, поэтому ничего не удалено. Закройте программы, которые ' +
        'могут её занимать, и запустите удаление ещё раз. Если не помогло, перезагрузите компьютер.',
        mbError, MB_OK, IDOK);
      Abort;
    end;

    // Автозапуск пишет окно в раздел текущего пользователя.
    RegDeleteValue(HKCU, '{#RunKey}', 'FreeTurn');

    // Профили с ключами и настройки лежат у пользователя. Удалять ли их, решает галочка в
    // окне удаления (ключ /DELETEDATA или /KEEPDATA). Тихое удаление без ключа удаляет их,
    // как и прежде.
    ProfilesDir := ExpandConstant('{localappdata}\FreeTurn');
    if DirExists(ProfilesDir) and not CmdLineHas('/KEEPDATA') then
      DelTree(ProfilesDir, True, True, True);
  end;
end;
