; Установщик FreeTurn. Собирается из build.ps1:
;   ISCC.exe /DAppVersion=1.0.0 /DRepoDir=<корень репозитория> installer\freeturn.iss
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
// Вызывается после подтверждения удаления: InitializeUninstall идёт раньше вопроса, и ответ
// «Нет» оставил бы программу без службы.
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

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  ProfilesDir: String;
begin
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

    // Профили с ключами лежат у пользователя, поэтому про них спрашиваем. Без вопроса
    // (тихое удаление) ответ «Да».
    ProfilesDir := ExpandConstant('{localappdata}\FreeTurn');
    if DirExists(ProfilesDir) then
      if SuppressibleMsgBox(
           'Удалить сохранённые профили и настройки FreeTurn?' + #13#10 + ProfilesDir + #13#10#13#10 +
           'В профилях лежат ключи. Если вы собираетесь установить программу снова, ответьте «Нет».',
           mbConfirmation, MB_YESNO, IDYES) = IDYES then
        DelTree(ProfilesDir, True, True, True);
  end;
end;
