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
Filename: "{app}\{#WebView2Setup}"; Parameters: "/silent /install"; StatusMsg: "Установка WebView2..."; Flags: waituntilterminated runhidden; Check: not CheckWebView2
Filename: "{app}\FreeTurn.exe"; Description: "Запустить FreeTurn"; Flags: nowait postinstall skipifsilent runasoriginaluser

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

// StopFreeTurn закрывает окно и останавливает службу. Остановка службы снимает туннель,
// адаптер и правила брандмауэра. Ошибки не важны: окна или службы может и не быть.
procedure StopFreeTurn;
var
  ResultCode: Integer;
begin
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM FreeTurn.exe', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(ExpandConstant('{sys}\net.exe'), 'stop FreeTurnService', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  StopFreeTurn;
  Result := '';
end;

// Регистрацию службы нельзя отдать разделу [Run]: он не проверяет код выхода, и неудавшаяся
// установка службы осталась бы незамеченной.
procedure CurStepChanged(CurStep: TSetupStep);
var
  ResultCode: Integer;
begin
  if CurStep = ssPostInstall then
  begin
    if not Exec(ExpandConstant('{app}\FreeTurnService.exe'), 'install', '', SW_HIDE, ewWaitUntilTerminated, ResultCode)
       or (ResultCode <> 0) then
      SuppressibleMsgBox(
        'Не удалось установить и запустить службу FreeTurn. Подробности в журнале событий Windows ' +
        '(источник FreeTurnService). Запустите установку ещё раз.',
        mbError, MB_OK, IDOK);
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  ResultCode: Integer;
  ProfilesDir: String;
begin
  if CurUninstallStep = usUninstall then
  begin
    // Окно закрывается раньше службы, иначе оно переподключится к ней. Служба снимает туннель
    // и удаляет себя, адаптер, маршруты и каталог {app}\Data. Файлы Inno удаляет после этого.
    Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM FreeTurn.exe', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    if not Exec(ExpandConstant('{app}\FreeTurnService.exe'), 'uninstall', '', SW_HIDE, ewWaitUntilTerminated, ResultCode)
       or (ResultCode <> 0) then
      SuppressibleMsgBox(
        'Службу FreeTurn удалить не удалось. Перезагрузите компьютер и удалите программу ещё раз, ' +
        'чтобы убрать адаптер и маршруты.',
        mbError, MB_OK, IDOK);

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
