# Исследование перед проектированием freeturn-windows

Дата: 2026-10-31. Это исходные данные для проектирования, а не принятые решения.
Спецификации и плана ещё нет.

## Цель

freeturn-windows это полная версия клиента FreeTurn для Windows рядом с
`..\freeturn-lite-windows`. Отличия от лайт-версии:

- устанавливается через установщик, а не портабельная;
- WireGuard внутри программы, внешний клиент не нужен.

Референс: amnezia-vpn/amnezia-client.

## Исходники рядом

| Что | Где |
| --- | --- |
| Лайт-версия (Java 17, Swing, jpackage) | `..\freeturn-lite-windows` |
| Ядро free-turn-proxy v4.1.1 (Go) | `<каталог репозиториев>\free-turn-proxy` |
| Android-клиент v5.3.1 | `<каталог репозиториев>\turn-proxy-android` |
| amnezia-client (7f9b7db4, 2026-10-29) | `<каталог репозиториев>\amnezia-client` |

Все три внешних репозитория только для чтения.

## Как WireGuard устроен в Amnezia на Windows

- Установленная служба `AmneziaVPN-service.exe` работает как SYSTEM и выполняет
  привилегированные действия по IPC от GUI.
- Туннель это отдельная служба Windows `AmneziaWGTunnel$AmneziaVPN`, она создаётся
  на каждое подключение через `CreateService` и удаляется при отключении.
  Запускается exe той же программы с аргументом `tunneldaemon "<wg-конфиг>"`.
- Процесс туннеля загружает `tunnel.dll` и вызывает
  `WireGuardTunnelService(settings, name)`. Код:
  `client/platforms/windows/daemon/windowsdaemontunnel.cpp`,
  `windowstunnelservice.cpp`.
- `tunnel.dll` собирается из amneziawg-windows v3.1.20260814:
  `go build -buildmode c-shared`, нужны Go и mingw (`recipes/awg-windows/conanfile.py`).
- Рядом лежит `wintun.dll` 0.14.1. Подпись проверена на установленной копии:
  WireGuard LLC, статус Valid.
- Статистика и пиры идут через UAPI по именованному каналу
  `\\.\pipe\ProtectedPrefix\Administrators\AmneziaWG\<имя>`.
- В конфиг ставится `Table = off`. Маршруты, исключения для адреса сервера
  (`windowsroutemonitor.cpp`) и kill switch на WFP (`windowsfirewall.cpp`) делает
  служба Amnezia.
- Установщик: WiX через CPack (`deploy/installer/wix`), в нём регистрация службы и
  закрытие клиента. `deploy/data/windows/post_uninstall.cmd` останавливает и удаляет
  службу туннеля.

Amnezia подходит как образец идей. Её код под GPLv3, поэтому копирование кода
накладывает GPLv3 на наш проект.

## Что важно в ядре

- У ядра уже есть встроенный userspace-туннель WireGuard/AmneziaWG:
  `internal/tunnel/awg`, зависимость `amneziawg-go/v3 v3.1.20260814`.
- Его использует Android-клиент через `mobile.StartTunnel(configJSON, tunFD)`.
  Устройство AWG общается с релеем через in-memory `netconn.PacketPipe`, без петли
  `127.0.0.1:9000`.
- На Windows это сейчас не работает:
  - `internal/tunnel/awg/tun_other.go` возвращает ошибку
    "tun from fd is supported on linux/android only";
  - `cmd/client/main.go` при наличии wg-конфига пишет предупреждение и выключает
    туннель, CLI встроенный туннель не поднимает.
- Адреса, DNS, маршруты и MTU интерфейса ядро не применяет, это работа платформы.
  Параметры отдаёт `mobile.ParseTunnelConfig`.
- Обход туннеля на Android делается через `SetProtect` и `netctl.SetControl`: хук
  на каждый сокет релея, TURN, VK API и DNS.
- `-routes` на Windows вызывает `cmd route add <ip> mask 255.255.255.255 <gateway>`,
  шлюз определяется один раз при старте. Нужны права администратора. Покрывает
  только адреса TURN.
- `proxy.mode: tcp` вместе с `tunnel.mode` wg/awg валидация отклоняет. Режим TCP/KCP
  (и bond) совместим только с внешним туннелем.
- `internal/*` нельзя импортировать из другого модуля, публичный вход только `mobile`.
- Лицензия ядра: Happy Bunny License, см. `LICENSE` в репозитории ядра.

## Два основных пути

### A. Схема Amnezia: два процесса

`tunnel.dll` в службе и `free-turn-proxy.exe` как есть, WireGuard ходит на
`127.0.0.1:9000`.

- Ядро не меняется, релизный exe подходит напрямую.
- Режим TCP/KCP работает, потому что туннель внешний для ядра.
- `tunnel.dll` надо собрать (mingw на этой машине нет) или получить из релиза.
- Нужен обход туннеля для адресов TURN, VK API и DNS, иначе петля маршрутизации.
  Для `AllowedIPs = 0.0.0.0/0` конфиг надо менять или добавлять исключения.

### B. Схема Android: ядро с туннелем в одном процессе

Своя Go-служба поверх ядра, создающая wintun-адаптер через `amneziawg-go/tun` и
запускающая тот же код, что `mobile.StartTunnel`.

- Нет петли через localhost и один источник логики с Android.
- Нужны изменения в ядре: `openTUN` для Windows и protect-хук для Windows
  (например, `IP_UNICAST_IF` на физический интерфейс). Это форк или вклад в апстрим.
- Режим TCP/KCP не работает в этой схеме.
- Адреса, маршруты и DNS интерфейса всё равно реализуем сами.

Не проверено: поддержка `tun.CreateTUN` на Windows в amneziawg-go v3 (модуля нет в
локальном кэше), сборка `-buildmode` без cgo, совместимость wintun 0.14.1.

## Уточнения после проверки (2026-10-31)

Эти факты проверены по коду ядра и отменяют часть выводов выше.

- `-mode tcp` это локальный TCP-порт для Xray/VLESS (`docs/modes.md` ядра). WireGuard
  шлёт UDP и подключиться к нему не может. Значит, TCP/KCP с WireGuard не работает
  ни в схеме A, ни в схеме B. Фраза «режим TCP/KCP работает» в схеме A неверна.
- Пакет `mobile` импортируется из другого модуля и собирается под Windows без cgo:
  `GOOS=windows CGO_ENABLED=0 go build ./mobile` прошёл на тулчейне 1.26.10.
- `mobile.SetProtect` и `mobile.Start` работают без `tunFD`. Хук `netctl.Apply` стоит
  на сокетах TURN (`turndial`, `netconn`) и DoH (`dnsdial`).
- Локальный UDP-сокет ядра открывается без хука (`session.go:504`), поэтому обход
  туннеля на него не влияет.
- Хук получает только `fd`: `mobile.SetProtect` отбрасывает `network` и `address`.
- Неизменённый `free-turn-proxy.exe` хука не имеет. `-routes` покрывает только адреса
  TURN и выключается при `Tunnel.Enabled()`, поэтому запросы к VK API и DoH при
  переподключении в схеме A попадут в туннель.
- В amneziawg-go v3.1.20260814 есть `tun/tun_windows.go`: `CreateTUN` на wintun и
  `LUID()`. Есть `conn/bind_windows.go` с `NewDefaultBind`.
- `ClientJSON` не принимает ссылку `freeturn://`: разбор URI в `internal`, у `mobile`
  такого входа нет. Разбор ссылки остаётся за нами.
- `CGO_ENABLED=0` снимает потребность в mingw для варианта на чистом Go.

### Схема C: своя Go-служба поверх `mobile`

Служба импортирует `mobile` без изменений, поднимает устройство amneziawg-go с wintun
и ходит в ядро через UDP на `127.0.0.1`. Сокеты ядра обходят туннель через
`SetProtect` и `IP_UNICAST_IF`.

Не проверено: `IP_UNICAST_IF` для TCP/TLS-сокетов ядра при маршруте по умолчанию через
туннель. Нужен быстрый опыт на машине пользователя с его согласия.

Модуль ядра объявлен как `github.com/samosvalishe/free-turn-proxy`, такого репозитория
нет. Код лежит в `hackdiaz-dev/free-turn-proxy`. Внешний модуль собирается через
`replace` на псевдоверсию `v0.0.0-20261028173317-562cfb4ba18b`: проба импортировала
`mobile`, собралась без cgo и запустилась.

## Состояние машины

- JDK 19 и 21, в `PATH` нет `jpackage`, он лежит в `jdk-21\bin`.
- Go 1.26.10: `go version` в каталоге ядра скачал тулчейн и отработал.
  Раньше тот же тулчейн зависал, поэтому сеть до Go-сервисов считать нестабильной.
- `GOPROXY=https://proxy.golang.org,direct`, proxy.golang.org и sum.golang.org
  отсюда ранее не открывались.
- .NET SDK 5.0.416 и 6.0.428, CMake, Python 3.10, Node.
- Нет: cl, gcc, WiX, Inno Setup, NSIS, Qt, Rust.
- Сертификата для подписи кода нет, установщик будет вызывать SmartScreen.
- Может быть установлен другой VPN-клиент, например AmneziaVPN. Новая программа
  должна сосуществовать с ним: другие имена службы и адаптера.

## Открытые вопросы к пользователю

1. Для кого программа: только для себя или для раздачи другим. Это влияет на подпись,
   автообновление и объём интерфейса.
2. Нужен ли режим TCP/KCP вместе со встроенным WireGuard. Это почти определяет выбор
   между A и B.
3. GUI: оставаться на Java/Swing, переиспользуя код лайт-версии, или брать другой стек.
4. Нужен ли kill switch в первой версии.
5. Что в конфигах пользователя: чистый WireGuard или параметры AmneziaWG. Android
   поддерживает оба варианта.

## Секреты

Ссылка `freeturn://` содержит приватный ключ WireGuard, ключ обфускации, Client ID
и ссылку на звонок. В репозиторий, тесты и отчёты она не попадает.
