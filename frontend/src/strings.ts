// Весь текст интерфейса. Коды из Go (model.ErrorCode, model.WarningCode, коды ошибок API,
// причины пропуска правил) обязаны иметь здесь текст: strings.test.ts читает Go-файлы и
// падает, если нового кода тут нет.

export const app = {
  name: "FreeTurn",
  loading: "Загрузка…",
};

export const tabs = {
  home: "Главная",
  profiles: "Профили",
  rules: "Исключения",
  settings: "Настройки",
  journal: "Журнал",
};

// Заголовок и пояснение для каждой фазы model.Phase.
export const phases: Record<string, { title: string; detail: string }> = {
  idle: { title: "Отключено", detail: "Нажмите кнопку, чтобы подключиться" },
  connecting: { title: "Подключение…", detail: "Это может занять до минуты" },
  captcha: {
    title: "Нужна проверка",
    detail: "Пройдите проверку в окне или откройте её в браузере",
  },
  connected: { title: "Подключено", detail: "Соединение работает" },
  reconnecting: { title: "Переподключение…", detail: "Связь прервалась, восстанавливаем" },
  error: { title: "Не удалось подключиться", detail: "Что-то пошло не так" },
  blocked: {
    title: "Интернет заблокирован",
    detail: "Туннель не работает, а защита не выпускает трафик мимо него",
  },
};

export const unknownPhase = { title: app.loading, detail: "" };

// Заголовок состояния, когда нет связи со службой.
export const serviceDownTitle = "Нет связи со службой";

// Подсказка под причиной блокировки.
export const blockedHint =
  "Нажмите «Отключить», чтобы вернуть интернет, или исправьте причину и подключитесь снова.";

// Тексты model.ErrorCode (раздел 11 спецификации).
export const errors: Record<string, string> = {
  no_network: "Нет подключения к интернету",
  no_handshake: "Сервер WireGuard не ответил, проверьте профиль",
  server_silent: "Сервер не отвечает. Проверьте адрес и что сервер версии 4.0.0 или новее",
  invalid_call_link: "Ссылка на звонок недействительна, замените её",
  call_full: "В звонке нет свободных мест",
  anon_blocked: "Звонок запрещает анонимных участников",
  captcha_failed: "Капча не пройдена",
  adapter: "Не удалось создать сетевой адаптер",
  core: "Ядро остановилось с ошибкой",
  bad_profile: "Профиль не подходит для подключения, проверьте его данные",
  service_down: "Служба FreeTurn не запущена, переустановите программу",
  fake_ip_dns:
    "Clash или Mihomo в режиме TUN подменяет адреса. Выключите режим TUN и подключитесь снова.",
};

// Коды, к тексту которых добавляется подробность из ядра или службы.
export const errorsWithDetail = new Set(["adapter", "bad_profile"]);
// Для кода core показывается сам текст ядра, а если его нет, запасной.
export const errorsDetailFirst = new Set(["core"]);

export const unknownError = "Неизвестная ошибка";

// Тексты предупреждений model.WarningCode. Value это правило, домен или имя VPN.
export const warnings: Record<string, (value: string) => string> = {
  other_vpn: (v) =>
    v
      ? `Другой VPN держит маршрут: ${v}. Отключите его или продолжайте как есть.`
      : "Другой VPN держит маршрут. Отключите его или продолжайте как есть.",
  rule_skipped: (v) =>
    v ? `Правило обхода «${v}» пропущено.` : "Одно из правил обхода пропущено.",
  domain_unresolved: (v) =>
    v
      ? `Не удалось найти адрес домена «${v}», он пока не в обходе.`
      : "Не удалось найти адрес одного из доменов, он пока не в обходе.",
  stale_handshake: () => "Сервер давно не отвечает, переподключаемся.",
  no_dns: () => "В профиле нет DNS, используется системный.",
};

export const unknownWarning = (v: string) => (v ? `Предупреждение: ${v}` : "Предупреждение");

// Причины пропуска правила обхода (split.Reason*).
export const skipReasons: Record<string, string> = {
  default_route: "правило направило бы весь трафик мимо туннеля",
  too_wide: "правило слишком широкое: почти весь трафик пошёл бы мимо туннеля",
  invalid: "правило не разобрано",
};

export const unknownSkipReason = "правило не подошло";

// Тексты кодов ошибок API (cmd/freeturn/api.go).
export const apiErrors: Record<string, string> = {
  bad_link: "Ссылка не подошла",
  bad_rule: "Правило не подошло",
  bad_config: "Конфиг WireGuard не подошёл, проверьте, что вставлен весь файл",
  bad_call_link: "Ссылка на звонок пуста или неверна",
  no_profile: "Профиль не найден, обновите список",
  incomplete: "В профиле не хватает данных для подключения",
  preview_expired: "Время подтверждения вышло, вставьте ссылку заново",
  service_down: errors.service_down,
  service: "Служба отклонила запрос, подробности в журнале",
  profiles_corrupt: "Файл профилей повреждён, импортируйте профили заново",
  storage: "Не удалось записать данные на диск",
  no_captcha: "Капча сейчас не запрошена",
  settings: "Не удалось сохранить настройки",
  busy: "Подключение уже идёт, подождите",
  too_many_rules: "Слишком много правил обхода: не больше 200",
};

// У этих кодов служба называет точную причину, она показывается после основного текста.
export const apiErrorsWithReason = new Set(["bad_link", "bad_rule"]);
// У этих кодов сообщение службы это готовая фраза, и показывается она одна.
export const apiErrorsReasonOnly = new Set(["bad_config"]);

export const unknownApiError = "Что-то пошло не так";

// Поля профиля (model.Field).
export const fields: Record<string, string> = {
  callLink: "ссылка на звонок",
  wgConfig: "конфиг WireGuard",
};

export const kinds: Record<string, string> = {
  ip: "Адрес",
  subnet: "Подсеть",
  domain: "Домен",
};

export const home = {
  connect: "Подключить",
  disconnect: "Отключить",
  chooseProfile: "Профиль",
  noProfiles: "Профилей пока нет",
  noProfilesHint: "Добавьте профиль по ссылке, которую вам прислали.",
  addProfile: "Добавить профиль",
  down: "Скачивание",
  up: "Отправка",
  streams: "Потоки",
  streamsOf: (n: number, total: number) => `${n} из ${total}`,
  openCaptcha: "Открыть проверку в браузере",
  saveDiagnostics: "Сохранить диагностику",
  updateAvailable: (version: string) =>
    version ? `Вышла новая версия ${version}` : "Вышла новая версия",
  updateOpen: "Открыть страницу",
};

export const units = {
  bytes: "Б",
  kb: "КБ",
  mb: "МБ",
  gb: "ГБ",
  perSecond: "/с",
};

export const profiles = {
  title: "Профили",
  importTitle: "Добавить профиль",
  paste: "Вставить из буфера",
  placeholder: "Ссылка freeturn://…",
  check: "Проверить",
  clipboardEmpty: "В буфере обмена пусто",
  clipboardFailed: "Не удалось прочитать буфер обмена",
  previewTitle: "Подтвердите профиль",
  previewName: "Название",
  previewPeer: "Сервер",
  previewMissing: (list: string) => `Не хватает: ${list}. Это можно добавить после импорта.`,
  previewComplete: "Все данные на месте.",
  add: "Добавить",
  cancel: "Отмена",
  added: "Профиль добавлен",
  generatedId: "Client ID для владельца сервера",
  generatedIdHint:
    "В ссылке не было Client ID, поэтому он создан здесь. Передайте его владельцу сервера, иначе сервер может не пустить вас.",
  copy: "Копировать",
  copied: "Скопировано",
  copyFailed: "Не удалось скопировать",
  empty: "Сохранённых профилей нет",
  unnamed: "Без названия",
  missing: (list: string) => `Не хватает: ${list}`,
  complete: "Готов к подключению",
  edit: "Изменить",
  callLink: "Ссылка на звонок",
  callLinkPlaceholder: "Вставьте новую ссылку на звонок",
  wgConfig: "Конфиг WireGuard",
  wgPlaceholder: "Вставьте содержимое файла .conf целиком",
  pickFile: "Выбрать файл .conf",
  fileFailed: "Не удалось прочитать файл",
  save: "Сохранить",
  saved: "Сохранено",
  delete: "Удалить",
  deleteTitle: "Удалить профиль?",
  deleteText: (name: string) =>
    `Профиль «${name}» будет удалён вместе с ключами. Чтобы вернуть его, понадобится ссылка.`,
  deleted: "Профиль удалён",
  corruptTitle: "Файл профилей повреждён",
  corruptText:
    "Профили не удалось прочитать. Начните заново: старый файл уберём в сторону, а профили нужно будет импортировать ещё раз.",
  corruptReset: "Начать заново",
  resetDone: "Готово, можно добавлять профили",
};

export const rules = {
  title: "Исключения",
  intro: "Адреса и сайты из этого списка пойдут мимо туннеля, напрямую.",
  placeholder: "Адрес, подсеть или сайт",
  add: "Добавить",
  empty: "Исключений нет",
  remove: "Убрать",
  duplicate: "Такое правило уже есть",
  added: "Правило добавлено",
  hint: [
    "Для сайта работает только точное имя: example.com не включает www.example.com. Добавьте оба.",
    "Сайты за сетями доставки (CDN) могут обходить туннель не полностью: браузер иногда получает другие адреса, особенно со своим DoH.",
    "Слишком широкие правила и 0.0.0.0/0 пропускаются, чтобы не отключить туннель целиком.",
  ],
  appliesNext: "Изменения применятся при следующем подключении.",
};

export const settings = {
  title: "Настройки",
  killSwitch: "Защита от утечек",
  killSwitchHint: "Если туннель оборвётся, интернет отключится, и трафик не пойдёт мимо него.",
  allowLAN: "Доступ к локальной сети",
  allowLANHint: "Принтеры, роутер и другие устройства дома остаются доступны.",
  autostart: "Запускать с Windows",
  autostartHint: "Окно будет на месте и сможет восстановить подключение.",
  connectOnLaunch: "Подключаться при запуске",
  connectOnLaunchHint: "Туннель включится сам, как только программа запустится.",
  appliesNext: "Защита и доступ к локальной сети применятся при следующем подключении.",
  resetBanner:
    "Файл настроек не удалось прочитать, взяты значения по умолчанию. Они сохранятся, как только вы что-нибудь измените.",
};

export const journal = {
  title: "Журнал",
  copy: "Копировать",
  copied: "Журнал скопирован",
  save: "Сохранить диагностику",
  savedTo: (path: string) => `Сохранено: ${path}`,
  empty: "Записей пока нет",
  hint: "Если что-то не работает, сохраните диагностику и отправьте файл тому, кто вам помогает. Ключей и ссылок в нём нет.",
};
