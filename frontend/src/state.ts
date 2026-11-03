// Чистые функции: превращают состояние и коды службы в тексты. Привязок Wails здесь нет,
// поэтому файл проверяется Vitest без окна.
import * as S from "./strings";

export interface Warning {
  Code: string;
  Value?: string;
}

// Status повторяет model.Status. Строки вместо перечислений привязок: так код не зависит
// от сгенерированных файлов, а привязанный Status подходит сюда без преобразования.
export interface Status {
  Phase: string;
  Code?: string;
  Detail?: string;
  Streams?: number;
  Total?: number;
  TxRate?: number;
  RxRate?: number;
  TxTotal?: number;
  RxTotal?: number;
  CaptchaURL?: string;
  ProfileID?: string;
  Warnings?: Warning[] | null;
  AwaitingProfile?: boolean;
}

export type ButtonKind = "connect" | "disconnect" | "disabled";

export interface StatusView {
  title: string;
  detail: string;
  button: ButtonKind;
}

// describeError возвращает текст ошибки по коду. detail это текст из ядра или службы:
// он нужен кодам, у которых своя подробность, и неизвестным кодам.
export function describeError(code: string, detail = ""): string {
  const text = S.errors[code];
  if (text === undefined) {
    return detail || S.unknownError;
  }
  if (S.errorsDetailFirst.has(code)) {
    return detail || text;
  }
  if (S.errorsWithDetail.has(code) && detail) {
    return `${text}: ${detail}`;
  }
  return text;
}

// describeWarning возвращает текст предупреждения. Неизвестный код не роняет окно.
export function describeWarning(w: Warning): string {
  const value = w.Value ?? "";
  const text = S.warnings[w.Code];
  return text ? text(value) : S.unknownWarning(value || w.Code);
}

// describeSkipReason возвращает причину, по которой служба пропустила правило обхода.
export function describeSkipReason(reason: string): string {
  return S.skipReasons[reason] ?? S.unknownSkipReason;
}

// describeStatus выбирает заголовок, пояснение и действие главной кнопки.
export function describeStatus(s: Status): StatusView {
  const phase = S.phases[s.Phase];
  if (!phase) {
    return { ...S.unknownPhase, button: "disabled" };
  }
  switch (s.Phase) {
    case "idle":
      return { ...phase, button: "connect" };
    case "connecting":
    case "captcha":
    case "connected":
    case "reconnecting":
      return { ...phase, button: "disconnect" };
    case "blocked":
      return { title: phase.title, detail: reason(s, phase.detail), button: "disconnect" };
    default: {
      // error. Без связи со службой подключиться нельзя: кнопка ждёт, пока служба вернётся.
      if (s.Code === "service_down") {
        return {
          title: S.serviceDownTitle,
          detail: describeError("service_down"),
          button: "disabled",
        };
      }
      return { title: phase.title, detail: reason(s, phase.detail), button: "connect" };
    }
  }
}

function reason(s: Status, fallback: string): string {
  if (s.Code) {
    return describeError(s.Code, s.Detail ?? "");
  }
  return s.Detail || fallback;
}

// ApiError это ошибка метода API, как её отдаёт Go (cmd/freeturn.Error).
export interface ApiErrorInfo {
  code: string;
  message: string;
  fields: string[];
}

// toApiError достаёт ошибку API из того, что бросил вызов привязки. Wails кладёт JSON
// ошибки в cause. Если там другое, возвращается пустой код.
export function toApiError(e: unknown): ApiErrorInfo {
  const cause = (e as { cause?: unknown } | null)?.cause;
  const src = cause !== null && typeof cause === "object" ? (cause as Record<string, unknown>) : null;
  const code = typeof src?.code === "string" ? src.code : "";
  const message = typeof src?.message === "string" ? src.message : "";
  const fields = Array.isArray(src?.fields) ? src.fields.filter((f): f is string => typeof f === "string") : [];
  return { code, message, fields };
}

// describeFields называет поля профиля, которых не хватает: «ссылка на звонок, конфиг WireGuard».
export function describeFields(fields: readonly string[]): string {
  return fields.map((f) => S.fields[f] ?? f).join(", ");
}

// describeApiError возвращает текст ошибки метода API.
export function describeApiError(e: ApiErrorInfo): string {
  const text = S.apiErrors[e.code];
  if (text === undefined) {
    return e.message || S.unknownApiError;
  }
  if (e.code === "incomplete" && e.fields.length > 0) {
    return `${text}: ${describeFields(e.fields)}`;
  }
  if (S.apiErrorsReasonOnly.has(e.code) && e.message) {
    return e.message.charAt(0).toUpperCase() + e.message.slice(1);
  }
  if (S.apiErrorsWithReason.has(e.code) && e.message) {
    return `${text}: ${e.message}`;
  }
  return text;
}

// formatBytes печатает размер с десятичной запятой: «1,5 МБ».
export function formatBytes(n: number): string {
  const units = [S.units.bytes, S.units.kb, S.units.mb, S.units.gb];
  let value = Math.max(0, n);
  let i = 0;
  while (value >= 1024 && i < units.length - 1) {
    value /= 1024;
    i++;
  }
  const digits = i === 0 || value >= 10 ? 0 : 1;
  const num = value.toFixed(digits).replace(".", ",").replace(/,0$/, "");
  return `${num} ${units[i]}`;
}

// formatRate печатает скорость: «1,5 МБ/с».
export function formatRate(bytesPerSecond: number): string {
  return formatBytes(bytesPerSecond) + S.units.perSecond;
}

export type SettingsFlag = "KillSwitch" | "AllowLAN" | "Autostart" | "ConnectOnLaunch";

interface FlagSettings {
  Autostart: boolean;
  ConnectOnLaunch: boolean;
  Options: { KillSwitch: boolean; AllowLAN: boolean };
}

// withFlag возвращает копию настроек, где один переключатель имеет новое значение.
// Остальные поля, в том числе правила обхода, остаются как были.
export function withFlag<T extends FlagSettings>(cur: T, flag: SettingsFlag, value: boolean): T {
  return {
    ...cur,
    Autostart: flag === "Autostart" ? value : cur.Autostart,
    ConnectOnLaunch: flag === "ConnectOnLaunch" ? value : cur.ConnectOnLaunch,
    Options: {
      ...cur.Options,
      KillSwitch: flag === "KillSwitch" ? value : cur.Options.KillSwitch,
      AllowLAN: flag === "AllowLAN" ? value : cur.Options.AllowLAN,
    },
  };
}
