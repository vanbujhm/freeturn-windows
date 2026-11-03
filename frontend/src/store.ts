// Общее состояние окна и подписки на его изменения.
import type { ImportPreview, ProfileView } from "../bindings/github.com/vanbujhm/freeturn-windows/cmd/freeturn/index.js";
import type { Settings } from "../bindings/github.com/vanbujhm/freeturn-windows/internal/profile/models.js";
import type { Status } from "./state";

export interface UpdateInfo {
  Version?: string;
  URL?: string;
}

export type Topic = "status" | "profiles" | "settings" | "log" | "update" | "import" | "banners";

export const MAX_LOG_LINES = 1000;

export interface AppState {
  status: Status;
  profiles: ProfileView[];
  settings: Settings | null;
  selectedId: string;
  corrupt: boolean;
  settingsReset: boolean;
  update: UpdateInfo | null;
  // import это превью ссылки, пришедшей при запуске или от второго экземпляра.
  import: ImportPreview | null;
  logs: string[];
  // logTotal растёт с каждым изменением журнала: вкладка по нему узнаёт, что дописать.
  logTotal: number;
}

export const state: AppState = {
  status: { Phase: "" },
  profiles: [],
  settings: null,
  selectedId: "",
  corrupt: false,
  settingsReset: false,
  update: null,
  import: null,
  logs: [],
  logTotal: 0,
};

const listeners = new Map<Topic, Set<() => void>>();

export function subscribe(topic: Topic, fn: () => void): void {
  let set = listeners.get(topic);
  if (!set) {
    set = new Set();
    listeners.set(topic, set);
  }
  set.add(fn);
}

export function notify(topic: Topic): void {
  for (const fn of listeners.get(topic) ?? []) fn();
}

// setUpdate запоминает найденную новую версию и сообщает баннеру. Пустое значение (на
// загрузке версии ещё не нашли) ничего не стирает: событие могло прийти раньше ответа.
export function setUpdate(u: UpdateInfo | null | undefined): void {
  if (!u) return;
  state.update = u;
  notify("update");
}

export function pushLog(line: string): void {
  state.logs.push(line);
  state.logTotal++;
  if (state.logs.length > MAX_LOG_LINES) {
    state.logs.splice(0, state.logs.length - MAX_LOG_LINES);
  }
  notify("log");
}

// mergeLogs ставит журнал, прочитанный у службы, перед строками, пришедшими событиями за
// время чтения. Строки, уже попавшие в прочитанное, не удваиваются. Длина ограничена.
export function mergeLogs(read: readonly string[]): void {
  const seen = new Set(read);
  const tail = state.logs.filter((l) => !seen.has(l));
  state.logs = [...read, ...tail].slice(-MAX_LOG_LINES);
  state.logTotal++;
}

// LatestGuard не даёт ответу, запрошенному раньше, затереть более новое состояние.
// Каждая запись из события (write) делает все ещё идущие запросы устаревшими. Запрос,
// вернувшийся позже более нового запроса, тоже отбрасывается.
export class LatestGuard {
  private writes = 0;
  private issued = 0;
  private applied = 0;

  // write вызывается при записи состояния из события.
  write(): void {
    this.writes++;
  }

  // begin вызывается до запроса. Возвращённая функция после ответа говорит, можно ли
  // применять его: true не более одного раза и только если ничего новее не записано.
  begin(): () => boolean {
    const writes = this.writes;
    const ticket = ++this.issued;
    return () => {
      if (this.writes !== writes || ticket <= this.applied) return false;
      this.applied = ticket;
      return true;
    };
  }
}

const statusGuard = new LatestGuard();

// setStatusFromEvent записывает состояние, пришедшее событием.
export function setStatusFromEvent(s: Status): void {
  statusGuard.write();
  state.status = s;
  reconcileSelection();
  notify("status");
}

// loadStatusWith читает состояние запросом fetch. Если за время запроса пришло событие
// или более новый ответ, этот ответ отбрасывается.
export async function loadStatusWith(fetch: () => Promise<Status>): Promise<void> {
  const fresh = statusGuard.begin();
  const s = await fetch();
  if (!fresh()) return;
  state.status = s;
  reconcileSelection();
  notify("status");
}

// serial ставит вызовы в очередь: следующий начинается, когда закончился предыдущий.
// Ошибка одного вызова очередь не ломает.
export function serial(): <T>(fn: () => Promise<T>) => Promise<T> {
  let tail: Promise<unknown> = Promise.resolve();
  return <T>(fn: () => Promise<T>): Promise<T> => {
    const run = tail.then(fn, fn);
    tail = run.catch(() => {});
    return run;
  };
}

// Профиль, к которому идёт или уже идёт подключение, показан выбранным. Иначе выбор
// остаётся за человеком, а при первом показе берётся профиль последнего подключения.
export function reconcileSelection(): void {
  const has = (id: string) => state.profiles.some((p) => p.ID === id);
  const active = state.status.Phase !== "idle" && state.status.Phase !== "error" && state.status.Phase !== "";
  const running = state.status.ProfileID;
  if (active && running && has(running)) {
    state.selectedId = running;
    return;
  }
  if (has(state.selectedId)) return;
  const last = state.settings?.LastProfileID ?? "";
  state.selectedId = has(last) ? last : (state.profiles[0]?.ID ?? "");
}

export type TabId = "home" | "profiles" | "rules" | "settings" | "journal";

// Screen это вкладка: корневой элемент и действие при показе.
export interface Screen {
  el: HTMLElement;
  onShow?(): void;
}

// Goto переключает вкладку.
export type Goto = (tab: TabId) => void;
