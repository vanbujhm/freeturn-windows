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

export function pushLog(line: string): void {
  state.logs.push(line);
  if (state.logs.length > MAX_LOG_LINES) {
    state.logs.splice(0, state.logs.length - MAX_LOG_LINES);
  }
  notify("log");
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
