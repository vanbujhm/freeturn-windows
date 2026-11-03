// Окно FreeTurn: вкладки, подписка на события службы и первая загрузка данных.
import { Events } from "@wailsio/runtime";
import type { ImportPreview } from "../bindings/github.com/vanbujhm/freeturn-windows/cmd/freeturn/index.js";
import "./style.css";
import { API, loadBanners, loadProfiles, loadSettings, loadStatus } from "./api";
import { h, icon } from "./dom";
import { createHome } from "./screens/home";
import { createJournal } from "./screens/journal";
import { createProfiles } from "./screens/profiles";
import { createRules } from "./screens/rules";
import { createSettings } from "./screens/settings";
import type { Status } from "./state";
import { type Screen, type TabId, type UpdateInfo, notify, pushLog, reconcileSelection, state } from "./store";
import * as S from "./strings";

interface Tab {
  id: TabId;
  label: string;
  paths: string[];
}

const TABS: Tab[] = [
  { id: "home", label: S.tabs.home, paths: ["M3 11l9-8 9 8v9a1 1 0 0 1-1 1h-5v-6H9v6H4a1 1 0 0 1-1-1z"] },
  { id: "profiles", label: S.tabs.profiles, paths: ["M4 5h16v5H4z", "M4 14h16v5H4z"] },
  { id: "rules", label: S.tabs.rules, paths: ["M4 12h6l4-6h6", "M10 12l4 6h6"] },
  {
    id: "settings",
    label: S.tabs.settings,
    paths: [
      "M4 7h8", "M18 7h2", "M14 7m-2 0a2 2 0 1 0 4 0a2 2 0 1 0 -4 0",
      "M4 17h2", "M12 17h8", "M8 17m-2 0a2 2 0 1 0 4 0a2 2 0 1 0 -4 0",
    ],
  },
  { id: "journal", label: S.tabs.journal, paths: ["M6 3h9l4 4v14H6z", "M9 12h7", "M9 16h7"] },
];

const buttons = new Map<TabId, HTMLButtonElement>();
const screens = new Map<TabId, Screen>();

function goto(tab: TabId): void {
  for (const [id, screen] of screens) screen.el.hidden = id !== tab;
  for (const [id, btn] of buttons) {
    if (id === tab) btn.setAttribute("aria-current", "page");
    else btn.removeAttribute("aria-current");
  }
  screens.get(tab)?.onShow?.();
}

function mount(root: HTMLElement): void {
  screens.set("home", createHome(goto));
  screens.set("profiles", createProfiles());
  screens.set("rules", createRules());
  screens.set("settings", createSettings());
  screens.set("journal", createJournal());

  const main = h("main", { class: "content" }, ...[...screens.values()].map((s) => s.el));
  const nav = h(
    "nav",
    { class: "tabbar", "aria-label": S.app.name },
    ...TABS.map((t) => {
      const btn = h("button", { class: "tab", type: "button", onclick: () => goto(t.id) }, icon(...t.paths), h("span", { text: t.label }));
      buttons.set(t.id, btn);
      return btn;
    }),
  );
  root.replaceChildren(main, nav);
  goto("home");
}

// События подписываются раньше первой загрузки, чтобы не потерять изменения между ними.
function subscribeEvents(): void {
  Events.On("status", (e) => {
    state.status = e.data as Status;
    reconcileSelection();
    notify("status");
  });
  Events.On("service-down", () => {
    state.status = { Phase: "error", Code: "service_down" };
    notify("status");
  });
  Events.On("log", (e) => pushLog(String(e.data ?? "")));
  Events.On("import", (e) => showImport(e.data as ImportPreview));
  Events.On("update", (e) => {
    state.update = (e.data as UpdateInfo | null) ?? null;
    notify("update");
  });
}

function showImport(p: ImportPreview | null): void {
  if (!p) return;
  state.import = p;
  notify("import");
  goto("profiles");
}

async function load(): Promise<void> {
  // Настройки первыми: по ним выбирается профиль последнего подключения.
  await loadSettings().catch(() => {});
  await Promise.allSettled([loadProfiles(), loadStatus(), loadBanners()]);
  // Ссылка, с которой запустили программу, могла прийти раньше подписки на событие.
  showImport(await API.PendingImport().catch(() => null));
}

mount(document.getElementById("app")!);
subscribeEvents();
void load();
// Окно могло долго быть скрыто в трее: при показе состояние читается заново.
document.addEventListener("visibilitychange", () => {
  if (!document.hidden) void loadStatus().catch(() => {});
});
