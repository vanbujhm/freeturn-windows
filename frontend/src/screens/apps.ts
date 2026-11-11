// Раздел «Только через VPN»: программы, которые во время подключения выходят в сеть только
// через туннель. Записывает настройки через экран маршрутизации: запись у экрана одна.
import type { Settings } from "../../bindings/github.com/vanbujhm/freeturn-windows/internal/profile/models.js";
import type { AppRule } from "../../bindings/github.com/vanbujhm/freeturn-windows/internal/model/models.js";
import { API, fail } from "../api";
import { h, toast } from "../dom";
import { state } from "../store";
import * as S from "../strings";
import { createCommentEditor } from "./comment-editor";

export interface SaveControl {
  busy(): boolean;
  // exclusive выполняет запись, если другая не идёт, и перерисовывает экран до и после.
  exclusive(fn: () => Promise<void>): Promise<void>;
  save(next: Settings): Promise<boolean>;
}

// Windows не различает регистр в путях, повтор ищется так же, как в службе.
const same = (a: AppRule, b: AppRule) => a.Path.toLowerCase() === b.Path.toLowerCase();
const fileName = (path: string) => path.split(/[\\/]/).pop() ?? path;

export function createApps(ctl: SaveControl): { el: HTMLElement; render(): void } {
  const addBtn = h("button", { class: "btn secondary apps-add", type: "button", text: S.apps.add });
  const notice = h("p", { class: "muted small-text", text: S.rules.appliesNext, hidden: true });
  const list = h("div", { class: "stack" });
  const el = h(
    "section",
    { class: "stack apps" },
    h("div", { class: "row between wrap" }, h("strong", { text: S.apps.title }), addBtn),
    notice,
    list,
    h("div", { class: "callout stack apps-hint" }, ...S.apps.hint.map((t) => h("p", { class: "small-text", text: t }))),
  );
  // Правка, которая сейчас записывается: список показывает её сразу, как у правил.
  let pending: { app: AppRule; patch: Partial<AppRule> } | null = null;

  const current = (): AppRule[] => state.settings?.Options.Apps ?? [];
  const editor = createCommentEditor<AppRule>({
    same,
    comment: (a) => a.Comment ?? "",
    label: (a) => `${S.rules.editComment}: ${a.Path}`,
    busy: () => ctl.busy(),
    save: (a, comment) => void update(a, { Comment: comment }),
    render,
  });

  async function saveApps(next: AppRule[]): Promise<boolean> {
    const cur = state.settings;
    if (!cur) return false;
    return ctl.save({ ...cur, Options: { ...cur.Options, Apps: next } });
  }

  // add открывает выбор файла и добавляет программу. Диалог тоже внутри записи: второй
  // выбор или правка правила не соберут настройки из устаревшего списка.
  function add(): Promise<void> {
    return ctl.exclusive(async () => {
      try {
        const path = await API.PickApp();
        if (!path) return;
        if (current().some((a) => same(a, { Path: path, Comment: "", Off: false }))) {
          toast(S.apps.duplicate, "error");
          return;
        }
        if (await saveApps([...current(), { Path: path, Comment: "", Off: false }])) toast(S.apps.added);
      } catch (e) {
        fail(e);
      }
    });
  }

  function update(app: AppRule, patch: Partial<AppRule>): Promise<void> {
    return ctl.exclusive(async () => {
      pending = { app, patch };
      render();
      try {
        await saveApps(current().map((a) => (same(a, app) ? { ...a, ...patch } : a)));
      } finally {
        pending = null;
      }
    });
  }

  function remove(app: AppRule): Promise<void> {
    return ctl.exclusive(async () => {
      await saveApps(current().filter((a) => !same(a, app)));
    });
  }

  function card(a: AppRule, disabled: boolean): HTMLElement {
    const toggle = h("input", { type: "checkbox", class: "switch-input", "aria-label": `${S.apps.appOn}: ${a.Path}` });
    toggle.checked = !a.Off;
    toggle.disabled = disabled;
    toggle.addEventListener("change", () => void update(a, { Off: !toggle.checked }));
    const comment =
      editor.field(a) ?? (a.Comment ? h("span", { class: "muted small-text rule-comment", text: a.Comment }) : null);
    return h(
      "div",
      { class: a.Off ? "card row between rule app dim" : "card row between rule app" },
      h("label", { class: "switch" }, toggle, h("span", { class: "track" })),
      h(
        "div",
        { class: "stack tight grow" },
        h("span", { class: "mono app-name", text: fileName(a.Path) }),
        h("span", { class: "muted small-text app-path", text: a.Path }),
        comment,
      ),
      h("button", {
        class: "btn plain-text rule-edit",
        type: "button",
        text: S.rules.editComment,
        disabled,
        "aria-label": `${S.rules.editComment}: ${a.Path}`,
        onclick: () => editor.start(a),
      }),
      h("button", {
        class: "btn danger-text",
        type: "button",
        text: S.apps.remove,
        disabled,
        "aria-label": `${S.apps.remove}: ${a.Path}`,
        onclick: () => void remove(a),
      }),
    );
  }

  addBtn.addEventListener("click", () => void add());

  function render(): void {
    const disabled = !state.settings || ctl.busy();
    addBtn.disabled = disabled;
    notice.hidden = !["connecting", "captcha", "connected", "reconnecting"].includes(state.status.Phase);
    const change = pending;
    const apps = change ? current().map((a) => (same(a, change.app) ? { ...a, ...change.patch } : a)) : current();
    if (apps.length === 0) {
      list.replaceChildren(h("p", { class: "muted small-text apps-empty", text: S.apps.empty }));
      return;
    }
    editor.rebuild(list, () => apps.map((a) => card(a, disabled)));
  }

  return { el, render };
}
