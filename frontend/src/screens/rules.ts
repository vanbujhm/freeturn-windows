// Исключения: адреса, подсети и сайты, которые идут мимо туннеля.
import type { Rule } from "../../bindings/github.com/vanbujhm/freeturn-windows/internal/model/models.js";
import { API, fail, loadSettings } from "../api";
import { h, toast } from "../dom";
import { type Screen, state, subscribe } from "../store";
import * as S from "../strings";

export function createRules(): Screen {
  let busy = false;

  const input = h("input", {
    class: "input",
    type: "text",
    placeholder: S.rules.placeholder,
    autocomplete: "off",
    spellcheck: "false",
    "aria-label": S.rules.placeholder,
  });
  const addBtn = h("button", { class: "btn primary", type: "button", text: S.rules.add });
  const notice = h("p", { class: "muted small-text", text: S.rules.appliesNext, hidden: true });
  const list = h("div", { class: "stack" });

  const el = h(
    "section",
    { class: "screen" },
    h("h2", { class: "screen-title", text: S.rules.title }),
    h("p", { class: "muted", text: S.rules.intro }),
    h("div", { class: "row" }, input, addBtn),
    notice,
    list,
    h("div", { class: "callout stack" }, ...S.rules.hint.map((t) => h("p", { class: "small-text", text: t }))),
  );

  addBtn.addEventListener("click", () => void add());
  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter") void add();
  });

  // save записывает список правил в настройки. Остальные поля берутся из текущих настроек.
  async function save(next: Rule[]): Promise<boolean> {
    const cur = state.settings;
    if (!cur) return false;
    try {
      await API.SaveSettings({ ...cur, Options: { ...cur.Options, Rules: next } });
      await loadSettings();
      return true;
    } catch (e) {
      fail(e);
      return false;
    }
  }

  async function add(): Promise<void> {
    const value = input.value.trim();
    if (!value || busy || !state.settings) return;
    busy = true;
    try {
      const rule = await API.ClassifyRule(value);
      const rules = state.settings.Options.Rules ?? [];
      if (rules.some((r) => r.Kind === rule.Kind && r.Value === rule.Value)) {
        toast(S.rules.duplicate, "error");
        return;
      }
      if (await save([...rules, rule])) {
        input.value = "";
        toast(S.rules.added);
      }
    } catch (e) {
      fail(e);
    } finally {
      busy = false;
    }
  }

  async function remove(rule: Rule): Promise<void> {
    if (busy || !state.settings) return;
    busy = true;
    try {
      const rules = state.settings.Options.Rules ?? [];
      await save(rules.filter((r) => !(r.Kind === rule.Kind && r.Value === rule.Value)));
    } finally {
      busy = false;
    }
  }

  function render(): void {
    const rules = state.settings?.Options.Rules ?? [];
    const live = ["connecting", "captcha", "connected", "reconnecting"].includes(state.status.Phase);
    notice.hidden = !live;
    if (rules.length === 0) {
      list.replaceChildren(h("p", { class: "muted center-text", text: S.rules.empty }));
      return;
    }
    list.replaceChildren(
      ...rules.map((r) =>
        h(
          "div",
          { class: "card row between rule" },
          h("div", { class: "stack tight" }, h("span", { class: "mono", text: r.Value }), h("span", { class: "label", text: S.kinds[r.Kind] ?? r.Kind })),
          h("button", {
            class: "btn danger-text",
            type: "button",
            text: S.rules.remove,
            "aria-label": `${S.rules.remove}: ${r.Value}`,
            onclick: () => void remove(r),
          }),
        ),
      ),
    );
  }

  subscribe("settings", render);
  subscribe("status", render);
  render();
  return { el, onShow: render };
}
