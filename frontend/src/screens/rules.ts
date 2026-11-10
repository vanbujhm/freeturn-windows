// Маршрутизация: раздельное туннелирование и список адресов, подсетей и сайтов. Список идёт
// либо напрямую (остальное через туннель), либо через туннель (остальное напрямую).
import type { Rule } from "../../bindings/github.com/vanbujhm/freeturn-windows/internal/model/models.js";
import { API, fail, loadSettings } from "../api";
import { h, toast } from "../dom";
import { createCheck } from "./check";
import { type SplitMode, splitView, withSplit } from "../state";
import { type Screen, state, subscribe } from "../store";
import * as S from "../strings";

export function createRules(): Screen {
  let busy = false;

  const splitInput = h("input", { type: "checkbox", class: "switch-input", id: "rules-split" });
  const splitHint = h("span", { class: "muted small-text" });
  const splitRow = h(
    "label",
    { class: "card row between toggle", for: "rules-split" },
    h("div", { class: "stack tight" }, h("strong", { text: S.rules.split }), splitHint),
    h("span", { class: "switch" }, splitInput, h("span", { class: "track" })),
  );

  const modeInputs = new Map<SplitMode, HTMLInputElement>();
  const modeOption = (mode: SplitMode, text: string) => {
    const input = h("input", { type: "radio", name: "rules-mode", id: `rules-mode-${mode || "bypass"}`, value: mode });
    modeInputs.set(mode, input);
    input.addEventListener("change", () => {
      if (input.checked) void saveSplit({ mode });
    });
    return h("label", { class: "segment" }, input, h("span", { text }));
  };
  const modeHint = h("span", { class: "muted small-text" });
  const modeWarn = h("span", { class: "small-text warn-text", text: S.rules.modeOnlyKillSwitch, hidden: true });
  const modeCard = h(
    "div",
    { class: "card stack" },
    h(
      "div",
      { class: "row between wrap" },
      h("strong", { text: S.rules.mode }),
      h(
        "div",
        { class: "segmented", role: "radiogroup", "aria-label": S.rules.mode },
        modeOption("", S.rules.modeBypass),
        modeOption("only", S.rules.modeOnly),
      ),
    ),
    modeHint,
    modeWarn,
  );

  const input = h("input", {
    class: "input",
    id: "rules-value",
    type: "text",
    placeholder: S.rules.placeholder,
    autocomplete: "off",
    spellcheck: "false",
    "aria-label": S.rules.placeholder,
  });
  const commentInput = h("input", {
    class: "input",
    id: "rules-comment",
    type: "text",
    maxlength: "80",
    placeholder: S.rules.commentPlaceholder,
    autocomplete: "off",
    "aria-label": S.rules.commentPlaceholder,
  });
  const addBtn = h("button", { class: "btn primary", type: "button", text: S.rules.add });
  // Открытое поле комментария одно. Оно живёт между перерисовками, чтобы ввод не терялся.
  let editing: Rule | null = null;
  let editInput: HTMLInputElement | null = null;
  // Правка правила, которая сейчас записывается. Список показывает её сразу: иначе
  // переключатель на время записи возвращался бы в прежнее положение.
  let pending: { rule: Rule; patch: Partial<Rule> } | null = null;
  const notice = h("p", { class: "muted small-text", text: S.rules.appliesNext, hidden: true });
  const allOff = h("p", { class: "small-text warn-text rules-all-off", text: S.rules.allOffOnly, hidden: true });
  const list = h("div", { class: "stack" });

  const el = h(
    "section",
    { class: "screen" },
    h("h2", { class: "screen-title", text: S.rules.title }),
    splitRow,
    modeCard,
    createCheck(),
    h("div", { class: "row wrap" }, input, commentInput, addBtn),
    notice,
    allOff,
    list,
    h("div", { class: "callout stack" }, ...S.rules.hint.map((t) => h("p", { class: "small-text", text: t }))),
  );

  splitInput.addEventListener("change", () => void saveSplit({ on: splitInput.checked }));
  addBtn.addEventListener("click", () => void add());
  for (const field of [input, commentInput]) {
    field.addEventListener("keydown", (e) => {
      if (e.key === "Enter") void add();
    });
  }

  // save записывает настройки и перечитывает их: что записалось на самом деле, показывает
  // ответ службы, а не нажатие.
  async function save(next: NonNullable<typeof state.settings>): Promise<boolean> {
    try {
      await API.SaveSettings(next);
      return true;
    } catch (e) {
      fail(e);
      return false;
    } finally {
      await loadSettings().catch(() => {});
    }
  }

  // saveSplit меняет переключатель или режим. Пока запись идёт, элементы недоступны: второе
  // нажатие не может собрать настройки из устаревших значений.
  async function saveSplit(patch: { on?: boolean; mode?: SplitMode }): Promise<void> {
    const cur = state.settings;
    if (!cur || busy) {
      render();
      return;
    }
    busy = true;
    render();
    try {
      await save(withSplit(cur, patch));
    } finally {
      busy = false;
      render();
    }
  }

  async function saveRules(next: Rule[]): Promise<boolean> {
    const cur = state.settings;
    if (!cur) return false;
    return save({ ...cur, Options: { ...cur.Options, Rules: next } });
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
      const comment = commentInput.value.trim();
      if (await saveRules([...rules, comment ? { ...rule, Comment: comment } : rule])) {
        input.value = "";
        commentInput.value = "";
        toast(S.rules.added);
      }
    } catch (e) {
      fail(e);
    } finally {
      busy = false;
      render();
    }
  }

  async function remove(rule: Rule): Promise<void> {
    if (busy || !state.settings) return;
    busy = true;
    try {
      const rules = state.settings.Options.Rules ?? [];
      await saveRules(rules.filter((r) => !(r.Kind === rule.Kind && r.Value === rule.Value)));
    } finally {
      busy = false;
      render();
    }
  }

  const same = (a: Rule, b: Rule) => a.Kind === b.Kind && a.Value === b.Value;

  // updateRule меняет одно правило, найденное по виду и значению.
  async function updateRule(rule: Rule, patch: Partial<Rule>): Promise<void> {
    if (busy || !state.settings) {
      render();
      return;
    }
    busy = true;
    pending = { rule, patch };
    render();
    try {
      const rules = state.settings.Options.Rules ?? [];
      await saveRules(rules.map((r) => (same(r, rule) ? { ...r, ...patch } : r)));
    } finally {
      busy = false;
      pending = null;
      render();
    }
  }

  function startEdit(rule: Rule): void {
    const field = h("input", {
      class: "input rule-comment-input",
      type: "text",
      maxlength: "80",
      placeholder: S.rules.commentPlaceholder,
      "aria-label": `${S.rules.editComment}: ${rule.Value}`,
    });
    field.value = rule.Comment ?? "";
    field.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        // Идёт другая запись: поле остаётся открытым, Enter сработает после неё.
        if (busy) return;
        const value = field.value.trim();
        editing = editInput = null;
        void updateRule(rule, { Comment: value });
      } else if (e.key === "Escape") {
        editing = editInput = null;
        render();
      }
    });
    editing = rule;
    editInput = field;
    render();
    field.focus();
  }

  function ruleCard(r: Rule): HTMLElement {
    const s = state.settings;
    const toggle = h("input", { type: "checkbox", class: "switch-input", "aria-label": `${S.rules.ruleOn}: ${r.Value}` });
    toggle.checked = !r.Off;
    toggle.disabled = !s || busy;
    toggle.addEventListener("change", () => void updateRule(r, { Off: !toggle.checked }));
    const edited = editing !== null && same(editing, r);
    const comment = edited
      ? editInput
      : r.Comment
        ? h("span", { class: "muted small-text rule-comment", text: r.Comment })
        : null;
    return h(
      "div",
      { class: r.Off ? "card row between rule dim" : "card row between rule" },
      h("label", { class: "switch" }, toggle, h("span", { class: "track" })),
      h(
        "div",
        { class: "stack tight grow" },
        h("span", { class: "mono", text: r.Value }),
        h("span", { class: "label", text: S.kinds[r.Kind] ?? r.Kind }),
        comment,
      ),
      h("button", {
        class: "btn plain-text rule-edit",
        type: "button",
        text: S.rules.editComment,
        disabled: !s || busy,
        "aria-label": `${S.rules.editComment}: ${r.Value}`,
        onclick: () => startEdit(r),
      }),
      h("button", {
        class: "btn danger-text",
        type: "button",
        text: S.rules.remove,
        "aria-label": `${S.rules.remove}: ${r.Value}`,
        onclick: () => void remove(r),
      }),
    );
  }

  function render(): void {
    const s = state.settings;
    const view = splitView(s?.Options);
    splitInput.checked = view.on;
    splitInput.disabled = !s || busy;
    splitHint.textContent = view.on ? S.rules.splitHint : S.rules.splitOffHint;
    for (const [mode, radio] of modeInputs) {
      radio.checked = mode === view.mode;
      radio.disabled = !s || busy || !view.on;
    }
    modeCard.classList.toggle("dim", !view.on);
    modeHint.textContent = view.mode === "only" ? S.rules.modeOnlyHint : S.rules.modeBypassHint;
    modeWarn.hidden = !(view.on && view.mode === "only" && s?.Options.KillSwitch);

    const live = ["connecting", "captcha", "connected", "reconnecting"].includes(state.status.Phase);
    notice.hidden = !live;
    const saved = s?.Options.Rules ?? [];
    const change = pending;
    const rules = change ? saved.map((r) => (same(r, change.rule) ? { ...r, ...change.patch } : r)) : saved;
    allOff.hidden = !(view.on && view.mode === "only" && rules.length > 0 && rules.every((r) => r.Off));
    if (rules.length === 0) {
      const empty = view.on && view.mode === "only" ? S.rules.emptyOnly : S.rules.empty;
      list.replaceChildren(h("p", { class: "muted center-text", text: empty }));
      return;
    }
    // Перестройка списка снимает фокус с открытого поля комментария, даже если оно
    // переносится в новую карточку. Статус приходит каждую секунду, поэтому фокус и курсор
    // возвращаются на место.
    const field = editInput;
    const focused = field !== null && document.activeElement === field;
    const start = field?.selectionStart ?? null;
    const end = field?.selectionEnd ?? null;
    list.replaceChildren(...rules.map(ruleCard));
    if (focused && field.isConnected) {
      field.focus();
      if (start !== null && end !== null) field.setSelectionRange(start, end);
    }
  }

  subscribe("settings", render);
  subscribe("status", render);
  render();
  return { el, onShow: render };
}
