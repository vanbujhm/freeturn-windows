// Журнал: поток строк от службы, «Копировать» и «Сохранить диагностику».
import { API, fail } from "../api";
import { copyText, h, toast } from "../dom";
import { type Screen, state, subscribe } from "../store";
import * as S from "../strings";

export function createJournal(): Screen {
  const box = h("div", { class: "log", role: "log", "aria-live": "off", tabindex: "0" });
  const empty = h("p", { class: "muted center-text", text: S.journal.empty });

  const el = h(
    "section",
    { class: "screen journal" },
    h("h2", { class: "screen-title", text: S.journal.title }),
    h("p", { class: "muted small-text", text: S.journal.hint }),
    h(
      "div",
      { class: "row" },
      h("button", {
        class: "btn secondary",
        type: "button",
        text: S.journal.copy,
        onclick: () => void copyText(state.logs.join("\r\n"), S.journal.copied),
      }),
      h("button", { class: "btn primary", type: "button", text: S.journal.save, onclick: () => void saveDiagnostics() }),
    ),
    box,
  );

  async function saveDiagnostics(): Promise<void> {
    try {
      toast(S.journal.savedTo(await API.SaveDiagnostics()));
    } catch (e) {
      fail(e);
    }
  }

  // Журнал службы читается при показе вкладки, дальше строки приходят событиями.
  async function load(): Promise<void> {
    try {
      const lines = await API.Logs();
      // События, пришедшие за время чтения, уже в списке: берём то, чего в нём нет.
      const tail = state.logs.filter((l) => !lines.includes(l));
      state.logs = [...lines, ...tail];
    } catch {
      // Службы нет: остаются строки, пришедшие событиями.
    }
    render();
    box.scrollTop = box.scrollHeight;
  }

  function render(): void {
    const stick = box.scrollHeight - box.scrollTop - box.clientHeight < 40;
    if (state.logs.length === 0) {
      box.replaceChildren(empty);
      return;
    }
    box.replaceChildren(...state.logs.map((l) => h("div", { class: "log-line", text: l })));
    if (stick) box.scrollTop = box.scrollHeight;
  }

  subscribe("log", render);
  render();
  return { el, onShow: () => void load() };
}
