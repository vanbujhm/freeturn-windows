// Журнал: поток строк от службы, «Копировать» и «Сохранить диагностику».
import { API, fail } from "../api";
import { copyText, h, toast } from "../dom";
import { MAX_LOG_LINES, type Screen, mergeLogs, state, subscribe } from "../store";
import * as S from "../strings";

export function createJournal(): Screen {
  const box = h("div", { class: "log", role: "log", "aria-live": "off", tabindex: "0" });
  const empty = h("p", { class: "muted center-text", text: S.journal.empty });
  // shownTotal это значение state.logTotal, до которого строки уже показаны.
  let shownTotal = -1;
  let frame = 0;

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
      mergeLogs(await API.Logs());
    } catch {
      // Службы нет: остаются строки, пришедшие событиями.
    }
    renderAll();
    box.scrollTop = box.scrollHeight;
  }

  const line = (text: string) => h("div", { class: "log-line", text });

  // renderAll строит вкладку заново. Нужен при показе и после чтения журнала у службы.
  function renderAll(): void {
    shownTotal = state.logTotal;
    if (state.logs.length === 0) {
      box.replaceChildren(empty);
      return;
    }
    box.replaceChildren(...state.logs.map(line));
  }

  // append дописывает новые строки и срезает лишние сверху, не трогая остальные узлы.
  function append(): void {
    frame = 0;
    if (el.hidden) return; // при показе вкладка перестроится целиком
    const added = Math.min(state.logTotal - shownTotal, state.logs.length);
    if (added <= 0) return;
    if (shownTotal < 0 || box.firstElementChild === empty || added >= state.logs.length) {
      renderAll();
      return;
    }
    const stick = box.scrollHeight - box.scrollTop - box.clientHeight < 40;
    box.append(...state.logs.slice(-added).map(line));
    while (box.childElementCount > MAX_LOG_LINES) box.firstElementChild?.remove();
    shownTotal = state.logTotal;
    if (stick) box.scrollTop = box.scrollHeight;
  }

  // На событие вкладка не перестраивается: строки копятся и дописываются раз за кадр.
  subscribe("log", () => {
    if (el.hidden || frame) return;
    frame = requestAnimationFrame(append);
  });
  renderAll();
  return { el, onShow: () => void load() };
}
