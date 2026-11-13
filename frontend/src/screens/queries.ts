// Вкладка «Запросы»: что спрашивали программы у DNS-прокси сеанса и куда пойдёт их трафик.
// Журнал живёт в памяти службы, окно спрашивает его раз в секунду, пока вкладка открыта.
import type { QueryEntry } from "../../bindings/github.com/vanbujhm/freeturn-windows/internal/model/models.js";
import { API, fail } from "../api";
import { h } from "../dom";
import { type Screen, state } from "../store";
import * as S from "../strings";

// MAX_ROWS - сколько строк держит окно, столько же, сколько журнал службы.
const MAX_ROWS = 2000;
const POLL_MS = 1000;

const timeText = (t: string): string => {
  const d = new Date(t);
  return Number.isNaN(d.getTime()) ? "" : d.toLocaleTimeString("ru-RU");
};

export function createQueries(o: { addRule(name: string): void }): Screen {
  const filter = h("input", {
    class: "input",
    id: "queries-filter",
    type: "search",
    placeholder: S.queries.filter,
    autocomplete: "off",
    spellcheck: "false",
    "aria-label": S.queries.filter,
  });
  const ruled = h("input", { type: "checkbox", id: "queries-ruled" });
  const clearBtn = h("button", { class: "btn secondary queries-clear", type: "button", text: S.queries.clear });
  const list = h("div", { class: "stack tight queries-list" });
  const el = h(
    "section",
    { class: "screen" },
    h("h2", { class: "screen-title", text: S.queries.title }),
    h(
      "div",
      { class: "row wrap" },
      filter,
      h("label", { class: "row", for: "queries-ruled" }, ruled, h("span", { text: S.queries.ruledOnly })),
      clearBtn,
    ),
    list,
  );

  let rows: QueryEntry[] = []; // новые сверху
  let last = 0;
  let active = false;
  let timer: ReturnType<typeof setInterval> | null = null;
  let inflight = false;

  function stop(): void {
    if (timer !== null) {
      clearInterval(timer);
      timer = null;
    }
  }

  function take(entries: QueryEntry[] | null | undefined): void {
    const fresh = [...(entries ?? [])].reverse();
    rows = [...fresh, ...rows].slice(0, MAX_ROWS);
  }

  async function poll(): Promise<void> {
    if (el.hidden) {
      stop();
      return;
    }
    if (inflight) return;
    inflight = true;
    try {
      let page = await API.Queries(last);
      // Номер меньше запомненного: служба перезапустилась, её журнал начался заново.
      if (page.Last < last) {
        rows = [];
        last = 0;
        page = await API.Queries(0);
      }
      take(page.Entries);
      last = page.Last;
      active = page.Active;
    } catch {
      // Служба недоступна: об этом говорит главная, здесь таблица просто не растёт.
    } finally {
      inflight = false;
    }
    render();
  }

  function row(e: QueryEntry): HTMLElement {
    const addrs = e.Addrs ?? [];
    const shown = addrs.slice(0, 2).join(", ") + (addrs.length > 2 ? ` ${S.queries.more(addrs.length - 2)}` : "");
    const line = h(
      "div",
      { class: "card row between wrap query" },
      h("span", { class: "muted small-text query-time", text: timeText(e.Time) }),
      h("span", { class: "mono grow query-name", text: e.Name }),
      h("span", { class: "mono small-text query-addrs", text: shown, title: addrs.join("\n") }),
      h("span", { class: "label query-route", text: e.Route === "direct" ? S.queries.direct : S.queries.tunnel }),
      h("span", { class: "small-text query-rule", text: e.Rule ?? "" }),
    );
    if (e.Late) line.append(h("span", { class: "small-text warn-text query-late", text: S.queries.late, title: S.queries.lateHint }));
    line.append(
      h("button", {
        class: "btn plain-text query-add",
        type: "button",
        text: S.queries.addRule,
        "aria-label": `${S.queries.addRule}: ${e.Name}`,
        onclick: () => o.addRule(e.Name),
      }),
    );
    return line;
  }

  function emptyText(): string {
    if (rows.length > 0) return S.queries.nothingFound;
    if (active) return S.queries.empty;
    const live = ["connecting", "captcha", "connected", "reconnecting"].includes(state.status.Phase);
    return live ? S.queries.noProxy : S.queries.idle;
  }

  function render(): void {
    const needle = filter.value.trim().toLowerCase();
    const visible = rows.filter((r) => (!needle || r.Name.toLowerCase().includes(needle)) && (!ruled.checked || !!r.Rule));
    if (visible.length === 0) {
      list.replaceChildren(h("p", { class: "muted center-text queries-empty", text: emptyText() }));
      return;
    }
    list.replaceChildren(...visible.map(row));
  }

  filter.addEventListener("input", render);
  ruled.addEventListener("change", render);
  clearBtn.addEventListener("click", () => {
    void (async () => {
      try {
        await API.ClearQueries();
        rows = [];
        render();
      } catch (e) {
        fail(e);
      }
    })();
  });

  render();
  return {
    el,
    onShow(): void {
      if (timer === null) timer = setInterval(() => void poll(), POLL_MS);
      void poll();
    },
  };
}
