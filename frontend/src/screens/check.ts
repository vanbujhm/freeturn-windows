// Карточка «Проверить адрес»: какое правило совпало и куда трафик адреса идёт сейчас.
import type { CheckHop, CheckResult } from "../../bindings/github.com/vanbujhm/freeturn-windows/cmd/freeturn/models.js";
import type { Rule } from "../../bindings/github.com/vanbujhm/freeturn-windows/internal/model/models.js";
import { API, fail } from "../api";
import { h } from "../dom";
import * as S from "../strings";

const where = (v: string): string => (v === "tunnel" ? S.check.tunnel : v === "direct" ? S.check.direct : v === "other" ? S.check.other : S.check.unknown);

// ruleText называет правило вместе с комментарием.
const ruleText = (r: Rule, text: (v: string) => string): string => (r.Comment ? `${text(r.Value)} (${r.Comment})` : text(r.Value));

export function createCheck(): HTMLElement {
  const input = h("input", {
    class: "input",
    id: "check-value",
    type: "text",
    placeholder: S.check.placeholder,
    autocomplete: "off",
    spellcheck: "false",
    "aria-label": S.check.placeholder,
  });
  const runBtn = h("button", { class: "btn secondary check-run", type: "button", text: S.check.run });
  const out = h("div", { class: "stack tight check-result", "aria-live": "polite" });
  // seq растёт с каждым запросом: ответ на устаревший запрос не затирает новый.
  let seq = 0;

  async function run(): Promise<void> {
    const value = input.value.trim();
    if (!value) return;
    const mine = ++seq;
    try {
      const res = await API.CheckAddress(value);
      if (mine === seq) out.replaceChildren(...render(res));
    } catch (e) {
      if (mine !== seq) return;
      out.replaceChildren();
      fail(e);
    }
  }

  runBtn.addEventListener("click", () => void run());
  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter") void run();
  });

  return h(
    "div",
    { class: "card stack" },
    h("strong", { text: S.check.title }),
    h("div", { class: "row" }, input, runBtn),
    out,
  );
}

function render(res: CheckResult): HTMLElement[] {
  const ex = res.Rules;
  let detail: string;
  if (ex.SplitOff) detail = S.check.splitOff;
  else if (ex.Match.Rule.Value) detail = `${where(ex.Verdict)}, ${ruleText(ex.Match.Rule, S.check.rule)}`;
  else if (ex.OffMatch.Rule.Value) detail = `${where(ex.Verdict)}, ${ruleText(ex.OffMatch.Rule, S.check.offRule)}`;
  else detail = `${where(ex.Verdict)}, ${S.check.noMatch}`;
  const blocks = [h("div", { class: "stack tight" }, h("span", { class: "label", text: S.check.byRules }), h("span", { text: detail }))];
  if (!res.Live) return blocks;

  const now = h("div", { class: "stack tight" }, h("span", { class: "label", text: S.check.now }));
  if (res.Unresolved) now.append(h("span", { class: "muted", text: S.check.unresolved }));
  for (const hop of res.Hops ?? []) now.append(hopLine(hop));
  blocks.push(now);
  return blocks;
}

function hopLine(hop: CheckHop): HTMLElement {
  const line = h(
    "div",
    { class: hop.Reason ? "check-hop mismatch" : "check-hop" },
    h("span", { class: "mono", text: hop.Addr }),
    h("span", { text: ` ${S.check.expect(where(hop.Expect))}, ${S.check.actual(where(hop.Via))}` }),
  );
  const reason = S.check.reasons[hop.Reason as keyof typeof S.check.reasons];
  if (reason) line.append(h("div", { class: "small-text warn-text", text: reason }));
  return line;
}
