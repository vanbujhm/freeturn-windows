// @vitest-environment jsdom
// Карточка «Проверить адрес»: ответ по правилам и факт маршрута.
import { beforeEach, describe, expect, test, vi } from "vitest";

const check = vi.hoisted(() => vi.fn());
const fail = vi.hoisted(() => vi.fn());

vi.mock("../api", () => ({
  API: { CheckAddress: (v: string) => check(v) },
  fail: (e: unknown) => fail(e),
}));

import * as S from "../strings";
import { createCheck } from "./check";

const rule = (Value: string, Comment = "") => ({ Kind: "ip", Value, Comment, Off: false });
const empty = { Rule: { Kind: "", Value: "", Comment: "", Off: false }, Addr: "" };
const explanation = (over: object = {}) => ({
  Input: rule("1.2.3.4"),
  Verdict: "direct",
  Match: { Rule: rule("1.2.3.4", "работа"), Addr: "1.2.3.4" },
  OffMatch: empty,
  SplitOff: false,
  ...over,
});
const result = (over: object = {}) => ({ Rules: explanation(), Live: false, Unresolved: false, Hops: [], ...over });

function mount(): HTMLElement {
  document.body.replaceChildren();
  const el = createCheck();
  document.body.append(el);
  return el;
}

async function run(el: HTMLElement, value = "1.2.3.4"): Promise<void> {
  el.querySelector<HTMLInputElement>("#check-value")!.value = value;
  el.querySelector<HTMLButtonElement>(".check-run")!.click();
  await vi.waitFor(() => expect(el.querySelector(".check-result")?.childElementCount ?? 0).toBeGreaterThan(0));
}

const text = (el: HTMLElement) => el.querySelector(".check-result")!.textContent ?? "";

beforeEach(() => {
  check.mockReset();
  fail.mockReset();
});

describe("проверка адреса", () => {
  test("без подключения только «По правилам»", async () => {
    check.mockResolvedValue(result());
    const el = mount();
    await run(el);
    expect(check).toHaveBeenCalledWith("1.2.3.4");
    expect(text(el)).toContain(S.check.byRules);
    expect(text(el)).toContain(S.check.direct);
    expect(text(el)).toContain(`${S.check.rule("1.2.3.4")} (работа)`);
    expect(text(el)).not.toContain(S.check.now);
  });

  test("раздельное туннелирование выключено", async () => {
    check.mockResolvedValue(result({ Rules: explanation({ SplitOff: true, Verdict: "tunnel", Match: empty }) }));
    const el = mount();
    await run(el);
    expect(text(el)).toContain(S.check.splitOff);
  });

  test("совпало бы с выключенным правилом", async () => {
    check.mockResolvedValue(
      result({ Rules: explanation({ Verdict: "tunnel", Match: empty, OffMatch: { Rule: rule("1.2.3.4"), Addr: "1.2.3.4" } }) }),
    );
    const el = mount();
    await run(el);
    expect(text(el)).toContain(S.check.offRule("1.2.3.4"));
  });

  test("факт совпадает с правилами", async () => {
    check.mockResolvedValue(
      result({ Live: true, Hops: [{ Addr: "1.2.3.4", Expect: "direct", Match: rule("1.2.3.4"), Via: "direct", Reason: "" }] }),
    );
    const el = mount();
    await run(el);
    expect(text(el)).toContain(S.check.now);
    const hop = el.querySelector(".check-hop")!;
    expect(hop.textContent).toContain("1.2.3.4");
    expect(hop.classList.contains("mismatch")).toBe(false);
  });

  test("расхождение подсвечено и объяснено", async () => {
    check.mockResolvedValue(
      result({
        Live: true,
        Hops: [{ Addr: "1.2.3.4", Expect: "direct", Match: rule("1.2.3.4"), Via: "tunnel", Reason: "rules_changed" }],
      }),
    );
    const el = mount();
    await run(el);
    const hop = el.querySelector(".check-hop")!;
    expect(hop.classList.contains("mismatch")).toBe(true);
    expect(hop.textContent).toContain(S.check.reasons.rules_changed);
  });

  test("домен не разрешился", async () => {
    check.mockResolvedValue(result({ Live: true, Unresolved: true }));
    const el = mount();
    await run(el, "example.com");
    expect(text(el)).toContain(S.check.unresolved);
  });

  test("ошибка убирает прежний ответ", async () => {
    check.mockResolvedValueOnce(result());
    const el = mount();
    await run(el);
    check.mockRejectedValueOnce(new Error("bad"));
    el.querySelector<HTMLButtonElement>(".check-run")!.click();
    await vi.waitFor(() => expect(fail).toHaveBeenCalledTimes(1));
    expect(el.querySelector(".check-result")!.childElementCount).toBe(0);
  });

  test("пустой ввод не проверяется, Enter запускает", async () => {
    check.mockResolvedValue(result());
    const el = mount();
    const input = el.querySelector<HTMLInputElement>("#check-value")!;
    input.value = "   ";
    el.querySelector<HTMLButtonElement>(".check-run")!.click();
    expect(check).not.toHaveBeenCalled();
    input.value = "1.2.3.4";
    input.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter" }));
    await vi.waitFor(() => expect(check).toHaveBeenCalledTimes(1));
  });

  test("устаревший ответ отбрасывается", async () => {
    let first!: (v: unknown) => void;
    check.mockImplementationOnce(() => new Promise((r) => (first = r)));
    check.mockResolvedValueOnce(result({ Rules: explanation({ SplitOff: true, Verdict: "tunnel", Match: empty }) }));
    const el = mount();
    const input = el.querySelector<HTMLInputElement>("#check-value")!;
    input.value = "1.1.1.1";
    el.querySelector<HTMLButtonElement>(".check-run")!.click();
    input.value = "2.2.2.2";
    input.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter" }));
    await vi.waitFor(() => expect(text(el)).toContain(S.check.splitOff));
    first(result());
    await Promise.resolve();
    expect(text(el)).toContain(S.check.splitOff);
  });
});
