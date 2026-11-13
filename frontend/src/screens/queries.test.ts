// @vitest-environment jsdom
// Вкладка «Запросы»: опрос службы, фильтр, перенос имени в правила, очистка.
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";

const queries = vi.hoisted(() => vi.fn());
const clearQueries = vi.hoisted(() => vi.fn());

vi.mock("../api", () => ({
  API: { Queries: (since: number) => queries(since), ClearQueries: () => clearQueries() },
  fail: vi.fn(),
}));

import { state } from "../store";
import * as S from "../strings";
import { createQueries } from "./queries";

type Entry = { Seq: number; Name: string; Addrs?: string[]; Route?: string; Rule?: string; Late?: boolean };
const entry = (e: Entry) => ({
  Time: "2026-11-13T12:00:00Z", Type: "A", Upstream: e.Route ?? "tunnel", RCode: "NOERROR", Took: 1,
  Addrs: [], Route: "tunnel", Rule: "", Late: false, ...e,
});
const page = (entries: Entry[], Last: number, Active = true) => ({ Entries: entries.map(entry), Last, Active });

let addRule = vi.fn<(name: string) => void>();

function mount() {
  document.body.replaceChildren();
  addRule = vi.fn<(name: string) => void>();
  const screen = createQueries({ addRule: (name: string) => addRule(name) });
  document.body.append(screen.el);
  return screen;
}

const names = (el: HTMLElement) => [...el.querySelectorAll(".query .query-name")].map((n) => n.textContent);
const tick = () => vi.advanceTimersByTimeAsync(1000);
const settle = () => vi.advanceTimersByTimeAsync(0);

beforeEach(() => {
  vi.useFakeTimers();
  queries.mockReset();
  clearQueries.mockReset();
  clearQueries.mockResolvedValue(undefined);
  state.status = { Phase: "connected" };
});

afterEach(() => vi.useRealTimers());

describe("вкладка «Запросы»", () => {
  test("показ спрашивает журнал с нуля, новые записи сверху", async () => {
    queries.mockResolvedValue(page([{ Seq: 1, Name: "a.example.com" }, { Seq: 2, Name: "b.example.com", Rule: "example.com", Route: "direct" }], 2));
    const s = mount();
    s.onShow?.();
    await settle();
    expect(queries).toHaveBeenCalledWith(0);
    expect(names(s.el)).toEqual(["b.example.com", "a.example.com"]);
    const first = s.el.querySelector(".query")!;
    expect(first.querySelector(".query-route")!.textContent).toBe(S.queries.direct);
    expect(first.querySelector(".query-rule")!.textContent).toBe("example.com");
    expect(first.querySelector(".query-time")!.textContent).not.toBe("");
    expect(s.el.querySelectorAll(".query")[1].querySelector(".query-route")!.textContent).toBe(S.queries.tunnel);
  });

  test("больше двух адресов сворачиваются", async () => {
    queries.mockResolvedValue(page([{ Seq: 1, Name: "a.example.com", Addrs: ["203.0.113.1", "203.0.113.2", "203.0.113.3", "203.0.113.4"] }], 1));
    const s = mount();
    s.onShow?.();
    await settle();
    const addrs = s.el.querySelector<HTMLElement>(".query-addrs")!;
    expect(addrs.textContent).toContain("203.0.113.1");
    expect(addrs.textContent).toContain("203.0.113.2");
    expect(addrs.textContent).not.toContain("203.0.113.3");
    expect(addrs.textContent).toContain(S.queries.more(2));
    expect(addrs.title).toContain("203.0.113.4");
  });

  test("поздний ответ помечен", async () => {
    queries.mockResolvedValue(page([{ Seq: 1, Name: "a.example.com", Rule: "example.com", Late: true }], 1));
    const s = mount();
    s.onShow?.();
    await settle();
    expect(s.el.querySelector(".query-late")!.textContent).toBe(S.queries.late);
  });

  test("такт спрашивает с последнего номера и добавляет сверху", async () => {
    queries.mockResolvedValueOnce(page([{ Seq: 1, Name: "a.example.com" }], 1));
    queries.mockResolvedValueOnce(page([{ Seq: 2, Name: "b.example.com" }], 2));
    const s = mount();
    s.onShow?.();
    await settle();
    await tick();
    expect(queries).toHaveBeenLastCalledWith(1);
    expect(names(s.el)).toEqual(["b.example.com", "a.example.com"]);
  });

  test("служба перезапустилась: таблица начинается заново", async () => {
    queries.mockResolvedValueOnce(page([{ Seq: 10, Name: "old.example.com" }], 10));
    queries.mockResolvedValueOnce(page([], 2));
    queries.mockResolvedValueOnce(page([{ Seq: 1, Name: "new.example.com" }, { Seq: 2, Name: "new2.example.com" }], 2));
    const s = mount();
    s.onShow?.();
    await settle();
    await tick();
    await settle();
    expect(queries).toHaveBeenLastCalledWith(0);
    expect(names(s.el)).toEqual(["new2.example.com", "new.example.com"]);
  });

  test("скрытая вкладка останавливает опрос", async () => {
    queries.mockResolvedValue(page([], 0));
    const s = mount();
    s.onShow?.();
    await settle();
    s.el.hidden = true;
    await tick();
    const calls = queries.mock.calls.length;
    await tick();
    await tick();
    expect(queries.mock.calls.length).toBe(calls);
  });

  test("пока ответа нет, новый запрос не уходит", async () => {
    let answer!: (v: unknown) => void;
    queries.mockImplementationOnce(() => new Promise((r) => (answer = r)));
    const s = mount();
    s.onShow?.();
    await tick();
    await tick();
    expect(queries).toHaveBeenCalledTimes(1);
    answer(page([], 0));
    await settle();
  });

  test("фильтр по имени и «только с правилом»", async () => {
    queries.mockResolvedValue(page([
      { Seq: 1, Name: "Mail.Example.com", Rule: "example.com" },
      { Seq: 2, Name: "iana.org" },
    ], 2));
    const s = mount();
    s.onShow?.();
    await settle();
    const filter = s.el.querySelector<HTMLInputElement>("#queries-filter")!;
    filter.value = "mail.EX";
    filter.dispatchEvent(new Event("input"));
    expect(names(s.el)).toEqual(["Mail.Example.com"]);
    filter.value = "";
    filter.dispatchEvent(new Event("input"));
    const ruled = s.el.querySelector<HTMLInputElement>("#queries-ruled")!;
    ruled.checked = true;
    ruled.dispatchEvent(new Event("change"));
    expect(names(s.el)).toEqual(["Mail.Example.com"]);
    filter.value = "nothing";
    filter.dispatchEvent(new Event("input"));
    expect(s.el.querySelector(".queries-empty")!.textContent).toBe(S.queries.nothingFound);
  });

  test("«Добавить правило» передаёт имя строки", async () => {
    queries.mockResolvedValue(page([{ Seq: 1, Name: "www.example.com" }], 1));
    const s = mount();
    s.onShow?.();
    await settle();
    s.el.querySelector<HTMLButtonElement>(".query-add")!.click();
    expect(addRule).toHaveBeenCalledWith("www.example.com");
  });

  test("«Очистить» очищает журнал и таблицу", async () => {
    queries.mockResolvedValue(page([{ Seq: 1, Name: "www.example.com" }], 1));
    const s = mount();
    s.onShow?.();
    await settle();
    s.el.querySelector<HTMLButtonElement>(".queries-clear")!.click();
    await settle();
    expect(clearQueries).toHaveBeenCalledTimes(1);
    expect(s.el.querySelectorAll(".query")).toHaveLength(0);
  });

  test("пояснения, почему пусто", async () => {
    queries.mockResolvedValue(page([], 0, false));
    state.status = { Phase: "idle" };
    const s = mount();
    s.onShow?.();
    await settle();
    expect(s.el.querySelector(".queries-empty")!.textContent).toBe(S.queries.idle);

    state.status = { Phase: "connected" };
    await tick();
    expect(s.el.querySelector(".queries-empty")!.textContent).toBe(S.queries.noProxy);

    queries.mockResolvedValue(page([], 0, true));
    await tick();
    expect(s.el.querySelector(".queries-empty")!.textContent).toBe(S.queries.empty);
  });
});
