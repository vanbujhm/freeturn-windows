// @vitest-environment jsdom
// Экран маршрутизации: переключатель и режим уходят в SaveSettings, список правил не теряется.
import { beforeEach, describe, expect, test, vi } from "vitest";

const saved: unknown[] = [];
const saveSettings = vi.fn(async (s: unknown) => {
  saved.push(s);
});
const classify = vi.hoisted(() => vi.fn());

vi.mock("../api", () => ({
  API: { SaveSettings: (s: unknown) => saveSettings(s), ClassifyRule: (v: string) => classify(v), CheckAddress: vi.fn() },
  fail: vi.fn(),
  loadSettings: async () => {
    const { state, notify } = await import("../store");
    state.settings = saved.at(-1) as never;
    notify("settings");
  },
}));

import { notify, state } from "../store";
import * as S from "../strings";
import { createRules } from "./rules";

const initial = () =>
  ({
    Options: { KillSwitch: true, AllowLAN: true, Rules: [{ Kind: "domain", Value: "example.com" }] },
    Autostart: true,
    ConnectOnLaunch: false,
    LastProfileID: "p1",
  }) as never;

function mount(): HTMLElement {
  document.body.replaceChildren();
  const { el } = createRules();
  document.body.append(el);
  notify("settings");
  return el;
}

const q = <T extends HTMLElement>(el: HTMLElement, sel: string) => el.querySelector<T>(sel)!;
type Saved = { Options: { SplitOff: boolean; SplitMode: string; Rules: unknown[]; KillSwitch: boolean } };

beforeEach(() => {
  saved.length = 0;
  saveSettings.mockClear();
  saveSettings.mockImplementation(async (s: unknown) => {
    saved.push(s);
  });
  classify.mockReset();
  state.settings = initial();
  state.status = { Phase: "idle" };
});

describe("экран маршрутизации", () => {
  test("старые настройки: туннелирование включено, список идёт напрямую", () => {
    const el = mount();
    expect(q<HTMLInputElement>(el, "#rules-split").checked).toBe(true);
    expect(q<HTMLInputElement>(el, "#rules-mode-bypass").checked).toBe(true);
    expect(q<HTMLInputElement>(el, "#rules-mode-only").checked).toBe(false);
  });

  test("выключение сохраняет SplitOff и не трогает список", async () => {
    const el = mount();
    q<HTMLInputElement>(el, "#rules-split").click();
    await vi.waitFor(() => expect(saveSettings).toHaveBeenCalledTimes(1));
    const p = saved[0] as Saved;
    expect(p.Options.SplitOff).toBe(true);
    expect(p.Options.SplitMode).toBe("");
    expect(p.Options.Rules).toHaveLength(1);
    expect(p.Options.KillSwitch).toBe(true);
    await vi.waitFor(() => expect(q<HTMLInputElement>(el, "#rules-mode-only").disabled).toBe(true));
  });

  test("режим «Через VPN» сохраняет only и предупреждает о защите", async () => {
    const el = mount();
    q<HTMLInputElement>(el, "#rules-mode-only").click();
    await vi.waitFor(() => expect(saveSettings).toHaveBeenCalledTimes(1));
    const p = saved[0] as Saved;
    expect(p.Options.SplitMode).toBe("only");
    expect(p.Options.SplitOff).toBe(false);
    expect(p.Options.Rules).toHaveLength(1);
    await vi.waitFor(() => expect(q<HTMLInputElement>(el, "#rules-mode-only").checked).toBe(true));
    const warn = [...el.querySelectorAll<HTMLElement>(".warn-text")].find((n) => n.textContent === S.rules.modeOnlyKillSwitch);
    expect(warn?.hidden).toBe(false);
  });
});

type Rules = { Options: { Rules: { Kind: string; Value: string; Comment?: string; Off?: boolean }[] } };
const lastRules = () => (saved.at(-1) as Rules).Options.Rules;
const withRules = (rules: unknown[]) => {
  const s = initial() as unknown as Rules;
  s.Options.Rules = rules as never;
  state.settings = s as never;
};
const key = (el: HTMLElement, k: string) => el.dispatchEvent(new KeyboardEvent("keydown", { key: k }));

describe("карточка правила", () => {
  test("переключатель правила сохраняет Off", async () => {
    let release!: () => void;
    saveSettings.mockImplementation(
      (s: unknown) =>
        new Promise<void>((r) => {
          saved.push(s);
          release = r;
        }),
    );
    const el = mount();
    const toggle = q<HTMLInputElement>(el, ".rule .switch-input");
    expect(toggle.checked).toBe(true);
    toggle.click();
    await vi.waitFor(() => expect(saveSettings).toHaveBeenCalledTimes(1));
    expect(q<HTMLInputElement>(el, ".rule .switch-input").disabled).toBe(true);
    expect(lastRules()[0]).toMatchObject({ Kind: "domain", Value: "example.com", Off: true });
    release();
    await vi.waitFor(() => expect(q<HTMLInputElement>(el, ".rule .switch-input").disabled).toBe(false));
  });

  test("выключенное правило тусклое", () => {
    withRules([{ Kind: "ip", Value: "1.2.3.4", Off: true }]);
    const el = mount();
    expect(q(el, ".rule").classList.contains("dim")).toBe(true);
    expect(q<HTMLInputElement>(el, ".rule .switch-input").checked).toBe(false);
  });

  test("комментарий: Enter сохраняет", async () => {
    const el = mount();
    q<HTMLButtonElement>(el, ".rule-edit").click();
    const input = q<HTMLInputElement>(el, ".rule-comment-input");
    input.value = "дом";
    key(input, "Enter");
    await vi.waitFor(() => expect(saveSettings).toHaveBeenCalledTimes(1));
    expect(lastRules()[0].Comment).toBe("дом");
    await vi.waitFor(() => expect(q(el, ".rule-comment").textContent).toBe("дом"));
  });

  test("комментарий: Esc отменяет", () => {
    withRules([{ Kind: "ip", Value: "1.2.3.4", Comment: "старый" }]);
    const el = mount();
    q<HTMLButtonElement>(el, ".rule-edit").click();
    const input = q<HTMLInputElement>(el, ".rule-comment-input");
    input.value = "новый";
    key(input, "Escape");
    expect(saveSettings).not.toHaveBeenCalled();
    expect(el.querySelector(".rule-comment-input")).toBeNull();
    expect(q(el, ".rule-comment").textContent).toBe("старый");
  });

  test("ввод не теряется при перерисовке", () => {
    const el = mount();
    q<HTMLButtonElement>(el, ".rule-edit").click();
    q<HTMLInputElement>(el, ".rule-comment-input").value = "черновик";
    notify("status");
    expect(q<HTMLInputElement>(el, ".rule-comment-input").value).toBe("черновик");
  });

  test("пустой комментарий убирает строку", async () => {
    withRules([{ Kind: "ip", Value: "1.2.3.4", Comment: "x" }]);
    const el = mount();
    q<HTMLButtonElement>(el, ".rule-edit").click();
    const input = q<HTMLInputElement>(el, ".rule-comment-input");
    input.value = "  \n ";
    key(input, "Enter");
    await vi.waitFor(() => expect(saveSettings).toHaveBeenCalledTimes(1));
    expect(lastRules()[0].Comment).toBe("");
    await vi.waitFor(() => expect(el.querySelector(".rule-comment")).toBeNull());
  });

  test("добавление с комментарием", async () => {
    classify.mockResolvedValue({ Kind: "ip", Value: "1.2.3.4" });
    const el = mount();
    q<HTMLInputElement>(el, "#rules-value").value = "1.2.3.4";
    const comment = q<HTMLInputElement>(el, "#rules-comment");
    comment.value = "работа";
    key(comment, "Enter");
    await vi.waitFor(() => expect(saveSettings).toHaveBeenCalledTimes(1));
    expect(lastRules()[1]).toMatchObject({ Kind: "ip", Value: "1.2.3.4", Comment: "работа" });
    await vi.waitFor(() => expect(comment.value).toBe(""));
    expect(q<HTMLInputElement>(el, "#rules-value").value).toBe("");
  });

  test("удаление ищет правило по виду и значению", async () => {
    withRules([
      { Kind: "ip", Value: "1.2.3.4", Comment: "a" },
      { Kind: "domain", Value: "example.com" },
    ]);
    const el = mount();
    q<HTMLButtonElement>(el, ".rule .danger-text").click();
    await vi.waitFor(() => expect(saveSettings).toHaveBeenCalledTimes(1));
    expect(lastRules()).toEqual([{ Kind: "domain", Value: "example.com" }]);
  });
});
