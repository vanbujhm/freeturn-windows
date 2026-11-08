// @vitest-environment jsdom
// Экран маршрутизации: переключатель и режим уходят в SaveSettings, список правил не теряется.
import { beforeEach, describe, expect, test, vi } from "vitest";

const saved: unknown[] = [];
const saveSettings = vi.fn(async (s: unknown) => {
  saved.push(s);
});

vi.mock("../api", () => ({
  API: { SaveSettings: (s: unknown) => saveSettings(s), ClassifyRule: vi.fn() },
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
