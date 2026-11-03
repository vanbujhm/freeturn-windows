// @vitest-environment jsdom
// Экран настроек в минимальном DOM: нажатие должно уйти в SaveSettings с новым значением.
import { beforeEach, describe, expect, test, vi } from "vitest";

const saved: unknown[] = [];
const saveSettings = vi.fn(async (s: unknown) => {
  saved.push(s);
});

vi.mock("../api", () => ({
  API: { SaveSettings: (s: unknown) => saveSettings(s) },
  fail: vi.fn(),
  // Служба возвращает то, что записали.
  loadSettings: async () => {
    const { state, notify } = await import("../store");
    state.settings = saved.at(-1) as never;
    notify("settings");
  },
}));

import { notify, state } from "../store";
import { createSettings } from "./settings";

const initial = () =>
  ({
    Options: { KillSwitch: false, AllowLAN: true, Rules: [{ Kind: "domain", Value: "example.com" }] },
    Autostart: true,
    ConnectOnLaunch: false,
    LastProfileID: "p1",
  }) as never;

// mount кладёт экран в документ: jsdom шлёт change только подключённым элементам.
function mount(): HTMLElement {
  document.body.replaceChildren();
  const { el } = createSettings();
  document.body.append(el);
  notify("settings");
  return el;
}

const box = (el: HTMLElement, flag: string) => el.querySelector<HTMLInputElement>(`#set-${flag}`)!;

beforeEach(() => {
  saved.length = 0;
  saveSettings.mockClear();
  state.settings = initial();
  state.status = { Phase: "idle" };
});

describe("экран настроек", () => {
  test("включение kill switch сохраняет true и остаётся включённым", async () => {
    const el = mount();
    const input = box(el, "KillSwitch");
    expect(input.checked).toBe(false);

    input.click();
    await vi.waitFor(() => expect(saveSettings).toHaveBeenCalledTimes(1));

    const payload = saved[0] as { Options: { KillSwitch: boolean; AllowLAN: boolean; Rules: unknown[] } };
    expect(payload.Options.KillSwitch).toBe(true);
    // Остальное не тронуто.
    expect(payload.Options.AllowLAN).toBe(true);
    expect(payload.Options.Rules).toHaveLength(1);
    await vi.waitFor(() => expect(input.disabled).toBe(false));
    expect(input.checked).toBe(true);
  });

  test.each([
    ["AllowLAN", (s: any) => s.Options.AllowLAN, false],
    ["Autostart", (s: any) => s.Autostart, false],
    ["ConnectOnLaunch", (s: any) => s.ConnectOnLaunch, true],
  ])("переключатель %s сохраняет новое значение", async (flag, read, expected) => {
    const el = mount();
    box(el, flag).click();
    await vi.waitFor(() => expect(saveSettings).toHaveBeenCalledTimes(1));
    expect(read(saved[0])).toBe(expected);
  });

  test("пока запись идёт, переключатели недоступны", async () => {
    let release!: () => void;
    saveSettings.mockImplementationOnce(
      (s: unknown) =>
        new Promise<void>((r) => {
          saved.push(s);
          release = r;
        }),
    );
    const el = mount();
    box(el, "KillSwitch").click();
    await vi.waitFor(() => expect(box(el, "AllowLAN").disabled).toBe(true));
    release();
    await vi.waitFor(() => expect(box(el, "AllowLAN").disabled).toBe(false));
  });
});
