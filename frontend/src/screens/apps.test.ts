// @vitest-environment jsdom
// Раздел «Только через VPN»: выбор программы, переключатель, удаление, комментарий.
import { beforeEach, describe, expect, test, vi } from "vitest";

const pickApp = vi.hoisted(() => vi.fn());
const toast = vi.hoisted(() => vi.fn());

vi.mock("../api", () => ({
  API: { PickApp: () => pickApp() },
  fail: vi.fn(),
}));

vi.mock("../dom", async (orig) => ({ ...(await orig<typeof import("../dom")>()), toast: (...a: unknown[]) => toast(...a) }));

import { state } from "../store";
import * as S from "../strings";
import { createApps, type SaveControl } from "./apps";

type App = { Path: string; Comment?: string; Off?: boolean };
type Saved = { Options: { Apps: App[]; KillSwitch: boolean } };

const appPath = "C:\\Apps\\App.exe";
let busy = false;
let view: { el: HTMLElement; render(): void };
const saved: Saved[] = [];
const ctl: SaveControl = {
  busy: () => busy,
  async exclusive(fn) {
    if (busy) return;
    busy = true;
    view.render();
    try {
      await fn();
    } finally {
      busy = false;
      view.render();
    }
  },
  save: vi.fn(async (next) => {
    saved.push(next as never);
    state.settings = next;
    return true;
  }),
};

function withApps(apps: App[]): void {
  state.settings = { Options: { KillSwitch: true, AllowLAN: true, Rules: [], Apps: apps }, Autostart: false } as never;
}

function mount(): HTMLElement {
  document.body.replaceChildren();
  view = createApps(ctl);
  document.body.append(view.el);
  view.render();
  return view.el;
}

const q = <T extends HTMLElement>(el: HTMLElement, sel: string) => el.querySelector<T>(sel)!;
const lastApps = () => saved.at(-1)!.Options.Apps;

beforeEach(() => {
  busy = false;
  saved.length = 0;
  vi.mocked(ctl.save).mockClear();
  pickApp.mockReset();
  toast.mockReset();
  state.status = { Phase: "idle" };
  withApps([]);
});

describe("раздел «Только через VPN»", () => {
  test("пустой список и подсказки", () => {
    const el = mount();
    expect(q(el, ".apps-empty").textContent).toBe(S.apps.empty);
    const hints = [...el.querySelectorAll(".apps-hint p")].map((p) => p.textContent);
    expect(hints).toEqual(S.apps.hint);
  });

  test("карточка показывает имя файла и путь, выключенная тусклая", () => {
    withApps([{ Path: appPath }, { Path: "D:\\Games\\game.exe", Off: true }]);
    const el = mount();
    const cards = el.querySelectorAll<HTMLElement>(".app");
    expect(cards).toHaveLength(2);
    expect(q(cards[0], ".app-name").textContent).toBe("App.exe");
    expect(q(cards[0], ".app-path").textContent).toBe(appPath);
    expect(cards[0].classList.contains("dim")).toBe(false);
    expect(cards[1].classList.contains("dim")).toBe(true);
    expect(q<HTMLInputElement>(cards[1], ".switch-input").checked).toBe(false);
  });

  test("добавление через выбор файла", async () => {
    pickApp.mockResolvedValue(appPath);
    const el = mount();
    q<HTMLButtonElement>(el, ".apps-add").click();
    await vi.waitFor(() => expect(ctl.save).toHaveBeenCalledTimes(1));
    expect(lastApps()).toEqual([{ Path: appPath, Comment: "", Off: false }]);
    await vi.waitFor(() => expect(toast).toHaveBeenCalledWith(S.apps.added));
    await vi.waitFor(() => expect(el.querySelectorAll(".app")).toHaveLength(1));
  });

  test("отмена выбора ничего не записывает", async () => {
    pickApp.mockResolvedValue("");
    const el = mount();
    q<HTMLButtonElement>(el, ".apps-add").click();
    await vi.waitFor(() => expect(pickApp).toHaveBeenCalledTimes(1));
    await vi.waitFor(() => expect(q<HTMLButtonElement>(el, ".apps-add").disabled).toBe(false));
    expect(ctl.save).not.toHaveBeenCalled();
    expect(toast).not.toHaveBeenCalled();
  });

  test("повтор в другом регистре не добавляется", async () => {
    withApps([{ Path: appPath }]);
    pickApp.mockResolvedValue("c:\\apps\\app.exe");
    const el = mount();
    q<HTMLButtonElement>(el, ".apps-add").click();
    await vi.waitFor(() => expect(toast).toHaveBeenCalledWith(S.apps.duplicate, "error"));
    expect(ctl.save).not.toHaveBeenCalled();
  });

  test("переключатель выключает только свою программу", async () => {
    withApps([{ Path: appPath }, { Path: "D:\\Games\\game.exe" }]);
    const el = mount();
    q<HTMLInputElement>(el, ".app .switch-input").click();
    await vi.waitFor(() => expect(ctl.save).toHaveBeenCalledTimes(1));
    expect(lastApps()[0]).toMatchObject({ Path: appPath, Off: true });
    expect(lastApps()[1].Off ?? false).toBe(false);
  });

  test("удаление", async () => {
    withApps([{ Path: appPath }, { Path: "D:\\Games\\game.exe" }]);
    const el = mount();
    q<HTMLButtonElement>(el, ".app .danger-text").click();
    await vi.waitFor(() => expect(ctl.save).toHaveBeenCalledTimes(1));
    expect(lastApps().map((a) => a.Path)).toEqual(["D:\\Games\\game.exe"]);
  });

  test("комментарий: Enter сохраняет", async () => {
    withApps([{ Path: appPath }]);
    const el = mount();
    q<HTMLButtonElement>(el, ".app .rule-edit").click();
    const input = q<HTMLInputElement>(el, ".rule-comment-input");
    input.value = " игра ";
    input.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter" }));
    await vi.waitFor(() => expect(ctl.save).toHaveBeenCalledTimes(1));
    expect(lastApps()[0].Comment).toBe("игра");
    await vi.waitFor(() => expect(q(el, ".app .rule-comment").textContent).toBe("игра"));
  });

  test("пока идёт запись, кнопки недоступны и выбор не открывается", () => {
    withApps([{ Path: appPath }]);
    busy = true;
    const el = mount();
    expect(q<HTMLButtonElement>(el, ".apps-add").disabled).toBe(true);
    expect(q<HTMLInputElement>(el, ".app .switch-input").disabled).toBe(true);
    q<HTMLButtonElement>(el, ".apps-add").click();
    expect(pickApp).not.toHaveBeenCalled();
  });
});
