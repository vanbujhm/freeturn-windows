// Настройки: четыре переключателя. Каждое нажатие сразу сохраняется.
import { API, fail, loadSettings } from "../api";
import { h } from "../dom";
import { type Screen, state, subscribe } from "../store";
import * as S from "../strings";

type Flag = "KillSwitch" | "AllowLAN" | "Autostart" | "ConnectOnLaunch";

interface Toggle {
  flag: Flag;
  title: string;
  hint: string;
}

const TOGGLES: Toggle[] = [
  { flag: "KillSwitch", title: S.settings.killSwitch, hint: S.settings.killSwitchHint },
  { flag: "AllowLAN", title: S.settings.allowLAN, hint: S.settings.allowLANHint },
  { flag: "Autostart", title: S.settings.autostart, hint: S.settings.autostartHint },
  { flag: "ConnectOnLaunch", title: S.settings.connectOnLaunch, hint: S.settings.connectOnLaunchHint },
];

export function createSettings(): Screen {
  const resetBanner = h("div", { class: "banner warn", hidden: true, text: S.settings.resetBanner });
  const notice = h("p", { class: "muted small-text", hidden: true, text: S.settings.appliesNext });
  const inputs = new Map<Flag, HTMLInputElement>();

  const rows = TOGGLES.map((t) => {
    const input = h("input", { type: "checkbox", class: "switch-input", id: `set-${t.flag}` });
    input.addEventListener("change", () => void change(t.flag, input));
    inputs.set(t.flag, input);
    return h(
      "label",
      { class: "card row between toggle", for: `set-${t.flag}` },
      h("div", { class: "stack tight" }, h("strong", { text: t.title }), h("span", { class: "muted small-text", text: t.hint })),
      h("span", { class: "switch" }, input, h("span", { class: "track" })),
    );
  });

  const el = h(
    "section",
    { class: "screen" },
    h("h2", { class: "screen-title", text: S.settings.title }),
    resetBanner,
    ...rows,
    notice,
  );

  async function change(flag: Flag, input: HTMLInputElement): Promise<void> {
    const cur = state.settings;
    if (!cur) return;
    const value = input.checked;
    const next = {
      ...cur,
      Autostart: flag === "Autostart" ? value : cur.Autostart,
      ConnectOnLaunch: flag === "ConnectOnLaunch" ? value : cur.ConnectOnLaunch,
      Options: {
        ...cur.Options,
        KillSwitch: flag === "KillSwitch" ? value : cur.Options.KillSwitch,
        AllowLAN: flag === "AllowLAN" ? value : cur.Options.AllowLAN,
      },
    };
    try {
      await API.SaveSettings(next);
      state.settingsReset = false;
    } catch (e) {
      fail(e);
    }
    // Что записалось на самом деле, показывает ответ службы, а не нажатие.
    await loadSettings().catch(() => {});
    render();
  }

  function render(): void {
    const s = state.settings;
    if (s) {
      inputs.get("KillSwitch")!.checked = s.Options.KillSwitch;
      inputs.get("AllowLAN")!.checked = s.Options.AllowLAN;
      inputs.get("Autostart")!.checked = s.Autostart;
      inputs.get("ConnectOnLaunch")!.checked = s.ConnectOnLaunch;
    }
    for (const input of inputs.values()) input.disabled = !s;
    resetBanner.hidden = !state.settingsReset;
    notice.hidden = !["connecting", "captcha", "connected", "reconnecting"].includes(state.status.Phase);
  }

  subscribe("settings", render);
  subscribe("banners", render);
  subscribe("status", render);
  render();
  return { el, onShow: render };
}
