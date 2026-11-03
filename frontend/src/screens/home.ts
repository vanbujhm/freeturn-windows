// Главный экран: большая кнопка, состояние, выбор профиля, скорость и предупреждения.
import { Browser } from "@wailsio/runtime";
import { API, errorText, fail } from "../api";
import { h, icon, toast } from "../dom";
import { describeStatus, describeWarning, formatRate, toApiError, type StatusView } from "../state";
import { type Goto, type Screen, state, subscribe } from "../store";
import * as S from "../strings";

const POWER = ["M12 3v8", "M6.3 6.8a8 8 0 1 0 11.4 0"];

// PENDING_LIMIT_MS: дольше кнопка не ждёт смены состояния после нажатия.
const PENDING_LIMIT_MS = 10_000;

export function createHome(goto: Goto): Screen {
  let pending = false;
  let pendingPhase = "";
  let pendingTimer = 0;
  // Каждое нажатие получает свой номер: release прежнего нажатия не трогает таймер нового.
  let pendingToken = 0;
  let view: StatusView = describeStatus(state.status);

  const updateText = h("span", { class: "grow" });
  const updateBtn = h("button", { class: "btn small primary", type: "button", text: S.home.updateOpen });
  const updateBanner = h("div", { class: "banner info", hidden: true }, updateText, updateBtn);
  updateBtn.addEventListener("click", () => {
    const url = state.update?.URL ?? "";
    if (/^https:\/\//i.test(url)) void Browser.OpenURL(url).catch(fail);
  });

  const select = h("select", { class: "select", "aria-label": S.home.chooseProfile });
  select.addEventListener("change", () => {
    state.selectedId = select.value;
  });
  const selectBox = h("label", { class: "field" }, h("span", { class: "label", text: S.home.chooseProfile }), select);
  const addProfile = h("button", {
    class: "btn secondary",
    type: "button",
    text: S.home.addProfile,
    onclick: () => goto("profiles"),
  });
  const emptyBox = h(
    "div",
    { class: "card stack center", hidden: true },
    h("strong", { text: S.home.noProfiles }),
    h("p", { class: "muted", text: S.home.noProfilesHint }),
    addProfile,
  );

  const label = h("span", { class: "power-label" });
  const power = h("button", { class: "power", type: "button" }, icon(...POWER), label);
  power.addEventListener("click", () => void onPower());

  const title = h("h1", { class: "state-title" });
  const detail = h("p", { class: "state-detail" });
  const hint = h("p", { class: "muted center-text", hidden: true, text: S.blockedHint });

  const rxValue = h("strong");
  const txValue = h("strong");
  const streamsValue = h("strong");
  const stats = h(
    "div",
    { class: "stats", hidden: true },
    h("div", { class: "stat" }, h("span", { class: "label", text: S.home.down }), rxValue),
    h("div", { class: "stat" }, h("span", { class: "label", text: S.home.up }), txValue),
    h("div", { class: "stat" }, h("span", { class: "label", text: S.home.streams }), streamsValue),
  );

  const captchaBtn = h("button", {
    class: "btn secondary",
    type: "button",
    hidden: true,
    text: S.home.openCaptcha,
    onclick: () => void API.OpenCaptchaInBrowser().catch(fail),
  });
  const diagBtn = h("button", {
    class: "btn secondary",
    type: "button",
    hidden: true,
    text: S.home.saveDiagnostics,
    onclick: () => void saveDiagnostics(),
  });
  const warnings = h("div", { class: "warnings", hidden: true });

  const el = h(
    "section",
    { class: "screen home" },
    updateBanner,
    selectBox,
    emptyBox,
    h("div", { class: "hero" }, power, title, detail, hint),
    stats,
    h("div", { class: "actions" }, captchaBtn, diagBtn),
    warnings,
  );

  async function onPower(): Promise<void> {
    if (pending || view.button === "disabled") return;
    // Кнопка остаётся занятой, пока фаза не сменится или не пройдёт PENDING_LIMIT_MS: так
    // она не мигает активной между ответом на вызов и событием состояния.
    pending = true;
    pendingPhase = state.status.Phase;
    const token = ++pendingToken;
    pendingTimer = window.setTimeout(() => release(token), PENDING_LIMIT_MS);
    render();
    try {
      if (view.button === "disconnect") {
        await API.Disconnect();
      } else {
        if (!state.selectedId) {
          release(token);
          toast(S.home.noProfiles, "error");
          goto("profiles");
          return;
        }
        await API.Connect(state.selectedId);
      }
    } catch (e) {
      release(token);
      toast(errorText(e), "error");
      if (toApiError(e).code === "incomplete") goto("profiles");
    }
  }

  // release снимает занятость кнопки, если нажатие с этим номером ещё последнее.
  function release(token: number): void {
    if (token !== pendingToken) return;
    window.clearTimeout(pendingTimer);
    pending = false;
    render();
  }

  async function saveDiagnostics(): Promise<void> {
    try {
      toast(S.journal.savedTo(await API.SaveDiagnostics()));
    } catch (e) {
      fail(e);
    }
  }

  function renderProfiles(): void {
    const has = state.profiles.length > 0;
    emptyBox.hidden = has;
    selectBox.hidden = !has;
    select.replaceChildren(
      ...state.profiles.map((p) => {
        const opt = h("option", { value: p.ID, text: p.Name || S.profiles.unnamed });
        opt.selected = p.ID === state.selectedId;
        return opt;
      }),
    );
    renderPower();
  }

  function renderPower(): void {
    const s = state.status;
    const busyPhase = s.Phase !== "idle" && s.Phase !== "error" && s.Phase !== "";
    // Пока туннель работает, выбирать другой профиль нельзя.
    select.disabled = busyPhase;
    select.value = state.selectedId;
    power.dataset.phase = s.Phase || "unknown";
    power.disabled = view.button === "disabled" || pending || (view.button === "connect" && state.profiles.length === 0);
    label.textContent = view.button === "disconnect" ? S.home.disconnect : S.home.connect;
    power.setAttribute("aria-label", label.textContent);
  }

  function render(): void {
    const s = state.status;
    if (pending && s.Phase !== pendingPhase) {
      window.clearTimeout(pendingTimer);
      pending = false;
    }
    view = describeStatus(s);
    title.textContent = view.title;
    detail.textContent = view.detail;
    hint.hidden = s.Phase !== "blocked";

    const live = s.Phase === "connected" || s.Phase === "reconnecting";
    stats.hidden = !live;
    rxValue.textContent = formatRate(s.RxRate ?? 0);
    txValue.textContent = formatRate(s.TxRate ?? 0);
    streamsValue.textContent = S.home.streamsOf(s.Streams ?? 0, s.Total ?? 0);

    captchaBtn.hidden = s.Phase !== "captcha";
    const failed = (s.Phase === "error" && s.Code !== "service_down") || s.Phase === "blocked";
    diagBtn.hidden = !failed;

    const list = s.Warnings ?? [];
    warnings.hidden = list.length === 0 || s.Phase === "idle";
    warnings.replaceChildren(...list.map((w) => h("div", { class: "banner warn", text: describeWarning(w) })));

    renderPower();
  }

  function renderUpdate(): void {
    const info = state.update;
    updateBanner.hidden = !info;
    if (info) updateText.textContent = S.home.updateAvailable(info.Version ?? "");
  }

  subscribe("status", render);
  subscribe("profiles", renderProfiles);
  subscribe("settings", renderProfiles);
  subscribe("update", renderUpdate);
  render();
  renderProfiles();
  return { el, onShow: renderProfiles };
}
