// Тонкая обёртка над привязками Wails: загрузка данных в общее состояние и перевод ошибок
// в текст. Привязки сгенерированы (npm run bindings) и в git не лежат. Ответы в консоль не
// выводятся: в них бывают данные профилей.
import { API } from "../bindings/github.com/vanbujhm/freeturn-windows/cmd/freeturn/index.js";
import { describeApiError, toApiError } from "./state";
import { notify, reconcileSelection, state } from "./store";
import { toast } from "./dom";

export { API };

// errorText возвращает текст ошибки вызова привязки.
export function errorText(e: unknown): string {
  return describeApiError(toApiError(e));
}

// fail показывает ошибку вызова всплывающим сообщением.
export function fail(e: unknown): void {
  toast(errorText(e), "error");
}

export async function loadProfiles(): Promise<void> {
  state.profiles = await API.ListProfiles();
  reconcileSelection();
  notify("profiles");
}

export async function loadSettings(): Promise<void> {
  state.settings = await API.Settings();
  reconcileSelection();
  notify("settings");
}

export async function loadStatus(): Promise<void> {
  state.status = await API.Status();
  reconcileSelection();
  notify("status");
}

export async function loadBanners(): Promise<void> {
  const [corrupt, reset] = await Promise.all([API.ProfilesCorrupt(), API.SettingsReset()]);
  state.corrupt = corrupt;
  state.settingsReset = reset;
  notify("banners");
}
