// Тонкая обёртка над привязками Wails: загрузка данных в общее состояние и перевод ошибок
// в текст. Привязки сгенерированы (npm run bindings) и в git не лежат. Ответы в консоль не
// выводятся: в них бывают данные профилей.
import { API } from "../bindings/github.com/vanbujhm/freeturn-windows/cmd/freeturn/index.js";
import { describeApiError, toApiError } from "./state";
import { loadStatusWith, notify, reconcileSelection, serial, state } from "./store";
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

// Чтения настроек идут по очереди: ответ, запрошенный раньше, не придёт после более нового.
const settingsQueue = serial();

export function loadSettings(): Promise<void> {
  return settingsQueue(async () => {
    state.settings = await API.Settings();
    reconcileSelection();
    notify("settings");
  });
}

// Ответ Status не затирает событие, пришедшее за время запроса (см. loadStatusWith).
export function loadStatus(): Promise<void> {
  return loadStatusWith(() => API.Status());
}

export async function loadBanners(): Promise<void> {
  const [corrupt, reset] = await Promise.all([API.ProfilesCorrupt(), API.SettingsReset()]);
  state.corrupt = corrupt;
  state.settingsReset = reset;
  notify("banners");
}
