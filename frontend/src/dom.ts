// Мелкие помощники для работы с DOM. Текст всегда уходит через textContent, innerHTML не
// используется, поэтому чужая строка не станет разметкой.
import { Clipboard } from "@wailsio/runtime";
import * as S from "./strings";

type Child = Node | string | null | undefined | false;
type Props = Record<string, unknown>;

// h создаёт элемент. Ключи on* становятся обработчиками, class задаёт класс, text текст,
// булевы значения включают и выключают атрибут, остальное записывается как атрибут.
export function h<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  props: Props = {},
  ...children: Child[]
): HTMLElementTagNameMap[K] {
  const el = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (value === undefined || value === null || value === false) continue;
    if (key === "class") el.className = String(value);
    else if (key === "text") el.textContent = String(value);
    else if (key.startsWith("on") && typeof value === "function") {
      el.addEventListener(key.slice(2), value as EventListener);
    } else if (value === true) el.setAttribute(key, "");
    else el.setAttribute(key, String(value));
  }
  for (const child of children) {
    if (child === null || child === undefined || child === false) continue;
    el.append(child);
  }
  return el;
}

const SVG_NS = "http://www.w3.org/2000/svg";

// icon рисует значок из путей viewBox 24x24: линии без заливки, цвет берётся из текста.
export function icon(...paths: string[]): SVGSVGElement {
  const svg = document.createElementNS(SVG_NS, "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("class", "icon");
  svg.setAttribute("aria-hidden", "true");
  for (const d of paths) {
    const p = document.createElementNS(SVG_NS, "path");
    p.setAttribute("d", d);
    svg.append(p);
  }
  return svg;
}

let toastBox: HTMLElement | null = null;

// toast показывает короткое сообщение внизу окна и убирает его само.
export function toast(text: string, kind: "info" | "error" = "info"): void {
  if (!toastBox) {
    toastBox = h("div", { class: "toasts", role: "status", "aria-live": "polite" });
    document.body.append(toastBox);
  }
  const el = h("div", { class: `toast ${kind}`, text });
  toastBox.append(el);
  window.setTimeout(() => el.remove(), kind === "error" ? 7000 : 3500);
}

interface ConfirmOptions {
  title: string;
  text: string;
  ok: string;
  danger?: boolean;
}

// confirmDialog спрашивает подтверждение. Системный confirm() в окне WebView не нужен.
export function confirmDialog(o: ConfirmOptions): Promise<boolean> {
  return new Promise((resolve) => {
    const previous = document.activeElement as HTMLElement | null;
    const close = (answer: boolean) => {
      document.removeEventListener("keydown", onKey);
      backdrop.remove();
      previous?.focus();
      resolve(answer);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") close(false);
    };
    const cancel = h("button", { class: "btn secondary", type: "button", text: S.profiles.cancel, onclick: () => close(false) });
    const ok = h("button", {
      class: `btn ${o.danger ? "danger" : "primary"}`,
      type: "button",
      text: o.ok,
      onclick: () => close(true),
    });
    const backdrop = h(
      "div",
      { class: "backdrop", onclick: (e: Event) => e.target === backdrop && close(false) },
      h(
        "div",
        { class: "modal", role: "dialog", "aria-modal": "true", "aria-label": o.title },
        h("h2", { text: o.title }),
        h("p", { text: o.text }),
        h("div", { class: "row end" }, cancel, ok),
      ),
    );
    document.addEventListener("keydown", onKey);
    document.body.append(backdrop);
    cancel.focus();
  });
}

// copyText кладёт текст в буфер обмена и сообщает человеку, получилось ли.
export async function copyText(text: string, doneMessage: string): Promise<void> {
  try {
    await Clipboard.SetText(text);
    toast(doneMessage);
  } catch {
    toast(S.profiles.copyFailed, "error");
  }
}
