// Профили: импорт по ссылке с подтверждением, список, дополнение недостающих полей, удаление.
import { Clipboard } from "@wailsio/runtime";
import type { ImportPreview, ProfileView } from "../../bindings/github.com/vanbujhm/freeturn-windows/cmd/freeturn/index.js";
import { API, fail, loadBanners, loadProfiles, loadSettings } from "../api";
import { confirmDialog, copyText, h, toast } from "../dom";
import { describeFields } from "../state";
import { type Screen, state, subscribe } from "../store";
import * as S from "../strings";

export function createProfiles(): Screen {
  // Профили, у которых раскрыто «Изменить»: список перестраивается, а выбор остаётся.
  const opened = new Set<string>();
  let preview: ImportPreview | null = null;
  let busy = false;

  const corruptBox = h("div", { class: "banner bad stack", hidden: true });
  const previewBox = h("div", { class: "card stack", hidden: true });
  const linkInput = h("input", {
    class: "input",
    type: "text",
    placeholder: S.profiles.placeholder,
    autocomplete: "off",
    spellcheck: "false",
    "aria-label": S.profiles.placeholder,
  });
  const checkBtn = h("button", { class: "btn secondary", type: "button", text: S.profiles.check });
  const pasteBtn = h("button", { class: "btn primary block", type: "button", text: S.profiles.paste });
  const list = h("div", { class: "stack" });

  const importCard = h(
    "div",
    { class: "card stack" },
    h("h2", { text: S.profiles.importTitle }),
    pasteBtn,
    h("div", { class: "row" }, linkInput, checkBtn),
  );

  const el = h(
    "section",
    { class: "screen" },
    h("h2", { class: "screen-title", text: S.profiles.title }),
    corruptBox,
    previewBox,
    importCard,
    list,
  );

  pasteBtn.addEventListener("click", () => void pasteFromClipboard());
  checkBtn.addEventListener("click", () => void checkLink(linkInput.value));
  linkInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter") void checkLink(linkInput.value);
  });

  async function pasteFromClipboard(): Promise<void> {
    let text = "";
    try {
      text = await Clipboard.Text();
    } catch {
      toast(S.profiles.clipboardFailed, "error");
      return;
    }
    if (!text.trim()) {
      toast(S.profiles.clipboardEmpty, "error");
      return;
    }
    await checkLink(text);
  }

  async function checkLink(raw: string): Promise<void> {
    if (!raw.trim() || busy) return;
    busy = true;
    try {
      preview = await API.PreviewLink(raw);
      linkInput.value = "";
      renderPreview();
    } catch (e) {
      fail(e);
    } finally {
      busy = false;
    }
  }

  async function confirmImport(): Promise<void> {
    if (!preview || busy) return;
    busy = true;
    try {
      await API.ConfirmImport(preview.Token);
      preview = null;
      renderPreview();
      toast(S.profiles.added);
      await loadProfiles();
    } catch (e) {
      fail(e);
      await loadBanners().catch(() => {});
    } finally {
      busy = false;
    }
  }

  function renderPreview(): void {
    previewBox.hidden = !preview;
    if (!preview) {
      previewBox.replaceChildren();
      return;
    }
    const p = preview;
    queueMicrotask(() => previewBox.scrollIntoView({ block: "nearest" }));
    const parts: (Node | null)[] = [
      h("h2", { text: S.profiles.previewTitle }),
      row(S.profiles.previewName, p.Name || S.profiles.unnamed),
      row(S.profiles.previewPeer, p.Peer),
      h("p", {
        class: p.Missing.length ? "muted" : "ok-text",
        text: p.Missing.length ? S.profiles.previewMissing(describeFields(p.Missing)) : S.profiles.previewComplete,
      }),
      p.GeneratedClientID ? clientIdBlock(p.GeneratedClientID) : null,
      h(
        "div",
        { class: "row end" },
        h("button", {
          class: "btn secondary",
          type: "button",
          text: S.profiles.cancel,
          onclick: () => {
            preview = null;
            renderPreview();
          },
        }),
        h("button", { class: "btn primary", type: "button", text: S.profiles.add, onclick: () => void confirmImport() }),
      ),
    ];
    previewBox.replaceChildren(...parts.filter((n): n is Node => n !== null));
  }

  function row(name: string, value: string): HTMLElement {
    return h("div", { class: "kv" }, h("span", { class: "label", text: name }), h("span", { class: "value", text: value }));
  }

  function clientIdBlock(id: string): HTMLElement {
    return h(
      "div",
      { class: "callout stack" },
      h("span", { class: "label", text: S.profiles.generatedId }),
      h(
        "div",
        { class: "row" },
        h("code", { class: "code grow", text: id }),
        h("button", {
          class: "btn secondary small",
          type: "button",
          text: S.profiles.copy,
          onclick: () => void copyText(id, S.profiles.copied),
        }),
      ),
      h("p", { class: "muted small-text", text: S.profiles.generatedIdHint }),
    );
  }

  function renderBanner(): void {
    corruptBox.hidden = !state.corrupt;
    if (!state.corrupt) return;
    corruptBox.replaceChildren(
      h("strong", { text: S.profiles.corruptTitle }),
      h("span", { text: S.profiles.corruptText }),
      h("button", {
        class: "btn danger",
        type: "button",
        text: S.profiles.corruptReset,
        onclick: () => void resetProfiles(),
      }),
    );
  }

  async function resetProfiles(): Promise<void> {
    try {
      await API.ResetProfiles();
      toast(S.profiles.resetDone);
      await loadBanners();
      await loadProfiles();
    } catch (e) {
      fail(e);
    }
  }

  function renderList(): void {
    if (state.profiles.length === 0) {
      list.replaceChildren(h("p", { class: "muted center-text", text: S.profiles.empty }));
      return;
    }
    list.replaceChildren(...state.profiles.map(profileCard));
  }

  function profileCard(p: ProfileView): HTMLElement {
    const missing = p.Missing ?? [];
    const name = p.Name || S.profiles.unnamed;

    const details = h("details", { class: "edit" }, h("summary", { text: S.profiles.edit }));
    details.open = opened.has(p.ID) || missing.length > 0;
    details.addEventListener("toggle", () => {
      if (details.open) opened.add(p.ID);
      else opened.delete(p.ID);
    });
    if (p.Provider !== "direct") details.append(callLinkEditor(p));
    details.append(wgEditor(p));

    return h(
      "div",
      { class: "card stack" },
      h(
        "div",
        { class: "row between" },
        h("strong", { class: "profile-name", text: name }),
        p.Provider ? h("span", { class: "badge", text: p.Provider }) : null,
      ),
      p.Peer ? h("span", { class: "muted mono", text: p.Peer }) : null,
      h("span", {
        class: missing.length ? "warn-text" : "ok-text",
        text: missing.length ? S.profiles.missing(describeFields(missing)) : S.profiles.complete,
      }),
      p.GeneratedClientID && p.ClientID ? clientIdBlock(p.ClientID) : null,
      details,
      h("div", { class: "row end" }, h("button", {
        class: "btn danger-text",
        type: "button",
        text: S.profiles.delete,
        onclick: () => void removeProfile(p, name),
      })),
    );
  }

  function callLinkEditor(p: ProfileView): HTMLElement {
    const input = h("input", {
      class: "input",
      type: "text",
      placeholder: S.profiles.callLinkPlaceholder,
      autocomplete: "off",
      spellcheck: "false",
      "aria-label": S.profiles.callLink,
    });
    const save = async () => {
      if (!input.value.trim()) return;
      try {
        await API.SetCallLink(p.ID, input.value);
        input.value = "";
        toast(S.profiles.saved);
        await loadProfiles();
      } catch (e) {
        fail(e);
      }
    };
    return h(
      "div",
      { class: "stack" },
      h("span", { class: "label", text: S.profiles.callLink }),
      h("div", { class: "row" }, input, h("button", { class: "btn secondary", type: "button", text: S.profiles.save, onclick: () => void save() })),
    );
  }

  function wgEditor(p: ProfileView): HTMLElement {
    const area = h("textarea", {
      class: "input mono",
      rows: 5,
      placeholder: S.profiles.wgPlaceholder,
      spellcheck: "false",
      "aria-label": S.profiles.wgConfig,
    });
    const file = h("input", { type: "file", accept: ".conf,text/plain", hidden: true });
    file.addEventListener("change", async () => {
      const f = file.files?.[0];
      if (!f) return;
      try {
        area.value = await f.text();
      } catch {
        toast(S.profiles.fileFailed, "error");
      }
      file.value = "";
    });
    const save = async () => {
      if (!area.value.trim()) return;
      try {
        await API.SetWGConfig(p.ID, area.value);
        area.value = "";
        toast(S.profiles.saved);
        await loadProfiles();
      } catch (e) {
        fail(e);
      }
    };
    return h(
      "div",
      { class: "stack" },
      h("span", { class: "label", text: S.profiles.wgConfig }),
      area,
      file,
      h(
        "div",
        { class: "row" },
        h("button", { class: "btn secondary", type: "button", text: S.profiles.pickFile, onclick: () => file.click() }),
        h("button", { class: "btn secondary", type: "button", text: S.profiles.save, onclick: () => void save() }),
      ),
    );
  }

  async function removeProfile(p: ProfileView, name: string): Promise<void> {
    const sure = await confirmDialog({
      title: S.profiles.deleteTitle,
      text: S.profiles.deleteText(name),
      ok: S.profiles.delete,
      danger: true,
    });
    if (!sure) return;
    try {
      await API.DeleteProfile(p.ID);
      opened.delete(p.ID);
      toast(S.profiles.deleted);
      await loadProfiles();
      await loadSettings();
    } catch (e) {
      fail(e);
    }
  }

  // Превью ссылки, пришедшей при запуске или от второго экземпляра, показывается здесь же.
  function takeImport(): void {
    if (!state.import) return;
    preview = state.import;
    state.import = null;
    renderPreview();
  }

  subscribe("profiles", renderList);
  subscribe("banners", renderBanner);
  subscribe("import", takeImport);
  renderList();
  renderBanner();
  takeImport();
  return { el };
}
