import { describe, expect, test } from "vitest";
import {
  describeApiError,
  describeError,
  describeFields,
  describeSkipReason,
  describeStatus,
  describeWarning,
  formatBytes,
  formatRate,
  toApiError,
  type Status,
} from "./state";
import * as S from "./strings";

const st = (s: Partial<Status>) => s as Status;

describe("describeStatus", () => {
  test("блокировка показывает причину и кнопку отключения", () => {
    const v = describeStatus(st({ Phase: "blocked", Code: "call_full" }));
    expect(v.title).toBe("Интернет заблокирован");
    expect(v.detail).toBe("В звонке нет свободных мест");
    expect(v.button).toBe("disconnect");
  });

  test.each([
    ["idle", "connect"],
    ["connecting", "disconnect"],
    ["captcha", "disconnect"],
    ["connected", "disconnect"],
    ["reconnecting", "disconnect"],
    ["error", "connect"],
    ["blocked", "disconnect"],
  ])("фаза %s: кнопка %s", (phase, button) => {
    const v = describeStatus(st({ Phase: phase }));
    expect(v.button).toBe(button);
    expect(v.title).not.toBe("");
  });

  test("блокировка без кода объясняет, что делать", () => {
    const v = describeStatus(st({ Phase: "blocked" }));
    expect(v.detail).not.toBe("");
  });

  test("ошибка берёт текст по коду", () => {
    const v = describeStatus(st({ Phase: "error", Code: "no_network" }));
    expect(v.detail).toBe("Нет подключения к интернету");
    expect(v.button).toBe("connect");
  });

  test("нет службы: кнопка ждёт возвращения службы", () => {
    const v = describeStatus(st({ Phase: "error", Code: "service_down" }));
    expect(v.detail).toBe("Служба FreeTurn не запущена, переустановите программу");
    expect(v.button).toBe("disabled");
  });

  test("неизвестная фаза и пустое состояние не роняют окно", () => {
    expect(describeStatus(st({})).button).toBe("disabled");
    expect(describeStatus(st({ Phase: "что-то новое" })).button).toBe("disabled");
  });

  test("неизвестный код: Detail из ядра", () => {
    const v = describeStatus(st({ Phase: "error", Code: "new_code", Detail: "текст ядра" }));
    expect(v.detail).toBe("текст ядра");
  });

  test("неизвестный код без Detail: запасной текст", () => {
    expect(describeError("new_code")).toBe(S.unknownError);
  });
});

describe("describeError", () => {
  test("fake-ip DNS дословно", () => {
    expect(describeError("fake_ip_dns")).toBe(
      "Clash или Mihomo в режиме TUN подменяет адреса. Выключите режим TUN и подключитесь снова.",
    );
  });

  test("ядро показывается своим текстом", () => {
    expect(describeError("core", "ядро упало")).toBe("ядро упало");
    expect(describeError("core")).toBe(S.errors.core);
  });

  test("адаптер добавляет описание", () => {
    expect(describeError("adapter", "нет прав")).toBe(`${S.errors.adapter}: нет прав`);
    expect(describeError("adapter")).toBe(S.errors.adapter);
  });

  test("у каждого ErrorCode и WarningCode есть непустой текст", () => {
    for (const [code, text] of Object.entries(S.errors)) {
      expect(text, code).not.toBe("");
      expect(describeError(code), code).not.toBe("");
    }
    for (const code of Object.keys(S.warnings)) {
      expect(describeWarning({ Code: code, Value: "x" }), code).not.toBe("");
      expect(describeWarning({ Code: code }), code).not.toBe("");
    }
  });
});

describe("describeWarning", () => {
  test("other_vpn называет программу", () => {
    expect(describeWarning({ Code: "other_vpn", Value: "AmneziaVPN" })).toContain("AmneziaVPN");
  });

  test("правило и домен называются в тексте", () => {
    expect(describeWarning({ Code: "rule_skipped", Value: "0.0.0.0/0" })).toContain("0.0.0.0/0");
    expect(describeWarning({ Code: "domain_unresolved", Value: "example.com" })).toContain("example.com");
  });

  test("неизвестный код не роняет окно", () => {
    expect(describeWarning({ Code: "new_warning", Value: "x" })).toContain("x");
    expect(describeWarning({ Code: "new_warning" })).toContain("new_warning");
  });
});

describe("причины пропуска правил", () => {
  test("известные и неизвестная", () => {
    for (const r of ["default_route", "too_wide", "invalid"]) {
      expect(describeSkipReason(r)).not.toBe(S.unknownSkipReason);
    }
    expect(describeSkipReason("новая")).toBe(S.unknownSkipReason);
  });
});

describe("ошибки API", () => {
  test("toApiError читает cause от Wails", () => {
    const e = Object.assign(new Error("x"), {
      cause: { code: "incomplete", message: "m", fields: ["callLink", "wgConfig"] },
    });
    expect(toApiError(e)).toEqual({ code: "incomplete", message: "m", fields: ["callLink", "wgConfig"] });
  });

  test("toApiError переживает чужие ошибки", () => {
    expect(toApiError(new Error("сеть")).code).toBe("");
    expect(toApiError(null).code).toBe("");
    expect(toApiError("строка").code).toBe("");
    expect(toApiError({ cause: 5 }).code).toBe("");
  });

  test("incomplete называет поля", () => {
    const text = describeApiError({ code: "incomplete", message: "", fields: ["callLink", "wgConfig"] });
    expect(text).toContain("ссылка на звонок");
    expect(text).toContain("конфиг WireGuard");
  });

  test("к bad_rule добавляется причина из службы", () => {
    const text = describeApiError({ code: "bad_rule", message: "шаблоны не поддерживаются", fields: [] });
    expect(text).toContain("шаблоны не поддерживаются");
  });

  test("bad_config показывается фразой службы", () => {
    expect(describeApiError({ code: "bad_config", message: "в конфиге должен быть ровно один пир", fields: [] })).toBe(
      "В конфиге должен быть ровно один пир",
    );
    expect(describeApiError({ code: "bad_config", message: "", fields: [] })).toBe(S.apiErrors.bad_config);
  });

  test("к busy причина не добавляется", () => {
    expect(describeApiError({ code: "busy", message: "engine: подключение уже идёт", fields: [] })).toBe(
      S.apiErrors.busy,
    );
  });

  test("неизвестный код: сообщение службы или запасной текст", () => {
    expect(describeApiError({ code: "new", message: "сообщение", fields: [] })).toBe("сообщение");
    expect(describeApiError({ code: "", message: "", fields: [] })).toBe(S.unknownApiError);
  });

  test("describeFields", () => {
    expect(describeFields(["wgConfig", "other"])).toBe("конфиг WireGuard, other");
  });
});

describe("форматирование", () => {
  test("байты", () => {
    expect(formatBytes(0)).toBe("0 Б");
    expect(formatBytes(512)).toBe("512 Б");
    expect(formatBytes(1536)).toBe("1,5 КБ");
    expect(formatBytes(1024 * 1024)).toBe("1 МБ");
    expect(formatBytes(15 * 1024 * 1024)).toBe("15 МБ");
    expect(formatBytes(-5)).toBe("0 Б");
  });

  test("скорость", () => {
    expect(formatRate(2048)).toBe("2 КБ/с");
  });
});
