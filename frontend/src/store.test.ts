import { beforeEach, describe, expect, test } from "vitest";
import {
  LatestGuard,
  MAX_LOG_LINES,
  loadStatusWith,
  mergeLogs,
  pushLog,
  reconcileSelection,
  serial,
  setStatusFromEvent,
  setUpdate,
  state,
  subscribe,
} from "./store";
import type { Status } from "./state";

const profile = (id: string) => ({ ID: id, Name: id }) as never;

beforeEach(() => {
  state.status = { Phase: "" };
  state.profiles = [];
  state.settings = null;
  state.selectedId = "";
  state.logs = [];
  state.logTotal = 0;
  state.update = null;
});

// deferred даёт ответ, который тест выдаёт сам, когда захочет.
function deferred<T>() {
  let resolve!: (v: T) => void;
  const promise = new Promise<T>((r) => (resolve = r));
  return { promise, resolve };
}

describe("pushLog", () => {
  test("журнал не длиннее MAX_LOG_LINES, старые строки уходят", () => {
    for (let i = 0; i < MAX_LOG_LINES + 25; i++) pushLog(`строка ${i}`);
    expect(state.logs).toHaveLength(MAX_LOG_LINES);
    expect(state.logs[0]).toBe("строка 25");
    expect(state.logs.at(-1)).toBe(`строка ${MAX_LOG_LINES + 24}`);
    expect(state.logTotal).toBe(MAX_LOG_LINES + 25);
  });
});

describe("mergeLogs", () => {
  test("строки события не удваиваются и порядок сохраняется", () => {
    state.logs = ["b", "c"];
    mergeLogs(["a", "b"]);
    expect(state.logs).toEqual(["a", "b", "c"]);
  });

  test("прочитанное у службы тоже ограничено по длине", () => {
    const read = Array.from({ length: MAX_LOG_LINES + 50 }, (_, i) => `r${i}`);
    mergeLogs(read);
    expect(state.logs).toHaveLength(MAX_LOG_LINES);
    expect(state.logs[0]).toBe("r50");
  });
});

describe("reconcileSelection", () => {
  test("первый профиль, если ничего не выбрано", () => {
    state.profiles = [profile("a"), profile("b")];
    reconcileSelection();
    expect(state.selectedId).toBe("a");
  });

  test("профиль последнего подключения важнее первого", () => {
    state.profiles = [profile("a"), profile("b")];
    state.settings = { LastProfileID: "b" } as never;
    reconcileSelection();
    expect(state.selectedId).toBe("b");
  });

  test("выбор человека сохраняется, пока профиль есть", () => {
    state.profiles = [profile("a"), profile("b")];
    state.selectedId = "b";
    reconcileSelection();
    expect(state.selectedId).toBe("b");
  });

  test("удалённый профиль заменяется", () => {
    state.profiles = [profile("a")];
    state.selectedId = "gone";
    reconcileSelection();
    expect(state.selectedId).toBe("a");
  });

  test("нет профилей: выбор пуст", () => {
    state.selectedId = "gone";
    reconcileSelection();
    expect(state.selectedId).toBe("");
  });

  test("при активном подключении выбран подключённый профиль", () => {
    state.profiles = [profile("a"), profile("b")];
    state.selectedId = "a";
    state.status = { Phase: "connected", ProfileID: "b" };
    reconcileSelection();
    expect(state.selectedId).toBe("b");
  });

  test("после ошибки выбор остаётся за человеком", () => {
    state.profiles = [profile("a"), profile("b")];
    state.selectedId = "a";
    state.status = { Phase: "error", ProfileID: "b" };
    reconcileSelection();
    expect(state.selectedId).toBe("a");
  });
});

describe("состояние: старый ответ не затирает новое", () => {
  test("событие, пришедшее за время запроса, остаётся", async () => {
    const d = deferred<Status>();
    const load = loadStatusWith(() => d.promise);
    setStatusFromEvent({ Phase: "connected" });
    d.resolve({ Phase: "idle" });
    await load;
    expect(state.status.Phase).toBe("connected");
  });

  test("без событий ответ применяется", async () => {
    await loadStatusWith(async () => ({ Phase: "idle" }));
    expect(state.status.Phase).toBe("idle");
  });

  test("событие до запроса не мешает ответу", async () => {
    setStatusFromEvent({ Phase: "connecting" });
    await loadStatusWith(async () => ({ Phase: "connected" }));
    expect(state.status.Phase).toBe("connected");
  });

  test("запрос, вернувшийся позже более нового, отбрасывается", async () => {
    const older = deferred<Status>();
    const newer = deferred<Status>();
    const a = loadStatusWith(() => older.promise);
    const b = loadStatusWith(() => newer.promise);
    newer.resolve({ Phase: "connected" });
    await b;
    older.resolve({ Phase: "idle" });
    await a;
    expect(state.status.Phase).toBe("connected");
  });
});

describe("LatestGuard", () => {
  test("ответ применяется один раз", () => {
    const g = new LatestGuard();
    const fresh = g.begin();
    expect(fresh()).toBe(true);
    expect(fresh()).toBe(false);
  });
});

describe("serial", () => {
  test("вызовы идут по одному, в порядке постановки", async () => {
    const run = serial();
    const order: string[] = [];
    const first = deferred<void>();
    const a = run(async () => {
      order.push("a:start");
      await first.promise;
      order.push("a:end");
    });
    const b = run(async () => {
      order.push("b");
    });
    await Promise.resolve();
    expect(order).toEqual(["a:start"]);
    first.resolve();
    await Promise.all([a, b]);
    expect(order).toEqual(["a:start", "a:end", "b"]);
  });

  test("ошибка не ломает очередь", async () => {
    const run = serial();
    await expect(run(async () => Promise.reject(new Error("x")))).rejects.toThrow("x");
    await expect(run(async () => 5)).resolves.toBe(5);
  });
});

describe("setUpdate", () => {
  test("находка попадает в состояние и будит баннер", () => {
    let woken = 0;
    subscribe("update", () => woken++);
    setUpdate({ Version: "1.2.0", URL: "https://github.com/o/r" });
    expect(state.update).toEqual({ Version: "1.2.0", URL: "https://github.com/o/r" });
    expect(woken).toBe(1);
  });

  test("пустой ответ PendingUpdate не стирает найденное событием", () => {
    setUpdate({ Version: "1.2.0" });
    setUpdate(null);
    setUpdate(undefined);
    expect(state.update).toEqual({ Version: "1.2.0" });
  });
});
