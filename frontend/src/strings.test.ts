// Коды из Go-файлов читаются с диска: новый код без текста роняет тест, а не показывает
// человеку пустую строку.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, test } from "vitest";
import * as S from "./strings";

function goSource(rel: string): string {
  return readFileSync(fileURLToPath(new URL(`../../${rel}`, import.meta.url)), "utf8");
}

// codes собирает значения строк-констант, найденных по шаблону.
function codes(src: string, re: RegExp): string[] {
  return [...src.matchAll(re)].map((m) => m[1]);
}

const status = goSource("internal/model/status.go");
const api = goSource("cmd/freeturn/api.go");
const rules = goSource("internal/split/rules.go");
const profile = goSource("internal/model/profile.go");

const errorCodes = codes(status, /^\s*Err\w+\s+ErrorCode\s*=\s*"([a-z_]+)"/gm);
const warningCodes = codes(status, /^\s*Warn\w+\s+WarningCode\s*=\s*"([a-z_]+)"/gm);
const phaseCodes = codes(status, /^\s*Phase\w+\s+Phase\s*=\s*"([a-z_]+)"/gm);
const apiCodes = codes(api, /^\s*code\w+\s*=\s*"([a-z_]+)"/gm);
const skipReasons = codes(rules, /^\s*Reason\w+\s*=\s*"([a-z_]+)"/gm);
const fieldCodes = codes(profile, /^\s*Field\w+\s+Field\s*=\s*"(\w+)"/gm);
const kindCodes = codes(profile, /^\s*Rule\w+\s+RuleKind\s*=\s*"(\w+)"/gm);

describe("в Go найдено то, что ожидается", () => {
  // Если разбор перестанет находить коды, остальные проверки стали бы пустыми.
  test.each([
    ["ErrorCode", errorCodes, 12],
    ["WarningCode", warningCodes, 5],
    ["Phase", phaseCodes, 7],
    ["коды API", apiCodes, 15],
    ["причины пропуска", skipReasons, 3],
    ["поля профиля", fieldCodes, 2],
    ["виды правил", kindCodes, 3],
  ])("%s", (_name, list, min) => {
    expect(list.length).toBeGreaterThanOrEqual(min as number);
  });
});

describe("у каждого кода из Go есть текст", () => {
  test.each(errorCodes)("ErrorCode %s", (code) => {
    expect(S.errors[code], code).toBeTruthy();
  });
  test.each(warningCodes)("WarningCode %s", (code) => {
    expect(S.warnings[code], code).toBeTypeOf("function");
    expect(S.warnings[code]("значение")).toBeTruthy();
    expect(S.warnings[code]("")).toBeTruthy();
  });
  test.each(phaseCodes)("Phase %s", (code) => {
    expect(S.phases[code]?.title, code).toBeTruthy();
  });
  test.each(apiCodes)("код API %s", (code) => {
    expect(S.apiErrors[code], code).toBeTruthy();
  });
  test.each(skipReasons)("причина пропуска %s", (code) => {
    expect(S.skipReasons[code], code).toBeTruthy();
  });
  test.each(fieldCodes)("поле профиля %s", (code) => {
    expect(S.fields[code], code).toBeTruthy();
  });
  test.each(kindCodes)("вид правила %s", (code) => {
    expect(S.kinds[code], code).toBeTruthy();
  });
});

describe("в strings.ts нет лишнего", () => {
  test("нет текстов для кодов, которых в Go нет", () => {
    expect(Object.keys(S.errors).sort()).toEqual([...errorCodes].sort());
    expect(Object.keys(S.warnings).sort()).toEqual([...warningCodes].sort());
    expect(Object.keys(S.phases).sort()).toEqual([...phaseCodes].sort());
    expect(Object.keys(S.apiErrors).sort()).toEqual([...apiCodes].sort());
    expect(Object.keys(S.skipReasons).sort()).toEqual([...skipReasons].sort());
  });
});
