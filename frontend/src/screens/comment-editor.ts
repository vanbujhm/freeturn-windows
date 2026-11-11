// Поле комментария в карточке списка: одно на список, живёт между перерисовками, чтобы ввод
// не терялся. Enter сохраняет обрезанное значение, Esc отменяет.
import { h } from "../dom";
import * as S from "../strings";

export interface CommentEditor<T> {
  // start открывает поле для item. Открытое поле одно на редактор.
  start(item: T): void;
  // field возвращает поле, если сейчас редактируется item.
  field(item: T): HTMLInputElement | null;
  // rebuild заменяет детей списка тем, что вернёт build, и возвращает фокус и курсор
  // открытому полю. Карточки строятся внутри: перенос поля в новую карточку уже снимает фокус.
  rebuild(list: HTMLElement, build: () => HTMLElement[]): void;
}

export function createCommentEditor<T>(o: {
  same(a: T, b: T): boolean;
  comment(item: T): string;
  label(item: T): string; // aria-label поля
  busy(): boolean; // идёт запись: Enter ничего не делает, поле остаётся открытым
  save(item: T, comment: string): void;
  render(): void;
}): CommentEditor<T> {
  let editing: T | null = null;
  let input: HTMLInputElement | null = null;

  return {
    start(item: T): void {
      const field = h("input", {
        class: "input rule-comment-input",
        type: "text",
        maxlength: "80",
        placeholder: S.rules.commentPlaceholder,
        "aria-label": o.label(item),
      });
      field.value = o.comment(item);
      field.addEventListener("keydown", (e) => {
        if (e.key === "Enter") {
          // Идёт другая запись: поле остаётся открытым, Enter сработает после неё.
          if (o.busy()) return;
          const value = field.value.trim();
          editing = input = null;
          o.save(item, value);
        } else if (e.key === "Escape") {
          editing = input = null;
          o.render();
        }
      });
      editing = item;
      input = field;
      o.render();
      field.focus();
    },

    field(item: T): HTMLInputElement | null {
      return editing !== null && o.same(editing, item) ? input : null;
    },

    // Перестройка списка снимает фокус с открытого поля, даже если оно переносится в новую
    // карточку. Статус приходит каждую секунду, поэтому фокус и курсор возвращаются на место.
    rebuild(list: HTMLElement, build: () => HTMLElement[]): void {
      const field = input;
      const focused = field !== null && document.activeElement === field;
      const start = field?.selectionStart ?? null;
      const end = field?.selectionEnd ?? null;
      list.replaceChildren(...build());
      if (focused && field.isConnected) {
        field.focus();
        if (start !== null && end !== null) field.setSelectionRange(start, end);
      }
    },
  };
}
