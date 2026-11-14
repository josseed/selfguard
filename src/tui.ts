/**
 * Tiny dependency-free terminal UI primitives: redraw-in-place rendering and
 * raw key handling with guaranteed terminal restore.
 */
import { emitKeypressEvents } from "node:readline";

export interface Key {
  name?: string;
  ctrl?: boolean;
  meta?: boolean;
  shift?: boolean;
  sequence?: string;
}

const stdin = process.stdin;
const stdout = process.stdout;

export function isInteractive(): boolean {
  return Boolean(stdin.isTTY && stdout.isTTY);
}

const ANSI = /\x1b\[[0-9;?]*[A-Za-z]/g;

export function visibleLength(s: string): number {
  return s.replace(ANSI, "").length;
}

export function columns(): number {
  return Math.max(40, stdout.columns ?? 80);
}

/** Truncate plain (uncolored) text to fit the terminal, keeping the end of paths visible. */
export function fitStart(s: string, max: number): string {
  return s.length <= max ? s : `…${s.slice(s.length - max + 1)}`;
}

/** Redraws a block of lines in place. */
export class Screen {
  private height = 0;

  render(lines: string[]): void {
    const width = columns() - 1;
    // Never let a line wrap: wrapped lines would break the in-place redraw.
    const safe = lines.map((l) => (visibleLength(l) > width ? `${l.replace(ANSI, "").slice(0, width - 1)}…` : l));
    let out = "";
    if (this.height > 0) out += `\x1b[${this.height}A`;
    out += "\r\x1b[J";
    out += safe.join("\n");
    this.height = safe.length - 1;
    stdout.write(out);
  }

  /** Leave the last frame on screen and move below it. */
  done(): void {
    stdout.write("\n");
    this.height = 0;
  }

  clear(): void {
    if (this.height > 0) stdout.write(`\x1b[${this.height}A`);
    stdout.write("\r\x1b[J");
    this.height = 0;
  }
}

let restoreInstalled = false;
function restoreTerminal(): void {
  try {
    if (stdin.isTTY) stdin.setRawMode(false);
  } catch {
    /* ignore */
  }
  stdout.write("\x1b[?25h"); // show cursor
}

/**
 * Feed raw keypresses to `onKey` until it calls `finish(value)`.
 * Ctrl+C always exits cleanly with the terminal restored.
 */
export function readKeys<T>(onKey: (key: Key, finish: (value: T) => void) => void): Promise<T> {
  if (!restoreInstalled) {
    process.on("exit", restoreTerminal);
    restoreInstalled = true;
  }
  emitKeypressEvents(stdin);
  stdin.setRawMode(true);
  stdin.resume();
  stdout.write("\x1b[?25l"); // hide cursor
  return new Promise<T>((resolve) => {
    const cleanup = (): void => {
      stdin.off("keypress", handler);
      stdin.setRawMode(false);
      stdin.pause();
      stdout.write("\x1b[?25h");
    };
    const handler = (str: string | undefined, key: Key | undefined): void => {
      const k: Key = { ...(key ?? {}), ...(str !== undefined ? { sequence: str } : {}) };
      if (k.ctrl && k.name === "c") {
        cleanup();
        stdout.write("\n");
        process.exit(130);
      }
      onKey(k, (value) => {
        cleanup();
        resolve(value);
      });
    };
    stdin.on("keypress", handler);
  });
}

/** Single-key yes/no question. Enter picks the default. */
export async function confirm(question: string, def = true): Promise<boolean> {
  const hint = def ? "[Y/n]" : "[y/N]";
  stdout.write(`${question} ${hint} `);
  const answer = await readKeys<boolean>((key, finish) => {
    if (key.name === "return" || key.name === "enter") finish(def);
    else if (key.name === "y") finish(true);
    else if (key.name === "n" || key.name === "escape") finish(false);
  });
  stdout.write(`${answer ? "yes" : "no"}\n`);
  return answer;
}

/** Is this a printable character we can insert into a text field? */
export function isPrintable(key: Key): boolean {
  const s = key.sequence;
  return !key.ctrl && !key.meta && typeof s === "string" && s.length === 1 && s >= " " && s !== "\x7f";
}

const FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

/** Show a spinner with a message while `work` runs. */
export async function withSpinner<T>(message: string, work: () => Promise<T>): Promise<T> {
  if (!stdout.isTTY) return work();
  let i = 0;
  stdout.write("\x1b[?25l");
  const timer = setInterval(() => {
    stdout.write(`\r${FRAMES[i++ % FRAMES.length]} ${message}`);
  }, 80);
  try {
    return await work();
  } finally {
    clearInterval(timer);
    stdout.write("\r\x1b[K\x1b[?25h");
  }
}
