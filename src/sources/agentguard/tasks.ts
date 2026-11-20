/**
 * VS Code tasks that run when the folder is opened (`runOptions.runOn: "folderOpen"`), the
 * trick of fake job-interview repos ("Contagious Interview"). Cursor and Windsurf read the
 * same file. The task's label is its key; nothing of the task is put in the message.
 */
import { stripJsonc } from "../agents/jsonc.ts";
import { lineAt } from "../agents/lines.ts";
import type { ExtractResult } from "../types.ts";
import { obj } from "./rules.ts";

type Warning = ExtractResult["warnings"][number];

const MAX_TASKS = 500;
const RUN_ON = /"runOn"\s*:\s*"folderOpen"/g;

export function autorunTasks(data: Record<string, unknown>, text: string, file: string): Warning[] {
  const tasks = Array.isArray(data.tasks) ? data.tasks.slice(0, MAX_TASKS) : [];
  const flagged = tasks.map(obj).filter((t) => obj(t?.runOptions)?.runOn === "folderOpen");
  if (flagged.length === 0) return [];
  // Best effort: the n-th `"runOn": "folderOpen"` in the text is the n-th flagged task.
  const offsets = [...stripJsonc(text).matchAll(RUN_ON)].map((m) => m.index);
  return flagged.map((t, i) => ({
    rule: "autorun-task",
    message:
      `A task runs automatically when this folder opens in VS Code, Cursor or Windsurf. ` +
      `Review ${file} before opening it; remove runOn "folderOpen" if you didn't add it.`,
    line: offsets.length === flagged.length ? lineAt(text, offsets[i]!) : 0,
    severity: "high" as const,
    key: typeof t?.label === "string" && t.label.trim() ? t.label.slice(0, 80) : `task ${i + 1}`,
    notify: true,
    urgent: true,
  }));
}
