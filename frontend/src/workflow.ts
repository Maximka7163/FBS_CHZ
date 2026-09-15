import type { FilterKey, WorkspaceItem } from "./types";

const POLLING_STATES = new Set([
  "CHECKING",
  "WAITING_AGENT",
  "WAITING_SIGNATURE",
  "SENDING",
  "VERIFYING",
]);

export function filterWorkspaceItems(
  items: WorkspaceItem[],
  filter: FilterKey,
  query: string,
): WorkspaceItem[] {
  const needle = query.trim().toLocaleLowerCase("ru-RU");
  return items.filter((item) => {
    const groupMatch = filter === "ALL" || item.filter_group === filter;
    const textMatch = !needle || item.kiz.toLocaleLowerCase("ru-RU").includes(needle);
    return groupMatch && textMatch;
  });
}

export function shouldPollWorkspace(items: WorkspaceItem[]): boolean {
  return items.some((item) => POLLING_STATES.has(item.ui_state));
}

export function stateTone(item: WorkspaceItem): "good" | "warn" | "danger" | "neutral" | "progress" {
  if (item.filter_group === "ERROR") return "danger";
  if (item.filter_group === "ATTENTION") return "warn";
  if (item.filter_group === "PROCESSING") return "progress";
  if (item.filter_group === "DONE") return "neutral";
  if (item.filter_group === "READY") return "good";
  return "neutral";
}

export function shortKiz(value: string): string {
  return value.length > 38 ? `${value.slice(0, 24)}…${value.slice(-10)}` : value;
}
