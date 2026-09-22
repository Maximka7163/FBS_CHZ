import type {
  BulkPreview,
  BulkResult,
  EventDetail,
  FileItem,
  UserInfo,
  WorkspaceHome,
  WorkspaceView,
} from "./types";

let csrfToken = "";

async function request<T>(url: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers || {});
  const method = (init.method || "GET").toUpperCase();
  if (method !== "GET" && method !== "HEAD") {
    if (!csrfToken) await seedCsrf();
    headers.set("X-CSRF-Token", csrfToken);
  }
  const response = await fetch(url, {
    ...init,
    headers,
    credentials: "same-origin",
    cache: "no-store",
  });
  if (!response.ok) {
    let message = `HTTP ${response.status}`;
    try {
      const body = (await response.json()) as { detail?: string | { code?: string; message?: string } };
      if (typeof body.detail === "string") message = body.detail;
      else if (body.detail?.message) message = body.detail.message;
    } catch {
      // Keep the HTTP status when the response is intentionally not JSON.
    }
    throw new Error(message);
  }
  if (response.status === 204) return undefined as T;
  return response.json() as Promise<T>;
}

export async function seedCsrf(): Promise<void> {
  const response = await fetch("/api/auth/csrf", {
    credentials: "same-origin",
    cache: "no-store",
  });
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  const body = (await response.json()) as { csrf_token: string };
  csrfToken = body.csrf_token;
}

export async function login(username: string, password: string): Promise<UserInfo> {
  return request<UserInfo>("/api/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
}

export async function logout(): Promise<void> {
  await request("/api/auth/logout", { method: "POST" });
  csrfToken = "";
}

export const me = () => request<UserInfo>("/api/me");
export const workspaceHome = () => request<WorkspaceHome>("/api/workspace");
export const workspace = (importId: string) => request<WorkspaceView>(`/api/files/${encodeURIComponent(importId)}/workspace`);
export const fileInfo = (importId: string) => request<FileItem>(`/api/files/${encodeURIComponent(importId)}`);
export const eventDetail = (eventId: string) => request<EventDetail>(`/api/events/${encodeURIComponent(eventId)}`);
export const bulkPreview = (importId: string) => request<BulkPreview>(`/api/files/${encodeURIComponent(importId)}/bulk-preview`);

export async function upload(file: File): Promise<FileItem> {
  const form = new FormData();
  form.append("file", file);
  return request<FileItem>("/api/files", { method: "POST", body: form });
}

export async function control(importId: string): Promise<unknown> {
  return request(`/api/files/${encodeURIComponent(importId)}/control`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ mode: "AUTO", event_ids: null }),
  });
}

export async function executeBulk(importId: string): Promise<BulkResult> {
  return request<BulkResult>(`/api/files/${encodeURIComponent(importId)}/bulk-actions`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ confirm: true }),
  });
}
