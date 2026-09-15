export type FilterKey = "ALL" | "READY" | "PROCESSING" | "ATTENTION" | "DONE" | "ERROR";

export type UiState =
  | "NOT_CHECKED"
  | "CHECKING"
  | "READY"
  | "WAITING_AGENT"
  | "WAITING_SIGNATURE"
  | "SENDING"
  | "VERIFYING"
  | "COMPLETED"
  | "ALREADY_DONE"
  | "MANUAL_REVIEW"
  | "ERROR";

export interface UserInfo {
  id: number;
  username: string;
  is_admin: boolean;
}

export interface FileItem {
  id: string;
  fingerprint: string;
  filename: string;
  imported_at: string | null;
  repeated: boolean;
  repeated_of_id: string | null;
  new_events: number;
  duplicate_events: number;
  rejected_rows: number;
  row_count: number;
  unique_kiz: number;
  sales: number;
  returns: number;
  dated: number;
  undated: number;
  status: string;
  workflow_status?: string;
  workflow_status_label?: string;
}

export interface WorkspaceItem {
  event_id: string;
  kiz: string;
  operation: string;
  operation_label: string;
  chz_status: string;
  decision: string | null;
  decision_label: string;
  action_label: string;
  result_label: string;
  ui_state: UiState;
  state_label: string;
  filter_group: Exclude<FilterKey, "ALL"> | "OTHER";
  ready_for_bulk: boolean;
  reason: string | null;
  error: string | null;
  attention_title: string | null;
  attention_detail: string | null;
  user_action: string | null;
  checked_at: string | null;
  write_operation_id: string | null;
  write_state: string | null;
  document_id: string | null;
  details: {
    task_number: string;
    sticker: string;
    receipt_number: string | null;
    fiscal_drive_number: string | null;
    occurred_at: string | null;
    amount: string;
    currency: string;
    reason_code: string | null;
  };
}

export interface BulkPreview {
  eligible_count: number;
  withdraw_count: number;
  return_count: number;
  excluded_count: number;
}

export interface WorkspaceView {
  file: FileItem;
  items: WorkspaceItem[];
  filters: Record<FilterKey, number>;
  bulk: BulkPreview;
  runtime: {
    agent_enabled: boolean;
    production_write_enabled: boolean;
  };
}

export interface WorkspaceHome {
  active_import_id: string | null;
  history: FileItem[];
}

export interface BulkResult {
  started_count: number;
  withdraw_count: number;
  return_count: number;
  manual_review_count: number;
  already_started_count: number;
  production_write_enabled: boolean;
}

export interface EventDetail {
  event_id: string;
  kiz: string;
  task_number: string;
  sticker: string;
  operation: string;
  occurred_at: string | null;
  receipt_number: string | null;
  fiscal_drive_number: string | null;
  amount: string | number;
  currency: string;
  decision: string | null;
  reason: string | null;
  reason_text: string | null;
  error: string | null;
  history: Array<{
    event_id: string;
    operation: string;
    occurred_at: string | null;
    task_number: string;
  }>;
  history_order_ambiguous: boolean;
}
