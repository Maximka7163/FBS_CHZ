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
  status: string | null;
  statusEx: string | null;
  withdrawReason: string | null;
  ownerInn: string | null;
  owner_match: boolean | null;
  productGroup: string | null;
  source: string | null;
  fetched_at: string | null;
  decision: string | null;
  decision_label: string;
  action_label: string;
  result_label: string;
  ui_state: UiState;
  state_label: string;
  filter_group: Exclude<FilterKey, "ALL"> | "OTHER";
  ready_for_bulk: boolean;
  reason: string | null;
  reason_code: string | null;
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
    source_row_number: number | null;
    source_file: string;
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
    fbs_dry_run_only: boolean;
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


export interface IntegrationItem {
  id: string;
  type: "true-api" | "wb" | "ozon" | "suz";
  display_name: string;
  configuration_status: string;
  runtime_status: string;
  contract_status: string;
  feature_gate_status: string;
  enabled: boolean;
  secret_configured: boolean | null;
  last_check_at: string | null;
  last_check_status: string | null;
  error_code: string | null;
  blockers: string[];
  read_only?: boolean | null;
  real_read_authorized?: boolean | null;
  certificate?: {
    thumbprint: string | null;
    valid_to: string | null;
    status: string;
    expiry_state: string;
    selection_state: string;
  };
  local_config_state?: string;
  wire_readiness?: string;
}

export interface AgentBindingStatus {
  id: string;
  display_name: string;
  runtime_status: "ONLINE" | "STALE" | "OFFLINE" | string;
  last_seen_at: string | null;
  last_poll_at: string | null;
  agent_version: string | null;
  capabilities: Record<string, unknown>;
}

export interface CertificateCandidate {
  id: string;
  thumbprint: string;
  subject: string | null;
  certificate_inn: string | null;
  valid_from: string | null;
  valid_to: string | null;
  has_private_key: boolean;
  crypto_provider: string | null;
  compatibility: string;
  match_state: string;
  expiry_state: string;
  readiness_state: string;
  reason_code: string | null;
}

export interface CertificateStatus {
  status: string;
  reason_code: string | null;
  observation: CertificateCandidate | null;
  candidates: CertificateCandidate[];
  eligible_count: number;
  selection_state: string;
  desired_certificate_thumbprint: string | null;
  cryptopro_available?: boolean;
}

export interface EnrollmentIntent {
  enrollment_id: string;
  enrollment_token: string;
  expires_at: string;
  requested_protocol_version: string | null;
}

export interface CisInventoryRequest {
  request_id: string;
  job_type: string;
  status: "pending" | "running" | "completed" | "failed";
  source: string;
  result?: {
    type?: string;
    items?: Array<{
      normalized?: {
        requested_cis?: string;
        cis?: string | null;
        gtin?: string | null;
        product_name?: string | null;
        product_group?: string | null;
        owner_inn?: string | null;
        owner_name?: string | null;
        status?: string | null;
        status_ex?: string | null;
        withdraw_reason?: string | null;
      } | null;
      item_error?: { code?: string | null; message?: string | null } | null;
    }>;
  } | null;
  fetched_at?: string | null;
}
