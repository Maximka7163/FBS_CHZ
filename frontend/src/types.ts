export type Mode="AUTO"|"CONTROL"|"WITHDRAW_ONLY"|"RETURN_ONLY";
export type FileItem={id:string;filename:string;imported_at:string|null;repeated:boolean;new_events:number;duplicate_events:number;rejected_rows:number;row_count:number;unique_kiz:number;sales:number;returns:number;dated:number;undated:number;status:string};
export type EventItem={event_id:string;kiz:string;operation:string;occurred_at:string|null;receipt_number:string|null;decision:string|null;reason:string|null;reason_text:string|null;error:string|null};
