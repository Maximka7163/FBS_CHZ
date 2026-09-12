let csrf="";
async function json<T>(url:string,init:RequestInit={}):Promise<T>{const headers=new Headers(init.headers||{});if(init.method&&init.method!=="GET"&&init.method!=="HEAD")headers.set("X-CSRF-Token",csrf);const r=await fetch(url,{...init,headers,credentials:"same-origin"});if(!r.ok){let m=`HTTP ${r.status}`;try{const b=await r.json();m=b.detail||m}catch{}throw new Error(m)}return r.json() as Promise<T>}
export async function seedCsrf(){const r=await json<{csrf_token:string}>("/api/auth/csrf");csrf=r.csrf_token}
export async function login(username:string,password:string){return json("/api/auth/login",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({username,password})})}
export async function me(){return json<{username:string;is_admin:boolean}>("/api/me")}
export async function logout(){return json("/api/auth/logout",{method:"POST"})}
export async function files(){return json<any[]>("/api/files")}
export async function upload(file:File){const f=new FormData();f.append("file",file);return json<any>("/api/files",{method:"POST",body:f})}
export async function fileInfo(id:string){return json<any>(`/api/files/${id}`)}
export async function events(id:string){return json<any[]>(`/api/files/${id}/events`)}
export async function control(id:string,mode:string,event_ids:string[]|null){return json<any>(`/api/files/${id}/control`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({mode,event_ids})})}
export async function preview(import_id:string,mode:string,event_ids:string[]){return json<any>("/api/operation-preview",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({import_id,mode,event_ids})})}
export async function capabilities(){return json<any>("/api/capabilities")}
