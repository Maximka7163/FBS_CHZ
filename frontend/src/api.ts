export async function api<T>(path:string, init?:RequestInit):Promise<T>{const r=await fetch(path,init);if(!r.ok)throw new Error(await r.text());return r.json()}
export async function upload(file:File){const f=new FormData();f.append('file',file);return api<any>('/api/imports',{method:'POST',body:f})}
