from __future__ import annotations
from datetime import datetime,timedelta,timezone
from fastapi import APIRouter,Depends,HTTPException,Request,Response
from pydantic import BaseModel,ConfigDict,Field
from sqlalchemy import select
from sqlalchemy.orm import Session
from wbcz_web.models import MembershipRecord,SessionRecord,User
from wbcz_web.repositories import AuditRepository
from wbcz_web.services import AuthService,AuthenticationError
from wbcz_web.services.authorization import AuthorizationError,AuthorizationService,MembershipService,Permission,Role
from .dependencies import AuthenticatedIdentity,SessionIdentity,get_db,require_csrf,require_session_user,require_user
security_router=APIRouter(prefix="/api")
class Strict(BaseModel):model_config=ConfigDict(extra="forbid")
class ScopeRequest(Strict):
 organisation_id:str=Field(min_length=1,max_length=36);participant_id:str|None=Field(default=None,min_length=1,max_length=36)
class InviteRequest(Strict):
 username:str|None=Field(default=None,min_length=1,max_length=128)
 invited_user_id:int|None=Field(default=None,ge=1)
 email:str|None=Field(default=None,min_length=3,max_length=320)
 role:Role
 participant_id:str|None=Field(default=None,min_length=1,max_length=36)
 expires_in_hours:int=Field(default=168,ge=1,le=336)
class AcceptRequest(Strict):token:str=Field(min_length=32,max_length=512)
class RoleRequest(Strict):role:Role
class PasswordRequest(Strict):current_password:str=Field(min_length=1,max_length=4096);new_password:str=Field(min_length=15,max_length=256)

def _scope(db:Session,identity:AuthenticatedIdentity):
 user=db.get(User,identity.user_id);session=db.get(SessionRecord,identity.session_id)
 if user is None or session is None:raise HTTPException(401,"Session is invalid")
 try:return AuthorizationService(db).resolve_session_scope(user,session)
 except AuthorizationError as exc:raise HTTPException(403,"Active organisation scope required") from exc

@security_router.get("/security/scopes")
def scopes(identity:SessionIdentity=Depends(require_session_user),db:Session=Depends(get_db))->dict:
 return {"registration_enabled":False,"scopes":AuthorizationService(db).list_scopes(identity.user_id)}

@security_router.post("/security/scope")
def set_scope(payload:ScopeRequest,identity:SessionIdentity=Depends(require_session_user),_:None=Depends(require_csrf),db:Session=Depends(get_db))->dict:
 user=db.get(User,identity.user_id);session=db.get(SessionRecord,identity.session_id)
 if user is None or session is None:raise HTTPException(401,"Session is invalid")
 try:s=AuthorizationService(db).set_active_scope(user,session,organisation_id=payload.organisation_id,participant_id=payload.participant_id)
 except AuthorizationError as exc:raise HTTPException(404,"Scope not found") from exc
 db.info["tenant_scope"]={"user_id":user.id,"organisation_id":s.organisation_id,"participant_id":s.participant_id,"participant_inn":s.participant_inn,"role":s.role.value}
 AuditRepository(db).append("SCOPE_CHANGED",user_id=user.id,entity_type="session",entity_id=session.id,metadata={"organisation_id":s.organisation_id,"participant_id":s.participant_id})
 return {"organisation_id":s.organisation_id,"participant_id":s.participant_id,"participant_inn":s.participant_inn,"role":s.role.value,"permissions":sorted(p.value for p in s.permissions)}

@security_router.get("/security/permissions")
def permissions(identity:AuthenticatedIdentity=Depends(require_user))->dict:
 return {"organisation_id":identity.organisation_id,"participant_id":identity.participant_id,"role":identity.role,"permissions":sorted(identity.permissions)}

@security_router.get("/security/memberships")
def memberships(identity:AuthenticatedIdentity=Depends(require_user),db:Session=Depends(get_db))->list[dict]:
 s=_scope(db,identity);AuthorizationService.require(s,Permission.MEMBERS_READ)
 rows=list(db.scalars(select(MembershipRecord).where(MembershipRecord.organisation_id==s.organisation_id,MembershipRecord.is_active.is_(True)).order_by(MembershipRecord.created_at,MembershipRecord.id)))
 return [{"membership_id":r.id,"user_id":r.user_id,"username":(db.get(User,r.user_id).username if db.get(User,r.user_id) else ""),"role":r.role,"is_active":r.is_active} for r in rows]

@security_router.post("/security/invitations")
def invite(payload:InviteRequest,identity:AuthenticatedIdentity=Depends(require_user),_:None=Depends(require_csrf),db:Session=Depends(get_db))->dict:
 s=_scope(db,identity)
 try:
  row,token=MembershipService(db).create_invitation(
   s,invitee_username=payload.username,invited_user_id=payload.invited_user_id,
   invited_email_normalized=payload.email,role=payload.role,participant_id=payload.participant_id,
   expires_at=datetime.now(timezone.utc)+timedelta(hours=payload.expires_in_hours),
  )
 except (AuthorizationError,ValueError) as exc:raise HTTPException(403,"Permission denied") from exc
 AuditRepository(db).append("INVITATION_CREATED",user_id=identity.user_id,entity_type="invitation",entity_id=row.id,metadata={"role":row.role,"identity_bound":True})
 return {"invitation_id":row.id,"token":token,"role":row.role,"expires_at":row.expires_at.isoformat()}

@security_router.delete("/security/invitations/{invitation_id}")
def revoke_invitation(invitation_id:str,identity:AuthenticatedIdentity=Depends(require_user),_:None=Depends(require_csrf),db:Session=Depends(get_db))->dict:
 s=_scope(db,identity)
 try:MembershipService(db).revoke_invitation(s,invitation_id)
 except KeyError as exc:raise HTTPException(404,"Invitation not found") from exc
 except AuthorizationError as exc:raise HTTPException(403,"Permission denied") from exc
 AuditRepository(db).append("INVITATION_REVOKED",user_id=identity.user_id,entity_type="invitation",entity_id=invitation_id)
 return {"ok":True}

@security_router.post("/security/invitations/accept")
def accept(payload:AcceptRequest,identity:SessionIdentity=Depends(require_session_user),_:None=Depends(require_csrf),db:Session=Depends(get_db))->dict:
 user=db.get(User,identity.user_id)
 if user is None:raise HTTPException(401,"Session is invalid")
 try:m=MembershipService(db).accept_invitation(user,payload.token)
 except AuthorizationError as exc:raise HTTPException(400,"Invitation is invalid") from exc
 db.info["tenant_scope"]={"user_id":user.id,"organisation_id":m.organisation_id,"participant_id":None,"participant_inn":None,"role":m.role}
 AuditRepository(db).append("INVITATION_ACCEPTED",user_id=user.id,entity_type="membership",entity_id=m.id,metadata={"organisation_id":m.organisation_id,"role":m.role})
 return {"membership_id":m.id,"organisation_id":m.organisation_id,"role":m.role}

@security_router.patch("/security/memberships/{membership_id}/role")
def change_role(membership_id:str,payload:RoleRequest,identity:AuthenticatedIdentity=Depends(require_user),_:None=Depends(require_csrf),db:Session=Depends(get_db))->dict:
 s=_scope(db,identity)
 try:m=MembershipService(db).change_role(s,membership_id,payload.role)
 except KeyError as exc:raise HTTPException(404,"Membership not found") from exc
 except AuthorizationError as exc:raise HTTPException(403,"Permission denied") from exc
 AuditRepository(db).append("ROLE_CHANGED",user_id=identity.user_id,entity_type="membership",entity_id=m.id,metadata={"role":m.role})
 return {"membership_id":m.id,"role":m.role}

@security_router.delete("/security/memberships/{membership_id}")
def remove_member(membership_id:str,identity:AuthenticatedIdentity=Depends(require_user),_:None=Depends(require_csrf),db:Session=Depends(get_db))->dict:
 s=_scope(db,identity)
 try:MembershipService(db).remove(s,membership_id)
 except KeyError as exc:raise HTTPException(404,"Membership not found") from exc
 except AuthorizationError as exc:raise HTTPException(403,"Permission denied") from exc
 AuditRepository(db).append("MEMBERSHIP_REMOVED",user_id=identity.user_id,entity_type="membership",entity_id=membership_id)
 return {"ok":True}

@security_router.post("/auth/change-password")
def change_password(payload:PasswordRequest,request:Request,response:Response,identity:SessionIdentity=Depends(require_session_user),_:None=Depends(require_csrf),db:Session=Depends(get_db))->dict:
 user=db.get(User,identity.user_id)
 if user is None:raise HTTPException(401,"Session is invalid")
 try:AuthService(db,request.app.state.config).change_password(user,current_password=payload.current_password,new_password=payload.new_password)
 except AuthenticationError as exc:raise HTTPException(400,str(exc)) from exc
 except ValueError as exc:raise HTTPException(400,str(exc)) from exc
 response.delete_cookie(request.app.state.config.session_cookie_name,path="/");return {"ok":True,"reauthenticate":True}

@security_router.post("/auth/logout-all")
def logout_all(request:Request,response:Response,identity:SessionIdentity=Depends(require_session_user),_:None=Depends(require_csrf),db:Session=Depends(get_db))->dict:
 count=AuthService(db,request.app.state.config).logout_all(identity.user_id);response.delete_cookie(request.app.state.config.session_cookie_name,path="/");return {"ok":True,"revoked":count}
