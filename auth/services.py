from bson import ObjectId
from fastapi import HTTPException, Request, status
from .models import User, TokenResponse
from .utils import generate_access_token, generate_refresh_token, get_payload
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from core.databse import client
from .schemas import user_from_dict


def generate_tokens(user:User) -> TokenResponse:
    '''
    This method generates access and refresh token and return TokenResponse.
    requires User
    '''
    payload = {'username':user.username, 'email':user.email, 'id':user.id}
    access_token = generate_access_token(payload)
    refresh_token = generate_refresh_token(payload)
    return TokenResponse(access_token=access_token, refresh_token=refresh_token)


def refresh_access_token(refresh_token:str) -> TokenResponse:
    user = get_user_by_token(refresh_token)
    payload = {'username':user.username, 'email':user.email, 'id':user.id}
    access_token = generate_access_token(payload)
    return TokenResponse(access_token=access_token, refresh_token=refresh_token)


def get_user_by_token(token:str) -> User :
    '''
    decodes token and return user from database
    '''
    payload = get_payload(token)
    if payload:
        return user_from_dict(client.database_name.users.find_one({'username':payload.get('username','')}))
    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid or expired token.")


class JWTBearer(HTTPBearer):
    
    '''
    JWTBearer class for user authentication
    returns currently logged in User
    secure routes by adding\n
    user = Depends(JWTBearer())
    '''
    
    def __init__(self, auto_error:bool = True):
        super(JWTBearer, self).__init__(auto_error=auto_error)
        
    async def __call__(self, request:Request):
        creds:HTTPAuthorizationCredentials = await super(JWTBearer, self).__call__(request)
        if not creds.scheme == 'Bearer':
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid authentication scheme, Bearer required.")
        user = get_user_by_token(creds.credentials)
        return user