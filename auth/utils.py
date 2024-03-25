from passlib.context import CryptContext
from core.settings import get_settings
from datetime import datetime, timedelta
import jwt


password_context = CryptContext(schemes=['bcrypt'], deprecated='auto')
settings = get_settings()

def get_hashed_password(raw_password:str) -> str:
    '''
    takes raw password as input and returns hashed password.
    '''
    return password_context.hash(raw_password)

def verify_password(raw_password:str, hashed_password:str) -> bool:
    '''
    takes raw_password and hashed_password as input and verify password
    returns True if password mached False otherwise.
    '''
    return password_context.verify(raw_password, hashed_password)

def generate_access_token(payload:dict) -> str:
    '''
    generates access token from payload
    '''
    token_payload = payload.copy()
    exp = datetime.utcnow() + timedelta(minutes=settings.JWT_EXPIRATION_TIME)
    token_payload.update({'exp':exp})
    access_token = jwt.encode(token_payload, settings.SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
    return access_token

def generate_refresh_token(payload:dict) -> str :
    '''
    generates refresh token from payload
    '''
    refresh_token = jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
    return refresh_token

def get_payload(token:str) -> dict|None:
    '''
    decode jwt and returns data as dict
    '''
    try:
        data = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
    except jwt.PyJWTError:
        return None