from fastapi import APIRouter, Depends, Header, status
from fastapi.responses import JSONResponse
from core.databse import client
from fastapi.exceptions import HTTPException
from .utils import get_hashed_password, verify_password
from .models import TokenResponse, User, UserSignUp, UserSignIn
from .schemas import user_from_dict
from .services import generate_tokens, JWTBearer, refresh_access_token


router = APIRouter(prefix='/auth')


@router.post('/signup', response_class=JSONResponse, status_code=status.HTTP_201_CREATED)
async def signup(user:UserSignUp):
    '''
    Creates a new user
    raise HttpException if user already exists
    '''
    #check if user already exists
    if client.database_name.users.find_one({'username':user.username}):
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail='account already exists with this username.')
    if client.database_name.users.find_one({'email':user.email}):
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail='account already exists with this email.')
    # create user
    user_data = User(**user.model_dump()).model_dump(exclude=['id'])
    user_data['password'] = get_hashed_password(user.password)
    client.database_name.users.insert_one(user_data)
    return {'message':f'account created!, please verify account by email sent to {user.email}.'}


@router.post('/signin', response_class=JSONResponse, response_model=TokenResponse, status_code=status.HTTP_200_OK)
async def signin(user:UserSignIn):
    '''
    takes username and password in a form and returns access and refresh token
    '''
    current_user = client.database_name.users.find_one({'username':user.username})
    # check if user data exists
    if not current_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='user not found.')
    current_user = user_from_dict(current_user)
    # verify password
    if not verify_password(user.password, current_user.password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='wrong password')
    # check if user is active or not
    if not current_user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='account not active.')
    # generate tokens and return token response
    return generate_tokens(current_user)


@router.get('/me', status_code=status.HTTP_200_OK, response_class=JSONResponse, response_model=User, response_model_exclude=['password'])
def current_user(user = Depends(JWTBearer())):
    '''
    Returns current user
    '''
    return user


@router.get('/refresh-token')
def refres_token(refresh_token = Header()):
    '''
    Refresh access token using refresh token
    '''
    return refresh_access_token(refresh_token)
    