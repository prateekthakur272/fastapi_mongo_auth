from .models import User, TokenResponse
from .utils import generate_access_token, generate_refresh_token

def generate_tokens(user:User) -> TokenResponse:
    '''
    This method generates access and refresh token and return TokenResponse.
    requires User
    '''
    payload = {'username':user.username, 'email':user.email, 'id':user.id}
    access_token = generate_access_token(payload)
    refresh_token = generate_refresh_token(payload)
    return TokenResponse(access_token=access_token, refresh_token=refresh_token)
