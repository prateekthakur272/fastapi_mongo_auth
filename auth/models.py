from pydantic import BaseModel, Field
from pydantic import EmailStr
    

class User(BaseModel):
    '''
    User class for data storage in database
    contains all the fields
    id, first_name, last_name, username, email, password, is_active, type
    '''
    id:str = Field(min_length=10, max_length=50, default='')
    first_name:str = Field(min_length=3, max_length=40)
    last_name:str = Field(max_length=40)
    username:str = Field(max_length=20, min_length=4)
    email:EmailStr = Field(max_length=50)
    password:str = Field()
    is_active:bool = Field(default=False)
    type:str = Field(max_length=10, default='user')
    

class UserSignIn(BaseModel):
    '''
    UserSignIn class for pydantic validation of data related to sign in operation
    contains username and password
    '''
    username:str = Field(min_length=4, max_length=20)
    password:str = Field(min_length=8, max_length=32)
    

class UserSignUp(BaseModel):
    '''
    UserSignUp class for pydantica validation of body/data related to sign up operations
    contains first_name, last_name, username, password, email
    '''
    first_name:str = Field(min_length=3, max_length=40)
    last_name:str = Field(max_length=40)
    username:str = Field(max_length=20, min_length=4)
    email:EmailStr = Field(max_length=50)
    password:str = Field(min_length=8, max_length=32)


class TokenResponse(BaseModel):
    '''
    TokenResponse class for sending refresh_token and access_token back to user.
    contains access_token and refresh_token
    '''
    access_token:str = Field()
    refresh_token:str = Field()