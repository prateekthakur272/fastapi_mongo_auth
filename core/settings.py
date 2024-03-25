from pydantic_settings import BaseSettings

class Settings(BaseSettings):

    DB_URL:str = ""
    SECRET_KEY:str = '1eb70e9ae3586b4bcd960d662adb0c5ee4e6c6e643ef8f61909411094c4ed464'
    JWT_ALGORITHM:str = 'HS256'
    JWT_EXPIRATION_TIME:int = 30
    
def get_settings():
    return Settings()
    