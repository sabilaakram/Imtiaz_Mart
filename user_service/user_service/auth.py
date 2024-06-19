from fastapi.security import OAuth2PasswordBearer
from passlib.context import CryptContext
from typing import Annotated
from sqlmodel import Session, select
from user_service.db import get_session
from fastapi import Depends, HTTPException, status
from user_service.models import User, TokenData, RefreshTokenData, Token
from datetime import timedelta, datetime, timezone
from jose import jwt, JWTError

SECRET_KEY = "f5b5748caacba07a52473a79e469d9c972c212f9b8e898007b51e2b103575fa3"
ALGORITHM = "HS256"
EXPIRY_TIME = 30
REFRESH_EXPIRY_DAYS = 7

oauth_scheme = OAuth2PasswordBearer(tokenUrl="/token")
pwd_context = CryptContext(schemes=["bcrypt"])


"""function to create the hash of the password"""
def hash_password(password) -> str:
    return pwd_context.hash(password)  # hash the password using salting


"""function to verify the hash of the password"""
def verify_password(password, hashed_password) -> bool:
    return pwd_context.verify(password, hashed_password)


"""function to get the user from the database"""
def get_user_from_db(
        session: Annotated[Session, Depends(get_session)],
        username: str | None = None,
        email: str | None = None,
) -> User | None:
    statment = select(User).where(User.username == username)
    user : User | None = session.exec(statment).first()
    if not user:
        statment = select(User).where(User.email == email)
        user: User | None = session.exec(statment).first()
        if user:
            return user
    return user


"""function to authenticate user with username and password"""
def authenticate_user(
        username,
        password,
        session: Annotated[Session, Depends(get_session)]
) -> User | None:
    db_user = get_user_from_db(session=session, username=username)
    if not db_user:
        return None
    if not verify_password(password, db_user.password):
        return None
    return db_user


"""function to create access token"""
def create_access_token(
        data: dict,
        expiry_time: timedelta | None
) -> str:
    data_To_encode = data.copy() # copy the origina code to the data_to_encode, so the orignal data will not be affected
    if expiry_time:
        expire = datetime.now(timezone.utc) + expiry_time
    else:
        expire= datetime.now(timezone.utc) + timedelta(minutes=5) #by default
    data_To_encode.update({"exp": expire} ) # we will update the copy of the data with the expire time, with key of exp
    encoded_jwt = jwt.encode(   # encode the data with jwt
        data_To_encode, SECRET_KEY, algorithm=ALGORITHM
    )
    return encoded_jwt



"""function to verify the access token"""
def current_user(
        token: Annotated[str, Depends(oauth_scheme)],
        session: Annotated[Session, Depends(get_session)]
) -> User:
    credential_exception = HTTPException(  # if the token is invalid, raise an exception
        status_code = status.HTTP_401_UNAUTHORIZED,
        detail = "Invalid token, Please login again",
        headers = {"WWW-Authenticate": "Bearer"}
    )
    try:
        payload = jwt.decode(token,  SECRET_KEY, ALGORITHM)
        username: str = payload.get("sub") #extract the username from the decoded token payload with the key of sub
        if username is None:
            raise credential_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credential_exception
    user = get_user_from_db(session, username=token_data.username)
    if not user:
        raise credential_exception
    return user


"""function to create refresh token"""
def create_refresh_token(
        data: dict,
        expiry_time: timedelta | None
) -> str:
    data_to_encode = data.copy()
    if expiry_time:
        expire = datetime.now(timezone.utc) + expiry_time
    else:
        expire= datetime.now(timezone.utc) + timedelta(minutes=5)  
    data_to_encode.update({"exp": expire} )
    encoded_jwt = jwt.encode(
        data_to_encode, SECRET_KEY, algorithm=ALGORITHM
    )  
    return encoded_jwt


"""function to verify / validate the refresh token"""
def validate_refresh_token(
        token: str,
        session: Annotated[Session, Depends(get_session)]
):
    credential_exception = HTTPException(
        status_code = status.HTTP_401_UNAUTHORIZED,
        detail = "Could not validate credentials",
        headers = {"WWW-Authenticate": "Bearer"}
    )
    try:
        payload = jwt.decode(token,  SECRET_KEY, ALGORITHM)
        email: str | None = payload.get("sub")
        if email is None:
            raise credential_exception
        token_data = RefreshTokenData(email=email)
    except:
        return JWTError
    user = get_user_from_db(session, email=token_data.email)
    if not user:
        raise credential_exception
    return user


"""function to create access and refresh token upon successful login"""
def token_service(user: User) -> Token:
    expire_time = timedelta(minutes=EXPIRY_TIME)
    access_token = create_access_token(
        {"sub": user.username}, expire_time
    )
    refresh_expire_time = timedelta(days= REFRESH_EXPIRY_DAYS)
    refresh_token = create_refresh_token(
        {"sub": user.email}, refresh_expire_time
    )
    return Token(access_token=access_token, refresh_token=refresh_token)