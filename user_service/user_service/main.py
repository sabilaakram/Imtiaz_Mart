from fastapi import FastAPI, Depends, HTTPException, status
from contextlib import asynccontextmanager
from user_service.db import create_tables, get_session
from user_service.models import Token, User, Register_User
from typing import Annotated
from fastapi.security import OAuth2PasswordRequestForm
from sqlmodel import Session

from user_service import auth


@asynccontextmanager #for async code
async def lifespan(app:FastAPI):
    print('creating tables')
    create_tables() # take this function from user_service.db
    print("Tables created")
    yield

app: FastAPI = FastAPI(
    lifespan = lifespan,
    title= "User Management Service",
    version= "1.0.0",
)

@app.get("/")
async def root():
    return {"message": "User Management Service"}

#login, username, password
@app.post("/token", response_model=Token) # response model which will be used to validate and serialize the reponse data
async def login(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    session: Annotated[Session, Depends(get_session)],
) -> Token:
    user: User|None = auth.authenticate_user(
        form_data.username, form_data.password, session
    )
    if user is None:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    else:
        return auth.token_service(user)
    

@app.post("/token/refresh", response_model=Token)
def refresh_token(
    old_refresh_token: str,
    session: Annotated[Session, Depends(get_session)],
) -> Token:
    credential_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    user: User = auth.validate_refresh_token(old_refresh_token, session) # from auth.py file we will import validate_refresh_token which pass 2 arguments (old_refresh_token, session) old_refresh_token is the refresh token, that needs to be validated and session is the session
    if user is None:
        raise credential_exception
    else:
        return auth.token_service(user)
    

@app.post("/register")
async def register_user(
    new_user: Annotated[Register_User, Depends()],
    session: Annotated[Session, Depends(get_session)],
):
    db_user = auth.get_user_from_db(session,new_user.username, new_user.email)
    if db_user:
        raise HTTPException(
            status_code= 409,
            detail="Username or Email already exists",
        )
    user = User(username = new_user.username, email = new_user.email, password = auth.hash_password(new_user.password))
    session.add(user)
    session.commit()
    session.refresh(user)
    return {"message": f""" User with {user.username} successfully registered """}


@app.get("/profile", response_model=User)
async def user_profile(
    current_user: Annotated[User, Depends(auth.current_user)]
) -> User:
    return current_user