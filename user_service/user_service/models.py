from sqlmodel import SQLModel, Field
from fastapi import Form
from typing import Annotated

class User (SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True) #Field is used to define the properties
    username: str
    email: str
    password: str


class Register_User(SQLModel):
    username: Annotated[str, Form()]
    email: Annotated[str, Form()]
    password: Annotated[str, Form()]

    
class Token(SQLModel):
    access_token: str
    token_type: str
    refresh_token: str

class TokenData(SQLModel):
    username: str

class RefreshTokenData(SQLModel):
    email: str