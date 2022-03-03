from pydantic import BaseModel, Field, EmailStr
from typing import Optional


class UserSchema(BaseModel):
    fullname: str = Field(...)
    email: EmailStr = Field(...)
    password: str = Field(...)
    disabled: Optional[bool] = False
    hashed_password: Optional[str] = None

    class Config:
        schema_extra = {
            "example": {
                "fullname": "John Doe",
                "email": "johndoe@gmail.com",
                "password": "password",
            }
        }


class UserLoginSchema(BaseModel):
    email: EmailStr = Field(...)
    password: str = Field(...)

    class Config:
        schema_extra = {
            "example": {"email": "johndoe@gmail.com", "password": "weakpassword"}
        }


class UserChangePasswordSchema(BaseModel):
    email: EmailStr = Field(...)
    password: str = Field(...)
    new_password: str = Field(...)

    class Config:
        schema_extra = {
            "example": {
                "email": "johndoe@gmail.com",
                "password": "password",
                "new_password": "new_password",
            }
        }


class BlogPostSchema(BaseModel):
    post: str = Field(...)
    title: str = Field(...)

    class Config:
        schema_extra = {
            "example": {
                "post": "hello there and welcome to my blog !",
                "title": "first post",
            }
        }
