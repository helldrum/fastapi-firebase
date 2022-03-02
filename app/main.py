import time
import os
import sys
import json
import requests
import firebase_admin
from firebase_admin import auth

from fastapi import FastAPI, Body, Depends
from fastapi.exceptions import HTTPException
from fastapi.security.http import HTTPBearer, HTTPBasicCredentials

from app.model import UserSchema, UserLoginSchema, UserChangePasswordSchema

FIREBASE_API_KEY = os.getenv("FIREBASE_API_KEY")
if not FIREBASE_API_KEY:
    print("env var FIREBASE_API_KEY is missing.")
    sys.exit(-1)

firebase_admin_app = firebase_admin.initialize_app()
USER_CLAIMS = {"profile": "user"}

bearer_auth = HTTPBearer()

app = FastAPI()


@app.get("/")
def root():
    return {""}


@app.post("/user/signup", tags=["user"])
async def create_user(user: UserSchema = Body(...)):
    try:
        user = auth.create_user(email=user.email, password=user.password)
        custom_token = auth.create_custom_token(user.uid, USER_CLAIMS)
        return {"token": custom_token}
    except firebase_admin._auth_utils.EmailAlreadyExistsError as msg_error:
        raise HTTPException(status_code=409, detail=str(msg_error))
        return {"error": str(msg_error)}

@app.post("/user/polite_if_you_are_admin", tags=["user"])
async def polite_if_you_are_admin(token: HTTPBasicCredentials = Depends(bearer_auth)):
    response = await sign_in_with_custom_token(token)
    if response.get("error"):
        return response

    user = auth.verify_id_token(response["idToken"])
    if not user:
        return {"error": "JWT token is not valid"}

    if "admin" not in user['profile']:
        return {"hey ! get the fuck out of here ! i'am gonna call the police !"}
    else:
        return {"welcome home, dear admin"}    


@app.post("/user/get_claims", tags=["user"])
async def get_user_claim(token: HTTPBasicCredentials = Depends(bearer_auth)):
    response = await sign_in_with_custom_token(token)
    if response.get("error"):
        return response

    user = auth.verify_id_token(response["idToken"])
    if not user:
        return {"error": "JWT token is not valid"}
    return {"profile": user['profile'], "user_id": user["user_id"]}


async def check_user_identity(email, password):
    request_ref = "https://www.googleapis.com/identitytoolkit/v3/relyingparty/verifyPassword?key={0}".format(
        FIREBASE_API_KEY
    )
    headers = {"content-type": "application/json; charset=UTF-8"}
    data = json.dumps({"email": email, "password": password, "returnSecureToken": True})
    request_object = requests.post(request_ref, headers=headers, data=data)
    if "20" not in str(request_object.status_code):
        time.sleep(3)
        msg_error="wrong login or password."
        raise HTTPException(status_code=403, detail=msg_error)
        return {"error": msg_error}

    return request_object.json()


async def sign_in_with_custom_token(token):
    request_ref = "https://identitytoolkit.googleapis.com/v1/accounts:signInWithCustomToken?key={0}".format(
        FIREBASE_API_KEY
    )
    headers = {"content-type": "application/json; charset=UTF-8"}

    data = json.dumps({"token": token.credentials,"returnSecureToken":True})

    request_object = requests.post(request_ref, headers=headers, data=data)

    if "20" not in str(request_object.status_code):
        time.sleep(3)
        msg_error="error during sign custom token."
        raise HTTPException(status_code=403, detail=msg_error)
        return {"error": msg_error}
    return request_object.json()


@app.post("/user/signin", tags=["user"])
async def login_user(user: UserLoginSchema = Body(...)):
    response = await check_user_identity(email=user.email, password=user.password)
    if response.get("error"):
        return response

    user = response
    custom_token = auth.create_custom_token(user["localId"], USER_CLAIMS)
    return {"token": custom_token}


@app.post("/user/changepassword", tags=["user"])
async def change_user_password(user: UserChangePasswordSchema = Body(...)):
    response = await check_user_identity(email=user.email, password=user.password)
    if response.get("error"):
        return response
    current_user = response

    auth.update_user(
        uid=current_user["localId"], email=user.email, password=user.new_password
    )

    response = await check_user_token(email=user.email, password=user.new_password)
    if response.get("error"):
        return {"error": "error during password change."}
    current_user = response

    custom_token = auth.create_custom_token(current_user["localId"], USER_CLAIMS)
    return {"token": custom_token}
