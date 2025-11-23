from fastapi import FastAPI,Form,Depends,Request
from jose import jwt
from passlib.context import CryptContext
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
from pydantic import  BaseModel
from fastapi.security import OAuth2PasswordRequestForm
import json
import os

app = FastAPI()

class Users(BaseModel):
    id:int
    username:str
    password:str

templates = Jinja2Templates(directory="templates")

data = []
user_data = 'data.json'

@app.get('/',response_class=HTMLResponse)
async def login(request:Request):
    return templates.TemplateResponse('login.html',{"request":request})

@app.post('/signup',response_class=HTMLResponse)
async def signup(username:str=Form(...),password:str=Form(...)):
        if os.path.getsize(user_data) == 0:
            data = []

        with open(user_data,"w") as f:
            new_data = {"id":0,"username":"","password":""}
            read_data = json.dump(new_data,f,indent=4)


@app.post('/',response_class=HTMLResponse)
async def login(username:str=Form(),password:str=Form()):
    return templates.TemplateResponse('login.html')

