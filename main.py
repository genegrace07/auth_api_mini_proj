from fastapi import FastAPI,Form,Depends,Request
from jose import jwt
from passlib.context import CryptContext
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse,RedirectResponse
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
pwd_context = CryptContext(schemes=['sha256_crypt'],deprecated="auto")

data = []

user_data = 'data.json'

@app.get('/',response_class=HTMLResponse)
async def login_get(request:Request):
    return templates.TemplateResponse('login.html',{"request":request})
@app.get('/signup',response_class=HTMLResponse)
async def signup_get(request:Request):
    return templates.TemplateResponse('signup.html',{"request":request})
@app.post('/signup',response_class=HTMLResponse)
async def signup_post(request:Request,username:str=Form(...),password:str=Form(...)):
        if os.path.getsize(user_data) == 0:
            data = []

        with open(user_data,'r') as f:
            data=json.load(f)

        new_id = len(data)
        pwd_hash = pwd_context.hash(password)
        new_entry = {"id":new_id,"username":username,"password":pwd_hash}
        data.append(new_entry)
        #print(data) #FOR CHECKING THE OUTPUT
        with open(user_data,"w") as f:
            json.dump(data,f,indent=4)
        return templates.TemplateResponse("signup.html",{"request":request})
@app.post('/',response_class=HTMLResponse)
async def login_post(username:str=Form(),password:str=Form()):
    return templates.TemplateResponse('login.html')

