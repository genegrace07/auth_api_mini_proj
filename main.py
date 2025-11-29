from fastapi import FastAPI,Form,Depends,Request,HTTPException,status
from jose import jwt
from passlib.context import CryptContext
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse,RedirectResponse
from pydantic import  BaseModel
from fastapi.security import OAuth2PasswordRequestForm,OAuth2PasswordBearer,HTTPBearer
import json
import os
from datetime import datetime,timedelta

app = FastAPI()

class Users(BaseModel):
    id:int
    username:str
    password:str

templates = Jinja2Templates(directory="templates")
pwd_context = CryptContext(schemes=['sha256_crypt'],deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl='/')
oauth2_scheme2 = OAuth2PasswordBearer(tokenUrl='/bearer_token')
bearer_scheme = HTTPBearer()
SECRET_KEY = "mysecretkey"
ALGORITHM = 'HS256'
token_expire = 15

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
        if not os.path.exists(user_data) or os.path.getsize(user_data) == 0:
            with open(user_data,'w') as f:
                json.dump([],f)

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
@app.get('/main',response_class=HTMLResponse)
def main(request:Request):
    return templates.TemplateResponse('main.html',{'request':request})

@app.post('/',response_class=HTMLResponse)
async def login_post(username:str=Form(),password:str=Form()):
    with open(user_data,'r') as f:
        data = json.load(f)
    get_data = next((d for d in data if username == d['username']),None)
    if not get_data:
        return 'Invalid username'
    verify_pwd = pwd_context.verify(password,get_data['password'])
    if not verify_pwd:
        return 'Invalid password'

    expiry = datetime.utcnow() + timedelta(minutes=token_expire)
    for_payload = {"id":get_data['id'],"username":get_data['username'],"exp":expiry}
    your_token = jwt.encode(for_payload,SECRET_KEY,algorithm=ALGORITHM)
    response = RedirectResponse('/main',status_code=303)
    response.set_cookie('token',your_token)
    return response
@app.post('/bearer_token')
async def bearer_token(form:OAuth2PasswordRequestForm=Depends()):
    username = form.username
    password = form.password
    with open(user_data,'r') as f:
        data = json.load(f)
    get_data = next((d for d in data if d['username'] == username),None)
    if not get_data:
        return 'Invalid username'
    get_pwd = pwd_context.verify(password,get_data['password'])
    if not get_pwd:
        return 'Invalid password'

    expire = datetime.utcnow() + timedelta(minutes=token_expire)
    for_payload = {'id':get_data['id'],'username':get_data['username'],'exp':expire}
    your_token = jwt.encode(for_payload,SECRET_KEY,algorithm=ALGORITHM)
    return {'access_token':your_token,'token_type':'bearer','user':get_data}
def verify_token(token:str):
    try:
        decode_token = jwt.decode(token,SECRET_KEY,algorithms=ALGORITHM)
        return decode_token
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail='Invalid token or token expired')
@app.get('/protected')
async def protected(request:Request,bearer_token:str=Depends(oauth2_scheme2)):

    if bearer_token:
        user = verify_token(bearer_token)
        return {'auth':'bearer','user':user}
    cookies_token = request.cookies.get('token')
    if cookies_token:
       user = verify_token(cookies_token)
       return {'auth':'cookies','user':user}
    return HTTPException(status_code=401,detail='Token invalid')
@app.get('/view_users')
async def view_users(token:str=Depends(oauth2_scheme2)):
    if not verify_token(token):
        return HTTPException(status_code=401,detail='Invalid or expired token')

    with open(user_data,'r') as f:
        data = json.load(f)
    return data

