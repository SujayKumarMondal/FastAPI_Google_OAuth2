import os
import httpx
from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.templating import Jinja2Templates
from jose import JWTError, jwt
from pydantic import BaseModel
from fastapi.security.oauth2 import OAuth2PasswordBearer
from dotenv import load_dotenv
from typing import Optional
from fastapi.middleware.cors import CORSMiddleware

# Load environment variables
load_dotenv()

# Load credentials from the environment
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
GOOGLE_DISCOVERY_URL = os.getenv("GOOGLE_DISCOVERY_URL")
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 60))

# FastAPI instance
app = FastAPI()

# CORS Configuration
origins = ["http://localhost:3000", "http://127.0.0.1:3000"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# OAuth2 instance
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Jinja2 templates configuration
templates = Jinja2Templates(directory="templates")

# User Model
class User(BaseModel):
    email: str
    name: Optional[str] = None

# Token model
class OAuth2Token(BaseModel):
    access_token: str
    token_type: str

# Home route for the login page
@app.get("/home", response_class=HTMLResponse)
async def home(request: Request):
    google_auth_url = (
        f"https://accounts.google.com/o/oauth2/v2/auth?"
        f"client_id={GOOGLE_CLIENT_ID}&redirect_uri=http://127.0.0.1:3000/auth&response_type=code&scope=openid%20profile%20email"
    )
    return templates.TemplateResponse("index.html", {"request": request, "google_auth_url": google_auth_url})

# Root route to redirect to login
@app.get("/", response_class=RedirectResponse)
async def root():
    return RedirectResponse(url="/home")

# Google OAuth2 Login route
@app.get("/login")
async def login(request: Request):
    google_authorization_url = (
        f"https://accounts.google.com/o/oauth2/v2/auth?"
        f"client_id={GOOGLE_CLIENT_ID}&response_type=code&scope=openid%20profile%20email&redirect_uri=http://127.0.0.1:3000/auth"
    )
    return RedirectResponse(google_authorization_url)

# Handle Google OAuth2 callback
@app.get("/auth")
async def auth(code: str):
    # Exchange authorization code for access token
    token_url = "https://oauth2.googleapis.com/token"
    data = {
        "code": code,
        "client_id": GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "redirect_uri": "http://127.0.0.1:3000/auth",
        "grant_type": "authorization_code",
    }
    
    async with httpx.AsyncClient() as client:
        response = await client.post(token_url, data=data)
        response_data = response.json()

        if "access_token" not in response_data:
            raise HTTPException(status_code=400, detail="Error getting access token from Google")

        access_token = response_data["access_token"]

        # Fetch user info using the access token
        user_info_url = "https://www.googleapis.com/oauth2/v3/userinfo"
        user_info_response = await client.get(user_info_url, headers={"Authorization": f"Bearer {access_token}"})
        user_info = user_info_response.json()

        if "email" not in user_info:
            raise HTTPException(status_code=400, detail="Error fetching user info from Google")

        user = User(email=user_info["email"], name=user_info.get("name"))
        
        # Create JWT token for the user
        jwt_token = create_access_token(data={"sub": user.email})

        return {"email": user.email, "access_token": jwt_token, "token_type": "bearer"}

# Function to create JWT access tokens
def create_access_token(data: dict):
    from datetime import datetime, timedelta
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Protected route that requires JWT token
@app.get("/users/me", response_model=User)
async def read_users_me(token: str = Depends(oauth2_scheme)):
    payload = verify_access_token(token)
    email = payload.get("sub")
    if email is None:
        raise HTTPException(status_code=403, detail="Invalid credentials")
    return {"email": email}

# Verify and decode JWT token
def verify_access_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        raise HTTPException(status_code=403, detail="Could not validate credentials")

# Route for unauthorized access error handling
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return templates.TemplateResponse("error.html", {"request": request, "detail": exc.detail}, status_code=exc.status_code)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=3000)
