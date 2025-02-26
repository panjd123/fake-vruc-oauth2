from fastapi import FastAPI, HTTPException, Form, Request
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
from jose import jwt
from datetime import datetime, timedelta, timezone
import secrets

app = FastAPI(title="Fake VRUC Authentication Server")

# Configuration
CLIENT_ID = "vruc_test_client"
CLIENT_SECRET = "vruc_test_secret"
SECRET_KEY = secrets.token_urlsafe(32)
AUTH_HOST = "http://localhost:8000"

# Simulated database for codes and tokens
auth_codes = {}  # {code: {"client_id": str, "redirect_uri": str, "scope": str}}
access_tokens = {}  # {token: {"uid": str, "scope": str, "expires": datetime}}

# Fake user data
FAKE_USER = {
    "uid": "1085379",
    "name": "张三",
    "username": "590a8272aeb84410e6709ce7",
    "email": "zhangsan@vruc.edu.cn",
    "gender": "male",
    "phone": "+8615201458657",
    "avatar": "http://10.21.5.93/data/logo/200_1085379_0.jpg",
    "birthday": "1989-10-05",
    "profiles": [
        {
            "id": "490997",
            "code": "bfsu",
            "schoolname": "中国人民大学",
            "departmenttype": "其他",
            "departmentname": "校医院",
            "departmentid": "3911",
            "roletype": "学生",
            "rolename": "本科生",
            "stno": "20150119",
            "isprimary": True
        }
    ]
}

class TokenResponse(BaseModel):
    access_token: str
    expires_in: int
    uid: str
    token_type: str = "Bearer"
    scope: str

@app.get("/authorize")
async def authorize(
    client_id: str,
    response_type: str,
    scope: str,
    redirect_uri: str,
    state: str = None,
    school_code: str = "ruc",
    theme: str = "schools"
):
    """Simulate the authorization endpoint."""
    if client_id != CLIENT_ID:
        return RedirectResponse(
            f"{redirect_uri}?error=access_denied&state={state or ''}"
        )
    if response_type != "code":
        return RedirectResponse(
            f"{redirect_uri}?error=unsupported_response_type&state={state or ''}"
        )

    # Generate a random authorization code
    code = secrets.token_urlsafe(16)
    auth_codes[code] = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope,
        "expires": datetime.now(timezone.utc) + timedelta(minutes=5)
    }

    # Redirect back with the code
    redirect_url = f"{redirect_uri}?code={code}&state={state or ''}"
    return RedirectResponse(redirect_url)

@app.post("/token", response_model=TokenResponse)
async def token(
    client_id: str = Form(...),
    client_secret: str = Form(...),
    grant_type: str = Form(...),
    code: str = Form(...)
):
    """Simulate the token endpoint."""
    if client_id != CLIENT_ID or client_secret != CLIENT_SECRET:
        raise HTTPException(status_code=401, detail="Invalid client credentials")
    if grant_type != "authorization_code":
        raise HTTPException(status_code=400, detail="Unsupported grant_type")

    # Validate the authorization code
    if code not in auth_codes:
        raise HTTPException(
            status_code=400,
            detail={"error": "invalid_grant", "error_description": "load authorize not found"}
        )
    auth_data = auth_codes.pop(code)  # Remove code after use (single-use)
    if auth_data["expires"] < datetime.now(timezone.utc):
        raise HTTPException(
            status_code=400,
            detail={"error": "invalid_grant", "error_description": "Code expired"}
        )

    # Generate an access token
    expires_in = 3600  # 1 hour
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=expires_in)
    token_payload = {
        "sub": FAKE_USER["uid"],
        "scope": auth_data["scope"],
        "exp": int(expires_at.timestamp())  # Convert to Unix timestamp for JWT
    }
    access_token = jwt.encode(token_payload, SECRET_KEY, algorithm="HS256")
    access_tokens[access_token] = {
        "uid": FAKE_USER["uid"],
        "scope": auth_data["scope"],
        "expires": expires_at  # Store as datetime object
    }

    return {
        "access_token": access_token,
        "expires_in": expires_in,
        "uid": FAKE_USER["uid"],
        "token_type": "Bearer",
        "scope": auth_data["scope"]
    }

@app.get("/apis/oauth2/v1/user")
async def get_user(request: Request):
    """Simulate the user info endpoint."""
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid authorization header")
    
    token = auth_header.split(" ")[1]
    if token not in access_tokens:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    
    token_data = access_tokens[token]
    if token_data["expires"] < datetime.now(timezone.utc):
        raise HTTPException(status_code=401, detail="Token expired")

    # Return basic user info
    return {
        "uid": FAKE_USER["uid"],
        "name": FAKE_USER["name"],
        "username": FAKE_USER["username"]
    }

@app.get("/apis/oauth2/v1/profile")
async def get_profile(request: Request):
    """Simulate the profile endpoint."""
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid authorization header")
    
    token = auth_header.split(" ")[1]
    if token not in access_tokens:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    
    token_data = access_tokens[token]
    if token_data["expires"] < datetime.now(timezone.utc):
        raise HTTPException(status_code=401, detail="Token expired")

    # Return full profile based on scope
    if "profile" in token_data["scope"]:
        return FAKE_USER
    else:
        raise HTTPException(status_code=403, detail="Insufficient scope")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)