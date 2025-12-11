from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from jose import jwt
import requests

app = FastAPI()
app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")

# ---------------- Keycloak Config ----------------
KEYCLOAK_SERVER = "http://localhost:8080"
REALM = "fastapi-demo"
CLIENT_ID = "fastapi-client"

# ---------------- Token Verification ----------------
def verify_token(token: str):
    
    try:
        jwks_url = f"{KEYCLOAK_SERVER}/realms/{REALM}/protocol/openid-connect/certs"
        jwks = requests.get(jwks_url).json()
        unverified_header = jwt.get_unverified_header(token)
        kid = unverified_header["kid"]
        key = next(k for k in jwks["keys"] if k["kid"] == kid)
        payload = jwt.decode(
            token,
            key,
            algorithms=["RS256"],
            options={"verify_aud": False}  # Skip audience check for demo
        )
        return payload
    except Exception as e:
        print("Token verification failed:", e)
        return None

def has_role(user, role_name: str):
    return role_name in user.get("realm_access", {}).get("roles", [])

# ---------------- Routes ----------------
@app.get("/", response_class=HTMLResponse)
def root():
    return RedirectResponse(url="/login")

@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login")
def login(request: Request, username: str = Form(...), password: str = Form(...)):
    token_url = f"{KEYCLOAK_SERVER}/realms/{REALM}/protocol/openid-connect/token"
    data = {
        "grant_type": "password",
        "client_id": CLIENT_ID,
        "username": username,
        "password": password
    }

    resp = requests.post(token_url, data=data)
    resp_json = resp.json()

    if "access_token" not in resp_json:
        error = resp_json.get("error_description", "Invalid credentials")
        return templates.TemplateResponse("login.html", {"request": request, "error": error})

    access_token = resp_json["access_token"]
    response = RedirectResponse(url="/home", status_code=302)
    # Use httponly for security, secure=False for localhost testing
    response.set_cookie(key="access_token", value=access_token, httponly=True, secure=False)
    return response

@app.get("/home", response_class=HTMLResponse)
def home(request: Request):
    access_token = request.cookies.get("access_token")
    if not access_token:
        return RedirectResponse(url="/login")
    user = verify_token(access_token)
    if not user:
        return RedirectResponse(url="/login")
    return templates.TemplateResponse("home.html", {"request": request, "user": user})

@app.get("/admin", response_class=HTMLResponse)
def admin_page(request: Request):
    access_token = request.cookies.get("access_token")
    if not access_token:
        return RedirectResponse(url="/login")
    user = verify_token(access_token)
    if not user:
        return RedirectResponse(url="/login")
    if not has_role(user, "admin"):
        return HTMLResponse("<h2>Access Denied: Admins only</h2>", status_code=403)
    return templates.TemplateResponse("admin.html", {"request": request, "user": user})

@app.get("/logout")
def logout():
    response = RedirectResponse(url="/login", status_code=302)
    response.delete_cookie("access_token")
    return response
