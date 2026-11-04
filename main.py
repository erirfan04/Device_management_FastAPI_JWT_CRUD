
from datetime import datetime, timedelta, timezone
import os

import jwt
from jwt.exceptions import InvalidTokenError

from dotenv import load_dotenv

from fastapi import (
    FastAPI,
    Depends,
    HTTPException,
    status,
    Request
)

from fastapi.security import (
    OAuth2PasswordBearer,
    OAuth2PasswordRequestForm
)

from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from pydantic import BaseModel, Field


# ==========================================
# 1. LOAD ENVIRONMENT VARIABLES
# ==========================================

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM", "HS256")

ACCESS_TOKEN_EXPIRE_MINUTES = int(
    os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30")
)

if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY is missing in .env")


# ==========================================
# 2. INITIALIZE FASTAPI
# ==========================================

app = FastAPI(
    title="Device Management API",
    description="JWT Secured CRUD API using FastAPI",
    version="1.0"
)


# ==========================================
# 3. OAUTH2 CONFIGURATION
# ==========================================

oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="login"
)


# ==========================================
# 4. DUMMY USER DATABASE
# ==========================================

fake_users_db = {
    "irfan": {
        "username": "irfan",
        "password": "admin123",
        "role": "ADMIN"
    },
    "user1": {
        "username": "user1",
        "password": "user123",
        "role": "USER"
    }
}


# ==========================================
# 5. DEVICE DATABASE
# ==========================================

devices_db = {}

device_id_counter = 1


# ==========================================
# 6. PYDANTIC MODELS
# ==========================================

class DeviceCreate(BaseModel):

    name: str = Field(min_length=3, max_length=50)

    device_type: str

    location: str


class DeviceUpdate(BaseModel):

    name: str | None = Field(
        default=None,
        min_length=3,
        max_length=50
    )

    device_type: str | None = None

    location: str | None = None


class TokenResponse(BaseModel):

    access_token: str

    token_type: str

    expires_in: int


# ==========================================
# 7. CUSTOM API EXCEPTION
# ==========================================

class APIException(Exception):

    def __init__(
        self,
        status_code: int,
        code: str,
        message: str,
        details=None
    ):

        self.status_code = status_code
        self.code = code
        self.message = message
        self.details = details


# ==========================================
# 8. GLOBAL EXCEPTION HANDLERS
# ==========================================

@app.exception_handler(APIException)
async def api_exception_handler(
    request: Request,
    exc: APIException
):

    return JSONResponse(
        status_code=exc.status_code,
        content={
            "success": False,
            "error": {
                "code": exc.code,
                "message": exc.message,
                "details": exc.details
            }
        }
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(
    request: Request,
    exc: RequestValidationError
):

    return JSONResponse(
        status_code=422,
        content={
            "success": False,
            "error": {
                "code": "VALIDATION_ERROR",
                "message": "Request validation failed",
                "details": exc.errors()
            }
        }
    )


@app.exception_handler(HTTPException)
async def http_exception_handler(
    request: Request,
    exc: HTTPException
):

    return JSONResponse(
        status_code=exc.status_code,
        headers=exc.headers,
        content={
            "success": False,
            "error": {
                "code": "HTTP_ERROR",
                "message": str(exc.detail),
                "details": None
            }
        }
    )


# ==========================================
# 9. AUTHENTICATE USER
# ==========================================

def authenticate_user(username: str, password: str):

    user = fake_users_db.get(username)

    if not user:
        return None

    if user["password"] != password:
        return None

    return user


# ==========================================
# 10. GENERATE JWT TOKEN
# ==========================================

def create_access_token(data: dict):

    to_encode = data.copy()

    expire = datetime.now(timezone.utc) + timedelta(
        minutes=ACCESS_TOKEN_EXPIRE_MINUTES
    )

    to_encode.update({
        "exp": expire
    })

    encoded_jwt = jwt.encode(
        to_encode,
        SECRET_KEY,
        algorithm=ALGORITHM
    )

    return encoded_jwt


# ==========================================
# 11. VALIDATE JWT TOKEN
# ==========================================

def get_current_user(
    token: str = Depends(oauth2_scheme)
):

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired access token",
        headers={
            "WWW-Authenticate": "Bearer"
        }
    )

    try:

        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM]
        )

        username = payload.get("sub")

        if username is None:
            raise credentials_exception

        user = fake_users_db.get(username)

        if user is None:
            raise credentials_exception

        return user

    except InvalidTokenError:
        raise credentials_exception


# ==========================================
# 12. LOGIN API
# ==========================================

@app.post("/login", response_model=TokenResponse)
def login(
    form_data: OAuth2PasswordRequestForm = Depends()
):

    user = authenticate_user(
        form_data.username,
        form_data.password
    )

    if not user:

        raise HTTPException(
            status_code=401,
            detail="Incorrect username or password",
            headers={
                "WWW-Authenticate": "Bearer"
            }
        )

    access_token = create_access_token(
        data={
            "sub": user["username"],
            "role": user["role"]
        }
    )

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60
    }


# ==========================================
# 13. HOME API
# ==========================================

@app.get("/")
def home():

    return {
        "success": True,
        "message": "Welcome to Device Management API"
    }


# ==========================================
# 14. CREATE DEVICE API
# ==========================================

@app.post("/devices/", status_code=201)
def create_device(
    device: DeviceCreate,
    current_user=Depends(get_current_user)
):

    global device_id_counter

    device_data = {
        "id": device_id_counter,
        "name": device.name,
        "device_type": device.device_type,
        "location": device.location,
        "created_by": current_user["username"]
    }

    devices_db[device_id_counter] = device_data

    device_id_counter += 1

    return {
        "success": True,
        "message": "Device created successfully",
        "data": device_data
    }


# ==========================================
# 15. GET ALL DEVICES API
# ==========================================

@app.get("/devices/")
def get_all_devices(
    current_user=Depends(get_current_user)
):

    return {
        "success": True,
        "message": "Devices retrieved successfully",
        "data": list(devices_db.values())
    }


# ==========================================
# 16. GET DEVICE BY ID API
# ==========================================

@app.get("/devices/{device_id}")
def get_device(
    device_id: int,
    current_user=Depends(get_current_user)
):

    device = devices_db.get(device_id)

    if not device:

        raise APIException(
            status_code=404,
            code="DEVICE_NOT_FOUND",
            message="Device not found"
        )

    return {
        "success": True,
        "message": "Device retrieved successfully",
        "data": device
    }


# ==========================================
# 17. UPDATE DEVICE API
# ==========================================

@app.put("/devices/{device_id}")
def update_device(
    device_id: int,
    device: DeviceUpdate,
    current_user=Depends(get_current_user)
):

    existing_device = devices_db.get(device_id)

    if not existing_device:

        raise APIException(
            status_code=404,
            code="DEVICE_NOT_FOUND",
            message="Device not found"
        )

    update_data = device.model_dump(
        exclude_unset=True
    )

    existing_device.update(update_data)

    return {
        "success": True,
        "message": "Device updated successfully",
        "data": existing_device
    }


# ==========================================
# 18. DELETE DEVICE API
# ==========================================

@app.delete("/devices/{device_id}")
def delete_device(
    device_id: int,
    current_user=Depends(get_current_user)
):

    device = devices_db.get(device_id)

    if not device:

        raise APIException(
            status_code=404,
            code="DEVICE_NOT_FOUND",
            message="Device not found"
        )

    del devices_db[device_id]

    return {
        "success": True,
        "message": "Device deleted successfully",
        "data": {
            "id": device_id
        }
    }


# ==========================================
# 19. CURRENT USER API
# ==========================================

@app.get("/users/me")
def get_logged_in_user(
    current_user=Depends(get_current_user)
):

    return {
        "success": True,
        "message": "User details retrieved successfully",
        "data": {
            "username": current_user["username"],
            "role": current_user["role"]
        }
    }
