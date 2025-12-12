# app.py - FINAL VERSION (100% WORKING)
from fastapi import FastAPI, Request, Form, HTTPException, Depends, Query, Cookie, UploadFile, File
from fastapi.responses import RedirectResponse, HTMLResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean, and_
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from datetime import datetime
import hashlib
from typing import List, Optional
import requests
from binance.client import Client
import json
import os
from cryptography.fernet import Fernet
import base64

# Encryption setup
ENCRYPTION_KEY = os.getenv('ENCRYPTION_KEY', base64.urlsafe_b64encode(os.urandom(32)).decode())
cipher = Fernet(ENCRYPTION_KEY.encode())

def encrypt_data(data: str) -> str:
    if not data:
        return ""
    return cipher.encrypt(data.encode()).decode()

def decrypt_data(encrypted_data: str) -> str:
    if not encrypted_data:
        return ""
    try:
        return cipher.decrypt(encrypted_data.encode()).decode()
    except:
        return ""

# ===================== DATABASE =====================
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, nullable=False, index=True)
    email = Column(String, unique=True, nullable=False, index=True)
    hashed_password = Column(String, nullable=False)
    first_name = Column(String)
    last_name = Column(String)
    country = Column(String)
    phone = Column(String)
    timezone = Column(String, default="UTC-5")
    bio = Column(String)
    experience = Column(String)
    trading_type = Column(String)
    default_timeframe = Column(String)
    theme = Column(String, default="dark")
    language = Column(String, default="English")
    chart_type = Column(String, default="candlestick")
    price_alerts = Column(Boolean, default=True)
    show_trading_stats = Column(Boolean, default=False)
    allow_messages = Column(Boolean, default=True)
    email_marketing = Column(Boolean, default=False)
    email_notifications = Column(Boolean, default=True)
    push_notifications = Column(Boolean, default=True)
    sms_notifications = Column(Boolean, default=False)
    enable_2fa = Column(Boolean, default=False)
    avatar_path = Column(String)
    binance_api_key = Column(String)
    binance_secret_key = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)

# Fix: Use proper SQLite URL and allow multi-thread
engine = create_engine(
    "sqlite:///database.db",
    connect_args={"check_same_thread": False},
    echo=False
)
Base.metadata.create_all(bind=engine)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# ===================== FASTAPI APP =====================
app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# Binance Client (public API, no keys needed)
binance_client = Client("", "")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

# ===================== ROUTES =====================

@app.get("/register")
async def register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})

@app.get("/login")
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

# FIXED: Proper async + correct query logic
@app.get("/api/check-username")
async def check_username(username: str = Query(...), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username.ilike(username.strip())).first()
    return {"available": user is None}

@app.get("/api/check-email")
async def check_email(email: str = Query(...), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email.ilike(email.strip())).first()
    return {"available": user is None}

# FIXED: Proper OR condition + strip inputs
@app.post("/register")
async def register(
    request: Request,
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    firstName: str = Form(""),
    lastName: str = Form(""),
    country: str = Form(""),
    phone: str = Form(""),
    experience: str = Form("intermediate"),
    tradingType: List[str] = Form([]),
    defaultTimeframe: str = Form("4h"),
    theme: str = Form("dark"),
    enable2fa: bool = Form(False),
    db: Session = Depends(get_db)
):
    username = username.strip()
    email = email.strip().lower()

    existing = db.query(User).filter(
        (User.username.ilike(username)) | (User.email.ilike(email))
    ).first()

    if existing:
        raise HTTPException(status_code=400, detail="Username or email already registered")

    user = User(
        username=username,
        email=email,
        hashed_password=hash_password(password),
        first_name=firstName,
        last_name=lastName,
        country=country,
        phone=phone,
        timezone="UTC-5",
        bio="",
        experience=experience,
        trading_type=",".join(tradingType) if tradingType else "futures",
        default_timeframe=defaultTimeframe,
        theme=theme,
        language="English",
        chart_type="candlestick",
        price_alerts=True,
        show_trading_stats=False,
        allow_messages=True,
        email_marketing=False,
        email_notifications=True,
        push_notifications=True,
        sms_notifications=False,
        enable_2fa=enable2fa,
        avatar_path=None,
        binance_api_key=None,
        binance_secret_key=None
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    return RedirectResponse("/login?registered=1", status_code=303)

# FIXED: Proper login with case-insensitive email
@app.post("/login")
async def login(
    email: str = Form(...),
    password: str = Form(...),
    remember: bool = Form(False),
    db: Session = Depends(get_db)
):
    email = email.strip().lower()
    user = db.query(User).filter(User.email.ilike(email)).first()

    if not user or user.hashed_password != hash_password(password):
        raise HTTPException(status_code=400, detail="Invalid credentials")

    response = RedirectResponse("/", status_code=303)
    max_age = 3600 * 24 * 30 if remember else 3600 * 24
    response.set_cookie(
        key="user_id",
        value=str(user.id),
        httponly=True,
        secure=False,
        samesite="lax",
        max_age=max_age
    )
    return response

@app.get("/logout")
async def logout():
    response = RedirectResponse("/", status_code=303)
    response.delete_cookie("user_id")
    return response

# ===================== BINANCE API ENDPOINTS =====================

@app.get("/api/binance/ticker")
async def get_binance_ticker():
    try:
        # Use requests for 24hr ticker data which includes change percentages
        url = "https://api.binance.com/api/v3/ticker/24hr"
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        tickers = response.json()
        return {"tickers": tickers}
    except requests.exceptions.RequestException as e:
        print(f"Ticker Request error: {e}")
        raise HTTPException(status_code=500, detail=f"Request error: {str(e)}")
    except Exception as e:
        print(f"Ticker General error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/binance/candles/{symbol}")
async def get_binance_candles(symbol: str, interval: str = "1h", limit: int = 100):
    try:
        candles = binance_client.get_klines(symbol=symbol.upper(), interval=interval, limit=limit)
        # Format candles for ApexCharts
        formatted_candles = []
        for candle in candles:
            formatted_candles.append({
                "x": int(candle[0]),  # timestamp
                "y": [float(candle[1]), float(candle[2]), float(candle[3]), float(candle[4])]  # OHLC
            })
        return {"candles": formatted_candles}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/binance/24hr")
async def get_binance_24hr():
    try:
        # Use requests directly for 24hr ticker
        url = "https://api.binance.com/api/v3/ticker/24hr"
        print(f"Making request to: {url}")
        response = requests.get(url, timeout=10)
        print(f"Response status: {response.status_code}")
        response.raise_for_status()
        stats = response.json()
        print(f"Got {len(stats)} stats")
        return {"stats": stats}
    except requests.exceptions.RequestException as e:
        print(f"Request error: {e}")
        raise HTTPException(status_code=500, detail=f"Request error: {str(e)}")
    except Exception as e:
        print(f"General error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# FINAL: Home page with NO CACHING + proper user detection
@app.get("/", response_class=HTMLResponse)
async def index(request: Request, user_id: Optional[str] = Cookie(None), db: Session = Depends(get_db)):
    user = None
    if user_id:
        try:
            uid = int(user_id)
            user = db.query(User).filter(User.id == uid).first()
        except:
            pass

    response = templates.TemplateResponse("index.html", {"request": request, "user": user})

    if user:
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"

    return response

# Dashboard (protected)
@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request, user_id: Optional[str] = Cookie(None), db: Session = Depends(get_db)):
    if not user_id:
        return RedirectResponse("/login", status_code=303)

    try:
        user = db.query(User).get(int(user_id))
        if not user:
            return RedirectResponse("/login", status_code=303)
    except:
        return RedirectResponse("/login", status_code=303)

    return templates.TemplateResponse("dashboard.html", {"request": request, "user": user})

# Profile (protected)
@app.get("/profile", response_class=HTMLResponse)
async def profile(request: Request, user_id: Optional[str] = Cookie(None), db: Session = Depends(get_db)):
    if not user_id:
        return RedirectResponse("/login", status_code=303)

    try:
        user = db.query(User).get(int(user_id))
        if not user:
            return RedirectResponse("/login", status_code=303)
    except:
        return RedirectResponse("/login", status_code=303)

    return templates.TemplateResponse("profile.html", {"request": request, "user": user})

# ===================== PROFILE API ENDPOINTS =====================

@app.post("/api/profile/personal")
async def update_personal_info(
    request: Request,
    first_name: str = Form(""),
    last_name: str = Form(""),
    phone: str = Form(""),
    country: str = Form(""),
    timezone: str = Form(""),
    bio: str = Form(""),
    user_id: Optional[str] = Cookie(None),
    db: Session = Depends(get_db)
):
    if not user_id:
        raise HTTPException(status_code=401, detail="Not authenticated")

    user = db.query(User).filter(User.id == int(user_id)).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.first_name = first_name.strip() or None
    user.last_name = last_name.strip() or None
    user.phone = phone.strip() or None
    user.country = country.strip() or None
    user.timezone = timezone.strip() or "UTC-5"
    user.bio = bio.strip() or None

    db.commit()
    return {"success": True, "message": "Personal information updated successfully"}

@app.post("/api/profile/password")
async def change_password(
    request: Request,
    current_password: str = Form(...),
    new_password: str = Form(...),
    confirm_password: str = Form(...),
    user_id: Optional[str] = Cookie(None),
    db: Session = Depends(get_db)
):
    if not user_id:
        raise HTTPException(status_code=401, detail="Not authenticated")

    user = db.query(User).filter(User.id == int(user_id)).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user.hashed_password != hash_password(current_password):
        raise HTTPException(status_code=400, detail="Current password is incorrect")

    if new_password != confirm_password:
        raise HTTPException(status_code=400, detail="New passwords do not match")

    if len(new_password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")

    user.hashed_password = hash_password(new_password)
    db.commit()
    return {"success": True, "message": "Password changed successfully"}

@app.post("/api/profile/2fa")
async def toggle_2fa(
    request: Request,
    enabled: bool = Form(...),
    user_id: Optional[str] = Cookie(None),
    db: Session = Depends(get_db)
):
    if not user_id:
        raise HTTPException(status_code=401, detail="Not authenticated")

    user = db.query(User).filter(User.id == int(user_id)).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.enable_2fa = enabled
    db.commit()
    return {"success": True, "message": f"2FA {'enabled' if enabled else 'disabled'} successfully"}

@app.post("/api/profile/preferences")
async def update_preferences(
    request: Request,
    theme: str = Form("dark"),
    chart_type: str = Form("candlestick"),
    default_timeframe: str = Form("1h"),
    price_alerts: bool = Form(True),
    show_trading_stats: bool = Form(False),
    allow_messages: bool = Form(True),
    email_marketing: bool = Form(False),
    user_id: Optional[str] = Cookie(None),
    db: Session = Depends(get_db)
):
    if not user_id:
        raise HTTPException(status_code=401, detail="Not authenticated")

    user = db.query(User).filter(User.id == int(user_id)).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.theme = theme
    user.chart_type = chart_type
    user.default_timeframe = default_timeframe
    user.price_alerts = price_alerts
    user.show_trading_stats = show_trading_stats
    user.allow_messages = allow_messages
    user.email_marketing = email_marketing

    db.commit()
    return {"success": True, "message": "Preferences updated successfully"}

@app.post("/api/profile/notifications")
async def update_notifications(
    request: Request,
    email_notifications: bool = Form(True),
    push_notifications: bool = Form(True),
    sms_notifications: bool = Form(False),
    user_id: Optional[str] = Cookie(None),
    db: Session = Depends(get_db)
):
    if not user_id:
        raise HTTPException(status_code=401, detail="Not authenticated")

    user = db.query(User).filter(User.id == int(user_id)).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.email_notifications = email_notifications
    user.push_notifications = push_notifications
    user.sms_notifications = sms_notifications

    db.commit()
    return {"success": True, "message": "Notification settings updated successfully"}

@app.post("/api/profile/trading")
async def update_trading_profile(
    request: Request,
    experience: str = Form(""),
    trading_type: str = Form(""),
    risk_tolerance: str = Form("medium"),
    trading_style: str = Form("swing"),
    user_id: Optional[str] = Cookie(None),
    db: Session = Depends(get_db)
):
    if not user_id:
        raise HTTPException(status_code=401, detail="Not authenticated")

    user = db.query(User).filter(User.id == int(user_id)).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.experience = experience.strip() if experience.strip() else None
    user.trading_type = trading_type.strip() if trading_type.strip() else None

    db.commit()
    return {"success": True, "message": "Trading profile updated successfully"}

@app.get("/api/profile/export")
async def export_user_data(
    request: Request,
    user_id: Optional[str] = Cookie(None),
    db: Session = Depends(get_db)
):
    if not user_id:
        raise HTTPException(status_code=401, detail="Not authenticated")

    user = db.query(User).filter(User.id == int(user_id)).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Create export data (exclude sensitive info)
    export_data = {
        "username": user.username,
        "email": user.email,
        "first_name": user.first_name,
        "last_name": user.last_name,
        "country": user.country,
        "phone": user.phone,
        "timezone": user.timezone,
        "bio": user.bio,
        "experience": user.experience,
        "trading_type": user.trading_type,
        "default_timeframe": user.default_timeframe,
        "theme": user.theme,
        "language": user.language,
        "chart_type": user.chart_type,
        "price_alerts": user.price_alerts,
        "show_trading_stats": user.show_trading_stats,
        "allow_messages": user.allow_messages,
        "email_marketing": user.email_marketing,
        "email_notifications": user.email_notifications,
        "push_notifications": user.push_notifications,
        "sms_notifications": user.sms_notifications,
        "enable_2fa": user.enable_2fa,
        "avatar_path": user.avatar_path,
        "binance_connected": bool(user.binance_api_key and user.binance_secret_key),
        "created_at": user.created_at.isoformat(),
        "exported_at": datetime.utcnow().isoformat()
    }

    import json
    from fastapi.responses import JSONResponse

    response = JSONResponse(content=export_data)
    response.headers["Content-Disposition"] = f'attachment; filename="{user.username}_profile_export.json"'
    return response

@app.post("/api/profile/avatar")
async def upload_avatar(
    request: Request,
    avatar: UploadFile = File(...),
    user_id: Optional[str] = Cookie(None),
    db: Session = Depends(get_db)
):
    if not user_id:
        raise HTTPException(status_code=401, detail="Not authenticated")

    user = db.query(User).filter(User.id == int(user_id)).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Validate file type
    if not avatar.content_type.startswith('image/'):
        raise HTTPException(status_code=400, detail="File must be an image")

    # Create uploads directory if it doesn't exist
    upload_dir = "static/uploads/avatars"
    os.makedirs(upload_dir, exist_ok=True)

    # Generate unique filename
    file_extension = os.path.splitext(avatar.filename)[1]
    filename = f"{user.id}_{datetime.utcnow().timestamp()}{file_extension}"
    file_path = os.path.join(upload_dir, filename)

    # Save file
    with open(file_path, "wb") as buffer:
        content = await avatar.read()
        buffer.write(content)

    # Update user avatar path
    user.avatar_path = f"/static/uploads/avatars/{filename}"
    db.commit()

    return {"success": True, "message": "Avatar uploaded successfully", "avatar_url": user.avatar_path}

@app.post("/api/profile/binance-keys")
async def update_binance_keys(
    request: Request,
    api_key: str = Form(""),
    secret_key: str = Form(""),
    user_id: Optional[str] = Cookie(None),
    db: Session = Depends(get_db)
):
    if not user_id:
        raise HTTPException(status_code=401, detail="Not authenticated")

    user = db.query(User).filter(User.id == int(user_id)).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Validate keys if provided
    if api_key and secret_key:
        try:
            # Test the keys by making a simple API call
            test_client = Client(api_key.strip(), secret_key.strip())
            test_client.get_account()
        except Exception as e:
            raise HTTPException(status_code=400, detail="Invalid API keys")

        # Encrypt and store keys
        user.binance_api_key = encrypt_data(api_key.strip())
        user.binance_secret_key = encrypt_data(secret_key.strip())
    else:
        # Remove keys
        user.binance_api_key = None
        user.binance_secret_key = None

    db.commit()
    return {"success": True, "message": "Binance API keys updated successfully"}

@app.get("/api/profile/binance-balance")
async def get_binance_balance(
    request: Request,
    user_id: Optional[str] = Cookie(None),
    db: Session = Depends(get_db)
):
    if not user_id:
        raise HTTPException(status_code=401, detail="Not authenticated")

    user = db.query(User).filter(User.id == int(user_id)).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if not user.binance_api_key or not user.binance_secret_key:
        raise HTTPException(status_code=400, detail="Binance API keys not configured")

    try:
        api_key = decrypt_data(user.binance_api_key)
        secret_key = decrypt_data(user.binance_secret_key)
        client = Client(api_key, secret_key)

        # Get account information
        account = client.get_account()
        balances = account['balances']

        # Filter out zero balances and format
        filtered_balances = []
        for balance in balances:
            free = float(balance['free'])
            locked = float(balance['locked'])
            total = free + locked
            if total > 0:
                filtered_balances.append({
                    'asset': balance['asset'],
                    'free': free,
                    'locked': locked,
                    'total': total
                })

        return {"balances": filtered_balances}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error fetching balance: {str(e)}")