"""
ВЕБ-МЕССЕНДЖЕР С ВИДЕОЗВОНКАМИ
Один файл - всё включено!
"""
import bcrypt
import os
import re
from datetime import datetime, timedelta
from typing import List, Optional

# Импорты
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect, Depends, HTTPException, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, validator
from sqlalchemy import create_engine, Column, Integer, String, DateTime, ForeignKey, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from jose import JWTError, jwt
import json

# Конфигурация из переменных окружения
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres:password@localhost:5432/messenger")
SECRET_KEY = os.getenv("SECRET_KEY", "supersecretkey123456")
PORT = int(os.getenv("PORT", 8000))

# Настройки JWT
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 дней

# Настройки базы данных (синхронная, без asyncpg)
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# JWT биндер
security = HTTPBearer()

# Инициализация FastAPI
app = FastAPI(title="Messenger with Video Calls")

# Шаблоны
templates = Jinja2Templates(directory="templates")


# ========== МОДЕЛИ БАЗЫ ДАННЫХ ==========
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    username = Column(String, unique=True, index=True, nullable=False)  # Должен начинаться с #
    full_name = Column(String, nullable=False)
    hashed_password = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Связи
    sent_messages = relationship("Message", foreign_keys="Message.sender_id", back_populates="sender")
    received_messages = relationship("Message", foreign_keys="Message.receiver_id", back_populates="receiver")


class Message(Base):
    __tablename__ = "messages"

    id = Column(Integer, primary_key=True, index=True)
    sender_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    receiver_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    content = Column(Text, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)

    # Связи
    sender = relationship("User", foreign_keys=[sender_id], back_populates="sent_messages")
    receiver = relationship("User", foreign_keys=[receiver_id], back_populates="received_messages")


# Создание таблиц при запуске (⚠️ БАЗА СОЗДАЕТСЯ АВТОМАТИЧЕСКИ)
Base.metadata.create_all(bind=engine)


# ========== СХЕМЫ PYDANTIC ==========
class UserCreate(BaseModel):
    email: EmailStr
    username: str
    full_name: str
    password: str

    @validator('username')
    def username_must_start_with_hash(cls, v):
        if not re.match(r'^#\w+$', v):
            raise ValueError('Username must start with # and contain only letters, numbers, underscore')
        return v


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class UserResponse(BaseModel):
    id: int
    email: str
    username: str
    full_name: str

    class Config:
        orm_mode = True


class MessageResponse(BaseModel):
    id: int
    sender_id: int
    receiver_id: int
    content: str
    timestamp: datetime

    class Config:
        orm_mode = True


class TokenResponse(BaseModel):
    access_token: str
    token_type: str


# ========== ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ==========
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def verify_password(plain_password, hashed_password):
    """Проверка пароля с помощью bcrypt"""
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))


def get_password_hash(password):
    """Хеширование пароля с помощью bcrypt"""
    # Ограничим пароль до 72 байт (ограничение bcrypt)
    if len(password.encode('utf-8')) > 72:
        password = password[:72]  # Обрезаем до 72 символов
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def decode_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return None


async def get_current_user(token: HTTPAuthorizationCredentials = Depends(security), db: Session = Depends(get_db)):
    payload = decode_token(token.credentials)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
        )
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
        )
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )
    return user


# ========== WEBSOCKET МЕНЕДЖЕР ==========
class ConnectionManager:
    def __init__(self):
        self.active_connections: dict[int, WebSocket] = {}

    async def connect(self, user_id: int, websocket: WebSocket):
        await websocket.accept()
        self.active_connections[user_id] = websocket

    def disconnect(self, user_id: int):
        if user_id in self.active_connections:
            del self.active_connections[user_id]

    async def send_personal_message(self, user_id: int, message: dict):
        if user_id in self.active_connections:
            await self.active_connections[user_id].send_json(message)

    async def broadcast(self, message: dict):
        for connection in self.active_connections.values():
            await connection.send_json(message)


manager = ConnectionManager()


# ========== ЭНДПОИНТЫ ==========
@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    """Редирект на страницу логина"""
    return RedirectResponse(url="/login")


@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    """Страница регистрации"""
    return templates.TemplateResponse("register.html", {"request": request})


@app.post("/register", response_class=JSONResponse)
async def register_user(user: UserCreate, db: Session = Depends(get_db)):
    """Регистрация нового пользователя (без подтверждения почты!)"""
    # Проверка существования пользователя
    db_user = db.query(User).filter(
        (User.email == user.email) | (User.username == user.username)
    ).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Email or username already registered")

    # Создание пользователя
    hashed_password = get_password_hash(user.password)
    db_user = User(
        email=user.email,
        username=user.username,
        full_name=user.full_name,
        hashed_password=hashed_password
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)

    return {"message": "User created successfully"}


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    """Страница входа"""
    return templates.TemplateResponse("login.html", {"request": request})


@app.post("/login", response_model=TokenResponse)
async def login(user_data: UserLogin, db: Session = Depends(get_db)):
    """Вход и получение JWT токена"""
    user = db.query(User).filter(User.email == user_data.email).first()
    if not user or not verify_password(user_data.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect email or password")

    access_token = create_access_token(data={"sub": str(user.id)})
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/chat", response_class=HTMLResponse)
async def chat_page(request: Request, token: str = None):
    """Главная страница чата"""
    return templates.TemplateResponse("chat.html", {"request": request})


@app.get("/api/contacts", response_model=List[UserResponse])
async def get_contacts(
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """Получить список всех пользователей кроме себя"""
    users = db.query(User).filter(User.id != current_user.id).all()
    return users


@app.get("/api/messages/{user_id}", response_model=List[MessageResponse])
async def get_messages(
        user_id: int,
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """Получить историю переписки с конкретным пользователем"""
    messages = db.query(Message).filter(
        ((Message.sender_id == current_user.id) & (Message.receiver_id == user_id)) |
        ((Message.sender_id == user_id) & (Message.receiver_id == current_user.id))
    ).order_by(Message.timestamp).all()
    return messages


@app.websocket("/ws/{user_id}")
async def websocket_endpoint(websocket: WebSocket, user_id: int, db: Session = Depends(get_db)):
    """WebSocket для сообщений и WebRTC сигнализации"""
    await manager.connect(user_id, websocket)

    try:
        while True:
            data = await websocket.receive_json()
            message_type = data.get("type")

            if message_type == "message":
                # Обычное сообщение
                receiver_id = data.get("receiver_id")
                content = data.get("content")

                # Сохраняем в БД
                db_message = Message(
                    sender_id=user_id,
                    receiver_id=receiver_id,
                    content=content
                )
                db.add(db_message)
                db.commit()

                # Отправляем получателю
                message_data = {
                    "type": "message",
                    "sender_id": user_id,
                    "content": content,
                    "timestamp": datetime.utcnow().isoformat()
                }
                await manager.send_personal_message(receiver_id, message_data)

                # Отправляем подтверждение отправителю
                await websocket.send_json({
                    "type": "message_delivered",
                    "receiver_id": receiver_id,
                    "content": content
                })

            elif message_type in ["offer", "answer", "ice-candidate"]:
                # WebRTC сигнализация
                target_user_id = data.get("target_user_id")
                if target_user_id:
                    await manager.send_personal_message(target_user_id, data)

    except WebSocketDisconnect:
        manager.disconnect(user_id)
    except Exception as e:
        print(f"WebSocket error: {e}")
        manager.disconnect(user_id)


# ========== ЗАПУСК ==========
if __name__ == "__main__":
    import uvicorn

    print(f"Starting server on port {PORT}")

    uvicorn.run("main:app", host="0.0.0.0", port=PORT, reload=True)
