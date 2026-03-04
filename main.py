"""
ВЕБ-МЕССЕНДЖЕР С ГРУППОВЫМ ЧАТОМ
"""

import os
import re
import bcrypt
from datetime import datetime, timedelta
from typing import List, Optional

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect, Depends, HTTPException, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, validator
from sqlalchemy import create_engine, Column, Integer, String, DateTime, ForeignKey, Text, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from jose import JWTError, jwt

# Конфигурация
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres:password@localhost:5432/messenger")
SECRET_KEY = os.getenv("SECRET_KEY", "supersecretkey123456")
PORT = int(os.getenv("PORT", 8000))

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 дней

# База данных
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# JWT
security = HTTPBearer()

# FastAPI
app = FastAPI(title="Messenger with Groups")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Шаблоны
templates = Jinja2Templates(directory="templates")

# ========== МОДЕЛИ БД ==========

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    username = Column(String, unique=True, index=True, nullable=False)
    full_name = Column(String, nullable=False)
    hashed_password = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Связи
    sent_messages = relationship("Message", foreign_keys="Message.sender_id", back_populates="sender")
    received_messages = relationship("Message", foreign_keys="Message.receiver_id", back_populates="receiver")
    group_memberships = relationship("GroupMember", back_populates="user")
    group_messages = relationship("GroupMessage", back_populates="sender")

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

# === НОВЫЕ МОДЕЛИ ДЛЯ ГРУПП ===

class Group(Base):
    __tablename__ = "groups"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    description = Column(String, nullable=True)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    avatar = Column(String, nullable=True)  # Для будущих аватарок
    
    # Связи
    creator = relationship("User", foreign_keys=[created_by])
    members = relationship("GroupMember", back_populates="group", cascade="all, delete-orphan")
    messages = relationship("GroupMessage", back_populates="group", cascade="all, delete-orphan")

class GroupMember(Base):
    __tablename__ = "group_members"
    
    id = Column(Integer, primary_key=True, index=True)
    group_id = Column(Integer, ForeignKey("groups.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    joined_at = Column(DateTime, default=datetime.utcnow)
    role = Column(String, default="member")  # admin, member
    is_active = Column(Boolean, default=True)
    
    # Связи
    group = relationship("Group", back_populates="members")
    user = relationship("User", back_populates="group_memberships")

class GroupMessage(Base):
    __tablename__ = "group_messages"
    
    id = Column(Integer, primary_key=True, index=True)
    group_id = Column(Integer, ForeignKey("groups.id"), nullable=False)
    sender_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    content = Column(Text, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)
    
    # Связи
    group = relationship("Group", back_populates="messages")
    sender = relationship("User", back_populates="group_messages")

# Создание таблиц
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
        from_attributes = True

class MessageResponse(BaseModel):
    id: int
    sender_id: int
    receiver_id: int
    content: str
    timestamp: datetime
    
    class Config:
        from_attributes = True

class TokenResponse(BaseModel):
    access_token: str
    token_type: str

# === НОВЫЕ СХЕМЫ ДЛЯ ГРУПП ===

class GroupCreate(BaseModel):
    name: str
    description: Optional[str] = None

class GroupResponse(BaseModel):
    id: int
    name: str
    description: Optional[str] = None
    created_by: int
    created_at: datetime
    member_count: Optional[int] = 0
    
    class Config:
        from_attributes = True

class GroupMemberResponse(BaseModel):
    id: int
    user_id: int
    username: str
    full_name: str
    role: str
    joined_at: datetime
    
    class Config:
        from_attributes = True

class GroupMessageResponse(BaseModel):
    id: int
    group_id: int
    sender_id: int
    sender_name: str
    content: str
    timestamp: datetime
    
    class Config:
        from_attributes = True

class AddGroupMember(BaseModel):
    user_id: int

# ========== ФУНКЦИИ ДЛЯ ПАРОЛЕЙ ==========

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Проверка пароля с помощью bcrypt"""
    try:
        return bcrypt.checkpw(
            plain_password.encode('utf-8'),
            hashed_password.encode('utf-8')
        )
    except Exception as e:
        print(f"Password verification error: {e}")
        return False

def get_password_hash(password: str) -> str:
    """Хеширование пароля с помощью bcrypt"""
    try:
        password_bytes = password.encode('utf-8')
        if len(password_bytes) > 72:
            password_bytes = password_bytes[:72]
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password_bytes, salt)
        return hashed.decode('utf-8')
    except Exception as e:
        print(f"Password hashing error: {e}")
        return f"$2b$12$temphash{password}"

# ========== ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ==========

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def decode_token(token: str):
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        return None

async def get_current_user(token: HTTPAuthorizationCredentials = Depends(security), db: Session = Depends(get_db)):
    payload = decode_token(token.credentials)
    if not payload:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
    user_id = payload.get("sub")
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
    return user

# ========== WEBSOCKET МЕНЕДЖЕР ==========

class ConnectionManager:
    def __init__(self):
        self.active_connections: dict[int, WebSocket] = {}

    async def connect(self, user_id: int, websocket: WebSocket):
        await websocket.accept()
        self.active_connections[user_id] = websocket
        print(f"User {user_id} connected. Total connections: {len(self.active_connections)}")

    def disconnect(self, user_id: int):
        if user_id in self.active_connections:
            del self.active_connections[user_id]
            print(f"User {user_id} disconnected. Total connections: {len(self.active_connections)}")

    async def send_personal_message(self, user_id: int, message: dict):
        if user_id in self.active_connections:
            try:
                await self.active_connections[user_id].send_json(message)
                return True
            except:
                return False
        return False

    async def send_to_group(self, group_members: list[int], message: dict, exclude_user: int = None):
        """Отправить сообщение всем участникам группы"""
        for member_id in group_members:
            if exclude_user and member_id == exclude_user:
                continue
            await self.send_personal_message(member_id, message)

manager = ConnectionManager()

# ========== ЭНДПОИНТЫ ==========

@app.get("/", response_class=HTMLResponse)
async def root():
    return RedirectResponse(url="/login")

@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})

@app.post("/register", response_class=JSONResponse)
async def register_user(user: UserCreate, db: Session = Depends(get_db)):
    # Проверка существования
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
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login", response_model=TokenResponse)
async def login(user_data: UserLogin, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == user_data.email).first()
    if not user or not verify_password(user_data.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    
    access_token = create_access_token(data={"sub": str(user.id)})
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/chat", response_class=HTMLResponse)
async def chat_page(request: Request):
    return templates.TemplateResponse("chat.html", {"request": request})

# ========== ЛИЧНЫЕ СООБЩЕНИЯ ==========

@app.get("/api/contacts", response_model=List[UserResponse])
async def get_contacts(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    users = db.query(User).filter(User.id != current_user.id).all()
    return users

@app.get("/api/messages/{user_id}", response_model=List[MessageResponse])
async def get_messages(user_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    messages = db.query(Message).filter(
        ((Message.sender_id == current_user.id) & (Message.receiver_id == user_id)) |
        ((Message.sender_id == user_id) & (Message.receiver_id == current_user.id))
    ).order_by(Message.timestamp).all()
    return messages

# ========== НОВЫЕ ЭНДПОИНТЫ ДЛЯ ГРУПП ==========

@app.post("/api/groups", response_model=GroupResponse)
async def create_group(group: GroupCreate, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Создать новую группу"""
    new_group = Group(
        name=group.name,
        description=group.description,
        created_by=current_user.id
    )
    db.add(new_group)
    db.commit()
    db.refresh(new_group)
    
    # Добавляем создателя как администратора
    member = GroupMember(
        group_id=new_group.id,
        user_id=current_user.id,
        role="admin"
    )
    db.add(member)
    db.commit()
    
    # Добавляем количество участников в ответ
    response = GroupResponse.from_orm(new_group)
    response.member_count = 1
    
    return response

@app.get("/api/groups", response_model=List[GroupResponse])
async def get_user_groups(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Получить все группы пользователя"""
    groups = db.query(Group).join(GroupMember).filter(
        GroupMember.user_id == current_user.id,
        GroupMember.is_active == True
    ).all()
    
    # Добавляем количество участников
    result = []
    for group in groups:
        group_data = GroupResponse.from_orm(group)
        group_data.member_count = db.query(GroupMember).filter(
            GroupMember.group_id == group.id,
            GroupMember.is_active == True
        ).count()
        result.append(group_data)
    
    return result

@app.get("/api/groups/{group_id}", response_model=GroupResponse)
async def get_group(group_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Получить информацию о группе"""
    group = db.query(Group).filter(Group.id == group_id).first()
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
    
    # Проверяем, является ли пользователь участником
    member = db.query(GroupMember).filter(
        GroupMember.group_id == group_id,
        GroupMember.user_id == current_user.id,
        GroupMember.is_active == True
    ).first()
    
    if not member:
        raise HTTPException(status_code=403, detail="You are not a member of this group")
    
    response = GroupResponse.from_orm(group)
    response.member_count = db.query(GroupMember).filter(
        GroupMember.group_id == group_id,
        GroupMember.is_active == True
    ).count()
    
    return response

@app.get("/api/groups/{group_id}/members", response_model=List[GroupMemberResponse])
async def get_group_members(group_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Получить список участников группы"""
    # Проверяем, является ли пользователь участником
    member = db.query(GroupMember).filter(
        GroupMember.group_id == group_id,
        GroupMember.user_id == current_user.id,
        GroupMember.is_active == True
    ).first()
    
    if not member:
        raise HTTPException(status_code=403, detail="You are not a member of this group")
    
    members = db.query(GroupMember).filter(
        GroupMember.group_id == group_id,
        GroupMember.is_active == True
    ).all()
    
    result = []
    for m in members:
        result.append(GroupMemberResponse(
            id=m.id,
            user_id=m.user_id,
            username=m.user.username,
            full_name=m.user.full_name,
            role=m.role,
            joined_at=m.joined_at
        ))
    
    return result

@app.post("/api/groups/{group_id}/members")
async def add_group_member(group_id: int, member_data: AddGroupMember, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Добавить пользователя в группу (только для админов)"""
    # Проверяем, является ли текущий пользователь админом
    admin = db.query(GroupMember).filter(
        GroupMember.group_id == group_id,
        GroupMember.user_id == current_user.id,
        GroupMember.role == "admin",
        GroupMember.is_active == True
    ).first()
    
    if not admin:
        raise HTTPException(status_code=403, detail="Only admins can add members")
    
    # Проверяем, существует ли пользователь
    user = db.query(User).filter(User.id == member_data.user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Проверяем, не состоит ли уже пользователь в группе
    existing = db.query(GroupMember).filter(
        GroupMember.group_id == group_id,
        GroupMember.user_id == member_data.user_id
    ).first()
    
    if existing:
        if existing.is_active:
            raise HTTPException(status_code=400, detail="User already in group")
        else:
            # Реактивируем
            existing.is_active = True
            db.commit()
            return {"message": "User reactivated in group"}
    
    # Добавляем нового участника
    new_member = GroupMember(
        group_id=group_id,
        user_id=member_data.user_id,
        role="member"
    )
    db.add(new_member)
    db.commit()
    
    return {"message": "User added to group"}

@app.delete("/api/groups/{group_id}/members/{user_id}")
async def remove_group_member(group_id: int, user_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Удалить пользователя из группы"""
    # Проверяем права (админ или сам пользователь)
    member = db.query(GroupMember).filter(
        GroupMember.group_id == group_id,
        GroupMember.user_id == user_id,
        GroupMember.is_active == True
    ).first()
    
    if not member:
        raise HTTPException(status_code=404, detail="Member not found")
    
    if current_user.id != user_id:
        # Проверяем, является ли текущий пользователь админом
        admin = db.query(GroupMember).filter(
            GroupMember.group_id == group_id,
            GroupMember.user_id == current_user.id,
            GroupMember.role == "admin",
            GroupMember.is_active == True
        ).first()
        
        if not admin:
            raise HTTPException(status_code=403, detail="Only admins can remove other members")
    
    # Мягкое удаление (деактивация)
    member.is_active = False
    db.commit()
    
    return {"message": "Member removed from group"}

@app.get("/api/groups/{group_id}/messages", response_model=List[GroupMessageResponse])
async def get_group_messages(group_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Получить сообщения группы"""
    # Проверяем, является ли пользователь участником
    member = db.query(GroupMember).filter(
        GroupMember.group_id == group_id,
        GroupMember.user_id == current_user.id,
        GroupMember.is_active == True
    ).first()
    
    if not member:
        raise HTTPException(status_code=403, detail="You are not a member of this group")
    
    messages = db.query(GroupMessage).filter(
        GroupMessage.group_id == group_id
    ).order_by(GroupMessage.timestamp).limit(100).all()
    
    result = []
    for msg in messages:
        result.append(GroupMessageResponse(
            id=msg.id,
            group_id=msg.group_id,
            sender_id=msg.sender_id,
            sender_name=msg.sender.full_name,
            content=msg.content,
            timestamp=msg.timestamp
        ))
    
    return result

# ========== WEBSOCKET ==========

@app.websocket("/ws/{user_id}")
async def websocket_endpoint(websocket: WebSocket, user_id: int, db: Session = Depends(get_db)):
    await manager.connect(user_id, websocket)
    
    try:
        while True:
            data = await websocket.receive_json()
            message_type = data.get("type")
            
            if message_type == "message":
                # Личное сообщение
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
                
            elif message_type == "group_message":
                # Групповое сообщение
                group_id = data.get("group_id")
                content = data.get("content")
                
                # Проверяем, является ли пользователь участником группы
                member = db.query(GroupMember).filter(
                    GroupMember.group_id == group_id,
                    GroupMember.user_id == user_id,
                    GroupMember.is_active == True
                ).first()
                
                if not member:
                    continue  # Игнорируем, если не участник
                
                # Сохраняем в БД
                db_message = GroupMessage(
                    group_id=group_id,
                    sender_id=user_id,
                    content=content
                )
                db.add(db_message)
                db.commit()
                
                # Получаем всех участников группы
                members = db.query(GroupMember).filter(
                    GroupMember.group_id == group_id,
                    GroupMember.is_active == True
                ).all()
                
                # Получаем имя отправителя
                sender = db.query(User).filter(User.id == user_id).first()
                sender_name = sender.full_name if sender else f"User {user_id}"
                
                # Отправляем всем участникам
                message_data = {
                    "type": "group_message",
                    "group_id": group_id,
                    "sender_id": user_id,
                    "sender_name": sender_name,
                    "content": content,
                    "timestamp": datetime.utcnow().isoformat()
                }
                
                for member in members:
                    if member.user_id != user_id:  # Не отправляем отправителю
                        await manager.send_personal_message(member.user_id, message_data)
                
            elif message_type in ["offer", "answer", "ice-candidate"]:
                # WebRTC сигнализация для личных звонков
                target_user_id = data.get("target_user_id")
                if target_user_id:
                    # Добавляем sender_id в данные
                    data["sender_id"] = user_id
                    await manager.send_personal_message(target_user_id, data)
                    
            elif message_type == "group_call_offer":
                # Сигнализация для групповых звонков
                target_user_id = data.get("target_user_id")
                group_id = data.get("group_id")
                if target_user_id and group_id:
                    data["sender_id"] = user_id
                    await manager.send_personal_message(target_user_id, data)
                    
            elif message_type == "group_call_answer":
                target_user_id = data.get("target_user_id")
                if target_user_id:
                    data["sender_id"] = user_id
                    await manager.send_personal_message(target_user_id, data)
                    
            elif message_type == "group_call_ice":
                target_user_id = data.get("target_user_id")
                if target_user_id:
                    data["sender_id"] = user_id
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
    uvicorn.run("main:app", host="0.0.0.0", port=PORT, reload=False)
