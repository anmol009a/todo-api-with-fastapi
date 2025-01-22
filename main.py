import os
from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy import create_engine, Column, Integer, String, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from pydantic import BaseModel
import bcrypt
import jwt
from typing import List

# Database configuration
DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./test.db")
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# Models
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)


class Todo(Base):
    __tablename__ = "todos"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(255), nullable=False)
    completed = Column(Boolean, default=False)
    owner_id = Column(Integer, nullable=False)


Base.metadata.create_all(bind=engine)


# Pydantic models
class TodoCreate(BaseModel):
    title: str
    completed: bool = False


class TodoResponse(TodoCreate):
    id: int
    owner_id: int

    class Config:
        orm_mode = True


class UserCreate(BaseModel):
    username: str
    password: str


class Token(BaseModel):
    access_token: str
    token_type: str


# Security
SECRET_KEY = os.environ.get(
    "SECRET_KEY", "your_secret_key"  # Ensure this key is kept secret and secure
)
ALGORITHM = os.environ.get("ALGORITHM", "HS256")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_current_user(
    token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)
) -> User:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user = db.query(User).filter(User.id == payload["sub"]).first()
        if not user:
            raise HTTPException(
                status_code=401, detail="Invalid authentication credentials"
            )
        return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")
    except Exception as e:
        raise HTTPException(
            status_code=500, detail="Server error during authentication"
        )


# FastAPI app
app = FastAPI()


@app.post("/users/", response_model=Token)
def create_user(user: UserCreate, db: Session = Depends(get_db)):
    hashed_password = bcrypt.hashpw(user.password.encode("utf-8"), bcrypt.gensalt())
    db_user = User(
        username=user.username, hashed_password=hashed_password.decode("utf-8")
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    token = jwt.encode({"sub": str(db_user.id)}, SECRET_KEY, algorithm=ALGORITHM)
    return {"access_token": token, "token_type": "bearer"}


@app.post("/token", response_model=Token)
def login(
    form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not bcrypt.checkpw(
        form_data.password.encode("utf-8"), user.hashed_password.encode("utf-8")
    ):
        raise HTTPException(status_code=400, detail="Invalid username or password")
    token = jwt.encode({"sub": str(user.id)}, SECRET_KEY, algorithm=ALGORITHM)
    return {"access_token": token, "token_type": "bearer"}


@app.post("/todos/", response_model=TodoResponse)
def create_todo(
    todo: TodoCreate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    db_todo = Todo(**todo.model_dump(), owner_id=user.id)
    db.add(db_todo)
    db.commit()
    db.refresh(db_todo)
    return db_todo


@app.get("/todos/", response_model=List[TodoResponse])
def get_todos(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    return db.query(Todo).filter(Todo.owner_id == user.id).all()


@app.put("/todos/{todo_id}", response_model=TodoResponse)
def update_todo(
    todo_id: int,
    todo: TodoCreate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    db_todo = (
        db.query(Todo).filter(Todo.id == todo_id, Todo.owner_id == user.id).first()
    )
    if not db_todo:
        raise HTTPException(status_code=404, detail="Todo not found")
    db_todo.title = todo.title
    db_todo.completed = todo.completed
    db.commit()
    db.refresh(db_todo)
    return db_todo


@app.delete("/todos/{todo_id}")
def delete_todo(
    todo_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)
):
    db_todo = (
        db.query(Todo).filter(Todo.id == todo_id, Todo.owner_id == user.id).first()
    )
    if not db_todo:
        raise HTTPException(status_code=404, detail="Todo not found")
    db.delete(db_todo)
    db.commit()
    return {"detail": "Todo deleted successfully"}
