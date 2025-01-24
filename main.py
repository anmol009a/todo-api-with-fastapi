"""
This module implements a FastAPI application for a Todo API with user authentication.
Modules:
  os: Provides a way of using operating system dependent functionality.
  fastapi: A modern, fast (high-performance), web framework for building APIs with Python 3.6+.
  sqlalchemy: SQL toolkit and Object-Relational Mapping (ORM) library for Python.
  pydantic: Data validation and settings management using Python type annotations.
  bcrypt: Library for hashing passwords.
  pyjwt: Library for encoding and decoding JSON Web Tokens.
  typing: Provides runtime support for type hints.
  dotenv: Reads key-value pairs from a .env file and can set them as environment variables.
Functions:
  get_db(): Dependency that provides a database session to be used in FastAPI routes.
  get_current_user(token: str, db: Session) -> User: Retrieve the current user based on the provided JWT token.
FastAPI Routes:
  create_user(user: UserCreate, db: Session) -> dict: Create a new user in the database.
  login(form_data: OAuth2PasswordRequestForm, db: Session) -> dict: Authenticates a user and returns a JWT token if the credentials are valid.
  create_todo(
    todo: TodoCreate, db: Session, user: User
  ) -> Todo: Create a new todo item.
  get_todos(db: Session, user: User) -> List[Todo]: Retrieve a list of todo items for the current user.
  update_todo(
    todo_id: int, todo: TodoCreate, db: Session, user: User
  ) -> Todo: Update an existing todo item.
  delete_todo(
    todo_id: int, db: Session, user: User
  ) -> dict: Delete a todo item.
Classes:
  User: Represents a user in the database.
  Todo: Represents a Todo item in the database.
  TodoCreate: Pydantic model used for creating a new Todo item.
  TodoResponse: Pydantic model that extends TodoCreate and includes additional fields for the todo item's ID and owner ID.
  UserCreate: Pydantic model used for creating a new user.
  Token: Pydantic model representing the structure of an authentication token.
"""

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
from dotenv import load_dotenv

load_dotenv("./.env")

# Database configuration
DATABASE_URL = os.getenv("DB_URL", "sqlite:///./todo.db")
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# Models
class User(Base):
    """
    Represents a user in the database.
    Attributes:
      id (int): The unique identifier for the user.
      username (str): The username of the user, must be unique and not null.
      hashed_password (str): The hashed password of the user, must not be null.
    """

    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)


class Todo(Base):
    """
    Represents a Todo item in the database.
    Attributes:
      id (int): The primary key of the todo item.
      title (str): The title of the todo item. Cannot be null.
      completed (bool): Indicates whether the todo item is completed. Defaults to False.
      owner_id (int): The ID of the owner of the todo item. Cannot be null.
    """

    __tablename__ = "todos"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(255), nullable=False)
    completed = Column(Boolean, default=False)
    owner_id = Column(Integer, nullable=False)


# Create tables if not exists
Base.metadata.create_all(bind=engine)


# Pydantic models
class TodoCreate(BaseModel):
    """
    TodoCreate is a Pydantic model used for creating a new Todo item.
    Attributes:
      title (str): The title of the Todo item.
      completed (bool): The completion status of the Todo item. Defaults to False.
    """

    title: str
    completed: bool = False


class TodoResponse(TodoCreate):
    """
    TodoResponse is a Pydantic model that extends TodoCreate and includes additional fields for the todo item's ID and owner ID.
    Attributes:
      id (int): The unique identifier for the todo item.
      owner_id (int): The unique identifier for the owner of the todo item.
    """

    id: int
    owner_id: int


class UserCreate(BaseModel):
    """
    UserCreate is a Pydantic model used for creating a new user.
    Attributes:
      username (str): The username of the user.
      password (str): The password of the user.
    """

    username: str
    password: str


class Token(BaseModel):
    """
    Token model representing the structure of an authentication token.
    Attributes:
      access_token (str): The access token string used for authentication.
      token_type (str): The type of the token, typically "Bearer".
    """

    access_token: str
    token_type: str


# Security
SECRET_KEY = os.getenv(
    "SECRET_KEY", "your_secret_key"  # Ensure this key is kept secret and secure
)
ALGORITHM = os.environ.get("ALGORITHM", "HS256")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def get_db():
    """
    Dependency that provides a database session to be used in FastAPI routes.
    Yields:
      Session: A SQLAlchemy database session.
    Ensures that the database session is properly closed after use.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_current_user(
    token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)
) -> User:
    """
    Retrieve the current user based on the provided JWT token.
    Args:
      token (str): The JWT token provided by the user.
      db (Session): The database session dependency.
    Returns:
      User: The authenticated user.
    Raises:
      HTTPException: If the token is invalid, expired, or if there is no user
               associated with the token.
      HTTPException: If there is a server error during authentication.
    """
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


@app.post("/users/", response_model=Token, status_code=201)
def create_user(user: UserCreate, db: Session = Depends(get_db)):
    """
    Create a new user in the database.
    Args:
      user (UserCreate): The user data to create a new user.
      db (Session, optional): The database session dependency.
    Returns:
      dict: A dictionary containing the access token and token type.
    """
    # check if user exists
    checkUser = db.query(User).filter(User.username == user.username).first()
    if checkUser is None:
        # create user
        hashed_password = bcrypt.hashpw(user.password.encode("utf-8"), bcrypt.gensalt())
        db_user = User(
            username=user.username, hashed_password=hashed_password.decode("utf-8")
        )
        db.add(db_user)
        db.commit()
        db.refresh(db_user)
        token = jwt.encode({"sub": str(db_user.id)}, SECRET_KEY, algorithm=ALGORITHM)
        return {"access_token": token, "token_type": "bearer"}
    else:
        raise HTTPException(status_code=400, detail="Username already exists.")


@app.post("/token", response_model=Token)
def login(
    form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)
):
    """
    Authenticates a user and returns a JWT token if the credentials are valid.
    Args:
      form_data (OAuth2PasswordRequestForm): The form data containing the username and password.
      db (Session): The database session dependency.
    Returns:
      dict: A dictionary containing the access token and token type.
    Raises:
      HTTPException: If the username or password is invalid.
    """

    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not bcrypt.checkpw(
        form_data.password.encode("utf-8"), user.hashed_password.encode("utf-8")
    ):
        raise HTTPException(status_code=400, detail="Invalid username or password")
    token = jwt.encode({"sub": str(user.id)}, SECRET_KEY, algorithm=ALGORITHM)
    return {"access_token": token, "token_type": "bearer"}


@app.post("/todos/", response_model=TodoResponse, status_code=201)
def create_todo(
    todo: TodoCreate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """
    Create a new todo item.
    Args:
      todo (TodoCreate): The todo item data to create.
      db (Session): The database session dependency.
      user (User): The current authenticated user dependency.
    Returns:
      Todo: The created todo item.
    """

    db_todo = Todo(**todo.model_dump(), owner_id=user.id)
    db.add(db_todo)
    db.commit()
    db.refresh(db_todo)
    return db_todo


@app.get("/todos/", response_model=List[TodoResponse], status_code=200)
def get_todos(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    """
    Retrieve a list of todo items for the current user.
    Args:
      db (Session): Database session dependency.
      user (User): Current authenticated user dependency.
    Returns:
      List[Todo]: A list of todo items that belong to the current user.
    """

    return db.query(Todo).filter(Todo.owner_id == user.id).all()


@app.put("/todos/{todo_id}", response_model=TodoResponse)
def update_todo(
    todo_id: int,
    todo: TodoCreate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """
    Update an existing todo item.
    Args:
      todo_id (int): The ID of the todo item to update.
      todo (TodoCreate): The new data for the todo item.
      db (Session, optional): The database session. Defaults to Depends(get_db).
      user (User, optional): The current authenticated user. Defaults to Depends(get_current_user).
    Raises:
      HTTPException: If the todo item is not found.
    Returns:
      Todo: The updated todo item.
    """

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


@app.delete("/todos/{todo_id}", status_code=204)
def delete_todo(
    todo_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)
):
    """
    Delete a todo item.
    Args:
      todo_id (int): The ID of the todo item to delete.
      db (Session): The database session dependency.
      user (User): The current authenticated user dependency.
    Raises:
      HTTPException: If the todo item is not found.
    Returns:
      dict: A dictionary containing a success message.
    """
    db_todo = (
        db.query(Todo).filter(Todo.id == todo_id, Todo.owner_id == user.id).first()
    )
    if not db_todo:
        raise HTTPException(status_code=404, detail="Todo not found")
    db.delete(db_todo)
    db.commit()
    return {"detail": "Todo deleted successfully"}
