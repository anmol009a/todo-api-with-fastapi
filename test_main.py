from fastapi.testclient import TestClient
import sqlite3
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from main import Base, get_db

from main import app  # Assuming your FastAPI app is in a file named main.py

client = TestClient(app)

# create test db
SQLALCHEMY_DATABASE_URL = "sqlite:///./test.db"
engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# reset test db
Base.metadata.drop_all(bind=engine)
Base.metadata.create_all(bind=engine)


def override_get_db():
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db


def create_user():
    return client.post("/users/", json={"username": "testuser", "password": "testpass"})


def login_with_api():
    return client.post("/token/", data={"username": "testuser", "password": "testpass"})


def test_create_user_with_api():
    response = create_user()
    assert response.status_code == 201


def test_login_with_api():
    response = login_with_api()
    assert response.status_code == 200
    assert "access_token" in response.json()


def test_create_todo():
    access_token = login_with_api().json()["access_token"]
    response = client.post(
        "/todos/",
        json={"title": "Test Todo"},
        headers={"Authorization": f"Bearer {access_token}"},
    )

    assert response.status_code == 201
    assert response.json()["title"] == "Test Todo"


def test_read_todo():
    access_token = login_with_api().json()["access_token"]
    response = client.get(
        "/todos/",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert response.status_code == 200


def test_update_todo():
    access_token = login_with_api().json()["access_token"]
    response = client.put(
        "/todos/1",
        json={"title": "Updated Todo"},
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert response.status_code == 200
    assert response.json()["title"] == "Updated Todo"


def test_delete_todo():
    access_token = login_with_api().json()["access_token"]

    response = client.delete(
        "/todos/1",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert response.status_code == 204
