from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from passlib.hash import bcrypt
import sqlite3

app = FastAPI(title="AuthGuard API")

conn = sqlite3.connect("users.db", check_same_thread=False)
cursor = conn.cursor()

cursor.execute(
    """
CREATE TABLE IF NOT EXISTS users (
    email TEXT PRIMARY KEY,
    password TEXT
)
"""
)
conn.commit()


class User(BaseModel):
    email: str
    password: str


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/register")
def register(user: User):
    hashed = bcrypt.hash(user.password)
    try:
        cursor.execute("INSERT INTO users VALUES (?, ?)", (user.email, hashed))
        conn.commit()
    except:
        raise HTTPException(status_code=400, detail="User already exists")

    return {"message": "User registered"}


@app.post("/login")
def login(user: User):
    cursor.execute("SELECT password FROM users WHERE email=?", (user.email,))
    row = cursor.fetchone()

    if not row or not bcrypt.verify(user.password, row[0]):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    return {"message": "Login successful"}
