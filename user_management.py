import sqlite3 as sql
import time
import random
from werkzeug.security import generate_password_hash, check_password_hash
from markupsafe import escape
import os

print("DB path:", os.path.abspath("database_files/database.db"))


def save_totp_secret(username, secret):
    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    cur.execute("SELECT username FROM users WHERE username = ?", (username,))
    print("User found:", cur.fetchone())
    cur.execute(
        "UPDATE users SET totp_secret = ? WHERE username = ?",
        (secret, username),
    )
    con.commit()
    con.close()


def get_totp_secret(username):
    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    cur.execute(
        "SELECT totp_secret FROM users WHERE username = ?",
        (username,),
    )
    row = cur.fetchone()
    con.close()
    if row:
        return row[0]
    return None


def insertUser(username, password, DoB):
    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    hashed_password = generate_password_hash(password)
    cur.execute(
        "INSERT INTO users (username,password,dateOfBirth) VALUES (?,?,?)",
        (username, hashed_password, DoB),
    )
    con.commit()
    con.close()


def retrieveUsers(username, password):
    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    cur.execute("SELECT password FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    if row is None:
        con.close()
        return False

    stored_hash = row[0]
    if check_password_hash(stored_hash, password):
        con.close()
        return True

    con.close()
    return False


def insertFeedback(feedback):
    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    cur.execute("INSERT INTO feedback (feedback) VALUES (?)", (feedback,))
    con.commit()
    con.close()


def listFeedback():
    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    data = cur.execute("SELECT * FROM feedback").fetchall()
    con.close()
    f = open("templates/partials/success_feedback.html", "w")
    for row in data:
        f.write("<p>\n")
        f.write(f"{escape(row[1])}\n")
        f.write("</p>\n")
    f.close()
