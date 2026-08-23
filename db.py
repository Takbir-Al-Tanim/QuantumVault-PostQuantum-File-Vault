from contextlib import contextmanager
import mysql.connector
from flask import current_app


def get_connection():
    return mysql.connector.connect(
        host=current_app.config['DB_HOST'],
        port=current_app.config['DB_PORT'],
        user=current_app.config['DB_USER'],
        password=current_app.config['DB_PASSWORD'],
        database=current_app.config['DB_NAME'],
        autocommit=False,
    )


@contextmanager
def db_cursor(dictionary=True):
    conn = get_connection()
    cur = conn.cursor(dictionary=dictionary)
    try:
        yield conn, cur
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        cur.close()
        conn.close()
