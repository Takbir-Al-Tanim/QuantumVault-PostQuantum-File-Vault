from pathlib import Path
import base64
import secrets

path = Path('.env')
if path.exists():
    print('.env already exists. Delete it first if you want to regenerate keys.')
    raise SystemExit(0)

flask_secret = secrets.token_urlsafe(48)
master_key = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()

content = f'''FLASK_SECRET_KEY={flask_secret}\nSERVER_MASTER_KEY_B64={master_key}\nDB_HOST=127.0.0.1\nDB_PORT=3306\nDB_USER=root\nDB_PASSWORD=\nDB_NAME=pq_file_vault\nMAX_CONTENT_MB=60\n'''
path.write_text(content, encoding='utf-8')
print('Created .env with fresh cryptographic secrets.')
print('Now edit DB_USER / DB_PASSWORD if your MySQL setup needs them.')
