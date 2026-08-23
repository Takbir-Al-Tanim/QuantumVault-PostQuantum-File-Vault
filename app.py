import base64
import csv
import io
import json
import os
import time
import tracemalloc
import uuid
from functools import wraps
from pathlib import Path

from cryptography.exceptions import InvalidTag
from flask import (
    Flask, Response, flash, jsonify, redirect, render_template, request,
    send_file, session, url_for
)
from flask_wtf.csrf import CSRFProtect
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

from config import Config
from db import db_cursor
from crypto.benchmark import run_single_benchmark
from crypto.engine import (
    MLKEM_ALGORITHM, create_share_envelope, decrypt_for_user, decrypt_shared_file,
    encrypt_for_user, generate_user_mlkem_keypair, recover_owner_file_key,
    wrap_user_secret_key
)

BASE_DIR = Path(__file__).resolve().parent
ENCRYPTED_DIR = BASE_DIR / 'storage' / 'encrypted'
ENCRYPTED_DIR.mkdir(parents=True, exist_ok=True)

ALLOWED_EXTENSIONS = {'txt', 'pdf', 'jpg', 'jpeg', 'png', 'csv', 'zip'}

app = Flask(__name__)
app.config.from_object(Config)
csrf = CSRFProtect(app)


def validate_runtime_config():
    if not app.config['SECRET_KEY'] or app.config['SECRET_KEY'] == 'replace_me':
        raise RuntimeError('FLASK_SECRET_KEY is missing. Run: python setup_env.py')
    if not app.config['SERVER_MASTER_KEY_B64'] or app.config['SERVER_MASTER_KEY_B64'] == 'replace_me':
        raise RuntimeError('SERVER_MASTER_KEY_B64 is missing. Run: python setup_env.py')


validate_runtime_config()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in first.', 'warning')
            return redirect(url_for('login'))
        return view(*args, **kwargs)
    return wrapped


def get_current_user():
    if 'user_id' not in session:
        return None
    with db_cursor() as (_, cur):
        cur.execute('SELECT * FROM users WHERE id=%s', (session['user_id'],))
        return cur.fetchone()


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def file_extension(filename):
    return filename.rsplit('.', 1)[1].lower() if '.' in filename else ''


def audit(user_id, action, target_type=None, target_id=None, detail=None):
    try:
        with db_cursor() as (_, cur):
            cur.execute(
                '''INSERT INTO audit_logs
                   (user_id, action, target_type, target_id, detail, ip_address)
                   VALUES (%s,%s,%s,%s,%s,%s)''',
                (user_id, action, target_type, target_id, detail, request.remote_addr),
            )
    except Exception:
        app.logger.exception('Audit logging failed')


def bytes_per_second_mbps(size_bytes, time_ms):
    if not time_ms or time_ms <= 0:
        return None
    mb = size_bytes / (1024 * 1024)
    return round(mb / (time_ms / 1000), 4)


def normalize_folder_id(value):
    if value in (None, '', 'root', 'null'):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def get_owned_folder(folder_id, user_id):
    if folder_id is None:
        return None
    with db_cursor() as (_, cur):
        cur.execute('SELECT * FROM folders WHERE id=%s AND owner_id=%s', (folder_id, user_id))
        return cur.fetchone()


def get_folder_breadcrumb(folder_id, user_id):
    crumbs = []
    current_id = folder_id
    seen = set()
    while current_id and current_id not in seen and len(crumbs) < 50:
        seen.add(current_id)
        with db_cursor() as (_, cur):
            cur.execute('SELECT id,name,parent_id FROM folders WHERE id=%s AND owner_id=%s', (current_id, user_id))
            row = cur.fetchone()
        if not row:
            break
        crumbs.append(row)
        current_id = row['parent_id']
    crumbs.reverse()
    return crumbs


def build_folder_options(user_id):
    with db_cursor() as (_, cur):
        cur.execute('SELECT id,name,parent_id FROM folders WHERE owner_id=%s ORDER BY name', (user_id,))
        rows = cur.fetchall()
    by_id = {r['id']: r for r in rows}
    cache = {}

    def label(row):
        if row['id'] in cache:
            return cache[row['id']]
        parts = [row['name']]
        parent_id = row['parent_id']
        seen = {row['id']}
        while parent_id and parent_id in by_id and parent_id not in seen:
            seen.add(parent_id)
            parent = by_id[parent_id]
            parts.append(parent['name'])
            parent_id = parent['parent_id']
        value = ' / '.join(reversed(parts))
        cache[row['id']] = value
        return value

    return [{'id': r['id'], 'name': r['name'], 'parent_id': r['parent_id'], 'path_label': label(r)} for r in rows]


def store_encrypted_file(user, safe_name, plaintext, folder_id=None, audit_action='UPLOAD_ENCRYPTED'):
    if folder_id is not None and not get_owned_folder(folder_id, user['id']):
        raise ValueError('Destination folder was not found.')

    file_uuid = str(uuid.uuid4())
    encrypted_filename = f'{file_uuid}.vault'
    target = ENCRYPTED_DIR / encrypted_filename

    total_start = time.perf_counter_ns()
    tracemalloc.start()
    try:
        crypto = encrypt_for_user(
            plaintext,
            bytes(user['mlkem_public_key']),
            user['id'],
            file_uuid,
        )
        target.write_bytes(crypto['encrypted'])

        total_end = time.perf_counter_ns()
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        total_ms = round((total_end - total_start) / 1_000_000, 4)

        with db_cursor() as (_, cur):
            cur.execute(
                '''INSERT INTO files
                   (file_uuid,owner_id,folder_id,original_filename,encrypted_filename,file_type,
                    original_size,encrypted_size,mlkem_ciphertext,hkdf_salt,chacha_nonce)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)''',
                (
                    file_uuid, user['id'], folder_id, safe_name, encrypted_filename,
                    file_extension(safe_name), len(plaintext), len(crypto['encrypted']),
                    crypto['kem_ciphertext'], crypto['salt'], crypto['nonce'],
                ),
            )
            file_id = cur.lastrowid

            timings = crypto['timings']
            throughput = bytes_per_second_mbps(len(plaintext), timings['encrypt_ms'])
            cur.execute(
                '''INSERT INTO performance_logs
                   (user_id,file_id,operation,file_type,file_size_bytes,ciphertext_size_bytes,
                    mlkem_encap_ms,hkdf_ms,encrypt_ms,total_ms,throughput_mbps,peak_memory_kb)
                   VALUES (%s,%s,'upload',%s,%s,%s,%s,%s,%s,%s,%s,%s)''',
                (
                    user['id'], file_id, file_extension(safe_name), len(plaintext),
                    len(crypto['encrypted']), timings['kem_encap_ms'], timings['hkdf_ms'],
                    timings['encrypt_ms'], total_ms, throughput, round(peak / 1024, 2),
                ),
            )

        audit(user['id'], audit_action, 'file', str(file_id), safe_name)

        trace = [
            {
                'name': 'Validate input', 'algorithm': 'Application', 'status': 'complete',
                'time_ms': 0, 'detail': f'{safe_name} accepted ({len(plaintext):,} bytes).',
                'summary': 'The app validates the file before cryptography starts.',
                'input_label': f'{safe_name} ({len(plaintext):,} bytes)',
                'output_label': 'Validated bytes',
                'why': 'Only supported, non-empty content enters the encryption pipeline.'
            },
            *crypto['trace'],
            {
                'name': 'Store ciphertext', 'algorithm': 'Secure storage', 'status': 'complete',
                'time_ms': round(max(0, total_ms - sum(x['time_ms'] for x in crypto['trace'])), 4),
                'detail': f'Saved as randomized server file {encrypted_filename}; plaintext was not written to permanent storage.',
                'summary': 'Only encrypted bytes and recovery metadata are saved permanently.',
                'input_label': 'Ciphertext + KEM metadata',
                'output_label': 'Encrypted vault item',
                'why': 'Readable plaintext is not kept in permanent vault storage.'
            },
        ]
        return {'file_id': file_id, 'trace': trace, 'total_ms': total_ms}
    except Exception:
        if tracemalloc.is_tracing():
            tracemalloc.stop()
        if target.exists():
            target.unlink(missing_ok=True)
        raise


@app.context_processor
def inject_user():
    return {'nav_user': get_current_user()}


@app.errorhandler(RequestEntityTooLarge)
def too_large(_):
    limit_mb = app.config['MAX_CONTENT_LENGTH'] // (1024 * 1024)
    if request.path.startswith('/api/'):
        return jsonify({'ok': False, 'error': f'File is too large. Maximum is {limit_mb} MB.'}), 413
    flash(f'File is too large. Maximum is {limit_mb} MB.', 'danger')
    return redirect(url_for('dashboard'))


@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')


@app.route('/learn')
def learn():
    return render_template('learn.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')

    name = request.form.get('name', '').strip()
    email = request.form.get('email', '').strip().lower()
    password = request.form.get('password', '')

    if len(name) < 2 or '@' not in email or len(password) < 8:
        flash('Use a valid name/email and a password of at least 8 characters.', 'danger')
        return render_template('register.html')

    with db_cursor() as (_, cur):
        cur.execute('SELECT id FROM users WHERE email=%s', (email,))
        if cur.fetchone():
            flash('An account with this email already exists.', 'warning')
            return render_template('register.html')

    try:
        public_key, secret_key, keygen_ms = generate_user_mlkem_keypair()
        wrapped_secret, secret_nonce = wrap_user_secret_key(
            secret_key, email, app.config['SERVER_MASTER_KEY_B64']
        )
        password_hash = generate_password_hash(password)

        with db_cursor() as (_, cur):
            cur.execute(
                '''INSERT INTO users
                   (name,email,password_hash,mlkem_public_key,mlkem_secret_key_enc,
                    mlkem_secret_key_nonce,key_algorithm)
                   VALUES (%s,%s,%s,%s,%s,%s,%s)''',
                (name, email, password_hash, public_key, wrapped_secret, secret_nonce, MLKEM_ALGORITHM),
            )
            user_id = cur.lastrowid

        audit(user_id, 'REGISTER', 'user', str(user_id), f'ML-KEM-768 key generation: {keygen_ms:.4f} ms')
        flash(f'Account created. ML-KEM-768 key pair prepared in {keygen_ms:.4f} ms.', 'success')
        return redirect(url_for('login'))
    except Exception as exc:
        app.logger.exception('Registration failed')
        flash(f'Registration failed: {exc}', 'danger')
        return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')

    email = request.form.get('email', '').strip().lower()
    password = request.form.get('password', '')

    with db_cursor() as (_, cur):
        cur.execute('SELECT id,name,email,password_hash FROM users WHERE email=%s', (email,))
        user = cur.fetchone()

    if not user or not check_password_hash(user['password_hash'], password):
        flash('Invalid email or password.', 'danger')
        return render_template('login.html')

    session.clear()
    session['user_id'] = user['id']
    session['user_name'] = user['name']
    audit(user['id'], 'LOGIN', 'user', str(user['id']))
    return redirect(url_for('dashboard'))


@app.route('/logout', methods=['POST'])
@login_required
def logout():
    user_id = session['user_id']
    audit(user_id, 'LOGOUT', 'user', str(user_id))
    session.clear()
    flash('Logged out.', 'info')
    return redirect(url_for('login'))


@app.route('/dashboard')
@login_required
def dashboard():
    q = request.args.get('q', '').strip()
    folder_id = request.args.get('folder', type=int)
    user_id = session['user_id']

    current_folder = None
    if folder_id is not None:
        current_folder = get_owned_folder(folder_id, user_id)
        if not current_folder:
            flash('Folder not found.', 'warning')
            return redirect(url_for('dashboard'))

    with db_cursor() as (_, cur):
        if q:
            cur.execute(
                '''SELECT f.*, fo.name AS folder_name
                   FROM files f
                   LEFT JOIN folders fo ON fo.id=f.folder_id
                   WHERE f.owner_id=%s AND f.original_filename LIKE %s
                   ORDER BY f.created_at DESC''',
                (user_id, f'%{q}%'),
            )
            files = cur.fetchall()
            cur.execute(
                '''SELECT fo.*,
                          (SELECT COUNT(*) FROM files f WHERE f.folder_id=fo.id) AS file_count
                   FROM folders fo
                   WHERE fo.owner_id=%s AND fo.name LIKE %s
                   ORDER BY fo.name''',
                (user_id, f'%{q}%'),
            )
            folders = cur.fetchall()
        else:
            cur.execute(
                '''SELECT f.*, fo.name AS folder_name
                   FROM files f
                   LEFT JOIN folders fo ON fo.id=f.folder_id
                   WHERE f.owner_id=%s AND f.folder_id <=> %s
                   ORDER BY f.created_at DESC''',
                (user_id, folder_id),
            )
            files = cur.fetchall()
            cur.execute(
                '''SELECT fo.*,
                          (SELECT COUNT(*) FROM files f WHERE f.folder_id=fo.id) AS file_count
                   FROM folders fo
                   WHERE fo.owner_id=%s AND fo.parent_id <=> %s
                   ORDER BY fo.name''',
                (user_id, folder_id),
            )
            folders = cur.fetchall()

        cur.execute(
            '''SELECT COUNT(*) AS file_count,
                      COALESCE(SUM(original_size),0) AS total_plain,
                      COALESCE(SUM(encrypted_size),0) AS total_encrypted
               FROM files WHERE owner_id=%s''',
            (user_id,),
        )
        stats = cur.fetchone()

        cur.execute('SELECT COUNT(*) AS c FROM file_shares WHERE recipient_id=%s', (user_id,))
        shared_count = cur.fetchone()['c']

    breadcrumbs = get_folder_breadcrumb(folder_id, user_id) if folder_id else []
    folder_options = build_folder_options(user_id)

    return render_template(
        'dashboard.html', files=files, folders=folders, stats=stats, q=q,
        current_folder=current_folder, current_folder_id=folder_id, breadcrumbs=breadcrumbs,
        folder_options=folder_options, shared_count=shared_count
    )


@app.route('/api/upload', methods=['POST'])
@login_required
def api_upload():
    user = get_current_user()
    uploaded = request.files.get('file')
    folder_id = normalize_folder_id(request.form.get('folder_id'))

    if not uploaded or not uploaded.filename:
        return jsonify({'ok': False, 'error': 'Choose a file first.'}), 400

    safe_name = secure_filename(uploaded.filename)
    if not safe_name or not allowed_file(safe_name):
        return jsonify({'ok': False, 'error': 'Allowed: TXT, PDF, JPG/JPEG, PNG, CSV, ZIP.'}), 400

    plaintext = uploaded.read()
    if not plaintext:
        return jsonify({'ok': False, 'error': 'The file is empty.'}), 400

    try:
        result = store_encrypted_file(user, safe_name, plaintext, folder_id)
        return jsonify({
            'ok': True,
            'message': 'File encrypted and stored.',
            'trace': result['trace'],
            'file_id': result['file_id'],
            'reload': True,
        })
    except ValueError as exc:
        return jsonify({'ok': False, 'error': str(exc)}), 400
    except Exception as exc:
        app.logger.exception('Upload failed')
        return jsonify({'ok': False, 'error': str(exc)}), 500


@app.route('/api/text-files', methods=['POST'])
@login_required
def api_create_text_file():
    user = get_current_user()
    payload = request.get_json(silent=True) or request.form
    name = secure_filename((payload.get('name') or '').strip())
    content = payload.get('content') or ''
    folder_id = normalize_folder_id(payload.get('folder_id'))

    if not name:
        return jsonify({'ok': False, 'error': 'Enter a file name.'}), 400
    if not name.lower().endswith('.txt'):
        name += '.txt'
    if len(name) > 255:
        return jsonify({'ok': False, 'error': 'File name is too long.'}), 400
    if not content.strip():
        return jsonify({'ok': False, 'error': 'Write something in the text file.'}), 400

    try:
        result = store_encrypted_file(
            user, name, content.encode('utf-8'), folder_id, audit_action='CREATE_TEXT_FILE'
        )
        return jsonify({
            'ok': True,
            'message': 'Secure text file created.',
            'trace': result['trace'],
            'file_id': result['file_id'],
        })
    except ValueError as exc:
        return jsonify({'ok': False, 'error': str(exc)}), 400
    except Exception as exc:
        app.logger.exception('Text file creation failed')
        return jsonify({'ok': False, 'error': str(exc)}), 500


@app.route('/api/folders', methods=['POST'])
@login_required
def api_create_folder():
    payload = request.get_json(silent=True) or request.form
    name = (payload.get('name') or '').strip()
    parent_id = normalize_folder_id(payload.get('parent_id'))
    user_id = session['user_id']

    if not name or len(name) > 120 or '/' in name or '\\' in name:
        return jsonify({'ok': False, 'error': 'Use a folder name from 1 to 120 characters without slashes.'}), 400
    if parent_id is not None and not get_owned_folder(parent_id, user_id):
        return jsonify({'ok': False, 'error': 'Parent folder was not found.'}), 404

    with db_cursor() as (_, cur):
        cur.execute(
            'SELECT id FROM folders WHERE owner_id=%s AND parent_id <=> %s AND name=%s',
            (user_id, parent_id, name),
        )
        if cur.fetchone():
            return jsonify({'ok': False, 'error': 'A folder with this name already exists here.'}), 409
        cur.execute(
            'INSERT INTO folders (owner_id,parent_id,name) VALUES (%s,%s,%s)',
            (user_id, parent_id, name),
        )
        folder_id = cur.lastrowid

    audit(user_id, 'CREATE_FOLDER', 'folder', str(folder_id), name)
    return jsonify({'ok': True, 'folder_id': folder_id, 'message': 'Folder created.'})


@app.route('/api/folders/<int:folder_id>/rename', methods=['POST'])
@login_required
def api_rename_folder(folder_id):
    payload = request.get_json(silent=True) or request.form
    name = (payload.get('name') or '').strip()
    user_id = session['user_id']
    folder = get_owned_folder(folder_id, user_id)
    if not folder:
        return jsonify({'ok': False, 'error': 'Folder not found.'}), 404
    if not name or len(name) > 120 or '/' in name or '\\' in name:
        return jsonify({'ok': False, 'error': 'Use a valid folder name.'}), 400
    with db_cursor() as (_, cur):
        cur.execute(
            'SELECT id FROM folders WHERE owner_id=%s AND parent_id <=> %s AND name=%s AND id<>%s',
            (user_id, folder['parent_id'], name, folder_id),
        )
        if cur.fetchone():
            return jsonify({'ok': False, 'error': 'A folder with this name already exists here.'}), 409
        cur.execute('UPDATE folders SET name=%s WHERE id=%s AND owner_id=%s', (name, folder_id, user_id))
    audit(user_id, 'RENAME_FOLDER', 'folder', str(folder_id), f"{folder['name']} -> {name}")
    return jsonify({'ok': True, 'message': 'Folder renamed.'})


@app.route('/api/folders/<int:folder_id>/delete', methods=['POST'])
@login_required
def api_delete_folder(folder_id):
    user_id = session['user_id']
    folder = get_owned_folder(folder_id, user_id)
    if not folder:
        return jsonify({'ok': False, 'error': 'Folder not found.'}), 404
    with db_cursor() as (_, cur):
        cur.execute('SELECT COUNT(*) AS c FROM files WHERE owner_id=%s AND folder_id=%s', (user_id, folder_id))
        file_count = cur.fetchone()['c']
        cur.execute('SELECT COUNT(*) AS c FROM folders WHERE owner_id=%s AND parent_id=%s', (user_id, folder_id))
        child_count = cur.fetchone()['c']
        if file_count or child_count:
            return jsonify({'ok': False, 'error': 'Folder is not empty. Move or delete its contents first.'}), 409
        cur.execute('DELETE FROM folders WHERE id=%s AND owner_id=%s', (folder_id, user_id))
    audit(user_id, 'DELETE_FOLDER', 'folder', str(folder_id), folder['name'])
    return jsonify({'ok': True, 'message': 'Folder deleted.'})


@app.route('/api/folders/<int:folder_id>/move', methods=['POST'])
@login_required
def api_move_folder(folder_id):
    payload = request.get_json(silent=True) or request.form
    target_parent_id = normalize_folder_id(payload.get('folder_id'))
    user_id = session['user_id']
    folder = get_owned_folder(folder_id, user_id)
    if not folder:
        return jsonify({'ok': False, 'error': 'Folder not found.'}), 404
    if target_parent_id == folder_id:
        return jsonify({'ok': False, 'error': 'A folder cannot be moved inside itself.'}), 400
    if target_parent_id is not None and not get_owned_folder(target_parent_id, user_id):
        return jsonify({'ok': False, 'error': 'Destination folder not found.'}), 404

    # Prevent moving a folder into one of its own descendants.
    cursor_id = target_parent_id
    seen = set()
    while cursor_id and cursor_id not in seen:
        if cursor_id == folder_id:
            return jsonify({'ok': False, 'error': 'A folder cannot be moved inside its own subfolder.'}), 400
        seen.add(cursor_id)
        parent = get_owned_folder(cursor_id, user_id)
        cursor_id = parent['parent_id'] if parent else None

    with db_cursor() as (_, cur):
        cur.execute(
            'SELECT id FROM folders WHERE owner_id=%s AND parent_id <=> %s AND name=%s AND id<>%s',
            (user_id, target_parent_id, folder['name'], folder_id),
        )
        if cur.fetchone():
            return jsonify({'ok': False, 'error': 'A folder with the same name already exists at the destination.'}), 409
        cur.execute('UPDATE folders SET parent_id=%s WHERE id=%s AND owner_id=%s', (target_parent_id, folder_id, user_id))
    audit(user_id, 'MOVE_FOLDER', 'folder', str(folder_id), folder['name'])
    return jsonify({'ok': True, 'message': 'Folder moved.'})


@app.route('/api/files/<int:file_id>/move', methods=['POST'])
@login_required
def api_move_file(file_id):
    payload = request.get_json(silent=True) or request.form
    target_folder_id = normalize_folder_id(payload.get('folder_id'))
    user_id = session['user_id']
    if target_folder_id is not None and not get_owned_folder(target_folder_id, user_id):
        return jsonify({'ok': False, 'error': 'Destination folder not found.'}), 404
    with db_cursor() as (_, cur):
        cur.execute('SELECT id,original_filename FROM files WHERE id=%s AND owner_id=%s', (file_id, user_id))
        row = cur.fetchone()
        if not row:
            return jsonify({'ok': False, 'error': 'File not found.'}), 404
        cur.execute('UPDATE files SET folder_id=%s WHERE id=%s AND owner_id=%s', (target_folder_id, file_id, user_id))
    audit(user_id, 'MOVE_FILE', 'file', str(file_id), row['original_filename'])
    return jsonify({'ok': True, 'message': 'File moved.'})


@app.route('/api/files/<int:file_id>/rename', methods=['POST'])
@login_required
def api_rename_file(file_id):
    payload = request.get_json(silent=True) or request.form
    new_name = secure_filename((payload.get('name') or '').strip())
    user_id = session['user_id']
    if not new_name or len(new_name) > 255:
        return jsonify({'ok': False, 'error': 'Enter a valid file name.'}), 400
    with db_cursor() as (_, cur):
        cur.execute('SELECT original_filename,file_type FROM files WHERE id=%s AND owner_id=%s', (file_id, user_id))
        row = cur.fetchone()
        if not row:
            return jsonify({'ok': False, 'error': 'File not found.'}), 404
        old_ext = file_extension(row['original_filename'])
        new_ext = file_extension(new_name)
        if new_ext != old_ext:
            return jsonify({'ok': False, 'error': f'Keep the original .{old_ext} extension when renaming.'}), 400
        cur.execute('UPDATE files SET original_filename=%s WHERE id=%s AND owner_id=%s', (new_name, file_id, user_id))
    audit(user_id, 'RENAME_FILE', 'file', str(file_id), f"{row['original_filename']} -> {new_name}")
    return jsonify({'ok': True, 'message': 'File renamed.'})


@app.route('/api/files/<int:file_id>/download')
@login_required
def api_download(file_id):
    user = get_current_user()

    with db_cursor() as (_, cur):
        cur.execute('SELECT * FROM files WHERE id=%s AND owner_id=%s', (file_id, user['id']))
        row = cur.fetchone()

    if not row:
        return jsonify({'ok': False, 'error': 'File not found or access denied.'}), 404

    path = ENCRYPTED_DIR / row['encrypted_filename']
    if not path.exists():
        return jsonify({'ok': False, 'error': 'Encrypted file is missing from server storage.'}), 404

    total_start = time.perf_counter_ns()
    tracemalloc.start()
    try:
        result = decrypt_for_user(
            path.read_bytes(),
            bytes(row['mlkem_ciphertext']),
            bytes(row['hkdf_salt']),
            bytes(row['chacha_nonce']),
            bytes(user['mlkem_secret_key_enc']),
            bytes(user['mlkem_secret_key_nonce']),
            user['email'],
            app.config['SERVER_MASTER_KEY_B64'],
            user['id'],
            row['file_uuid'],
        )
        total_end = time.perf_counter_ns()
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        total_ms = round((total_end - total_start) / 1_000_000, 4)

        timings = result['timings']
        throughput = bytes_per_second_mbps(len(result['plaintext']), timings['decrypt_ms'])
        with db_cursor() as (_, cur):
            cur.execute(
                '''INSERT INTO performance_logs
                   (user_id,file_id,operation,file_type,file_size_bytes,ciphertext_size_bytes,
                    mlkem_decap_ms,hkdf_ms,decrypt_ms,total_ms,throughput_mbps,peak_memory_kb)
                   VALUES (%s,%s,'download',%s,%s,%s,%s,%s,%s,%s,%s,%s)''',
                (
                    user['id'], row['id'], row['file_type'], row['original_size'], row['encrypted_size'],
                    timings['kem_decap_ms'], timings['hkdf_ms'], timings['decrypt_ms'], total_ms,
                    throughput, round(peak / 1024, 2),
                ),
            )

        audit(user['id'], 'DOWNLOAD_DECRYPTED', 'file', str(file_id), row['original_filename'])

        trace_json = json.dumps([
            {
                'name': 'Verify that this file belongs to you', 'algorithm': 'Access control', 'status': 'complete',
                'time_ms': 0, 'detail': 'Database owner ID matches the authenticated user.',
                'summary': 'The app first checks that the logged-in account owns this file before any decryption is attempted.',
                'input_label': 'Logged-in user ID + stored owner ID',
                'output_label': 'Access approved',
                'why': 'Strong encryption still needs authorization so one user cannot request another user file.'
            },
            *result['trace'],
            {
                'name': 'Send the recovered file to your browser', 'algorithm': 'Application', 'status': 'complete',
                'time_ms': 0, 'detail': 'Plaintext exists only in process memory for this response.',
                'summary': 'After successful authentication and decryption, the original file is returned as the download response.',
                'input_label': 'Verified plaintext in process memory',
                'output_label': 'Browser download',
                'why': 'The application does not need to save a permanent plaintext copy just to let you download it.'
            },
        ], separators=(',', ':'))
        trace_header = base64.urlsafe_b64encode(trace_json.encode()).decode()

        response = send_file(
            io.BytesIO(result['plaintext']),
            as_attachment=True,
            download_name=row['original_filename'],
            mimetype='application/octet-stream',
        )
        response.headers['X-Crypto-Trace'] = trace_header
        response.headers['X-Total-Crypto-Time-Ms'] = str(total_ms)
        return response
    except InvalidTag:
        if tracemalloc.is_tracing():
            tracemalloc.stop()
        audit(user['id'], 'TAMPER_DETECTED', 'file', str(file_id), row['original_filename'])
        return jsonify({'ok': False, 'error': 'Authentication failed: ciphertext/metadata was modified or corrupted.'}), 409
    except Exception as exc:
        if tracemalloc.is_tracing():
            tracemalloc.stop()
        app.logger.exception('Download failed')
        return jsonify({'ok': False, 'error': str(exc)}), 500


@app.route('/files/<int:file_id>/delete', methods=['POST'])
@login_required
def delete_file(file_id):
    user_id = session['user_id']
    with db_cursor() as (_, cur):
        cur.execute('SELECT id,encrypted_filename,original_filename FROM files WHERE id=%s AND owner_id=%s', (file_id, user_id))
        row = cur.fetchone()
        if not row:
            flash('File not found or access denied.', 'danger')
            return redirect(url_for('dashboard'))
        cur.execute('DELETE FROM files WHERE id=%s AND owner_id=%s', (file_id, user_id))

    (ENCRYPTED_DIR / row['encrypted_filename']).unlink(missing_ok=True)
    audit(user_id, 'DELETE_FILE', 'file', str(file_id), row['original_filename'])
    flash('Encrypted file and metadata deleted.', 'success')
    return_folder = normalize_folder_id(request.form.get('return_to_folder'))
    return redirect(url_for('dashboard', folder=return_folder) if return_folder else url_for('dashboard'))

@app.route('/sharing')
@login_required
def sharing():
    user_id = session['user_id']
    selected_file_id = request.args.get('file_id', type=int)
    with db_cursor() as (_, cur):
        cur.execute(
            '''SELECT id, original_filename, file_type, original_size, created_at
               FROM files WHERE owner_id=%s ORDER BY created_at DESC''',
            (user_id,),
        )
        own_files = cur.fetchall()

        cur.execute(
            '''SELECT s.id AS share_id, s.created_at AS shared_at,
                      f.id AS file_id, f.original_filename, f.file_type, f.original_size,
                      u.name AS recipient_name, u.email AS recipient_email
               FROM file_shares s
               JOIN files f ON f.id=s.file_id
               JOIN users u ON u.id=s.recipient_id
               WHERE s.owner_id=%s
               ORDER BY s.created_at DESC''',
            (user_id,),
        )
        outgoing = cur.fetchall()

        cur.execute(
            '''SELECT s.id AS share_id, s.created_at AS shared_at,
                      f.id AS file_id, f.original_filename, f.file_type, f.original_size,
                      u.name AS owner_name, u.email AS owner_email
               FROM file_shares s
               JOIN files f ON f.id=s.file_id
               JOIN users u ON u.id=s.owner_id
               WHERE s.recipient_id=%s
               ORDER BY s.created_at DESC''',
            (user_id,),
        )
        incoming = cur.fetchall()

    return render_template(
        'sharing.html', own_files=own_files, outgoing=outgoing,
        incoming=incoming, selected_file_id=selected_file_id
    )


@app.route('/api/shares', methods=['POST'])
@login_required
def api_create_share():
    owner = get_current_user()
    payload = request.get_json(silent=True) or request.form
    try:
        file_id = int(payload.get('file_id', 0))
    except (TypeError, ValueError):
        file_id = 0
    recipient_email = (payload.get('recipient_email') or '').strip().lower()

    if not file_id or '@' not in recipient_email:
        return jsonify({'ok': False, 'error': 'Choose a file and enter a valid recipient email.'}), 400
    if recipient_email == owner['email'].lower():
        return jsonify({'ok': False, 'error': 'You already own this file. Choose another registered user.'}), 400

    with db_cursor() as (_, cur):
        cur.execute('SELECT * FROM files WHERE id=%s AND owner_id=%s', (file_id, owner['id']))
        row = cur.fetchone()
        if not row:
            return jsonify({'ok': False, 'error': 'File not found or you are not the owner.'}), 404

        cur.execute('SELECT * FROM users WHERE email=%s', (recipient_email,))
        recipient = cur.fetchone()
        if not recipient:
            return jsonify({'ok': False, 'error': 'That email is not registered in QuantumVault yet.'}), 404

        cur.execute(
            'SELECT id FROM file_shares WHERE file_id=%s AND recipient_id=%s',
            (file_id, recipient['id']),
        )
        if cur.fetchone():
            return jsonify({'ok': False, 'error': 'This file is already shared with that user.'}), 409

    total_start = time.perf_counter_ns()
    tracemalloc.start()
    try:
        owner_recovery = recover_owner_file_key(
            bytes(row['mlkem_ciphertext']),
            bytes(row['hkdf_salt']),
            bytes(owner['mlkem_secret_key_enc']),
            bytes(owner['mlkem_secret_key_nonce']),
            owner['email'],
            app.config['SERVER_MASTER_KEY_B64'],
            owner['id'],
            row['file_uuid'],
        )
        envelope = create_share_envelope(
            owner_recovery['file_key'],
            bytes(recipient['mlkem_public_key']),
            row['file_uuid'],
            owner['id'],
            recipient['id'],
        )

        with db_cursor() as (_, cur):
            cur.execute(
                '''INSERT INTO file_shares
                   (file_id,owner_id,recipient_id,mlkem_ciphertext,hkdf_salt,wrap_nonce,wrapped_file_key)
                   VALUES (%s,%s,%s,%s,%s,%s,%s)''',
                (
                    row['id'], owner['id'], recipient['id'], envelope['kem_ciphertext'],
                    envelope['salt'], envelope['nonce'], envelope['wrapped_file_key'],
                ),
            )
            share_id = cur.lastrowid

        total_end = time.perf_counter_ns()
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        total_ms = round((total_end - total_start) / 1_000_000, 4)

        recovery_t = owner_recovery['timings']
        env_t = envelope['timings']
        with db_cursor() as (_, cur):
            cur.execute(
                '''INSERT INTO performance_logs
                   (user_id,file_id,operation,file_type,file_size_bytes,ciphertext_size_bytes,
                    mlkem_encap_ms,mlkem_decap_ms,hkdf_ms,encrypt_ms,total_ms,peak_memory_kb)
                   VALUES (%s,%s,'share_create',%s,%s,%s,%s,%s,%s,%s,%s,%s)''',
                (
                    owner['id'], row['id'], row['file_type'], row['original_size'],
                    len(envelope['wrapped_file_key']), env_t['kem_encap_ms'],
                    recovery_t['kem_decap_ms'], recovery_t['hkdf_ms'] + env_t['hkdf_ms'],
                    env_t['wrap_ms'], total_ms, round(peak / 1024, 2),
                ),
            )

        audit(
            owner['id'], 'SHARE_GRANTED', 'share', str(share_id),
            f"{row['original_filename']} -> {recipient['email']}"
        )

        trace = [
            {
                'name': 'Confirm owner and recipient', 'algorithm': 'Access control', 'status': 'complete',
                'time_ms': 0, 'detail': f"Owner verified; recipient account {recipient['email']} found.",
                'summary': 'The app confirms that you own the file and that the recipient is a registered QuantumVault user.',
                'input_label': 'Owner session + selected file + recipient email',
                'output_label': 'Authorized sharing request',
                'why': 'Only the owner should be able to create or revoke access to a file.'
            },
            *owner_recovery['trace'],
            *envelope['trace'],
            {
                'name': 'Save the share permission', 'algorithm': 'Secure storage', 'status': 'complete',
                'time_ms': 0, 'detail': 'Stored only the recipient-specific key envelope and permission metadata; the encrypted file was not duplicated.',
                'summary': 'QuantumVault stores a small recipient-specific key envelope. The original encrypted file remains a single copy.',
                'input_label': 'Share KEM ciphertext + salt + nonce + wrapped file key',
                'output_label': f"Access granted to {recipient['email']}",
                'why': 'This keeps sharing efficient and makes revocation a permission change instead of deleting extra file copies.'
            },
        ]
        return jsonify({
            'ok': True,
            'message': f"Secure access granted to {recipient['name']}.",
            'share_id': share_id,
            'trace': trace,
        })
    except Exception as exc:
        if tracemalloc.is_tracing():
            tracemalloc.stop()
        app.logger.exception('Secure share creation failed')
        return jsonify({'ok': False, 'error': str(exc)}), 500


@app.route('/api/shares/<int:share_id>/download')
@login_required
def api_shared_download(share_id):
    recipient = get_current_user()
    with db_cursor() as (_, cur):
        cur.execute(
            '''SELECT s.*, f.file_uuid, f.original_filename, f.encrypted_filename,
                      f.file_type, f.original_size, f.encrypted_size, f.chacha_nonce,
                      u.name AS owner_name, u.email AS owner_email
               FROM file_shares s
               JOIN files f ON f.id=s.file_id
               JOIN users u ON u.id=s.owner_id
               WHERE s.id=%s AND s.recipient_id=%s''',
            (share_id, recipient['id']),
        )
        row = cur.fetchone()

    if not row:
        return jsonify({'ok': False, 'error': 'Share not found, revoked, or access denied.'}), 404

    path = ENCRYPTED_DIR / row['encrypted_filename']
    if not path.exists():
        return jsonify({'ok': False, 'error': 'Encrypted file is missing from server storage.'}), 404

    total_start = time.perf_counter_ns()
    tracemalloc.start()
    try:
        result = decrypt_shared_file(
            path.read_bytes(),
            bytes(row['chacha_nonce']),
            row['file_uuid'],
            row['owner_id'],
            bytes(row['mlkem_ciphertext']),
            bytes(row['hkdf_salt']),
            bytes(row['wrap_nonce']),
            bytes(row['wrapped_file_key']),
            bytes(recipient['mlkem_secret_key_enc']),
            bytes(recipient['mlkem_secret_key_nonce']),
            recipient['email'],
            app.config['SERVER_MASTER_KEY_B64'],
            recipient['id'],
        )
        total_end = time.perf_counter_ns()
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        total_ms = round((total_end - total_start) / 1_000_000, 4)

        timings = result['timings']
        effective_decrypt_ms = timings['unwrap_ms'] + timings['decrypt_ms']
        throughput = bytes_per_second_mbps(len(result['plaintext']), timings['decrypt_ms'])
        with db_cursor() as (_, cur):
            cur.execute(
                '''INSERT INTO performance_logs
                   (user_id,file_id,operation,file_type,file_size_bytes,ciphertext_size_bytes,
                    mlkem_decap_ms,hkdf_ms,decrypt_ms,total_ms,throughput_mbps,peak_memory_kb)
                   VALUES (%s,%s,'shared_download',%s,%s,%s,%s,%s,%s,%s,%s,%s)''',
                (
                    recipient['id'], row['file_id'], row['file_type'], row['original_size'],
                    row['encrypted_size'], timings['kem_decap_ms'], timings['hkdf_ms'],
                    effective_decrypt_ms, total_ms, throughput, round(peak / 1024, 2),
                ),
            )

        audit(
            recipient['id'], 'SHARED_DOWNLOAD', 'share', str(share_id),
            f"{row['original_filename']} from {row['owner_email']}"
        )

        trace_json = json.dumps([
            {
                'name': 'Check your share permission', 'algorithm': 'Access control', 'status': 'complete',
                'time_ms': 0, 'detail': f"Active share record found for recipient {recipient['email']}.",
                'summary': 'The app confirms that this file is currently shared with your account before any key recovery happens.',
                'input_label': 'Logged-in account + share record',
                'output_label': 'Shared access approved',
                'why': 'If the owner revokes the share, this record disappears and the download is blocked.'
            },
            *result['trace'],
            {
                'name': 'Send the recovered file to your browser', 'algorithm': 'Application', 'status': 'complete',
                'time_ms': 0, 'detail': 'Plaintext is returned from process memory and is not saved as a permanent server copy.',
                'summary': 'After the share envelope and encrypted file both pass authentication, the original file is returned to your browser.',
                'input_label': 'Verified plaintext in memory',
                'output_label': 'Browser download',
                'why': 'The vault can keep one encrypted file while authorized users receive plaintext only when they request it.'
            },
        ], separators=(',', ':'))
        trace_header = base64.urlsafe_b64encode(trace_json.encode()).decode()

        response = send_file(
            io.BytesIO(result['plaintext']),
            as_attachment=True,
            download_name=row['original_filename'],
            mimetype='application/octet-stream',
        )
        response.headers['X-Crypto-Trace'] = trace_header
        response.headers['X-Total-Crypto-Time-Ms'] = str(total_ms)
        return response
    except InvalidTag:
        if tracemalloc.is_tracing():
            tracemalloc.stop()
        audit(recipient['id'], 'SHARED_TAMPER_DETECTED', 'share', str(share_id), row['original_filename'])
        return jsonify({'ok': False, 'error': 'Authentication failed: the share envelope or encrypted file was modified.'}), 409
    except Exception as exc:
        if tracemalloc.is_tracing():
            tracemalloc.stop()
        app.logger.exception('Shared download failed')
        return jsonify({'ok': False, 'error': str(exc)}), 500


@app.route('/shares/<int:share_id>/revoke', methods=['POST'])
@login_required
def revoke_share(share_id):
    owner_id = session['user_id']
    with db_cursor() as (_, cur):
        cur.execute(
            '''SELECT s.id, f.original_filename, u.email AS recipient_email
               FROM file_shares s
               JOIN files f ON f.id=s.file_id
               JOIN users u ON u.id=s.recipient_id
               WHERE s.id=%s AND s.owner_id=%s''',
            (share_id, owner_id),
        )
        row = cur.fetchone()
        if not row:
            flash('Share not found or you are not the owner.', 'danger')
            return redirect(url_for('sharing'))
        cur.execute('DELETE FROM file_shares WHERE id=%s AND owner_id=%s', (share_id, owner_id))

    audit(
        owner_id, 'SHARE_REVOKED', 'share', str(share_id),
        f"{row['original_filename']} -> {row['recipient_email']}"
    )
    flash('Access revoked. Future shared downloads are blocked.', 'success')
    return redirect(url_for('sharing'))


@app.route('/performance')
@login_required
def performance():
    user_id = session['user_id']
    with db_cursor() as (_, cur):
        cur.execute(
            '''SELECT * FROM performance_logs WHERE user_id=%s
               ORDER BY created_at DESC LIMIT 200''',
            (user_id,),
        )
        logs = cur.fetchall()
        cur.execute(
            '''SELECT operation, COUNT(*) runs,
                      ROUND(AVG(total_ms),4) avg_total_ms,
                      ROUND(AVG(throughput_mbps),4) avg_throughput_mbps,
                      ROUND(AVG(peak_memory_kb),2) avg_peak_memory_kb
               FROM performance_logs WHERE user_id=%s
               GROUP BY operation''',
            (user_id,),
        )
        summary = cur.fetchall()
    return render_template('performance.html', logs=logs, summary=summary)


@app.route('/api/benchmark', methods=['POST'])
@login_required
def api_benchmark():
    uploaded = request.files.get('file')
    repeats_raw = request.form.get('repeats', '1')
    label = request.form.get('label', '').strip()[:120]

    if not uploaded or not uploaded.filename:
        return jsonify({'ok': False, 'error': 'Choose a benchmark file.'}), 400
    safe_name = secure_filename(uploaded.filename)
    if not safe_name or not allowed_file(safe_name):
        return jsonify({'ok': False, 'error': 'Unsupported benchmark file type.'}), 400
    try:
        repeats = int(repeats_raw)
    except ValueError:
        return jsonify({'ok': False, 'error': 'Repeats must be a number.'}), 400
    if repeats < 1 or repeats > 30:
        return jsonify({'ok': False, 'error': 'Repeats must be between 1 and 30.'}), 400

    data = uploaded.read()
    if not data:
        return jsonify({'ok': False, 'error': 'Benchmark file is empty.'}), 400

    results = []
    user_id = session['user_id']
    try:
        for i in range(repeats):
            r = run_single_benchmark(data)
            r['run'] = i + 1
            results.append(r)
            with db_cursor() as (_, cur):
                cur.execute(
                    '''INSERT INTO performance_logs
                       (user_id,operation,benchmark_label,file_type,file_size_bytes,ciphertext_size_bytes,
                        mlkem_keygen_ms,mlkem_encap_ms,mlkem_decap_ms,hkdf_ms,encrypt_ms,decrypt_ms,
                        total_ms,throughput_mbps,peak_memory_kb)
                       VALUES (%s,'benchmark',%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)''',
                    (
                        user_id, label or safe_name, file_extension(safe_name), r['file_size_bytes'],
                        r['ciphertext_size_bytes'], r['mlkem_keygen_ms'], r['mlkem_encap_ms'],
                        r['mlkem_decap_ms'], r['hkdf_ms'], r['encrypt_ms'], r['decrypt_ms'],
                        r['total_ms'], r['throughput_mbps'], r['peak_memory_kb'],
                    ),
                )

        keys = ['mlkem_keygen_ms','mlkem_encap_ms','mlkem_decap_ms','hkdf_ms','encrypt_ms','decrypt_ms','total_ms','throughput_mbps','peak_memory_kb']
        avg = {k: round(sum(float(x[k]) for x in results if x[k] is not None) / len(results), 4) for k in keys}
        audit(user_id, 'RUN_BENCHMARK', 'benchmark', label or safe_name, f'{repeats} repetitions')
        return jsonify({'ok': True, 'runs': repeats, 'average': avg, 'results': results})
    except Exception as exc:
        app.logger.exception('Benchmark failed')
        return jsonify({'ok': False, 'error': str(exc)}), 500


@app.route('/performance/export.csv')
@login_required
def export_performance_csv():
    user_id = session['user_id']
    with db_cursor() as (_, cur):
        cur.execute('SELECT * FROM performance_logs WHERE user_id=%s ORDER BY created_at', (user_id,))
        rows = cur.fetchall()

    output = io.StringIO()
    if rows:
        writer = csv.DictWriter(output, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    else:
        output.write('no_data\n')

    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=pq_vault_performance.csv'},
    )


@app.route('/audit')
@login_required
def audit_page():
    with db_cursor() as (_, cur):
        cur.execute(
            'SELECT * FROM audit_logs WHERE user_id=%s ORDER BY created_at DESC LIMIT 200',
            (session['user_id'],),
        )
        logs = cur.fetchall()
    return render_template('audit.html', logs=logs)


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=True)
