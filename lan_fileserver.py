"""
LAN File Server (single-file Flask app)

Features:
 - Upload files (single or multiple)
 - List files with metadata (filename, original name, size, uploaded_at)
 - Download files
 - Generate share links (unguessable token) for public download
 - Delete files (requires admin password)

NOTE: For LAN/testing only. Do NOT expose to the open internet without additional hardening.
"""

import os
import json
import uuid
import threading
from datetime import datetime
from functools import wraps
from flask import (
    Flask, request, redirect, url_for, send_from_directory,
    render_template_string, flash, jsonify, abort
)
from werkzeug.utils import secure_filename

# ---------- Configuration ----------
UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'files')
METADATA_FILE = os.path.join(UPLOAD_FOLDER, 'files.json')
SHARES_FILE = os.path.join(UPLOAD_FOLDER, 'shares.json')
ALLOWED_EXTENSIONS = None  # None = allow all. Or set like {'txt','png','jpg'}
MAX_CONTENT_LENGTH = 1024 * 1024 * 1024  # 1 GB max upload default
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'adminpass')
HOST = '0.0.0.0'
PORT = 5000
DEBUG = False
# -----------------------------------

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET', 'change_this_secret')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

_lock = threading.Lock()

# util functions for metadata persistence
def _load_json(path, default):
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        return default
    except Exception:
        return default

def _save_json(path, data):
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

# ensure files metadata exists
if not os.path.exists(METADATA_FILE):
    _save_json(METADATA_FILE, {})

if not os.path.exists(SHARES_FILE):
    _save_json(SHARES_FILE, {})

def allowed_file(filename):
    if ALLOWED_EXTENSIONS is None:
        return True
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# small decorator for admin actions using simple password
def require_admin(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        pwd = request.values.get('admin_password') or request.headers.get('X-ADMIN-PASSWORD')
        if not pwd or pwd != ADMIN_PASSWORD:
            return jsonify({'error': 'admin password required'}), 403
        return func(*args, **kwargs)
    return wrapper

# templates (embedded)
INDEX_HTML = """
<!doctype html>
<title>LAN File Server</title>
<style>
body { font-family: system-ui, Arial; margin: 24px; background:#f9f9fb; color:#111; }
.container { max-width: 900px; margin: 0 auto; }
h1 { margin-bottom: 0.5rem; }
.actions { display:flex; gap:8px; margin-bottom: 12px; }
.file-row { display:flex; gap:12px; align-items:center; padding:8px; border-radius:8px; background:white; margin-bottom:8px; box-shadow: 0 1px 4px rgba(0,0,0,0.04); }
.small { font-size:0.9rem; color:#555; }
.btn { padding:6px 10px; border-radius:6px; text-decoration:none; background:#0b74de; color:white; font-weight:600; }
.btn-muted { background:#e6eefc; color:#0b74de; font-weight:600; }
.form-row { display:flex; gap:8px; align-items:center; margin-bottom:12px; }
.footer { margin-top:24px; color:#666; font-size:0.9rem; }
</style>

<div class="container">
  <h1>LAN File Server</h1>
  <p class="small">Upload, download, and generate share links across your local network.</p>

  <div style="background:#fff;padding:12px;border-radius:10px;margin-bottom:16px;">
    <form action="{{ url_for('upload') }}" method="post" enctype="multipart/form-data">
      <div class="form-row">
        <input type="file" name="files" multiple>
        <button class="btn" type="submit">Upload</button>
      </div>
    </form>

    <form id="create-share" action="{{ url_for('create_share') }}" method="post" style="margin-top:8px;">
      <label class="small">Create share link for filename:</label>
      <div class="form-row">
        <input type="text" name="filename" placeholder="exact stored filename (from list)" style="flex:1;">
        <button class="btn-muted" type="submit">Create Share Link</button>
      </div>
    </form>

    <details style="margin-top:8px;">
      <summary class="small">Admin: delete a file</summary>
      <form action="{{ url_for('delete') }}" method="post" style="margin-top:8px;">
        <div class="form-row">
          <input name="filename" placeholder="stored filename (from list)" required style="flex:1;">
          <input name="admin_password" placeholder="admin password" required>
          <button class="btn" type="submit">Delete</button>
        </div>
      </form>
      <p class="small">Admin password is required to delete files. (Change ADMIN_PASSWORD in server config.)</p>
    </details>
  </div>

  <h3>Files</h3>
  {% if files %}
    {% for key, meta in files.items() %}
      <div class="file-row">
        <div style="flex:1;">
          <div><strong>{{ key }}</strong> <span class="small">({{ meta.original_name }})</span></div>
          <div class="small">Size: {{ meta.size|filesize }} • Uploaded: {{ meta.uploaded_at }}</div>
        </div>
        <div style="display:flex;gap:6px;">
          <a class="btn-muted" href="{{ url_for('download', filename=key) }}">Download</a>
          <form action="{{ url_for('create_share') }}" method="post" style="display:inline;">
            <input type="hidden" name="filename" value="{{ key }}">
            <input type="hidden" name="create_only" value="1">
            <button class="btn" type="submit">Create Share</button>
          </form>
        </div>
      </div>
    {% endfor %}
  {% else %}
    <p class="small">No files uploaded yet.</p>
  {% endif %}

  <h3>Active Share Links</h3>
  {% if shares %}
    <ul class="small">
      {% for token, info in shares.items() %}
        <li>
          <strong>{{ token }}</strong> → {{ info.filename }} — 
          <a href="{{ request.host_url.rstrip('/') + url_for('shared_download', token=token) }}" target="_blank">link</a>
          {% if info.expires_at %} (expires: {{ info.expires_at }}){% endif %}
        </li>
      {% endfor %}
    </ul>
  {% else %}
    <p class="small">No active shares.</p>
  {% endif %}

  <div class="footer">
    <p>Access the server on other devices at: <code>{{ host_display }}</code></p>
    <p>Warning: This server is intended for private local networks. Do not expose to the public without securing.</p>
  </div>
</div>
"""

# Jinja filter for human-readable filesize
def _filesize_format(value):
    try:
        n = int(value)
    except Exception:
        return str(value)
    for unit in ['B','KB','MB','GB','TB']:
        if n < 1024:
            return f"{n}{unit}"
        n = round(n/1024, 2)
    return f"{n}PB"

app.jinja_env.filters['filesize'] = _filesize_format

# ---------- Routes ----------
@app.route('/')
def index():
    files_meta = _load_json(METADATA_FILE, {})
    shares = _load_json(SHARES_FILE, {})
    # host display helpful for LAN users
    host_display = f"http://{request.host.split(':')[0]}:{PORT}"
    return render_template_string(INDEX_HTML, files=files_meta, shares=shares, host_display=host_display)

@app.route('/upload', methods=['POST'])
def upload():
    # support both single-file and multiple-file upload fields
    files = request.files.getlist('files')
    if not files:
        flash('No file part')
        return redirect(url_for('index'))

    files_meta = _load_json(METADATA_FILE, {})
    saved = []

    for f in files:
        if f and f.filename:
            filename = secure_filename(f.filename)
            if not filename:
                continue
            if not allowed_file(filename):
                continue
            # create a stored filename to avoid collisions: uuid_filename
            ext = ''
            if '.' in filename:
                ext = '.' + filename.rsplit('.', 1)[1]
            stored_name = f"{uuid.uuid4().hex}{ext}"
            target = os.path.join(app.config['UPLOAD_FOLDER'], stored_name)
            f.save(target)
            st = os.stat(target)
            meta = {
                'original_name': filename,
                'stored_name': stored_name,
                'size': st.st_size,
                'uploaded_at': datetime.utcnow().isoformat() + 'Z'
            }
            with _lock:
                files_meta[stored_name] = meta
                _save_json(METADATA_FILE, files_meta)
            saved.append(stored_name)
    if not saved:
        flash('No files were uploaded.')
    else:
        flash(f'Uploaded: {", ".join(saved)}')
    return redirect(url_for('index'))

@app.route('/download/<filename>')
def download(filename):
    # download by stored filename
    files_meta = _load_json(METADATA_FILE, {})
    if filename not in files_meta:
        abort(404)
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True,
                               attachment_filename=files_meta[filename].get('original_name', filename))

@app.route('/share/create', methods=['POST'])
def create_share():
    filename = request.form.get('filename')
    if not filename:
        return redirect(url_for('index'))
    files_meta = _load_json(METADATA_FILE, {})
    if filename not in files_meta:
        flash('File not found for sharing.')
        return redirect(url_for('index'))
    shares = _load_json(SHARES_FILE, {})
    # create token
    token = uuid.uuid4().hex
    share_info = {
        'filename': filename,
        'created_at': datetime.utcnow().isoformat() + 'Z',
        # optional expiration could be added; None means no expiry
        'expires_at': None
    }
    with _lock:
        shares[token] = share_info
        _save_json(SHARES_FILE, shares)
    flash(f'Share created: {token}')
    # if request from "create_only", just show message; else redirect to index
    return redirect(url_for('index'))

@app.route('/s/<token>')
def shared_download(token):
    # allow download via token
    shares = _load_json(SHARES_FILE, {})
    if token not in shares:
        abort(404)
    info = shares[token]
    filename = info['filename']
    files_meta = _load_json(METADATA_FILE, {})
    if filename not in files_meta:
        abort(404)
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True,
                               attachment_filename=files_meta[filename].get('original_name', filename))

@app.route('/delete', methods=['POST'])
@require_admin
def delete():
    filename = request.form.get('filename')
    if not filename:
        return jsonify({'error': 'filename required'}), 400
    files_meta = _load_json(METADATA_FILE, {})
    if filename not in files_meta:
        return jsonify({'error': 'file not found'}), 404
    path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    try:
        os.remove(path)
    except FileNotFoundError:
        pass
    with _lock:
        files_meta.pop(filename, None)
        _save_json(METADATA_FILE, files_meta)
        # also remove shares that reference it
        shares = _load_json(SHARES_FILE, {})
        to_delete = [t for t,i in shares.items() if i.get('filename') == filename]
        for t in to_delete:
            shares.pop(t, None)
        _save_json(SHARES_FILE, shares)
    return redirect(url_for('index'))

@app.route('/api/files')
def api_list_files():
    return jsonify(_load_json(METADATA_FILE, {}))

@app.route('/api/shares')
def api_list_shares():
    return jsonify(_load_json(SHARES_FILE, {}))

# helpful 404 message
@app.errorhandler(404)
def page_not_found(e):
    return "<h3>Not found</h3><p>The requested item was not found.</p>", 404

# ---------- Run ----------
if __name__ == '__main__':
    print("Starting LAN File Server")
    print(f"Upload folder: {UPLOAD_FOLDER}")
    print(f"Admin password: (set ADMIN_PASSWORD env var) default={ADMIN_PASSWORD}")
    app.run(host=HOST, port=PORT, debug=DEBUG)
