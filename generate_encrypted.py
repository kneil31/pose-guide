#!/usr/bin/env python3
"""Pose Guide — Encrypted GitHub Pages build pipeline.

Usage:
    python3 generate_encrypted.py              # Full build
    python3 generate_encrypted.py --init       # Create .secret with random password
    python3 generate_encrypted.py --link       # Print convenience URL
    python3 generate_encrypted.py --prune      # Remove stale chunks not in current index.html
    python3 generate_encrypted.py --link --base-url https://custom.domain/
"""

import argparse
import base64
import hashlib
import json
import mimetypes
import os
import secrets
import shutil
import sys
from pathlib import Path

# Fail-fast on missing deps
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
except ImportError:
    print("Missing: cryptography")
    print("  pip3 install cryptography")
    sys.exit(1)

try:
    from PIL import Image
except ImportError:
    print("Missing: Pillow")
    print("  pip3 install Pillow")
    sys.exit(1)

SCRIPT_DIR = Path(__file__).resolve().parent
IMAGES_DIR = SCRIPT_DIR / "images"
DIST_DIR = SCRIPT_DIR / "dist"
SECRET_FILE = SCRIPT_DIR / ".secret"
CHUNKS_DIR = SCRIPT_DIR / "chunks"
INDEX_HTML = SCRIPT_DIR / "index.html"

PBKDF2_ITERATIONS = 400_000
MAX_CHUNK_MB = 80
WARN_CHUNK_MB = 70
FAIL_CHUNK_MB = 95
OPTIMIZE_LONG_EDGE = 800
THUMB_LONG_EDGE = 80
THUMB_QUALITY = 40
JPEG_QUALITY = 82
IMAGE_EXTS = {".jpg", ".jpeg", ".png", ".webp", ".gif", ".bmp", ".tiff", ".tif"}

DEFAULT_BASE_URL = "https://kneil31.github.io/pose-guide/"

CATEGORY_ICONS = {
    "baby_shower": "\U0001f37c",
    "maternity": "\U0001f930",
    "kids": "\U0001f476",
    "newborn": "\U0001f467",
    "couples": "\U0001f491",
    "family": "\U0001f468\u200d\U0001f469\u200d\U0001f467\u200d\U0001f466",
    "wedding": "\U0001f48d",
    "uncategorized": "\U0001f4f7",
}

CATEGORY_DISPLAY = {
    "baby_shower": "Baby Shower",
    "maternity": "Maternity",
    "kids": "Kids",
    "newborn": "Newborn",
    "couples": "Couples",
    "family": "Family",
    "wedding": "Wedding",
    "uncategorized": "Uncategorized",
}


# ── Crypto ──────────────────────────────────────────────────────────────────

def encrypt_bytes(plaintext_bytes: bytes, password: str) -> bytes:
    """AES-256-GCM encrypt. Returns raw bytes: salt(16) + iv(12) + ciphertext."""
    salt = os.urandom(16)
    iv = os.urandom(12)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=PBKDF2_ITERATIONS)
    key = kdf.derive(password.encode("utf-8"))
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(iv, plaintext_bytes, None)
    return salt + iv + ciphertext


def content_hash(data: bytes, length: int = 8) -> str:
    """First N hex chars of SHA-256."""
    return hashlib.sha256(data).hexdigest()[:length]


def file_sha256(path: Path, length: int = 12) -> str:
    """First N hex chars of SHA-256 of file contents."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()[:length]


# ── Image processing ────────────────────────────────────────────────────────

def has_transparency(img: Image.Image) -> bool:
    if img.mode in ("RGBA", "LA"):
        return True
    if img.mode == "P":
        if "transparency" in img.info:
            return True
        try:
            img.getchannel("A")
            return True
        except ValueError:
            pass
    return False


def optimize_image(src: Path, dest: Path) -> None:
    """Resize to max long edge, convert PNG→JPEG unless transparent."""
    img = Image.open(src)
    img.thumbnail((OPTIMIZE_LONG_EDGE, OPTIMIZE_LONG_EDGE), Image.LANCZOS)
    if src.suffix.lower() == ".png" and not has_transparency(img):
        dest = dest.with_suffix(".jpg")
        img = img.convert("RGB")
        img.save(dest, "JPEG", quality=JPEG_QUALITY, optimize=True)
    else:
        if img.mode in ("RGBA", "LA"):
            img.save(dest, "PNG", optimize=True)
        else:
            img = img.convert("RGB")
            img.save(dest.with_suffix(".jpg"), "JPEG", quality=JPEG_QUALITY, optimize=True)
    return dest if dest.exists() else dest.with_suffix(".jpg")


def make_thumbnail_b64(src: Path) -> str:
    """Create tiny JPEG thumbnail as base64 string."""
    img = Image.open(src)
    img.thumbnail((THUMB_LONG_EDGE, THUMB_LONG_EDGE), Image.LANCZOS)
    if img.mode != "RGB":
        img = img.convert("RGB")
    from io import BytesIO
    buf = BytesIO()
    img.save(buf, "JPEG", quality=THUMB_QUALITY, optimize=True)
    return base64.b64encode(buf.getvalue()).decode("ascii")


# ── Build pipeline ──────────────────────────────────────────────────────────

def load_secret() -> str:
    if not SECRET_FILE.exists():
        print(f"Error: {SECRET_FILE} not found. Run with --init first.")
        sys.exit(1)
    data = json.loads(SECRET_FILE.read_text())
    return data["password"]


def discover_categories() -> dict:
    """Returns {slug: [(source_path, original_filename), ...]}."""
    categories = {}
    for cat_dir in sorted(IMAGES_DIR.iterdir()):
        if not cat_dir.is_dir() or cat_dir.name.startswith("."):
            continue
        slug = cat_dir.name.replace(" ", "_")
        files = sorted(
            f for f in cat_dir.iterdir()
            if f.is_file() and f.suffix.lower() in IMAGE_EXTS
        )
        if files:
            categories[slug] = files
    return categories


def build(password: str) -> None:
    """Full build pipeline: optimize → IDs → thumbs → encrypt → index.html."""
    categories = discover_categories()
    if not categories:
        print("No images found in images/")
        sys.exit(1)

    # Clean dist
    opt_dir = DIST_DIR / "optimized"
    site_dir = DIST_DIR / "site"
    if DIST_DIR.exists():
        shutil.rmtree(DIST_DIR)
    opt_dir.mkdir(parents=True)
    (site_dir / "chunks").mkdir(parents=True)

    print(f"Found {sum(len(v) for v in categories.values())} images across {len(categories)} categories\n")

    # Phase 1: Optimize + generate IDs + thumbnails
    manifest_data = {"version": 1, "categories": []}
    all_chunk_info = []  # [(slug, encrypted_bytes, image_count)]

    for slug, source_files in categories.items():
        display = CATEGORY_DISPLAY.get(slug, slug.replace("_", " ").title())
        cat_opt_dir = opt_dir / slug
        cat_opt_dir.mkdir()

        images_meta = []  # For manifest
        images_data = []  # For chunk (full base64)

        for src in source_files:
            # Stable ID from original source file
            img_id = file_sha256(src, 12)

            # Optimize
            opt_name = f"{slug}_{src.stem}{src.suffix.lower()}"
            opt_path = cat_opt_dir / opt_name
            actual_path = optimize_image(src, opt_path)

            # Thumbnail from optimized
            thumb_b64 = make_thumbnail_b64(actual_path)

            # Full image base64 for chunk
            mime = mimetypes.guess_type(actual_path.name)[0] or "image/jpeg"
            img_b64 = base64.b64encode(actual_path.read_bytes()).decode("ascii")

            images_meta.append({
                "id": img_id,
                "name": actual_path.name,
                "thumb": f"data:image/jpeg;base64,{thumb_b64}",
                "category": slug,
            })
            images_data.append({
                "id": img_id,
                "name": actual_path.name,
                "mime": mime,
                "b64": img_b64,
            })

        # Encrypt chunk(s) — split if > MAX_CHUNK_MB
        chunk_json = json.dumps(images_data).encode("utf-8")
        chunk_mb = len(chunk_json) / (1024 * 1024)

        chunk_filenames = []
        if chunk_mb > MAX_CHUNK_MB:
            # Split into parts
            part_size = len(images_data) // 2
            parts = [images_data[:part_size], images_data[part_size:]]
            for i, part in enumerate(parts, 1):
                part_bytes = json.dumps(part).encode("utf-8")
                enc = encrypt_bytes(part_bytes, password)
                h = content_hash(enc)
                fname = f"{slug}-{i}-{h}.enc"
                (site_dir / "chunks" / fname).write_bytes(enc)
                chunk_filenames.append(fname)
                part_mb = len(enc) / (1024 * 1024)
                all_chunk_info.append((f"{slug}-{i}", enc, len(part), part_mb))
        else:
            enc = encrypt_bytes(chunk_json, password)
            h = content_hash(enc)
            fname = f"{slug}-{h}.enc"
            (site_dir / "chunks" / fname).write_bytes(enc)
            chunk_filenames.append(fname)
            enc_mb = len(enc) / (1024 * 1024)
            all_chunk_info.append((slug, enc, len(images_data), enc_mb))

        manifest_data["categories"].append({
            "name": display,
            "slug": slug,
            "icon": CATEGORY_ICONS.get(slug, "\U0001f4f7"),
            "count": len(images_meta),
            "chunks": chunk_filenames,
            "images": images_meta,
        })

        print(f"  {display}: {len(images_meta)} images → {len(chunk_filenames)} chunk(s)")

    # Encrypt manifest
    manifest_json = json.dumps(manifest_data).encode("utf-8")
    manifest_enc = encrypt_bytes(manifest_json, password)
    manifest_hash = content_hash(manifest_enc)
    manifest_fname = f"manifest-{manifest_hash}.enc"
    (site_dir / "chunks" / manifest_fname).write_bytes(manifest_enc)

    # Generate index.html
    html = generate_index_html(manifest_fname)
    (site_dir / "index.html").write_text(html)

    # Copy from dist/site/ to repo root (additive)
    CHUNKS_DIR.mkdir(exist_ok=True)
    current_chunks = []
    for f in (site_dir / "chunks").iterdir():
        shutil.copy2(f, CHUNKS_DIR / f.name)
        current_chunks.append(f.name)
    shutil.copy2(site_dir / "index.html", INDEX_HTML)

    # Write current chunk list for --prune
    (SCRIPT_DIR / ".current_chunks.json").write_text(json.dumps(sorted(current_chunks), indent=2) + "\n")

    # Build report
    print(f"\nBuild complete:")
    manifest_kb = len(manifest_enc) / 1024
    total_images = sum(len(c["images"]) for c in manifest_data["categories"])
    print(f"  {manifest_fname:40s} {manifest_kb:6.1f} KB  ({total_images} images, {len(manifest_data['categories'])} categories)")

    total_mb = manifest_kb / 1024
    warnings = []
    failures = []
    for name, enc, count, mb in all_chunk_info:
        print(f"  {name + '-' + content_hash(enc) + '.enc':40s} {mb:6.1f} MB  ({count} images)")
        total_mb += mb
        if mb > FAIL_CHUNK_MB:
            failures.append(name)
        elif mb > WARN_CHUNK_MB:
            warnings.append(name)

    print(f"  {'Total:':40s} {total_mb:6.1f} MB across {len(all_chunk_info) + 1} files")

    if failures:
        print(f"\n  FAIL: Chunks over {FAIL_CHUNK_MB} MB: {', '.join(failures)}")
        sys.exit(1)
    elif warnings:
        print(f"\n  WARNING: Chunks over {WARN_CHUNK_MB} MB: {', '.join(warnings)}")

    ok = all(mb < MAX_CHUNK_MB for _, _, _, mb in all_chunk_info)
    if ok:
        print(f"  All chunks under {MAX_CHUNK_MB} MB \u2713")


def prune_chunks() -> None:
    """Delete chunk files not referenced by the current build."""
    chunks_list = SCRIPT_DIR / ".current_chunks.json"
    if not chunks_list.exists():
        print("No .current_chunks.json found — run a build first.")
        return
    if not CHUNKS_DIR.exists():
        print("No chunks/ directory — nothing to prune.")
        return

    current = set(json.loads(chunks_list.read_text()))
    removed = 0
    kept = 0
    for f in sorted(CHUNKS_DIR.iterdir()):
        if not f.name.endswith(".enc"):
            continue
        if f.name in current:
            kept += 1
        else:
            size_kb = f.stat().st_size / 1024
            print(f"  Removing stale: {f.name} ({size_kb:.1f} KB)")
            f.unlink()
            removed += 1

    print(f"Pruned {removed} stale chunk(s), kept {kept} current.")


# ── index.html generation ───────────────────────────────────────────────────

def generate_index_html(manifest_fname: str) -> str:
    """Generate the self-contained encrypted viewer HTML."""
    # Read CSS from pose_guide.html lines 7-376 (the <style> block)
    css = _get_css()
    return f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, user-scalable=no">
<title>Rsquare Studios — Pose Guide</title>
<style>
{css}

/* Password gate */
.pw-gate {{
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  min-height: 100vh;
  padding: 20px;
}}
.pw-gate h2 {{
  color: #fff;
  font-size: 24px;
  margin-bottom: 8px;
}}
.pw-gate p {{
  color: #888;
  font-size: 14px;
  margin-bottom: 24px;
}}
.pw-gate input {{
  background: #252525;
  border: 2px solid #333;
  color: #fff;
  font-size: 16px;
  padding: 14px 20px;
  border-radius: 12px;
  width: 100%;
  max-width: 300px;
  text-align: center;
  outline: none;
  transition: border-color 0.2s;
}}
.pw-gate input:focus {{
  border-color: #a855f7;
}}
.pw-gate .error {{
  color: #e74c6f;
  font-size: 13px;
  margin-top: 12px;
  display: none;
}}
.pw-gate .loading {{
  color: #a855f7;
  font-size: 13px;
  margin-top: 12px;
  display: none;
}}

/* Category loading spinner */
.cat-loading {{
  text-align: center;
  padding: 60px 20px;
  color: #a855f7;
  font-size: 14px;
}}
</style>
</head>
<body>

<!-- Password Gate -->
<div id="pwGate" class="pw-gate">
  <h2>Pose Guide</h2>
  <p>Rsquare Studios</p>
  <input type="password" id="pwInput" placeholder="Enter password" autocomplete="off">
  <div class="error" id="pwError">Wrong password</div>
  <div class="loading" id="pwLoading">Decrypting...</div>
</div>

<!-- App (hidden until unlocked) -->
<div id="app" style="display:none">
  <div class="header">
    <button class="back-btn" id="backBtn" onclick="goBack()">&#8592; Back</button>
    <h1 id="pageTitle">Pose Guide</h1>
    <button class="loved-filter-btn" id="lovedFilterBtn" onclick="toggleLovedFilter()">&#9829;</button>
    <button class="clear-btn" id="clearBtn" onclick="clearShotList()">Clear All</button>
  </div>
  <div class="categories" id="categories"></div>
  <div class="gallery" id="gallery"></div>
  <div class="lightbox" id="lightbox">
    <button class="lb-close" onclick="closeLightbox()">&times;</button>
    <button class="lb-nav lb-prev" onclick="navLightbox(-1)">&#8249;</button>
    <button class="lb-nav lb-next" onclick="navLightbox(1)">&#8250;</button>
    <img id="lbImg" src="" alt="Pose reference">
    <div class="lb-bottom">
      <button class="lb-heart" id="lbHeart" onclick="toggleLove()">&#9829;</button>
      <button class="lb-check" id="lbCheck" onclick="toggleDone()">&#10003;</button>
      <div class="lb-counter" id="lbCounter"></div>
    </div>
  </div>
</div>

<script>
const MANIFEST_URL = "chunks/{manifest_fname}";
const PBKDF2_ITERATIONS = {PBKDF2_ITERATIONS};

let manifestData = null;   // Decrypted manifest
let chunkCache = {{}};      // slug -> array of image objects
let blobUrls = [];          // Track for revocation
let currentImages = [];     // array of image objects
let currentIdx = 0;
let touchStartX = 0;
let currentView = 'home';
let currentCat = '';
let shotlistFilter = 'remaining'; // 'all' | 'remaining' | 'done'
let categoryLovedOnly = false;     // filter loved-only in category view
let allCategoryImages = [];        // unfiltered images for current category
let _password = '';

// ── Crypto ──────────────────────────────────────────────────────────────

async function deriveKey(password, salt) {{
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    {{ name: 'PBKDF2', salt, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' }},
    keyMaterial,
    {{ name: 'AES-GCM', length: 256 }},
    false,
    ['decrypt']
  );
}}

async function decryptChunk(url, password) {{
  const buf = await fetch(url).then(r => {{
    if (!r.ok) throw new Error('Fetch failed: ' + r.status);
    return r.arrayBuffer();
  }});
  const bytes = new Uint8Array(buf);
  const salt = bytes.slice(0, 16);
  const iv = bytes.slice(16, 28);
  const ciphertext = bytes.slice(28);
  const key = await deriveKey(password, salt);
  const plain = await crypto.subtle.decrypt({{ name: 'AES-GCM', iv }}, key, ciphertext);
  return new TextDecoder().decode(plain);
}}

// ── Storage (localStorage, keyed by 12-char content-hash IDs) ───────────

const STORAGE_KEY = 'pose_guide_loved';
const DONE_KEY = 'pose_guide_done';

function getLoved() {{
  try {{ return JSON.parse(localStorage.getItem(STORAGE_KEY)) || {{}}; }}
  catch {{ return {{}}; }}
}}
function saveLoved(loved) {{ localStorage.setItem(STORAGE_KEY, JSON.stringify(loved)); }}
function isLoved(id) {{ return !!getLoved()[id]; }}
function toggleLoveById(id) {{
  const loved = getLoved();
  if (loved[id]) delete loved[id];
  else loved[id] = Date.now();
  saveLoved(loved);
}}
function lovedCount() {{ return Object.keys(getLoved()).length; }}
function lovedCountForCat(slug) {{
  const loved = getLoved();
  if (!manifestData) return 0;
  const cat = manifestData.categories.find(c => c.slug === slug);
  if (!cat) return 0;
  return cat.images.filter(img => loved[img.id]).length;
}}

function getDone() {{
  try {{ return JSON.parse(localStorage.getItem(DONE_KEY)) || {{}}; }}
  catch {{ return {{}}; }}
}}
function saveDone(done) {{ localStorage.setItem(DONE_KEY, JSON.stringify(done)); }}
function isDone(id) {{ return !!getDone()[id]; }}
function toggleDoneById(id) {{
  const done = getDone();
  if (done[id]) delete done[id];
  else done[id] = Date.now();
  saveDone(done);
}}
function doneCount() {{
  const done = getDone();
  const loved = getLoved();
  return Object.keys(done).filter(id => loved[id]).length;
}}

// ── Password Gate ───────────────────────────────────────────────────────

document.getElementById('pwInput').addEventListener('keydown', async (e) => {{
  if (e.key !== 'Enter') return;
  const pw = e.target.value.trim();
  if (!pw) return;
  await tryUnlock(pw);
}});

// Check for ?k= convenience param
(async () => {{
  const params = new URLSearchParams(location.search);
  const k = params.get('k');
  if (k) {{
    // Clear from URL bar
    history.replaceState(null, '', location.pathname);
    await tryUnlock(k);
  }}
}})();

async function tryUnlock(pw) {{
  const errorEl = document.getElementById('pwError');
  const loadingEl = document.getElementById('pwLoading');
  errorEl.style.display = 'none';
  loadingEl.style.display = 'block';

  try {{
    const json = await decryptChunk(MANIFEST_URL, pw);
    manifestData = JSON.parse(json);
    _password = pw;
    document.getElementById('pwGate').style.display = 'none';
    document.getElementById('app').style.display = 'block';
    renderCategories();
  }} catch {{
    loadingEl.style.display = 'none';
    errorEl.style.display = 'block';
    document.getElementById('pwInput').value = '';
    document.getElementById('pwInput').focus();
  }}
}}

// ── Render Categories ───────────────────────────────────────────────────

function renderCategories() {{
  const el = document.getElementById('categories');
  if (!manifestData || !manifestData.categories.length) {{
    el.innerHTML = '<div class="empty">No categories found.</div>';
    return;
  }}

  const total = lovedCount();
  let html = '';

  // Shot List tile
  if (total > 0) {{
    html += `<div class="tile shotlist-tile" onclick="openShotList()">
      <div class="tile-accent"></div>
      <div class="tile-icon">\\u2764\\ufe0f</div>
      <div class="tile-name">Shot List</div>
      <div class="tile-count">${{doneCount()}}/${{total}} done</div>
    </div>`;
  }}

  html += manifestData.categories.map(cat => {{
    const loved = lovedCountForCat(cat.slug);
    return `<div class="tile" onclick="openCategory('${{cat.slug}}')">
      <div class="tile-accent"></div>
      <div class="tile-icon">${{cat.icon}}</div>
      <div class="tile-name">${{cat.name}}</div>
      <div class="tile-count">${{cat.count}} pose${{cat.count !== 1 ? 's' : ''}}</div>
      ${{loved > 0 ? `<div class="tile-loved">\\u2764 ${{loved}} selected</div>` : ''}}
    </div>`;
  }}).join('');
  el.innerHTML = html;
}}

// ── Category Chunks ─────────────────────────────────────────────────────

function revokeOldBlobs() {{
  blobUrls.forEach(u => URL.revokeObjectURL(u));
  blobUrls = [];
}}

async function loadCategoryChunks(slug) {{
  if (chunkCache[slug]) return chunkCache[slug];

  const cat = manifestData.categories.find(c => c.slug === slug);
  if (!cat) return [];

  let allImages = [];
  for (const chunkFile of cat.chunks) {{
    const json = await decryptChunk('chunks/' + chunkFile, _password);
    const data = JSON.parse(json);
    allImages = allImages.concat(data);
  }}

  // Create Blob URLs
  const result = allImages.map(img => {{
    const bytes = Uint8Array.from(atob(img.b64), c => c.charCodeAt(0));
    const blob = new Blob([bytes], {{ type: img.mime }});
    const url = URL.createObjectURL(blob);
    blobUrls.push(url);
    return {{ id: img.id, name: img.name, blobUrl: url }};
  }});

  chunkCache[slug] = result;
  return result;
}}

function findBlobUrl(id) {{
  for (const slug in chunkCache) {{
    const img = chunkCache[slug].find(i => i.id === id);
    if (img) return img.blobUrl;
  }}
  return null;
}}

// ── Gallery Rendering ───────────────────────────────────────────────────

function renderItem(img, i) {{
  const loved = isLoved(img.id);
  const done = isDone(img.id);
  const doneClass = (loved && done) ? ' shot-done' : '';
  // Use thumbnail for shot list, blob URL for category gallery
  const src = img.src || img.thumb || '';
  return `<div class="gallery-item${{doneClass}}" onclick="openLightbox(${{i}})">
    <div class="heart-badge${{loved ? ' loved' : ''}}" onclick="event.stopPropagation(); toggleGrid(${{i}})">\\u2661</div>
    ${{loved ? `<div class="check-badge${{done ? ' done' : ''}}" onclick="event.stopPropagation(); toggleGridDone(${{i}})">\\u2713</div>` : ''}}
    <img src="${{src}}" loading="lazy" alt="Pose ${{i+1}}">
  </div>`;
}}

async function openCategory(slug) {{
  currentCat = slug;
  currentView = 'category';

  // Show loading
  document.getElementById('categories').style.display = 'none';
  const gallery = document.getElementById('gallery');
  gallery.style.display = 'block';
  gallery.innerHTML = '<div class="cat-loading">Loading...</div>';
  document.getElementById('pageTitle').textContent = CATEGORY_DISPLAY[slug] || slug;
  document.getElementById('backBtn').classList.add('visible');

  // Revoke old blob URLs and clear cache for memory
  revokeOldBlobs();
  chunkCache = {{}};

  const images = await loadCategoryChunks(slug);
  const cat = manifestData.categories.find(c => c.slug === slug);

  // Build currentImages with blob URLs
  allCategoryImages = (cat ? cat.images : []).map(meta => {{
    const loaded = images.find(i => i.id === meta.id);
    return {{
      id: meta.id,
      src: loaded ? loaded.blobUrl : meta.thumb,
      thumb: meta.thumb,
      key: meta.id,
      category: slug,
    }};
  }});

  categoryLovedOnly = false;
  applyCategoryFilter();
  showGallery(CATEGORY_DISPLAY[slug] || slug);
}}

function toggleLovedFilter() {{
  categoryLovedOnly = !categoryLovedOnly;
  applyCategoryFilter();
  showGallery(CATEGORY_DISPLAY[currentCat] || currentCat);
}}

function applyCategoryFilter() {{
  if (categoryLovedOnly) {{
    const loved = getLoved();
    currentImages = allCategoryImages.filter(img => loved[img.id]);
  }} else {{
    currentImages = [...allCategoryImages];
  }}
  const btn = document.getElementById('lovedFilterBtn');
  btn.classList.toggle('active', categoryLovedOnly);
}}

const CATEGORY_DISPLAY = {json.dumps({k: v for k, v in CATEGORY_DISPLAY.items()})};

async function openShotList() {{
  currentView = 'shotlist';
  currentCat = '';
  const loved = getLoved();

  // Collect all loved images from manifest
  currentImages = [];
  const neededSlugs = new Set();
  for (const cat of manifestData.categories) {{
    for (const img of cat.images) {{
      if (loved[img.id]) {{
        currentImages.push({{
          id: img.id,
          src: img.thumb,
          thumb: img.thumb,
          key: img.id,
          category: cat.slug,
        }});
        neededSlugs.add(cat.slug);
      }}
    }}
  }}
  currentImages.sort((a, b) => (loved[a.id] || 0) - (loved[b.id] || 0));
  shotlistFilter = 'remaining';

  // Show immediately with thumbs, then upgrade to full-res
  showGallery('Shot List');
  document.getElementById('clearBtn').classList.add('visible');

  // Fetch all needed category chunks in parallel
  await Promise.all([...neededSlugs].map(slug => loadCategoryChunks(slug)));

  // Upgrade image sources to full-res blob URLs
  for (const img of currentImages) {{
    const blobUrl = findBlobUrl(img.id);
    if (blobUrl) img.src = blobUrl;
  }}
  // Re-render with full-res
  showGallery('Shot List');
  document.getElementById('clearBtn').classList.add('visible');
}}

function setShotlistFilter(f) {{
  shotlistFilter = f;
  showGallery('Shot List');
  document.getElementById('clearBtn').classList.add('visible');
}}

function showGallery(title) {{
  document.getElementById('categories').style.display = 'none';
  const gallery = document.getElementById('gallery');
  const shotlistEl = document.getElementById('shotlist-container');

  if (!currentImages.length) {{
    const msg = currentView === 'shotlist'
      ? 'No poses selected yet.<br>Browse categories and tap \\u2764 to build your shot list.'
      : 'No images yet.';
    gallery.style.display = 'block';
    gallery.innerHTML = `<div class="empty">${{msg}}</div>`;
    if (shotlistEl) shotlistEl.style.display = 'none';
  }} else if (currentView === 'shotlist') {{
    gallery.style.display = 'none';
    const doneState = getDone();
    const toShoot = [];
    const finished = [];
    currentImages.forEach((img, i) => {{
      if (doneState[img.id]) finished.push({{ img, i }});
      else toShoot.push({{ img, i }});
    }});

    // Filter tabs
    let html = '<div class="filter-tabs">';
    html += `<button class="filter-tab${{shotlistFilter === 'remaining' ? ' active' : ''}}" onclick="setShotlistFilter('remaining')">Remaining (${{toShoot.length}})</button>`;
    html += `<button class="filter-tab${{shotlistFilter === 'all' ? ' active' : ''}}" onclick="setShotlistFilter('all')">All (${{currentImages.length}})</button>`;
    html += `<button class="filter-tab${{shotlistFilter === 'done' ? ' active done-tab' : ''}}" onclick="setShotlistFilter('done')">Done (${{finished.length}})</button>`;
    html += '</div>';

    html += '<div class="shotlist-grid">';
    if (shotlistFilter === 'remaining' || shotlistFilter === 'all') {{
      if (toShoot.length) {{
        if (shotlistFilter === 'all') {{
          html += `<div class="shotlist-section-label">\\ud83c\\udfaf To Shoot — ${{toShoot.length}} remaining</div>`;
        }}
        html += toShoot.map(({{ img, i }}) => renderItem(img, i)).join('');
      }} else if (shotlistFilter === 'remaining') {{
        html += '<div class="empty">All done! \\ud83c\\udf89</div>';
      }}
    }}
    if (shotlistFilter === 'done' || shotlistFilter === 'all') {{
      if (finished.length) {{
        if (shotlistFilter === 'all') {{
          html += `<div class="shotlist-section-label done-label">\\u2705 Done — ${{finished.length}} completed</div>`;
        }}
        html += finished.map(({{ img, i }}) => renderItem(img, i)).join('');
      }} else if (shotlistFilter === 'done') {{
        html += '<div class="empty">No poses marked done yet.</div>';
      }}
    }}
    html += '</div>';

    let el = document.getElementById('shotlist-container');
    if (!el) {{
      el = document.createElement('div');
      el.id = 'shotlist-container';
      gallery.parentNode.insertBefore(el, gallery.nextSibling);
    }}
    el.innerHTML = html;
    el.style.display = 'block';
  }} else {{
    gallery.style.display = 'block';
    if (shotlistEl) shotlistEl.style.display = 'none';
    gallery.innerHTML = currentImages.map((img, i) => renderItem(img, i)).join('');
  }}

  document.getElementById('pageTitle').textContent = title;
  document.getElementById('backBtn').classList.add('visible');

  // Show heart filter in category view, hide in shot list
  const filterBtn = document.getElementById('lovedFilterBtn');
  if (currentView === 'category') {{
    filterBtn.classList.add('visible');
    filterBtn.classList.toggle('active', categoryLovedOnly);
  }} else {{
    filterBtn.classList.remove('visible');
  }}
}}

function goBack() {{
  if (currentView === 'home') return;
  document.getElementById('categories').style.display = 'grid';
  document.getElementById('gallery').style.display = 'none';
  const shotlistEl = document.getElementById('shotlist-container');
  if (shotlistEl) shotlistEl.style.display = 'none';
  document.getElementById('pageTitle').textContent = 'Pose Guide';
  document.getElementById('backBtn').classList.remove('visible');
  document.getElementById('lovedFilterBtn').classList.remove('visible', 'active');
  document.getElementById('clearBtn').classList.remove('visible');
  currentView = 'home';
  renderCategories();
}}

function toggleGrid(idx) {{
  toggleLoveById(currentImages[idx].id);
  refreshGallery();
}}

function toggleGridDone(idx) {{
  toggleDoneById(currentImages[idx].id);
  refreshGallery();
}}

function refreshGallery() {{
  if (currentView === 'shotlist') openShotList();
  else if (currentView === 'category') {{
    applyCategoryFilter();
    showGallery(CATEGORY_DISPLAY[currentCat] || currentCat);
  }}
}}

function clearShotList() {{
  if (!confirm('Clear all selected poses?')) return;
  saveLoved({{}});
  saveDone({{}});
  goBack();
}}

// ── Lightbox ────────────────────────────────────────────────────────────

async function openLightbox(idx) {{
  currentIdx = idx;
  const img = currentImages[idx];

  // If from shot list, need to fetch the category chunk for full-res
  if (currentView === 'shotlist' && img.category) {{
    const blobUrl = findBlobUrl(img.id);
    if (!blobUrl) {{
      // Fetch chunk
      document.getElementById('lbImg').src = img.thumb;
      document.getElementById('lightbox').classList.add('open');
      updateLightboxUI();

      const loaded = await loadCategoryChunks(img.category);
      const full = loaded.find(i => i.id === img.id);
      if (full) {{
        document.getElementById('lbImg').src = full.blobUrl;
        img.src = full.blobUrl;  // Cache for next time
      }}
      return;
    }} else {{
      img.src = blobUrl;
    }}
  }}

  document.getElementById('lbImg').src = img.src;
  document.getElementById('lightbox').classList.add('open');
  updateLightboxUI();
}}

function closeLightbox() {{
  document.getElementById('lightbox').classList.remove('open');
  refreshGallery();
}}

function navLightbox(dir) {{
  currentIdx = (currentIdx + dir + currentImages.length) % currentImages.length;
  const img = currentImages[currentIdx];

  // For shot list, try to get full-res from cache
  if (currentView === 'shotlist' && img.category) {{
    const blobUrl = findBlobUrl(img.id);
    if (blobUrl) {{
      img.src = blobUrl;
    }}
  }}

  document.getElementById('lbImg').src = img.src || img.thumb;
  updateLightboxUI();
}}

function toggleLove() {{
  toggleLoveById(currentImages[currentIdx].id);
  updateLightboxUI();
}}

function toggleDone() {{
  toggleDoneById(currentImages[currentIdx].id);
  updateLightboxUI();
}}

function updateLightboxUI() {{
  const img = currentImages[currentIdx];
  document.getElementById('lbCounter').textContent = (currentIdx + 1) + ' / ' + currentImages.length;
  const heart = document.getElementById('lbHeart');
  const loved = isLoved(img.id);
  heart.classList.toggle('loved', loved);
  const check = document.getElementById('lbCheck');
  if (loved) {{
    check.classList.add('visible');
    check.classList.toggle('done', isDone(img.id));
  }} else {{
    check.classList.remove('visible', 'done');
  }}
}}

// ── Touch swipe ─────────────────────────────────────────────────────────

document.getElementById('lightbox').addEventListener('touchstart', e => {{
  touchStartX = e.touches[0].clientX;
}}, {{ passive: true }});

document.getElementById('lightbox').addEventListener('touchend', e => {{
  const dx = e.changedTouches[0].clientX - touchStartX;
  if (Math.abs(dx) > 50) navLightbox(dx < 0 ? 1 : -1);
}}, {{ passive: true }});

// ── Keyboard ────────────────────────────────────────────────────────────

document.addEventListener('keydown', e => {{
  if (!document.getElementById('lightbox').classList.contains('open')) return;
  if (e.key === 'ArrowLeft') navLightbox(-1);
  if (e.key === 'ArrowRight') navLightbox(1);
  if (e.key === 'Escape') closeLightbox();
  if (e.key === ' ' || e.key === 'l') {{ e.preventDefault(); toggleLove(); }}
  if (e.key === 'd') {{ e.preventDefault(); if (isLoved(currentImages[currentIdx].id)) toggleDone(); }}
}});
</script>
</body>
</html>'''


def _get_css() -> str:
    """Extract CSS from pose_guide.html (reuse directly)."""
    return '''* { margin: 0; padding: 0; box-sizing: border-box; }
body {
  background: #191919;
  color: #e0e0e0;
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
  -webkit-tap-highlight-color: transparent;
  overflow-x: hidden;
}

/* Header */
.header {
  padding: 24px 20px 12px;
  display: flex;
  align-items: center;
  gap: 12px;
}
.header h1 {
  font-size: 22px;
  font-weight: 600;
  color: #fff;
  flex: 1;
}
.back-btn {
  display: none;
  background: none;
  border: none;
  color: #b48eff;
  font-size: 16px;
  cursor: pointer;
  padding: 8px 12px 8px 0;
}
.back-btn.visible { display: inline-block; }

/* Category Tiles */
.categories {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 16px;
  padding: 16px 20px 40px;
}
.tile {
  background: #252525;
  border-radius: 16px;
  padding: 28px 20px;
  cursor: pointer;
  transition: transform 0.15s, background 0.15s;
  position: relative;
  overflow: hidden;
}
.tile:active { transform: scale(0.97); background: #2e2e2e; }
.tile-icon { font-size: 36px; margin-bottom: 10px; }
.tile-name {
  font-size: 17px;
  font-weight: 600;
  color: #fff;
  text-transform: capitalize;
}
.tile-count {
  font-size: 13px;
  color: #888;
  margin-top: 4px;
}
.tile-loved {
  font-size: 12px;
  color: #e74c6f;
  margin-top: 2px;
}
.tile-accent {
  position: absolute;
  top: 0; right: 0;
  width: 60px; height: 60px;
  background: radial-gradient(circle at top right, rgba(180,142,255,0.15), transparent 70%);
  border-radius: 0 16px 0 0;
}

/* Shot List tile (special) */
.tile.shotlist-tile {
  background: linear-gradient(135deg, #2a1a2e, #252525);
  border: 1px solid rgba(231,76,111,0.3);
  grid-column: 1 / -1;
}
.tile.shotlist-tile .tile-icon { font-size: 32px; }

/* Gallery Grid */
.gallery {
  display: none;
  padding: 8px 12px 40px;
  columns: 3;
  column-gap: 8px;
}
.gallery-item {
  break-inside: avoid;
  margin-bottom: 8px;
  border-radius: 10px;
  overflow: hidden;
  cursor: pointer;
  line-height: 0;
  position: relative;
}
.gallery-item img {
  width: 100%;
  border-radius: 10px;
  transition: opacity 0.2s;
}
.gallery-item:active img { opacity: 0.8; }

/* Heart overlay on grid */
.heart-badge {
  position: absolute;
  top: 6px;
  right: 6px;
  width: 28px;
  height: 28px;
  background: rgba(0,0,0,0.5);
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 15px;
  z-index: 2;
  backdrop-filter: blur(4px);
  -webkit-backdrop-filter: blur(4px);
  pointer-events: auto;
}
.heart-badge.loved {
  background: rgba(231,76,111,0.85);
  color: #fff;
}
.gallery-item.dimmed img {
  opacity: 0.3;
}

/* Check (done) badge on grid */
.check-badge {
  position: absolute;
  bottom: 6px;
  right: 6px;
  width: 28px;
  height: 28px;
  background: rgba(0,0,0,0.5);
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 14px;
  z-index: 2;
  backdrop-filter: blur(4px);
  -webkit-backdrop-filter: blur(4px);
  pointer-events: auto;
  color: #666;
}
.check-badge.done {
  background: rgba(76,175,80,0.9);
  color: #fff;
}
.gallery-item.shot-done img {
  opacity: 0.4;
  filter: saturate(0.3);
}
.gallery-item.shot-done::after {
  content: '';
  position: absolute;
  inset: 0;
  background: rgba(76,175,80,0.08);
  border-radius: 10px;
  pointer-events: none;
}

/* Lightbox */
.lightbox {
  display: none;
  position: fixed;
  inset: 0;
  background: rgba(0,0,0,0.95);
  z-index: 100;
  flex-direction: column;
  align-items: center;
  justify-content: center;
}
.lightbox.open { display: flex; }
.lightbox img {
  max-width: 95vw;
  max-height: 75vh;
  object-fit: contain;
  border-radius: 6px;
  user-select: none;
  -webkit-user-drag: none;
}
.lb-bottom {
  display: flex;
  align-items: center;
  gap: 20px;
  margin-top: 16px;
}
.lb-counter {
  color: #888;
  font-size: 14px;
}
.lb-heart {
  background: none;
  border: 2px solid #555;
  color: #555;
  width: 48px;
  height: 48px;
  border-radius: 50%;
  font-size: 22px;
  cursor: pointer;
  display: flex;
  align-items: center;
  justify-content: center;
  transition: all 0.2s;
}
.lb-heart.loved {
  border-color: #e74c6f;
  color: #fff;
  background: #e74c6f;
  transform: scale(1.1);
}
.lb-heart:active { transform: scale(0.9); }
.lb-check {
  background: none;
  border: 2px solid #555;
  color: #555;
  width: 48px;
  height: 48px;
  border-radius: 50%;
  font-size: 22px;
  cursor: pointer;
  display: none;
  align-items: center;
  justify-content: center;
  transition: all 0.2s;
}
.lb-check.visible { display: flex; }
.lb-check.done {
  border-color: #4caf50;
  color: #fff;
  background: #4caf50;
  transform: scale(1.1);
}
.lb-check:active { transform: scale(0.9); }
.lb-close {
  position: absolute;
  top: 16px; right: 20px;
  background: none;
  border: none;
  color: #fff;
  font-size: 28px;
  cursor: pointer;
  padding: 8px;
  z-index: 101;
}
.lb-nav {
  position: absolute;
  top: 50%;
  transform: translateY(-50%);
  background: rgba(255,255,255,0.1);
  border: none;
  color: #fff;
  font-size: 24px;
  padding: 16px 12px;
  cursor: pointer;
  border-radius: 8px;
  z-index: 101;
}
.lb-nav:active { background: rgba(255,255,255,0.2); }
.lb-prev { left: 12px; }
.lb-next { right: 12px; }

/* Clear shot list button */
.clear-btn {
  display: none;
  background: none;
  border: 1px solid #444;
  color: #888;
  font-size: 12px;
  padding: 4px 10px;
  border-radius: 12px;
  cursor: pointer;
  margin-left: auto;
}
.clear-btn.visible { display: inline-block; }

/* Shot List layout */
.shotlist-grid {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 10px;
  padding: 8px 12px 20px;
  max-width: 1000px;
  margin: 0 auto;
}
.shotlist-grid .gallery-item {
  break-inside: auto;
  margin-bottom: 0;
}
.shotlist-section-label {
  grid-column: 1 / -1;
  font-size: 13px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 1px;
  padding: 16px 4px 6px;
  color: #888;
}
.shotlist-section-label.done-label { color: #4caf50; }
.shotlist-done-grid {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 6px;
  grid-column: 1 / -1;
}
.shotlist-done-grid .gallery-item {
  margin-bottom: 0;
}

/* Loved filter button in header */
.loved-filter-btn {
  display: none;
  background: none;
  border: 2px solid #444;
  color: #666;
  width: 36px;
  height: 36px;
  border-radius: 50%;
  font-size: 18px;
  cursor: pointer;
  transition: all 0.2s;
  flex-shrink: 0;
}
.loved-filter-btn.visible { display: flex; align-items: center; justify-content: center; }
.loved-filter-btn.active {
  border-color: #e74c6f;
  color: #fff;
  background: #e74c6f;
}

/* Filter tabs */
.filter-tabs {
  display: flex;
  gap: 8px;
  padding: 8px 16px 4px;
  justify-content: center;
}
.filter-tab {
  background: #252525;
  border: 1px solid #333;
  color: #888;
  font-size: 13px;
  font-weight: 600;
  padding: 8px 18px;
  border-radius: 20px;
  cursor: pointer;
  transition: all 0.2s;
}
.filter-tab.active {
  background: rgba(168,85,247,0.15);
  border-color: #a855f7;
  color: #a855f7;
}
.filter-tab.done-tab {
  background: rgba(76,175,80,0.15);
  border-color: #4caf50;
  color: #4caf50;
}

/* Responsive: iPad landscape */
@media (min-width: 768px) {
  .categories {
    grid-template-columns: repeat(3, 1fr);
    max-width: 800px;
    margin: 0 auto;
  }
  .tile.shotlist-tile { grid-column: 1 / -1; }
  .gallery { columns: 4; max-width: 1000px; margin: 0 auto; }
  .shotlist-grid { grid-template-columns: repeat(3, 1fr); }
  .shotlist-done-grid { grid-template-columns: repeat(6, 1fr); }
}

/* Phone */
@media (max-width: 480px) {
  .gallery { columns: 2; }
}

/* Empty state */
.empty {
  text-align: center;
  padding: 60px 20px;
  color: #666;
  font-size: 15px;
  column-span: all;
}'''


# ── CLI ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Pose Guide — encrypted build pipeline")
    parser.add_argument("--init", action="store_true", help="Create .secret with random password")
    parser.add_argument("--link", action="store_true", help="Print convenience URL")
    parser.add_argument("--prune", action="store_true", help="Remove stale chunks not in current index.html")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL, help="Base URL for convenience link")
    args = parser.parse_args()

    if args.init:
        if SECRET_FILE.exists():
            print(f".secret already exists. Delete it first to regenerate.")
            sys.exit(1)
        pw = secrets.token_urlsafe(16)
        SECRET_FILE.write_text(json.dumps({"password": pw}, indent=2) + "\n")
        print(f"Created .secret with password: {pw}")
        return

    if args.prune:
        prune_chunks()
        return

    if args.link:
        pw = load_secret()
        base = args.base_url.rstrip("/")
        print(f"\nConvenience URL (password in query param):")
        print(f"  {base}/?k={pw}")
        print(f"\nDirect URL (manual password entry):")
        print(f"  {base}/")
        return

    # Full build
    password = load_secret()
    build(password)


if __name__ == "__main__":
    main()
