#!/usr/bin/env python3
"""
nft_scraper.py - fetch and store NFT metadata + media from IPFS (OpenSea metadata standard).

Given an ipfs:// URL (or gateway URL / bare CID / ar:// / https:// / data: URI) it will:
  1. resolve the token metadata JSON through a pool of IPFS gateways (failover + retry + backoff)
  2. parse OpenSea-style fields (name, description, image, image_data, animation_url, attributes...)
  3. resolve relative asset paths, download the image (and optionally animation) via streaming
  4. detect the real file type from magic bytes, hash it (sha256), write everything atomically
  5. record provenance in record.json and a SQLite index (resumable; completed items are skipped)

Install:   pip install aiohttp
Examples:
  python nft_scraper.py ipfs://bafybei.../1.json
  python nft_scraper.py -f urls.txt -o ./nfts --concurrency 16
  python nft_scraper.py --collection ipfs://QmBase... --range 1-10000 --suffix .json
Library:
  async with NFTScraper(out_dir="nfts") as s:
      rec = await s.process("ipfs://Qm.../1.json")
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import ipaddress
import json
import logging
import mimetypes
import os
import posixpath
import re
import socket
import sqlite3
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional
from urllib.parse import quote, unquote, urljoin, urlparse

import aiohttp

log = logging.getLogger("nft_scraper")

# Public gateways change over time - override with --gateway or IPFS_GATEWAYS (comma separated).
DEFAULT_GATEWAYS = [
    "https://ipfs.io/ipfs/",
    "https://dweb.link/ipfs/",
    "https://w3s.link/ipfs/",
    "https://nftstorage.link/ipfs/",
    "https://gateway.pinata.cloud/ipfs/",
    "https://4everland.io/ipfs/",
    "https://trustless-gateway.link/ipfs/",
]
ARWEAVE_GATEWAYS = ["https://arweave.net/", "https://ar-io.net/"]

CID_RE = re.compile(
    r"(?:Qm[1-9A-HJ-NP-Za-km-z]{44}"          # CIDv0
    r"|b[a-z2-7]{50,}"                         # CIDv1 base32
    r"|k[a-z0-9]{40,}"                         # CIDv1 base36
    r"|z[1-9A-HJ-NP-Za-km-z]{40,}"             # CIDv1 base58btc
    r"|f[0-9a-f]{50,})"                        # CIDv1 base16
)
SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*:")


# --------------------------------------------------------------------------- errors
class FetchError(Exception):
    pass


class SizeError(FetchError):
    pass


class TransientError(Exception):
    pass


class PermanentError(Exception):
    pass


# --------------------------------------------------------------------------- URL handling
@dataclass(frozen=True)
class IpfsRef:
    cid: str
    path: str = ""

    def uri(self) -> str:
        return f"ipfs://{self.cid}" + (f"/{self.path}" if self.path else "")

    def gateway_suffix(self) -> str:
        return self.cid + (("/" + quote(self.path, safe="/")) if self.path else "")


def parse_ipfs(s: str) -> Optional[IpfsRef]:
    """Accepts ipfs://, ipfs://ipfs/, /ipfs/, path/subdomain gateway URLs and bare CIDs."""
    s = s.strip()
    if s.lower().startswith("ipfs://"):
        rest = s[7:]
        if rest.startswith("ipfs/"):
            rest = rest[5:]
    elif s.lower().startswith(("http://", "https://")):
        u = urlparse(s)
        m = re.match(r"^([^.]+)\.ipfs\.", u.hostname or "")
        if m and CID_RE.fullmatch(m.group(1)):
            rest = m.group(1) + u.path
        elif "/ipfs/" in u.path:
            rest = u.path.split("/ipfs/", 1)[1]
        else:
            return None
    elif s.startswith("/ipfs/"):
        rest = s[6:]
    elif SCHEME_RE.match(s) and not CID_RE.match(s):
        return None
    else:
        rest = s
    rest = rest.split("?", 1)[0].split("#", 1)[0]
    cid, _, path = rest.partition("/")
    if not CID_RE.fullmatch(cid):
        return None
    return IpfsRef(cid, unquote(path).strip("/"))


def resolve_target(target: str, base: str) -> str:
    """Resolve a (possibly relative) asset reference against the metadata URL."""
    t = target.strip()
    if t.startswith("data:") or SCHEME_RE.match(t) and not CID_RE.match(t) or parse_ipfs(t):
        return t
    base_ref = parse_ipfs(base)
    if base_ref:
        rel = posixpath.normpath(posixpath.join(posixpath.dirname(base_ref.path), t)).lstrip("./")
        return IpfsRef(base_ref.cid, rel).uri()
    return urljoin(base, t)


def safe_key(source: str) -> str:
    ref = parse_ipfs(source)
    raw = ref.uri()[7:] if ref else re.sub(r"^[a-z]+://", "", source)
    key = re.sub(r"[^A-Za-z0-9._-]+", "_", raw).strip("_")
    if not key or len(key) > 150 or source.startswith("data:"):
        key = hashlib.sha256(source.encode()).hexdigest()[:32]
    return key


# --------------------------------------------------------------------------- file type sniffing
def sniff_ext(head: bytes) -> Optional[str]:
    h = head
    if h.startswith(b"\x89PNG\r\n\x1a\n"):
        return ".png"
    if h.startswith(b"\xff\xd8\xff"):
        return ".jpg"
    if h[:4] == b"GIF8":
        return ".gif"
    if h[:4] == b"RIFF" and h[8:12] == b"WEBP":
        return ".webp"
    if h[:4] == b"RIFF" and h[8:12] == b"WAVE":
        return ".wav"
    if h[:2] == b"BM":
        return ".bmp"
    if h[:4] in (b"II*\x00", b"MM\x00*"):
        return ".tiff"
    if h[4:8] == b"ftyp":
        brand = h[8:12]
        if brand in (b"avif", b"avis"):
            return ".avif"
        if brand in (b"heic", b"heix", b"mif1"):
            return ".heic"
        return ".mp4"
    if h[:4] == b"\x1a\x45\xdf\xa3":
        return ".webm"
    if h[:4] == b"glTF":
        return ".glb"
    if h[:4] == b"OggS":
        return ".ogg"
    if h[:3] == b"ID3" or h[:2] in (b"\xff\xfb", b"\xff\xf3"):
        return ".mp3"
    if h[:4] == b"%PDF":
        return ".pdf"
    if b"<svg" in h[:2048].lower():
        return ".svg"
    return None


def looks_like_html(head: bytes, ctype: Optional[str]) -> bool:
    h = head.lstrip(b"\xef\xbb\xbf \t\r\n")[:20].lower()
    if h.startswith((b"<!doctype html", b"<html")):
        return True
    return bool(ctype and ctype.lower().startswith("text/html"))


def pick_ext(head: bytes, ctype: Optional[str]) -> str:
    ext = sniff_ext(head)
    if ext:
        return ext
    if ctype:
        guess = mimetypes.guess_extension(ctype.split(";")[0].strip())
        if guess:
            return {".jpe": ".jpg"}.get(guess, guess)
    return ".bin"


# --------------------------------------------------------------------------- data model
@dataclass
class Fetched:
    path: Path
    sha256: str
    size: int
    content_type: Optional[str]
    url: str

    def head(self, n: int = 4096) -> bytes:
        with open(self.path, "rb") as f:
            return f.read(n)


def atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".tmp_")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


# --------------------------------------------------------------------------- scraper
class NFTScraper:
    def __init__(
        self,
        out_dir: str | Path = "nft_data",
        gateways: Optional[list[str]] = None,
        concurrency: int = 8,
        retries: int = 3,
        read_timeout: float = 30,
        total_timeout: float = 300,
        max_meta_bytes: int = 5 * 1024 * 1024,
        max_media_bytes: int = 200 * 1024 * 1024,
        download_animation: bool = False,
        allow_private: bool = False,
        force: bool = False,
    ):
        env = os.environ.get("IPFS_GATEWAYS")
        gws = gateways or ([g for g in env.split(",") if g] if env else DEFAULT_GATEWAYS)
        self.gateways = [g if g.endswith("/") else g + "/" for g in gws]
        self.out = Path(out_dir)
        self.tmpdir = self.out / ".tmp"
        self.sem = asyncio.Semaphore(concurrency)
        self.retries = retries
        self.read_timeout = read_timeout
        self.total_timeout = total_timeout
        self.max_meta = max_meta_bytes
        self.max_media = max_media_bytes
        self.animation = download_animation
        self.allow_private = allow_private
        self.force = force
        self.session: Optional[aiohttp.ClientSession] = None
        self.db: Optional[sqlite3.Connection] = None

    # ---- lifecycle
    async def __aenter__(self) -> "NFTScraper":
        (self.out / "items").mkdir(parents=True, exist_ok=True)
        self.tmpdir.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.out / "index.db")
        self.db.execute(
            """CREATE TABLE IF NOT EXISTS items(
                 source TEXT PRIMARY KEY, key TEXT, status TEXT, name TEXT,
                 image_source TEXT, image_file TEXT, image_sha256 TEXT, image_bytes INTEGER,
                 metadata_file TEXT, gateway TEXT, error TEXT, fetched_at REAL)"""
        )
        self.session = aiohttp.ClientSession(
            headers={"User-Agent": "nft-scraper/1.0 (+metadata archiver)", "Accept": "*/*"},
            connector=aiohttp.TCPConnector(limit=64, limit_per_host=8, ttl_dns_cache=300),
        )
        return self

    async def __aexit__(self, *exc) -> None:
        if self.session:
            await self.session.close()
        if self.db:
            self.db.commit()
            self.db.close()
        try:
            for p in self.tmpdir.glob("*"):
                p.unlink(missing_ok=True)
            self.tmpdir.rmdir()
        except OSError:
            pass

    # ---- candidate URL construction
    def candidates(self, source: str) -> list[str]:
        ref = parse_ipfs(source)
        if ref:
            urls = [g + ref.gateway_suffix() for g in self.gateways]
            if source.lower().startswith(("http://", "https://")) and source not in urls:
                urls.insert(0, source)  # honour the explicit gateway first
            return urls
        if source.lower().startswith("ar://"):
            return [g + source[5:].lstrip("/") for g in ARWEAVE_GATEWAYS]
        if source.lower().startswith(("http://", "https://")):
            return [source]
        raise FetchError(f"unsupported URI scheme: {source[:60]}")

    async def _ensure_public(self, url: str) -> None:
        """SSRF guard: metadata is untrusted, don't let it point us at internal hosts."""
        host = urlparse(url).hostname
        if not host:
            raise FetchError(f"bad URL: {url}")
        loop = asyncio.get_running_loop()
        try:
            infos = await loop.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        except socket.gaierror as e:
            raise TransientError(f"DNS failure for {host}: {e}")
        for info in infos:
            if not ipaddress.ip_address(info[4][0]).is_global:
                raise FetchError(f"refusing non-public address for {host} (use --allow-private)")

    # ---- core download (streams to disk, caps size, hashes on the fly)
    async def _download(self, url: str, max_bytes: int) -> Fetched:
        assert self.session
        timeout = aiohttp.ClientTimeout(total=None, connect=10, sock_connect=10, sock_read=self.read_timeout)
        async with self.session.get(url, timeout=timeout, allow_redirects=True, max_redirects=5) as r:
            if r.status == 429:
                try:
                    wait = min(float(r.headers.get("Retry-After", "5")), 30)
                except ValueError:
                    wait = 5
                await asyncio.sleep(wait)
                raise TransientError("429 rate limited")
            if r.status in (408, 425) or r.status >= 500:
                raise TransientError(f"HTTP {r.status}")
            if r.status != 200:
                raise PermanentError(f"HTTP {r.status}")
            clen = r.content_length
            if clen and clen > max_bytes:
                raise SizeError(f"{clen} bytes exceeds limit {max_bytes}")
            ctype = r.headers.get("Content-Type")
            fd, tmp = tempfile.mkstemp(dir=self.tmpdir, prefix="dl_")
            h, size = hashlib.sha256(), 0
            try:
                with os.fdopen(fd, "wb") as f:
                    async for chunk in r.content.iter_chunked(64 * 1024):
                        size += len(chunk)
                        if size > max_bytes:
                            raise SizeError(f"download exceeds limit {max_bytes}")
                        h.update(chunk)
                        f.write(chunk)
                if clen is not None and not r.headers.get("Content-Encoding") and size != clen:
                    raise TransientError(f"truncated body ({size}/{clen})")
                if size == 0:
                    raise TransientError("empty body")
            except BaseException:
                if os.path.exists(tmp):
                    os.unlink(tmp)
                raise
            return Fetched(Path(tmp), h.hexdigest(), size, ctype, url)

    async def acquire(self, source: str, max_bytes: int) -> Fetched:
        """Fetch any supported source with gateway failover, retries and exponential backoff."""
        if source.startswith("data:"):
            return self._from_data_uri(source, max_bytes)
        urls = self.candidates(source)
        needs_ssrf_check = parse_ipfs(source) is None and not source.lower().startswith("ar://")
        last: Optional[BaseException] = None
        for url in urls:
            if needs_ssrf_check and not self.allow_private:
                await self._ensure_public(url)
            for attempt in range(1, self.retries + 1):
                try:
                    got = await asyncio.wait_for(self._download(url, max_bytes), self.total_timeout)
                    head = got.head()
                    if looks_like_html(head, got.content_type) and not head.lstrip().startswith(b"<svg"):
                        got.path.unlink(missing_ok=True)
                        raise PermanentError("received HTML instead of content")
                    return got
                except SizeError:
                    raise
                except PermanentError as e:
                    last = e
                    break  # try next gateway
                except (TransientError, aiohttp.ClientError, asyncio.TimeoutError, OSError) as e:
                    last = e
                    if attempt < self.retries:
                        delay = min(2 ** attempt, 20) * (0.5 + (hash((url, attempt)) % 100) / 100)
                        log.debug("retry %s (%s) in %.1fs", url, e or type(e).__name__, delay)
                        await asyncio.sleep(delay)
            log.debug("gateway failed: %s -> %r", url, last)
        raise FetchError(f"all sources failed for {source}: {last!r}")

    def _from_data_uri(self, uri: str, max_bytes: int) -> Fetched:
        m = re.match(r"^data:([^,;]*)((?:;[^,;]*)*),(.*)$", uri, re.S)
        if not m:
            raise FetchError("malformed data URI")
        ctype, params, payload = m.group(1) or None, m.group(2), m.group(3)
        data = base64.b64decode(payload + "=" * (-len(payload) % 4)) if ";base64" in params else unquote(payload).encode()
        if len(data) > max_bytes:
            raise SizeError("data URI exceeds limit")
        fd, tmp = tempfile.mkstemp(dir=self.tmpdir, prefix="dl_")
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        return Fetched(Path(tmp), hashlib.sha256(data).hexdigest(), len(data), ctype, "data:")

    # ---- asset storage
    def _store_asset(self, got: Fetched, dest_dir: Path, stem: str) -> dict[str, Any]:
        ext = pick_ext(got.head(), got.content_type)
        final = dest_dir / f"{stem}{ext}"
        dest_dir.mkdir(parents=True, exist_ok=True)
        os.replace(got.path, final)
        return {"file": final.name, "sha256": got.sha256, "bytes": got.size,
                "content_type": got.content_type, "fetched_from": got.url}

    async def _save_asset(self, target: str, base: str, dest_dir: Path, stem: str) -> dict[str, Any]:
        if target.lstrip().startswith("<svg") or target.lstrip().startswith("<?xml"):  # inline image_data
            data = target.encode()
            atomic_write(dest_dir / f"{stem}.svg", data)
            return {"file": f"{stem}.svg", "sha256": hashlib.sha256(data).hexdigest(),
                    "bytes": len(data), "content_type": "image/svg+xml", "fetched_from": "inline"}
        resolved = resolve_target(target, base)
        got = await self.acquire(resolved, self.max_media)
        info = self._store_asset(got, dest_dir, stem)
        info["source"] = resolved
        return info

    # ---- main entry
    async def process(self, source: str) -> dict[str, Any]:
        async with self.sem:
            key = safe_key(source)
            item_dir = self.out / "items" / key
            rec_path = item_dir / "record.json"
            if not self.force and rec_path.exists():
                try:
                    old = json.loads(rec_path.read_text())
                    if old.get("status") == "ok" and all((item_dir / a["file"]).exists() for a in old.get("assets", {}).values()):
                        log.info("skip   %s (already complete)", source)
                        return old
                except (OSError, ValueError):
                    pass
            record: dict[str, Any] = {"source": source, "key": key, "status": "error", "fetched_at": time.time(), "assets": {}}
            try:
                meta_fetch = await self.acquire(source, self.max_meta)
                raw = meta_fetch.path.read_bytes()
                head = raw[:4096]
                meta: Optional[dict] = None
                try:
                    parsed = json.loads(raw.decode("utf-8-sig"))
                    meta = parsed if isinstance(parsed, dict) else {"_value": parsed}
                except (UnicodeDecodeError, ValueError):
                    pass

                if meta is None:
                    if sniff_ext(head) or (meta_fetch.content_type or "").startswith(("image/", "video/", "audio/")):
                        # The URL pointed straight at media, not at a metadata JSON.
                        record["assets"]["image"] = self._store_asset(meta_fetch, item_dir, "image")
                        record.update(status="ok", note="source was media, not JSON metadata")
                    else:
                        raise FetchError("response is neither JSON metadata nor recognised media")
                else:
                    meta_fetch.path.unlink(missing_ok=True)
                    atomic_write(item_dir / "metadata.json", raw)  # exact bytes as served
                    norm = normalize_metadata(meta)
                    record["metadata_source"] = meta_fetch.url
                    record["normalized"] = norm
                    if norm["image"]:
                        record["assets"]["image"] = await self._save_asset(norm["image"], source, item_dir, "image")
                    if self.animation and norm["animation_url"]:
                        try:
                            record["assets"]["animation"] = await self._save_asset(norm["animation_url"], source, item_dir, "animation")
                        except FetchError as e:  # animation is best-effort
                            record["animation_error"] = str(e)
                    record["status"] = "ok" if (not norm["image"] or "image" in record["assets"]) else "error"
                    if not norm["image"]:
                        record["note"] = "metadata has no image field"
                log.info("ok     %s", source)
            except Exception as e:  # noqa: BLE001 - record every failure, keep batch going
                record["error"] = f"{type(e).__name__}: {e}"
                log.warning("FAILED %s: %s", source, record["error"])
            finally:
                item_dir.mkdir(parents=True, exist_ok=True)
                atomic_write(rec_path, json.dumps(record, indent=2, ensure_ascii=False).encode())
                self._index(record)
            return record

    def _index(self, rec: dict[str, Any]) -> None:
        assert self.db
        img = rec.get("assets", {}).get("image", {})
        self.db.execute(
            "INSERT OR REPLACE INTO items VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (rec["source"], rec["key"], rec["status"], (rec.get("normalized") or {}).get("name"),
             img.get("source"), img.get("file"), img.get("sha256"), img.get("bytes"),
             "metadata.json" if "normalized" in rec else None, rec.get("metadata_source"),
             rec.get("error"), rec["fetched_at"]),
        )
        self.db.commit()

    async def run(self, sources: list[str]) -> list[dict[str, Any]]:
        results = await asyncio.gather(*(self.process(s) for s in sources))
        ok = sum(r["status"] == "ok" for r in results)
        log.info("done: %d ok, %d failed, %d total", ok, len(results) - ok, len(results))
        failed = [r for r in results if r["status"] != "ok"]
        if failed:
            with open(self.out / "failures.jsonl", "a") as f:
                for r in failed:
                    f.write(json.dumps({"source": r["source"], "error": r.get("error")}) + "\n")
        return results


# --------------------------------------------------------------------------- metadata normalisation
def _first(d: dict, *keys: str) -> Any:
    for k in keys:
        v = d.get(k)
        if v not in (None, ""):
            return v
    return None


def normalize_metadata(meta: dict) -> dict[str, Any]:
    """Map the many real-world variants onto the OpenSea metadata standard."""
    image = _first(meta, "image", "image_url", "imageUrl", "image_uri", "imageURI", "image_data", "imageData")
    if isinstance(image, dict):  # e.g. {"url": "..."}
        image = _first(image, "url", "src", "uri")
    attrs = _first(meta, "attributes", "traits", "properties") or []
    if isinstance(attrs, dict):
        attrs = [{"trait_type": k, "value": (v.get("value") if isinstance(v, dict) else v)} for k, v in attrs.items()]
    elif isinstance(attrs, list):
        attrs = [a if isinstance(a, dict) else {"value": a} for a in attrs]
    else:
        attrs = []
    return {
        "name": _first(meta, "name", "title"),
        "description": meta.get("description"),
        "image": image if isinstance(image, str) else None,
        "animation_url": _first(meta, "animation_url", "animationUrl", "animation"),
        "external_url": _first(meta, "external_url", "externalUrl", "external_link"),
        "background_color": meta.get("background_color"),
        "attributes": attrs,
    }


# --------------------------------------------------------------------------- CLI
def read_sources(args: argparse.Namespace) -> list[str]:
    srcs = list(args.sources)
    if args.file:
        for line in Path(args.file).read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                srcs.append(line)
    if args.collection:
        lo, _, hi = (args.range or "1-1").partition("-")
        base = args.collection.rstrip("/")
        srcs += [f"{base}/{i}{args.suffix}" for i in range(int(lo), int(hi or lo) + 1)]
    seen, uniq = set(), []
    for s in srcs:
        if s not in seen:
            seen.add(s)
            uniq.append(s)
    return uniq


def main() -> int:
    p = argparse.ArgumentParser(description="Archive NFT metadata + media from IPFS.")
    p.add_argument("sources", nargs="*", help="ipfs:// URLs, gateway URLs, CIDs, ar://, https://")
    p.add_argument("-f", "--file", help="text file with one URL per line")
    p.add_argument("--collection", help="base URI of a token folder, e.g. ipfs://CID")
    p.add_argument("--range", help="token id range for --collection, e.g. 1-10000")
    p.add_argument("--suffix", default="", help="appended to each token id, e.g. .json")
    p.add_argument("-o", "--out", default="nft_data")
    p.add_argument("-c", "--concurrency", type=int, default=8)
    p.add_argument("--retries", type=int, default=3)
    p.add_argument("--timeout", type=float, default=30, help="per-read socket timeout (s)")
    p.add_argument("--max-media-mb", type=float, default=200)
    p.add_argument("--gateway", action="append", help="IPFS gateway base (repeatable; replaces defaults)")
    p.add_argument("--animation", action="store_true", help="also download animation_url")
    p.add_argument("--allow-private", action="store_true", help="allow non-public http(s) hosts")
    p.add_argument("--force", action="store_true", help="re-download completed items")
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args()
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)-7s %(message)s", datefmt="%H:%M:%S")
    sources = read_sources(args)
    if not sources:
        p.error("no sources given")

    async def go() -> int:
        async with NFTScraper(
            out_dir=args.out, gateways=args.gateway, concurrency=args.concurrency, retries=args.retries,
            read_timeout=args.timeout, max_media_bytes=int(args.max_media_mb * 1024 * 1024),
            download_animation=args.animation, allow_private=args.allow_private, force=args.force,
        ) as s:
            results = await s.run(sources)
        return 0 if all(r["status"] == "ok" for r in results) else 1

    try:
        return asyncio.run(go())
    except KeyboardInterrupt:
        log.warning("interrupted - rerun the same command to resume")
        return 130


if __name__ == "__main__":
    sys.exit(main())
