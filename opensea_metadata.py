#!/usr/bin/env python3
"""
opensea_metadata.py - turn raw NFT images + a CSV of traits into OpenSea-standard metadata JSON,
saved next to (and named after) each image, with a manifest that ties image <-> JSON by sha256.

Commands
  template  IMAGES_DIR -o metadata.csv      scan images, write a pre-filled CSV to edit
  build     metadata.csv --images DIR       CSV + images -> one OpenSea JSON per image (+ manifest.csv)
  export    JSON_DIR -o metadata.csv        existing OpenSea JSON -> CSV (round-trip)
  validate  JSON_DIR                        check JSON files against OpenSea's metadata rules

CSV format (header row; column order is free)
  Reserved columns : token_id, filename, name, description, image, external_url,
                     animation_url, background_color, youtube_url
  Trait columns    : any other column = string trait, e.g.  Background, Eyes
                     or explicit      : trait:Level|number|max=100
                     display types    : number | boost_number | boost_percentage | date
  Cell shortcuts   : "45/100" in a numeric trait column -> value 45, max_value 100
                     date cells may be unix seconds or ISO (2021-03-01 / 2021-03-01T12:00:00Z)
  Empty cells are skipped (trait omitted for that token).

Image <-> row matching: `filename` column if present, else the number in the image filename
(7.png, Cat_0007.png, 64-hex ERC-1155 ids) is matched to `token_id`.

Stdlib only; Pillow is used (if installed) to record image width/height in the manifest.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import mimetypes
import os
import re
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
from urllib.parse import quote, unquote

IMG_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".avif", ".bmp",
           ".mp4", ".webm", ".glb", ".gltf", ".mp3", ".wav"}
RESERVED = ["token_id", "filename", "name", "description", "image", "external_url",
            "animation_url", "background_color", "youtube_url"]
DISPLAY_TYPES = {"number", "boost_number", "boost_percentage", "date"}
NUMERIC_TYPES = {"number", "boost_number", "boost_percentage"}
META_ORDER = ["name", "description", "image", "external_url", "animation_url",
              "background_color", "youtube_url", "attributes"]


# --------------------------------------------------------------------------- helpers
@dataclass(frozen=True)
class TraitSpec:
    name: str
    display_type: Optional[str] = None
    max_value: Optional[float] = None

    def header(self) -> str:
        if not self.display_type and self.max_value is None:
            return self.name if self.name.lower() not in RESERVED else f"trait:{self.name}"
        parts = [f"trait:{self.name}"]
        if self.display_type:
            parts.append(self.display_type)
        if self.max_value is not None:
            parts.append(f"max={fmt_num(self.max_value)}")
        return "|".join(parts)


def fmt_num(x: float) -> str:
    return str(int(x)) if float(x).is_integer() else str(x)


def to_number(s: Any) -> int | float:
    if isinstance(s, (int, float)) and not isinstance(s, bool):
        return s
    f = float(str(s).strip())
    return int(f) if f.is_integer() else f


def parse_header(h: str) -> tuple[str, Any]:
    raw = h.strip().lstrip("\ufeff")
    if raw.lower() in RESERVED:
        return "field", raw.lower()
    spec = raw[6:] if raw.lower().startswith("trait:") else raw
    name, *mods = [p.strip() for p in spec.split("|")]
    if not name:
        raise ValueError(f"empty trait name in header {h!r}")
    dt, mx = None, None
    for m in mods:
        if m in DISPLAY_TYPES:
            dt = m
        elif m.startswith("max="):
            mx = to_number(m[4:])
        else:
            raise ValueError(f"unknown modifier {m!r} in header {h!r} (display types: {sorted(DISPLAY_TYPES)})")
    return "trait", TraitSpec(name, dt, mx)


def token_id_from_stem(stem: str) -> Optional[int]:
    if re.fullmatch(r"[0-9a-fA-F]{64}", stem):  # ERC-1155 {id} convention
        return int(stem, 16)
    nums = re.findall(r"\d+", stem)
    return int(nums[-1]) if nums else None


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def image_size(p: Path) -> tuple[Optional[int], Optional[int]]:
    try:
        from PIL import Image  # type: ignore
        with Image.open(p) as im:
            return im.size
    except Exception:  # noqa: BLE001 - Pillow missing or unsupported format
        return None, None


def atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".tmp_")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as f:
            f.write(text)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def index_images(d: Path) -> tuple[dict[str, Path], dict[int, list[Path]]]:
    by_name: dict[str, Path] = {}
    by_id: dict[int, list[Path]] = {}
    for p in sorted(d.iterdir()):
        if p.is_file() and p.suffix.lower() in IMG_EXT:
            by_name[p.name] = p
            tid = token_id_from_stem(p.stem)
            if tid is not None:
                by_id.setdefault(tid, []).append(p)
    return by_name, by_id


# --------------------------------------------------------------------------- attribute building
def parse_date(s: str) -> int:
    s = s.strip()
    try:
        return int(float(s))
    except ValueError:
        pass
    dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp())


def build_attribute(spec: TraitSpec, cell: str) -> dict[str, Any]:
    cell = cell.strip()
    attr: dict[str, Any] = {}
    if spec.display_type:
        attr["display_type"] = spec.display_type
    attr["trait_type"] = spec.name
    max_v = spec.max_value
    if spec.display_type in NUMERIC_TYPES:
        if "/" in cell:
            cell, _, m = cell.partition("/")
            max_v = to_number(m)
        attr["value"] = to_number(cell)
        if max_v is not None and spec.display_type == "number":
            attr["max_value"] = max_v
    elif spec.display_type == "date":
        attr["value"] = parse_date(cell)
    else:
        attr["value"] = cell  # keep text exactly (e.g. "007", "Gold")
    return attr


def normalize_color(c: str) -> str:
    return c.strip().lstrip("#").upper()


# --------------------------------------------------------------------------- validation
def validate_metadata(meta: dict[str, Any]) -> list[str]:
    errs: list[str] = []
    if not isinstance(meta, dict):
        return ["top level must be a JSON object"]
    if not meta.get("name"):
        errs.append("missing 'name'")
    if not meta.get("image"):
        errs.append("missing 'image'")
    elif not re.match(r"^(ipfs://|https?://|ar://|data:)", str(meta["image"])):
        errs.append("'image' is not an absolute URL (ipfs://, https://, ar://, data:) - OpenSea cannot load it")
    bg = meta.get("background_color")
    if bg is not None and not re.fullmatch(r"[0-9A-Fa-f]{6}", str(bg)):
        errs.append("'background_color' must be 6 hex digits without '#'")
    attrs = meta.get("attributes", [])
    if not isinstance(attrs, list):
        return errs + ["'attributes' must be a list"]
    seen = set()
    for i, a in enumerate(attrs):
        where = f"attributes[{i}]"
        if not isinstance(a, dict) or "value" not in a:
            errs.append(f"{where}: needs 'value'")
            continue
        dt, tt, v = a.get("display_type"), a.get("trait_type"), a["value"]
        if dt is not None and dt not in DISPLAY_TYPES:
            errs.append(f"{where}: bad display_type {dt!r}")
        if dt in NUMERIC_TYPES | {"date"} and (isinstance(v, bool) or not isinstance(v, (int, float))):
            errs.append(f"{where}: display_type {dt} needs a numeric value, got {v!r}")
        if "max_value" in a and isinstance(v, (int, float)) and v > a["max_value"]:
            errs.append(f"{where}: value {v} exceeds max_value {a['max_value']}")
        if dt == "date" and isinstance(v, (int, float)) and v > 1e11:
            errs.append(f"{where}: date must be unix SECONDS, not milliseconds")
        if tt is not None:
            if tt in seen:
                errs.append(f"{where}: duplicate trait_type {tt!r}")
            seen.add(tt)
    return errs


# --------------------------------------------------------------------------- build
def cmd_build(a: argparse.Namespace) -> int:
    img_dir = Path(a.images)
    out_dir = Path(a.out) if a.out else img_dir  # default: JSON saved beside the image
    by_name, by_id = index_images(img_dir)
    if not by_name:
        print(f"no images found in {img_dir}", file=sys.stderr)
        return 2

    with open(a.csv, newline="", encoding="utf-8-sig") as f:
        reader = csv.reader(f)
        try:
            headers = next(reader)
        except StopIteration:
            print("CSV is empty", file=sys.stderr)
            return 2
        cols = [parse_header(h) for h in headers]
        rows = [r for r in reader if any(c.strip() for c in r)]

    image_base = a.image_base
    if image_base and not image_base.endswith("/"):
        image_base += "/"
    written: dict[str, int] = {}
    manifest: list[dict[str, Any]] = []
    problems = 0

    for n, row in enumerate(rows, start=2):  # CSV line numbers (header = line 1)
        row = row + [""] * (len(cols) - len(row))
        fields: dict[str, str] = {}
        traits: list[tuple[TraitSpec, str]] = []
        for (kind, spec), cell in zip(cols, row):
            if not cell.strip():
                continue
            if kind == "field":
                fields[spec] = cell.strip()
            else:
                traits.append((spec, cell))

        # ---- identify the image for this row
        tid: Optional[int] = None
        if fields.get("token_id"):
            tid = to_number(fields["token_id"])  # type: ignore[assignment]
            tid = int(tid)
        path: Optional[Path] = None
        if fields.get("filename"):
            path = by_name.get(fields["filename"]) or next(
                (p for k, p in by_name.items() if k.lower() == fields["filename"].lower()), None)
            if not path:
                print(f"line {n}: image {fields['filename']!r} not found in {img_dir}", file=sys.stderr)
                problems += 1
                continue
            file_tid = token_id_from_stem(path.stem)
            if tid is None:
                tid = file_tid
            elif file_tid is not None and file_tid != tid:
                print(f"line {n}: warning - token_id {tid} != number in filename {path.name}", file=sys.stderr)
        elif tid is not None:
            cands = by_id.get(tid, [])
            if len(cands) != 1:
                print(f"line {n}: token_id {tid} matches {len(cands)} images - add a 'filename' column", file=sys.stderr)
                problems += 1
                continue
            path = cands[0]
        else:
            print(f"line {n}: row needs 'token_id' or 'filename'", file=sys.stderr)
            problems += 1
            continue

        # ---- assemble metadata in OpenSea field order
        meta: dict[str, Any] = {}
        meta["name"] = fields.get("name") or a.name_template.format(id=tid if tid is not None else path.stem, stem=path.stem)
        desc = fields.get("description") or a.description
        if desc:
            meta["description"] = desc
        if fields.get("image"):
            meta["image"] = fields["image"]
        elif image_base:
            meta["image"] = image_base + quote(path.name)
        else:
            meta["image"] = path.name  # relative placeholder; validation will flag it
        for k in ("external_url", "animation_url", "youtube_url"):
            if fields.get(k):
                meta[k] = fields[k]
        if fields.get("background_color"):
            meta["background_color"] = normalize_color(fields["background_color"])
        try:
            meta["attributes"] = [build_attribute(s, c) for s, c in traits]
        except ValueError as e:
            print(f"line {n}: bad trait value ({e})", file=sys.stderr)
            problems += 1
            continue
        digest = sha256_file(path)
        if a.embed_hash:
            meta["image_integrity"] = "sha256-" + digest  # ignored by OpenSea, handy for audits
        meta = {k: meta[k] for k in META_ORDER if k in meta} | {k: v for k, v in meta.items() if k not in META_ORDER}

        errs = [e for e in validate_metadata(meta) if not (not image_base and "absolute URL" in e)]
        if errs:
            problems += 1
            print(f"line {n} ({path.name}): " + "; ".join(errs), file=sys.stderr)
            if a.strict:
                continue

        # ---- choose the JSON filename
        if a.naming == "image":
            jname = path.stem + ".json"
        elif a.naming == "token":
            jname = f"{tid}.json"
        elif a.naming == "noext":
            jname = str(tid)
        else:  # hex64: ERC-1155 {id} substitution (64 lowercase hex digits)
            jname = f"{tid:064x}.json"
        if jname in written:
            print(f"line {n}: output name {jname} already produced by line {written[jname]}", file=sys.stderr)
            problems += 1
            continue
        written[jname] = n
        atomic_write_text(out_dir / jname, json.dumps(meta, indent=2, ensure_ascii=False) + "\n")

        w, h = image_size(path)
        manifest.append({
            "token_id": tid, "image_file": path.name, "image_sha256": digest,
            "image_bytes": path.stat().st_size,
            "mime": mimetypes.guess_type(path.name)[0] or "", "width": w or "", "height": h or "",
            "metadata_file": jname, "image_url": meta["image"],
        })

    if manifest:
        mp = out_dir / "manifest.csv"
        buf = []
        import io
        sio = io.StringIO()
        wtr = csv.DictWriter(sio, fieldnames=list(manifest[0].keys()), lineterminator="\n")
        wtr.writeheader()
        wtr.writerows(sorted(manifest, key=lambda m: (m["token_id"] is None, m["token_id"] or 0)))
        atomic_write_text(mp, sio.getvalue())
        del buf
    print(f"wrote {len(manifest)} metadata files to {out_dir}"
          + (f" ({problems} problem rows)" if problems else ""))
    unmatched = set(by_name) - {m["image_file"] for m in manifest}
    if unmatched:
        print(f"{len(unmatched)} images had no CSV row (e.g. {sorted(unmatched)[:3]})")
    return 1 if problems and a.strict else 0


# --------------------------------------------------------------------------- template
def cmd_template(a: argparse.Namespace) -> int:
    by_name, _ = index_images(Path(a.images))
    if not by_name:
        print("no images found", file=sys.stderr)
        return 2
    specs = [parse_header(t)[1] if parse_header(t)[0] == "trait" else TraitSpec(t)
             for t in (a.traits or [])]
    header = ["token_id", "filename", "name", "description", "external_url"] + [s.header() for s in specs]
    rows = []
    for p in by_name.values():
        tid = token_id_from_stem(p.stem)
        name = a.name_template.format(id=tid if tid is not None else p.stem, stem=p.stem)
        rows.append(([tid if tid is not None else "", p.name, name, a.description or "", ""]
                     + [""] * len(specs), tid if tid is not None else 1 << 60))
    rows.sort(key=lambda r: r[1])
    import io
    sio = io.StringIO()
    w = csv.writer(sio, lineterminator="\n")
    w.writerow(header)
    w.writerows(r for r, _ in rows)
    atomic_write_text(Path(a.output), sio.getvalue())
    print(f"template with {len(rows)} images -> {a.output}")
    return 0


# --------------------------------------------------------------------------- export
def cmd_export(a: argparse.Namespace) -> int:
    d = Path(a.json_dir)
    items = []
    for p in sorted(d.iterdir()):
        if not p.is_file() or p.name == "manifest.csv" or p.suffix not in (".json", ""):
            continue
        try:
            meta = json.loads(p.read_text(encoding="utf-8-sig"))
        except ValueError:
            continue
        if isinstance(meta, dict):
            items.append((p, meta))
    specs: dict[tuple, TraitSpec] = {}
    for _, m in items:
        for at in m.get("attributes", []) if isinstance(m.get("attributes"), list) else []:
            if isinstance(at, dict):
                key = (at.get("trait_type", ""), at.get("display_type"))
                specs.setdefault(key, TraitSpec(str(key[0]), key[1]))
    header = ["token_id", "filename", "name", "description", "external_url", "animation_url",
              "background_color", "youtube_url"] + [s.header() for s in specs.values()]
    out_rows = []
    for p, m in items:
        tid = token_id_from_stem(p.stem)
        img = str(m.get("image", ""))
        row = [tid if tid is not None else "", unquote(img.rsplit("/", 1)[-1]) if img else "",
               m.get("name", ""), m.get("description", ""), m.get("external_url", ""),
               m.get("animation_url", ""), m.get("background_color", ""), m.get("youtube_url", "")]
        cells = {}
        for at in m.get("attributes", []) if isinstance(m.get("attributes"), list) else []:
            if isinstance(at, dict):
                v = at.get("value", "")
                if at.get("display_type") == "number" and "max_value" in at:
                    v = f"{fmt_num(v)}/{fmt_num(at['max_value'])}"
                cells[(at.get("trait_type", ""), at.get("display_type"))] = v
        row += [cells.get(k, "") for k in specs]
        out_rows.append((tid if tid is not None else 1 << 60, row))
    import io
    sio = io.StringIO()
    w = csv.writer(sio, lineterminator="\n")
    w.writerow(header)
    w.writerows(r for _, r in sorted(out_rows, key=lambda x: x[0]))
    atomic_write_text(Path(a.output), sio.getvalue())
    print(f"exported {len(items)} files -> {a.output}")
    return 0


# --------------------------------------------------------------------------- validate
def cmd_validate(a: argparse.Namespace) -> int:
    bad = total = 0
    for p in sorted(Path(a.json_dir).iterdir()):
        if not p.is_file() or p.name == "manifest.csv" or p.suffix not in (".json", ""):
            continue
        total += 1
        try:
            errs = validate_metadata(json.loads(p.read_text(encoding="utf-8-sig")))
        except ValueError as e:
            errs = [f"invalid JSON: {e}"]
        if errs:
            bad += 1
            print(f"{p.name}: " + "; ".join(errs))
    print(f"{total - bad}/{total} files valid")
    return 1 if bad else 0


# --------------------------------------------------------------------------- CLI
def main() -> int:
    ap = argparse.ArgumentParser(description="OpenSea metadata builder (CSV <-> JSON, matched to images).")
    sub = ap.add_subparsers(dest="cmd", required=True)

    t = sub.add_parser("template", help="scan images and write a pre-filled CSV")
    t.add_argument("images")
    t.add_argument("-o", "--output", default="metadata.csv")
    t.add_argument("--traits", nargs="*", help='trait columns, e.g. Background Eyes "Level|number|max=100"')
    t.add_argument("--name-template", default="Token #{id}")
    t.add_argument("--description")
    t.set_defaults(fn=cmd_template)

    b = sub.add_parser("build", help="CSV + images -> OpenSea JSON beside each image")
    b.add_argument("csv")
    b.add_argument("--images", required=True)
    b.add_argument("--out", help="output dir (default: the images dir)")
    b.add_argument("--image-base", help="public base URI of the uploaded images, e.g. ipfs://CID/")
    b.add_argument("--naming", choices=["image", "token", "noext", "hex64"], default="image",
                   help="image: 7.png->7.json | token: <id>.json | noext: <id> | hex64: ERC-1155 padded hex")
    b.add_argument("--name-template", default="Token #{id}", help="used when a row has no name")
    b.add_argument("--description", help="default description when a row has none")
    b.add_argument("--embed-hash", action="store_true", help="add image_integrity: sha256-<hex>")
    b.add_argument("--strict", action="store_true", help="skip rows that fail validation; exit 1")
    b.set_defaults(fn=cmd_build)

    e = sub.add_parser("export", help="OpenSea JSON dir -> CSV")
    e.add_argument("json_dir")
    e.add_argument("-o", "--output", default="metadata.csv")
    e.set_defaults(fn=cmd_export)

    v = sub.add_parser("validate", help="validate OpenSea JSON files")
    v.add_argument("json_dir")
    v.set_defaults(fn=cmd_validate)

    args = ap.parse_args()
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
