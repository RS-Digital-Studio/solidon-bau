"""Startwerkzeug des Bau-Repositorys von Solidon.

Läuft auf den Läufern des öffentlichen Bau-Repositorys. Den Quelltext von
Solidon sieht dieses Repository nie unverschlüsselt: Er kommt als Paket über
einen unveröffentlichten Release-Entwurf, jedes Artefakt geht verschlüsselt
hinaus, und jeder Schritt schreibt seine Ausgabe in ein Protokoll, das
ebenfalls verschlüsselt hochgeladen wird. Ins öffentliche Log gehen nur
Zahlen und Ausgang.

Befehle (der Schlüssel kommt immer aus ``SOLIDON_BAU_KEY``, nie als Argument):

* ``setup`` richtet eine eigene Umgebung mit ``cryptography`` ein und legt
  Pfade, Ereignis und Frist des Jobs in ``GITHUB_ENV`` ab.
* ``source`` entschlüsselt das Paket des Laufs und stellt daraus einen flachen
  Git-Checkout genau des Commits her, mit Auftrag und Beilagen daneben.
* ``pack`` und ``unpack`` verschließen ein Artefakt vor dem Hochladen und
  öffnen es nach dem Laden.
* ``step`` fährt einen Workflowschritt still.
* ``crosscheck`` prüft die Swift-Fassung der Hülle (``box.swift``) gegen diese.

Die Hülle: ``MAGIC``, Kopflänge (4 Byte), Kopf als JSON, danach AES-256-GCM in
Blöcken zu ``BLOCK`` Byte. Die Nonce eines Blocks ist ein zufälliges Präfix
(7 Byte), seine Nummer (4 Byte) und ein Schlussbit — ein abgeschnittenes,
umgestelltes oder verlängertes Paket fällt so auf. Der ganze Vorspann ist
zusätzlich authentisierte Angabe jedes Blocks; Art, Name, Commit und Lauf sind
damit an den Inhalt gebunden.

Erzeugt aus dem privaten Repository (``tools/ci_relay.py``); hier nicht von
Hand bearbeiten.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import re
import secrets
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import time
import venv
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any, BinaryIO

MAGIC = b"SOLIDON-BAU-1\n"
BLOCK = 4 * 1024 * 1024
TAG = 16
PREFIX = 7
KEY_VARIABLE = "SOLIDON_BAU_KEY"
SOURCE_NAME = "source"
ORDER_MEMBER = "order.json"
PACK_MEMBER = "source.pack"
ATTACHMENT_FOLDER = "attachments"
BOX_SUFFIX = ".box"
#: So viel Zeit bleibt einem Job nach der Frist seiner Schritte für das
#: Verschließen und Hochladen von Berichten und Protokoll.
RESERVE_SECONDS = 10 * 60

_NAME = re.compile(r"[A-Za-z0-9._-]{1,200}")
_COMMIT = re.compile(r"[0-9a-f]{40}")
_NONCE = re.compile(r"[0-9a-f]{32}")
_REF = re.compile(r"refs/(?:heads|tags)/[A-Za-z0-9._/-]{1,100}")
_EVENTS = frozenset({"push", "workflow_dispatch"})
_GLOB = re.compile(r"[*?\[]")
#: Zeilen, die ein Schritt ins öffentliche Log geben darf: Zusammenfassungen
#: von pytest, mypy und ruff, die nur aus Zahlen und festen Wörtern bestehen.
_PYTEST_PART = r"\d+ (?:passed|failed|skipped|deselected|xfailed|xpassed|errors?|warnings?|rerun)"
_PYTEST_TIME = r"(?: in \d+(?:\.\d+)?s(?: \(\d+:\d\d:\d\d\))?)"
_SAFE_LINE = re.compile(
    "|".join(
        (
            rf"=*\s*{_PYTEST_PART}(?:, {_PYTEST_PART})*{_PYTEST_TIME}?\s*=*",
            r"=*\s*no tests ran in \d+(?:\.\d+)?s\s*=*",
            r"Found \d+ errors? in \d+ files? \(checked \d+ source files?\)",
            r"Success: no issues found in \d+ source files?",
            r"All checks passed!",
            r"Found \d+ errors?\.",
            r"\d+ files? (?:already formatted|would be reformatted|left unchanged)"
            r"(?:, \d+ files? (?:already formatted|would be reformatted|left unchanged))*",
        )
    )
)


class RefusalError(Exception):
    """Ein Halt — die Meldung nennt, was zu tun ist, und darf ins öffentliche Log.

    ``detail`` nennt Pfade und Namen des Stands; es geht nur ins verschlossene
    Protokoll des Jobs (:func:`main`).
    """

    def __init__(self, message: str, detail: str = "") -> None:
        super().__init__(message)
        self.detail = detail


# --- Hülle -----------------------------------------------------------------------


def parse_key(text: str) -> bytes:
    """Der Schlüssel als 32 Byte aus seiner Hexschreibweise."""
    value = text.strip().lower()
    if re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise RefusalError(
            "Der Schlüssel ist kein 64-stelliger Hexwert — Schlüsseldatei oder "
            f"Geheimnis {KEY_VARIABLE} prüfen."
        )
    return bytes.fromhex(value)


def key_from_environment() -> bytes:
    """Der Schlüssel des Laufs aus der Umgebung des Schritts."""
    text = os.environ.get(KEY_VARIABLE, "")
    if not text:
        raise RefusalError(
            f"{KEY_VARIABLE} fehlt — ein gerufener Workflow bekommt ihn nur über secrets: vom "
            "Aufrufer; den Lauf mit tools/ci_relay.py starten, das ihn setzt."
        )
    return parse_key(text)


def _checked(value: str, pattern: re.Pattern[str], what: str) -> str:
    if pattern.fullmatch(value) is None:
        raise RefusalError(f"Ungültige Angabe für {what}: {value!r} — Aufruf des Werkzeugs prüfen.")
    return value


def _nonce(prefix: bytes, index: int, last: bool) -> bytes:
    if index >= 2**32:
        raise RefusalError("Die Hülle ist zu groß — Artefakt teilen.")
    return prefix + index.to_bytes(4, "big") + (b"\x01" if last else b"\x00")


def _cipher(key: bytes) -> Any:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    return AESGCM(key)


def seal(
    key: bytes, source: BinaryIO, target: BinaryIO, *, kind: str, name: str, commit: str, run: str
) -> None:
    """Verschließt ``source`` nach ``target``, gebunden an Art, Name, Commit und Lauf."""
    fields = {
        "block": BLOCK,
        "commit": _checked(commit, _COMMIT, "Commit"),
        "format": 1,
        "kind": _checked(kind, _NAME, "Art"),
        "name": _checked(name, _NAME, "Name"),
        "prefix": secrets.token_bytes(PREFIX).hex(),
        "run": _checked(run, _NONCE, "Lauf"),
    }
    header = json.dumps(fields, sort_keys=True, separators=(",", ":")).encode("ascii")
    associated = MAGIC + len(header).to_bytes(4, "big") + header
    target.write(associated)
    cipher = _cipher(key)
    prefix = bytes.fromhex(str(fields["prefix"]))
    index = 0
    current = source.read(BLOCK)
    while True:
        following = source.read(BLOCK) if len(current) == BLOCK else b""
        last = not following
        target.write(cipher.encrypt(_nonce(prefix, index, last), current, associated))
        if last:
            return
        current = following
        index += 1


def read_header(source: BinaryIO) -> tuple[dict[str, Any], bytes]:
    """Kopf einer Hülle und die authentisierte Angabe; noch ungeprüft gegen den Inhalt."""
    magic = source.read(len(MAGIC))
    if magic != MAGIC:
        raise RefusalError("Keine Solidon-Hülle — Datei und Artefakt prüfen.")
    size_bytes = source.read(4)
    size = int.from_bytes(size_bytes, "big") if len(size_bytes) == 4 else 0
    header = source.read(size) if 0 < size <= 4096 else b""
    try:
        fields = json.loads(header) if header else None
    except ValueError:
        fields = None
    if (
        not isinstance(fields, dict)
        or fields.get("format") != 1
        or fields.get("block") != BLOCK
        or not isinstance(fields.get("prefix"), str)
        or re.fullmatch(r"[0-9a-f]{14}", fields["prefix"]) is None
        or not all(isinstance(fields.get(key), str) for key in ("kind", "name", "commit", "run"))
    ):
        raise RefusalError("Der Kopf der Hülle ist beschädigt — Artefakt neu erzeugen.")
    return fields, magic + size_bytes + header


def unseal(
    key: bytes, source: BinaryIO, target: BinaryIO, *, kind: str, name: str, commit: str, run: str
) -> None:
    """Öffnet eine Hülle; jede Abweichung in Kopf, Inhalt oder Schlüssel hält an.

    Der Aufrufer verwirft ``target``, wenn diese Funktion abbricht: Die Blöcke
    vor einem verfälschten sind dann schon geschrieben.
    """
    fields, associated = read_header(source)
    for field, expected in (("kind", kind), ("name", name), ("commit", commit), ("run", run)):
        if fields[field] != expected:
            raise RefusalError(
                f"Die Hülle gehört zu {field} {fields[field]!r}, erwartet {expected!r} — "
                "falsches Artefakt, anderer Commit oder anderer Lauf."
            )
    from cryptography.exceptions import InvalidTag

    cipher = _cipher(key)
    prefix = bytes.fromhex(fields["prefix"])
    index = 0
    chunk = source.read(BLOCK + TAG)
    while True:
        following = source.read(BLOCK + TAG) if len(chunk) == BLOCK + TAG else b""
        last = not following
        try:
            plain = cipher.decrypt(_nonce(prefix, index, last), chunk, associated)
        except InvalidTag as error:
            raise RefusalError(
                "Die Hülle ist verändert oder mit einem anderen Schlüssel verschlossen — "
                "Artefakt neu erzeugen oder den Schlüssel prüfen."
            ) from error
        target.write(plain)
        if last:
            return
        chunk = following
        index += 1


def seal_file(key: bytes, source: Path, target: Path, **binding: str) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    with source.open("rb") as reading, target.open("wb") as writing:
        seal(key, reading, writing, **binding)


def unseal_file(key: bytes, source: Path, target: Path, **binding: str) -> None:
    """Öffnet in eine Zwischendatei und benennt erst nach vollständigem Erfolg um."""
    target.parent.mkdir(parents=True, exist_ok=True)
    partial = target.with_name(target.name + ".teil")
    try:
        with source.open("rb") as reading, partial.open("wb") as writing:
            unseal(key, reading, writing, **binding)
        partial.replace(target)
    finally:
        partial.unlink(missing_ok=True)


# --- Quelle ----------------------------------------------------------------------


def write_source_payload(
    target: Path, order: Mapping[str, Any], pack: Path, attachments: Mapping[str, Path]
) -> None:
    """Der Inhalt eines Quellpakets: Auftrag, Git-Pack und Beilagen als tar."""
    with tarfile.open(target, "w", format=tarfile.PAX_FORMAT) as archive:
        data = json.dumps(order, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8")
        info = tarfile.TarInfo(ORDER_MEMBER)
        info.size = len(data)
        info.mode = 0o644
        archive.addfile(info, _bytes_reader(data))
        archive.add(pack, arcname=PACK_MEMBER, recursive=False)
        for name, path in sorted(attachments.items()):
            archive.add(path, arcname=f"{ATTACHMENT_FOLDER}/{_checked(name, _NAME, 'Beilage')}")


def _bytes_reader(data: bytes) -> BinaryIO:
    import io

    return io.BytesIO(data)


def _git(*arguments: str, cwd: Path, stdin: BinaryIO | None = None) -> str:
    done = subprocess.run(
        ["git", *arguments], cwd=cwd, stdin=stdin, capture_output=True, check=False
    )
    if done.returncode != 0:
        raise RefusalError(
            f"git {arguments[0]} endete mit {done.returncode} — Paket und Git des Läufers prüfen."
        )
    return done.stdout.decode("utf-8", "replace")


def restore_checkout(pack: Path, commit: str, target: Path) -> None:
    """Ein flacher Checkout genau dieses Commits, wie ``actions/checkout`` ihn legt.

    Git prüft beim Einlesen jede Objekt-SHA; ``HEAD`` ist danach der Commit,
    der Baum sauber, und Vorgänger gibt es nicht (``.git/shallow``).
    """
    target.mkdir(parents=True, exist_ok=True)
    if any(target.iterdir()):
        raise RefusalError(
            "Das Ziel der Quelle ist nicht leer — der Checkout gehört in einen leeren Ordner; "
            "die Reihenfolge der Schritte im Workflow prüfen.",
            detail=str(target),
        )
    _git("init", "-q", "-b", "main", cwd=target)
    with pack.open("rb") as stream:
        _git("index-pack", "--stdin", cwd=target, stdin=stream)
    (target / ".git" / "shallow").write_text(commit + "\n", encoding="ascii")
    _git("update-ref", "refs/heads/main", commit, cwd=target)
    _git("reset", "-q", "--hard", "main", cwd=target)
    if _git("rev-parse", "HEAD", cwd=target).strip() != commit:
        raise RefusalError(
            "Der Checkout steht nicht auf dem Commit des Pakets — Paket neu erzeugen."
        )
    if _git("status", "--porcelain", "--untracked-files=all", cwd=target).strip():
        raise RefusalError("Der Checkout weicht vom Commit ab — Paket neu erzeugen.")


def open_source(
    key: bytes,
    package: Path,
    *,
    commit: str,
    run: str,
    inputs: Mapping[str, str],
    target: Path,
    state: Path,
) -> dict[str, Any]:
    """Öffnet das Quellpaket, prüft den Auftrag gegen die Eingaben und legt den Checkout.

    Jede Eingabe des Handstarts außer der Paketnummer steht auch im Auftrag;
    eine abweichende hält an. So steuert keine Eingabe den Lauf, die nicht
    mit dem Paket verschlossen wurde.
    """
    state.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=state) as directory:
        work = Path(directory)
        payload = work / "payload.tar"
        unseal_file(key, package, payload, kind="source", name=SOURCE_NAME, commit=commit, run=run)
        with tarfile.open(payload) as archive:
            members = archive.getmembers()
            names = [member.name for member in members]
            attached = [name for name in names if name.startswith(ATTACHMENT_FOLDER + "/")]
            if (
                len(set(names)) != len(names)
                or {ORDER_MEMBER, PACK_MEMBER} - set(names)
                or set(names) - {ORDER_MEMBER, PACK_MEMBER, *attached}
                or any(not member.isfile() for member in members)
                or any(_NAME.fullmatch(name.split("/", 1)[1]) is None for name in attached)
            ):
                raise RefusalError("Das Paket enthält Unerwartetes — Paket neu erzeugen.")
            order_file = archive.extractfile(ORDER_MEMBER)
            order = json.loads(order_file.read().decode("utf-8")) if order_file else None
            if not isinstance(order, dict):
                raise RefusalError("Der Auftrag im Paket ist unlesbar — Paket neu erzeugen.")
            _check_order(order, commit=commit, run=run, inputs=inputs)
            archive.extractall(work / "payload", filter="data")
        attachments = state / ATTACHMENT_FOLDER
        shutil.rmtree(attachments, ignore_errors=True)
        attachments.mkdir(parents=True)
        declared = order.get("attachments", {})
        for path in sorted((work / "payload" / ATTACHMENT_FOLDER).glob("*")):
            if declared.get(path.name) != _sha256(path):
                raise RefusalError(
                    f"Beilage {path.name} passt nicht zum Auftrag — Paket neu erzeugen."
                )
            shutil.move(path, attachments / path.name)
        if set(declared) != {path.name for path in attachments.iterdir()}:
            raise RefusalError("Eine Beilage des Auftrags fehlt — Paket neu erzeugen.")
        restore_checkout(work / "payload" / PACK_MEMBER, commit, target)
    (state / ORDER_MEMBER).write_text(
        json.dumps(order, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return order


def _check_order(
    order: Mapping[str, Any], *, commit: str, run: str, inputs: Mapping[str, str]
) -> None:
    recorded = order.get("inputs")
    given = {name: value for name, value in inputs.items() if name != "package_asset"}
    if (
        order.get("format") != 1
        or order.get("commit") != commit
        or order.get("run") != run
        or not isinstance(recorded, dict)
        or recorded != given
    ):
        raise RefusalError(
            "Auftrag und Eingaben des Laufs weichen ab — "
            "den Lauf nur mit tools/ci_relay.py starten."
        )


def _sha256(path: Path) -> str:
    import hashlib

    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


# --- Artefakte -------------------------------------------------------------------


def _search_path(pattern: str, base: Path) -> Path:
    """Der Teil eines Musters vor dem ersten Platzhalter, wie bei ``@actions/glob``."""
    path = Path(pattern) if Path(pattern).is_absolute() else base / pattern
    fixed: list[str] = []
    for part in path.parts:
        if _GLOB.search(part):
            break
        fixed.append(part)
    return Path(*fixed)


def _matches(pattern: str, base: Path, search: Path) -> list[Path]:
    """Was ein Muster trifft: der Rest hinter dem Suchpfad als ``Path.glob``."""
    path = Path(pattern) if Path(pattern).is_absolute() else base / pattern
    rest = path.parts[len(search.parts) :]
    if not rest:
        return [search] if search.exists() else []
    return sorted(search.glob("/".join(rest)))


def collect(
    patterns: Iterable[str], base: Path, *, include_hidden: bool = False
) -> tuple[Path, list[tuple[Path, str]]]:
    """Dateien und Wurzel eines Artefakts nach den Regeln von ``upload-artifact``.

    Wurzel ist der gemeinsame Vorfahr der Suchpfade, bei einer einzelnen Datei
    ihr Ordner; ein getroffener Ordner bringt alle Dateien darunter mit, und
    versteckte Dateien bleiben draußen, wenn ``include_hidden`` nicht gesetzt ist.
    """
    searches: list[Path] = []
    found: dict[Path, Path] = {}
    for raw in patterns:
        pattern = raw.strip()
        if not pattern:
            continue
        if pattern.startswith("!"):
            raise RefusalError(
                f"Ausschlussmuster {pattern!r} kennt die Kiste nicht — Workflow prüfen."
            )
        search = _search_path(pattern, base)
        searches.append(search.resolve())
        for hit in _matches(pattern, base, search):
            for file in sorted(hit.rglob("*")) if hit.is_dir() else [hit]:
                if file.is_file():
                    found.setdefault(file.resolve(), file)
    if not searches:
        raise RefusalError("Das Artefakt nennt keinen Pfad — Workflow prüfen.")
    unique = sorted(set(searches))
    root = unique[0] if len(unique) == 1 else Path(os.path.commonpath([str(p) for p in unique]))
    if root.is_file():
        root = root.parent
    files: list[tuple[Path, str]] = []
    for resolved in sorted(found):
        try:
            relative = resolved.relative_to(root)
        except ValueError as error:
            raise RefusalError(
                "Eine Datei liegt außerhalb der Artefaktwurzel — die Muster des Artefakts prüfen.",
                detail=f"{resolved} außerhalb von {root}",
            ) from error
        if not include_hidden and any(part.startswith(".") for part in relative.parts):
            continue
        files.append((resolved, relative.as_posix()))
    return root, files


def pack_artifact(
    key: bytes,
    patterns: Iterable[str],
    base: Path,
    box: Path,
    *,
    name: str,
    commit: str,
    run: str,
    if_empty: str = "warn",
    include_hidden: bool = False,
) -> int:
    """Verschließt die Dateien eines Artefakts in ``box``; liefert ihre Zahl."""
    _root, files = collect(patterns, base, include_hidden=include_hidden)
    if not files:
        if if_empty == "error":
            raise RefusalError(f"Keine Dateien für das Artefakt {name} — vorige Schritte prüfen.")
        return 0
    box.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=box.parent) as directory:
        plain = Path(directory) / "artifact.tar"
        with tarfile.open(plain, "w", format=tarfile.PAX_FORMAT) as archive:
            for path, arcname in files:
                archive.add(path, arcname=arcname, recursive=False)
        seal_file(key, plain, box, kind="artifact", name=name, commit=commit, run=run)
    return len(files)


def unpack_artifact(
    key: bytes, folder: Path, target: Path, *, name: str, commit: str, run: str
) -> int:
    """Öffnet die eine Hülle in ``folder`` nach ``target``; liefert die Zahl der Dateien."""
    boxes = sorted(folder.rglob("*" + BOX_SUFFIX))
    if len(boxes) != 1:
        raise RefusalError(
            f"Im Artefakt {name} liegt nicht genau eine Hülle, sondern {len(boxes)} — "
            "Artefakt neu erzeugen."
        )
    target.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=folder) as directory:
        plain = Path(directory) / "artifact.tar"
        unseal_file(key, boxes[0], plain, kind="artifact", name=name, commit=commit, run=run)
        with tarfile.open(plain) as archive:
            members = archive.getmembers()
            archive.extractall(target, filter="data")
    return sum(1 for member in members if member.isfile())


# --- Schritte --------------------------------------------------------------------


def _deadline() -> float | None:
    text = os.environ.get("SOLIDON_DEADLINE", "")
    return float(text) if re.fullmatch(r"\d+", text) else None


def _command(shell: str, script: Path) -> list[str]:
    bash = os.environ.get("SOLIDON_BASH") or "bash"
    if shell == "default":
        shell = "pwsh" if os.name == "nt" else "bash-e"
    if shell == "bash":
        return [bash, "--noprofile", "--norc", "-eo", "pipefail", str(script)]
    if shell == "bash-e":
        return [bash, "-e", str(script)]
    if shell == "pwsh":
        return ["pwsh", "-command", f". '{script}'"]
    raise RefusalError(f"Unbekannte Shell {shell!r} — Workflow prüfen.")


def _child_environment(summary: Path) -> dict[str, str]:
    """Die Umgebung des Schritts, mit Ereignis, Ref und Commit des privaten Repositorys."""
    child = dict(os.environ)
    child.pop(KEY_VARIABLE, None)
    ref = os.environ.get("SOLIDON_REF", "")
    mapped = {
        "GITHUB_SHA": os.environ.get("SOLIDON_SHA", ""),
        "GITHUB_REF": ref,
        "GITHUB_REF_NAME": ref.split("/", 2)[-1] if ref else "",
        "GITHUB_REF_TYPE": "tag" if ref.startswith("refs/tags/") else "branch",
        "GITHUB_EVENT_NAME": os.environ.get("SOLIDON_EVENT", ""),
        "GITHUB_STEP_SUMMARY": str(summary),
    }
    child.update({name: value for name, value in mapped.items() if value})
    return child


def _stop(process: subprocess.Popen[bytes]) -> None:
    """Beendet den Schritt samt allem, was er gestartet hat."""
    if sys.platform == "win32":
        subprocess.run(
            ["taskkill", "/PID", str(process.pid), "/T", "/F"], capture_output=True, check=False
        )
    else:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)


def _forward_signals(process: subprocess.Popen[bytes]) -> None:
    """Bricht GitHub den Schritt ab, endet auch seine eigene Prozessgruppe."""

    def forward(signum: int, _frame: object) -> None:
        _stop(process)
        raise SystemExit(128 + signum)

    if sys.platform != "win32":
        for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            signal.signal(signum, forward)


def run_step(number: str, shell: str, script: str, state: Path) -> int:
    """Fährt ein Skript wie GitHub; Ausgabe und Schrittbericht gehen ins Protokoll."""
    protocol = state / "protocol"
    protocol.mkdir(parents=True, exist_ok=True)
    suffix = ".ps1" if shell == "pwsh" or (shell == "default" and os.name == "nt") else ".sh"
    file = state / f"step-{number}{suffix}"
    if suffix == ".ps1":
        script = (
            "$ErrorActionPreference = 'stop'\n"
            + script
            + "\nif ((Test-Path -LiteralPath variable:\\LASTEXITCODE)) { exit $LASTEXITCODE }\n"
        )
    file.write_text(script, encoding="utf-8", newline="")
    log = protocol / f"{number}.log"
    summary = protocol / f"{number}-summary.md"
    name = os.environ.get("SOLIDON_STEP_NAME", "")
    if name:
        (protocol / f"{number}.name").write_text(name + "\n", encoding="utf-8")
    deadline = _deadline()
    started = time.monotonic()
    if deadline is not None and time.time() >= deadline:
        code = 124
        log.write_text("Die Frist des Jobs war schon erreicht.\n", encoding="utf-8")
    else:
        with log.open("wb") as output:
            process = subprocess.Popen(
                _command(shell, file),
                stdout=output,
                stderr=subprocess.STDOUT,
                env=_child_environment(summary),
                start_new_session=sys.platform != "win32",
            )
            _forward_signals(process)
            try:
                code = process.wait(
                    timeout=None if deadline is None else max(1.0, deadline - time.time())
                )
            except subprocess.TimeoutExpired:
                _stop(process)
                process.wait()
                code = 124
                output.write(b"\nAngehalten: Die Frist des Jobs ist erreicht.\n")
    seconds = round(time.monotonic() - started)
    safe = _safe_lines(log)
    lines = [*safe, f"Schritt {number}: Exit {code} nach {seconds} s"]
    print("\n".join(lines), flush=True)
    real_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if real_summary:
        with Path(real_summary).open("a", encoding="utf-8") as stream:
            stream.write("\n".join(lines) + "\n\n")
    return code


def _safe_lines(log: Path) -> list[str]:
    try:
        text = log.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    found = [line.strip() for line in text.splitlines() if _SAFE_LINE.fullmatch(line.strip())]
    return found[-10:]


# --- Einrichten und Gegenprobe -----------------------------------------------------


def setup(bash: str, minutes: int) -> None:
    """Prüft die Eingaben, richtet die Umgebung ein und schreibt sie nach ``GITHUB_ENV``."""
    expected = os.environ.get("SOLIDON_REPOSITORY", "")
    if os.environ.get("GITHUB_REPOSITORY") != expected:
        raise RefusalError(f"Dieser Workflow läuft nur in {expected}.")
    event = os.environ.get("SOLIDON_EVENT", "")
    if event not in _EVENTS:
        raise RefusalError(f"Unbekanntes Ereignis {event!r} — mit tools/ci_relay.py starten.")
    ref = _checked(os.environ.get("SOLIDON_REF", ""), _REF, "Ref")
    sha = _checked(os.environ.get("SOLIDON_SHA", ""), _COMMIT, "Commit")
    nonce = _checked(os.environ.get("SOLIDON_NONCE", ""), _NONCE, "Lauf")
    if sys.platform == "win32" and bash.endswith("/usr/bin/bash.exe"):
        # Wie ``shell: bash`` bei GitHub der Starter aus ``Git\\bin``: Er stellt
        # die Werkzeuge von MSYS vor den PATH, die bash selbst täte es nicht.
        starter = bash.removesuffix("/usr/bin/bash.exe") + "/bin/bash.exe"
        bash = starter if Path(starter).is_file() else bash
    temporary = Path(os.environ["RUNNER_TEMP"])
    state = temporary / "solidon-ci"
    (state / "protocol").mkdir(parents=True, exist_ok=True)
    environment = temporary / "solidon-venv"
    venv.create(environment, with_pip=True, clear=True)
    python = environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    requirements = Path(__file__).with_name("requirements.txt")
    with (state / "protocol" / "00-setup.log").open("wb") as log:
        done = subprocess.run(
            [
                str(python),
                "-m",
                "pip",
                "install",
                "--disable-pip-version-check",
                "-r",
                str(requirements),
            ],
            stdout=log,
            stderr=subprocess.STDOUT,
            check=False,
        )
    if done.returncode != 0:
        raise RefusalError(
            "Die Umgebung des Bauwerkzeugs ließ sich nicht einrichten (pip) — 00-setup.log im "
            "Protokoll des Jobs lesen (ci_relay.py fetch <lauf>)."
        )
    deadline = int(time.time()) + minutes * 60 - RESERVE_SECONDS
    values = {
        "SOLIDON_PYTHON": python.as_posix(),
        "SOLIDON_TOOL": Path(__file__).resolve().as_posix(),
        "SOLIDON_STATE": state.as_posix(),
        "SOLIDON_BASH": bash,
        "SOLIDON_EVENT": event,
        "SOLIDON_REF": ref,
        "SOLIDON_SHA": sha,
        "SOLIDON_NONCE": nonce,
        "SOLIDON_DEADLINE": str(deadline),
    }
    with Path(os.environ["GITHUB_ENV"]).open("a", encoding="utf-8") as stream:
        stream.writelines(f"{name}={value}\n" for name, value in values.items())
    print("Bauwerkzeug bereit.")


def crosscheck(box: Path, work: Path) -> int:
    """Python und Swift öffnen gegenseitig, was der andere verschlossen hat."""
    key = secrets.token_bytes(32)
    binding = {"name": "gegenprobe", "commit": "0" * 40, "run": "0" * 32}
    environment = dict(
        os.environ,
        **{
            # Mit Zeilenende, wie ein Geheimnis aus der Weboberfläche: bau.py trimmt es,
            # die Swift-Hülle muss es ebenso nehmen.
            KEY_VARIABLE: key.hex() + "\n",
            "SOLIDON_ARTIFACT": binding["name"],
            "SOLIDON_SHA": binding["commit"],
            "SOLIDON_NONCE": binding["run"],
        },
    )
    sizes = (0, 1000, BLOCK, 2 * BLOCK + 123)
    equal = 0
    for size in sizes:
        plain = work / f"klar-{size}"
        plain.write_bytes(secrets.token_bytes(size))
        sealed = work / f"python-{size}.box"
        seal_file(key, plain, sealed, kind="artifact", **binding)
        opened = work / f"swift-{size}"
        subprocess.run(
            [str(box), "open", "artifact", str(sealed), str(opened)], env=environment, check=True
        )
        resealed = work / f"swift-{size}.box"
        subprocess.run(
            [str(box), "seal", "artifact", str(plain), str(resealed)], env=environment, check=True
        )
        back = work / f"python-{size}"
        unseal_file(key, resealed, back, kind="artifact", **binding)
        if opened.read_bytes() == plain.read_bytes() == back.read_bytes():
            equal += 1
    print(f"Swift-Hülle: {equal} von {len(sizes)} gleich")
    if equal != len(sizes):
        print(
            "Swift- und Python-Hülle weichen ab — box.swift gegen bau.py halten, bevor ein "
            "Signierjob sie braucht (tests/test_ci_relay.py, Konstanten der Hülle)."
        )
    return 0 if equal == len(sizes) else 1


# --- Aufruf ----------------------------------------------------------------------


def _binding() -> dict[str, str]:
    return {
        "commit": _checked(os.environ.get("SOLIDON_SHA", ""), _COMMIT, "Commit"),
        "run": _checked(os.environ.get("SOLIDON_NONCE", ""), _NONCE, "Lauf"),
    }


def _state() -> Path:
    return Path(os.environ.get("SOLIDON_STATE") or Path(os.environ["RUNNER_TEMP"]) / "solidon-ci")


def _write_environment(values: Mapping[str, str]) -> None:
    target = os.environ.get("GITHUB_ENV")
    if target:
        with Path(target).open("a", encoding="utf-8") as stream:
            stream.writelines(f"{name}={value}\n" for name, value in values.items())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    setup_command = commands.add_parser("setup")
    setup_command.add_argument("--bash", required=True)
    setup_command.add_argument("--minutes", type=int, required=True)
    source_command = commands.add_parser("source")
    source_command.add_argument("--package", type=Path, required=True)
    source_command.add_argument("--target", type=Path, required=True)
    pack_command = commands.add_parser("pack")
    pack_command.add_argument("--box", type=Path, required=True)
    unpack_command = commands.add_parser("unpack")
    unpack_command.add_argument("--from", dest="folder", type=Path, required=True)
    unpack_command.add_argument("--target", type=Path, required=True)
    step_command = commands.add_parser("step")
    step_command.add_argument("--number", required=True)
    step_command.add_argument("--shell", required=True)
    cross_command = commands.add_parser("crosscheck")
    cross_command.add_argument("--box", type=Path, required=True)
    arguments = parser.parse_args(argv)
    try:
        if arguments.command == "setup":
            setup(arguments.bash, arguments.minutes)
        elif arguments.command == "source":
            inputs = json.loads(os.environ.get("SOLIDON_INPUTS") or "{}")
            if not isinstance(inputs, dict):
                raise RefusalError(
                    "Die Eingaben des Laufs sind unlesbar — nur mit tools/ci_relay.py starten."
                )
            packages = sorted(arguments.package.rglob("*" + BOX_SUFFIX))
            if len(packages) != 1:
                raise RefusalError("Das Quellpaket fehlt im Lauf — Job „Quelle holen“ prüfen.")
            state = _state()
            order = open_source(
                key_from_environment(),
                packages[0],
                inputs={name: str(value) for name, value in inputs.items()},
                target=arguments.target,
                state=state,
                **_binding(),
            )
            _write_environment(
                {
                    "SOLIDON_ORDER": (state / ORDER_MEMBER).as_posix(),
                    "SOLIDON_ATTACHMENTS": (state / ATTACHMENT_FOLDER).as_posix(),
                }
            )
            print(f"Quelle bereit: {order['commit'][:12]}")
        elif arguments.command == "pack":
            name = _checked(os.environ.get("SOLIDON_ARTIFACT", ""), _NAME, "Artefakt")
            count = pack_artifact(
                key_from_environment(),
                sys.stdin.buffer.read().decode("utf-8").splitlines(),
                Path.cwd(),
                arguments.box / (name + BOX_SUFFIX),
                name=name,
                if_empty=os.environ.get("SOLIDON_IF_EMPTY", "warn"),
                include_hidden=os.environ.get("SOLIDON_HIDDEN", "false") == "true",
                **_binding(),
            )
            print(f"Artefakt verschlossen: {count} Dateien")
        elif arguments.command == "unpack":
            name = _checked(os.environ.get("SOLIDON_ARTIFACT", ""), _NAME, "Artefakt")
            count = unpack_artifact(
                key_from_environment(),
                arguments.folder,
                arguments.target,
                name=name,
                **_binding(),
            )
            print(f"Artefakt geöffnet: {count} Dateien")
        elif arguments.command == "step":
            script = sys.stdin.buffer.read().decode("utf-8")
            return run_step(arguments.number, arguments.shell, script, _state())
        elif arguments.command == "crosscheck":
            with tempfile.TemporaryDirectory() as directory:
                return crosscheck(arguments.box, Path(directory))
    except RefusalError as problem:
        _record_failure(arguments.command, problem.detail)
        print(f"Angehalten: {problem}", file=sys.stderr)
        return 1
    except Exception as problem:
        # Eine unerwartete Ausnahme nennt Pfade und Namen des Stands; ins öffentliche Log
        # geht nur ihre Art, die Einzelheit ins verschlossene Protokoll.
        import traceback

        _record_failure(arguments.command, traceback.format_exc())
        print(
            f"Angehalten: {arguments.command} scheiterte unerwartet ({type(problem).__name__}) — "
            "errors.log im Protokoll des Jobs lesen (ci_relay.py fetch <lauf>).",
            file=sys.stderr,
        )
        return 1
    return 0


def _record_failure(command: str, detail: str) -> None:
    if not detail:
        return
    try:
        protocol = _state() / "protocol"
        protocol.mkdir(parents=True, exist_ok=True)
        with (protocol / "errors.log").open("a", encoding="utf-8") as stream:
            stream.write(f"--- {command}\n{detail}\n")
    except OSError, KeyError:
        pass


if __name__ == "__main__":
    raise SystemExit(main())
