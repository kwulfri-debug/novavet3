"""Capa de acceso a datos SQLite para novaVet."""

from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import secrets
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "novavet.db"
SCHEMA_PATH = BASE_DIR / "schema.sql"
PBKDF2_ITERATIONS = 120_000
SESSION_TTL_HOURS = 24


def hash_password(password: str) -> str:
    """Genera un hash PBKDF2-HMAC-SHA256 con salt aleatorio."""
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        PBKDF2_ITERATIONS,
    ).hex()
    return f"pbkdf2_sha256${salt}${digest}"


def verify_password(password: str, stored_hash: str) -> bool:
    """Verifica una contraseña contra su hash almacenado."""
    if not stored_hash or "$" not in stored_hash:
        return hmac.compare_digest(password, stored_hash or "")
    parts = stored_hash.split("$", 2)
    if len(parts) != 3 or parts[0] != "pbkdf2_sha256":
        return False
    _, salt, expected = parts
    candidate = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        PBKDF2_ITERATIONS,
    ).hex()
    return hmac.compare_digest(candidate, expected)


@contextmanager
def get_connection(db_path: Path | None = None) -> Iterator[sqlite3.Connection]:
    """Abre una conexión SQLite configurada con claves foráneas y cierre seguro."""
    conn = sqlite3.connect(db_path or DB_PATH, timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA busy_timeout = 5000;")
    try:
        yield conn
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db(db_path: Path | None = None) -> None:
    """Crea las tablas desde schema.sql y siembra datos iniciales si está vacía."""
    target = db_path or DB_PATH
    schema_sql = SCHEMA_PATH.read_text(encoding="utf-8")
    with get_connection(target) as conn:
        conn.execute("PRAGMA journal_mode = DELETE;")
        conn.executescript(schema_sql)
        count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        if count == 0:
            _seed_initial_data(conn)
        conn.commit()


def _seed_initial_data(conn: sqlite3.Connection) -> None:
    today = dt.date.today().isoformat()
    users = [
        (1, "Dirección General", "admin@sanfrancisco.vet", hash_password("admin123"), "ADMIN", 1),
        (2, "Dra. Valentina Ríos", "vet@sanfrancisco.vet", hash_password("vet123"), "VET", 1),
        (3, "Recepción Principal", "recepcion@sanfrancisco.vet", hash_password("recep123"), "RECEP", 1),
    ]
    conn.executemany(
        "INSERT INTO users (id, name, email, password_hash, role, active) VALUES (?, ?, ?, ?, ?, ?)",
        users,
    )
    conn.execute(
        "INSERT INTO owners (id, name, phone, address) VALUES (?, ?, ?, ?)",
        (1, "Andrés Castro", "3004567890", "Cra. 50 # 72-14"),
    )
    conn.execute(
        "INSERT INTO pets (id, owner_id, name, species, breed, age) VALUES (?, ?, ?, ?, ?, ?)",
        (1, 1, "Max", "Canino", "Golden Retriever", "3 años"),
    )
    conn.execute(
        """
        INSERT INTO appointments (id, pet_id, vet_id, vet_name, date, time, reason, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (1, 1, 2, "Dra. Valentina Ríos", today, "09:00", "Control general y vacunación", "Confirmada"),
    )
    inventory = [
        (1, "Vacuna Antirrábica", "Biológicos", 20, 10),
        (2, "Amoxicilina Suspensión 250mg", "Medicamentos", 12, 8),
        (3, "Gasas Estériles (Paquete)", "Insumos", 15, 10),
    ]
    conn.executemany(
        "INSERT INTO inventory (id, item, category, stock, min_stock) VALUES (?, ?, ?, ?, ?)",
        inventory,
    )


def serialize_user(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "name": row["name"],
        "email": row["email"],
        "role": row["role"],
        "active": bool(row["active"]),
    }


def get_full_state(conn: sqlite3.Connection) -> dict[str, Any]:
    """Devuelve todo el estado operativo en el formato esperado por el frontend."""
    users = [
        serialize_user(r)
        for r in conn.execute(
            "SELECT id, name, email, role, active FROM users ORDER BY id ASC"
        ).fetchall()
    ]
    owners = [
        {
            "id": r["id"],
            "name": r["name"],
            "phone": r["phone"],
            "address": r["address"],
        }
        for r in conn.execute(
            "SELECT id, name, phone, address FROM owners ORDER BY id ASC"
        ).fetchall()
    ]
    pets = [
        {
            "id": r["id"],
            "ownerId": r["owner_id"],
            "name": r["name"],
            "species": r["species"],
            "breed": r["breed"],
            "age": r["age"],
        }
        for r in conn.execute(
            "SELECT id, owner_id, name, species, breed, age FROM pets ORDER BY id ASC"
        ).fetchall()
    ]
    appointments = [
        {
            "id": r["id"],
            "petId": r["pet_id"],
            "vetId": r["vet_id"],
            "vetName": r["vet_name"],
            "date": r["date"],
            "time": r["time"],
            "reason": r["reason"],
            "status": r["status"],
        }
        for r in conn.execute(
            "SELECT id, pet_id, vet_id, vet_name, date, time, reason, status FROM appointments ORDER BY date ASC, time ASC, id ASC"
        ).fetchall()
    ]
    records = [
        {
            "id": r["id"],
            "petId": r["pet_id"],
            "vetId": r["vet_id"],
            "vetName": r["vet_name"],
            "date": r["date"],
            "diagnosis": r["diagnosis"],
            "prescription": r["prescription"],
        }
        for r in conn.execute(
            "SELECT id, pet_id, vet_id, vet_name, date, diagnosis, prescription FROM records ORDER BY id DESC"
        ).fetchall()
    ]
    inventory = [
        {
            "id": r["id"],
            "item": r["item"],
            "category": r["category"],
            "stock": r["stock"],
            "minStock": r["min_stock"],
        }
        for r in conn.execute(
            "SELECT id, item, category, stock, min_stock FROM inventory ORDER BY id ASC"
        ).fetchall()
    ]
    return {
        "users": users,
        "owners": owners,
        "pets": pets,
        "appointments": appointments,
        "records": records,
        "inventory": inventory,
    }


def export_backup(conn: sqlite3.Connection) -> dict[str, Any]:
    """Exporta un respaldo completo compatible para restauración."""
    state = get_full_state(conn)
    hashes = {
        r["id"]: r["password_hash"]
        for r in conn.execute("SELECT id, password_hash FROM users").fetchall()
    }
    for user in state["users"]:
        user["passwordHash"] = hashes.get(user["id"], "")
    state["meta"] = {
        "app": "novaVet",
        "engine": "sqlite",
        "exportedAt": dt.datetime.now().isoformat(timespec="seconds"),
    }
    return state


def import_backup(conn: sqlite3.Connection, payload: dict[str, Any]) -> None:
    """Restaura un respaldo JSON dentro de una transacción atómica."""
    required = ("users", "owners", "pets", "appointments", "records", "inventory")
    if not all(isinstance(payload.get(k), list) for k in required):
        raise ValueError("Formato de respaldo inválido.")
    if len(payload["users"]) == 0:
        raise ValueError("El respaldo debe incluir al menos un usuario.")

    conn.execute("DELETE FROM sessions")
    conn.execute("DELETE FROM records")
    conn.execute("DELETE FROM appointments")
    conn.execute("DELETE FROM pets")
    conn.execute("DELETE FROM owners")
    conn.execute("DELETE FROM inventory")
    conn.execute("DELETE FROM users")

    for u in payload["users"]:
        pw_hash = u.get("passwordHash") or (
            hash_password(str(u["password"])) if u.get("password") else hash_password("novavet123")
        )
        conn.execute(
            "INSERT INTO users (id, name, email, password_hash, role, active) VALUES (?, ?, ?, ?, ?, ?)",
            (
                int(u["id"]),
                str(u["name"]).strip(),
                str(u["email"]).strip().lower(),
                pw_hash,
                str(u["role"]),
                1 if u.get("active", True) else 0,
            ),
        )

    for o in payload["owners"]:
        conn.execute(
            "INSERT INTO owners (id, name, phone, address) VALUES (?, ?, ?, ?)",
            (
                int(o["id"]),
                str(o["name"]).strip(),
                str(o["phone"]).strip(),
                str(o.get("address") or "No registrada").strip(),
            ),
        )

    for p in payload["pets"]:
        conn.execute(
            "INSERT INTO pets (id, owner_id, name, species, breed, age) VALUES (?, ?, ?, ?, ?, ?)",
            (
                int(p["id"]),
                int(p["ownerId"]),
                str(p["name"]).strip(),
                str(p["species"]).strip(),
                str(p["breed"]).strip(),
                str(p["age"]).strip(),
            ),
        )

    vet_by_name = {
        r["name"]: r["id"]
        for r in conn.execute("SELECT id, name FROM users WHERE role = 'VET'").fetchall()
    }

    for a in payload["appointments"]:
        vet_name = str(a["vetName"]).strip()
        vet_id = a.get("vetId") if a.get("vetId") is not None else vet_by_name.get(vet_name)
        conn.execute(
            """
            INSERT INTO appointments (id, pet_id, vet_id, vet_name, date, time, reason, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                int(a["id"]),
                int(a["petId"]),
                int(vet_id) if vet_id is not None else None,
                vet_name,
                str(a["date"]).strip(),
                str(a["time"]).strip(),
                str(a["reason"]).strip(),
                str(a.get("status") or "Confirmada"),
            ),
        )

    for r in payload["records"]:
        vet_name = str(r["vetName"]).strip()
        vet_id = r.get("vetId") if r.get("vetId") is not None else vet_by_name.get(vet_name)
        conn.execute(
            """
            INSERT INTO records (id, pet_id, vet_id, vet_name, date, diagnosis, prescription)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                int(r["id"]),
                int(r["petId"]),
                int(vet_id) if vet_id is not None else None,
                vet_name,
                str(r["date"]).strip(),
                str(r["diagnosis"]).strip(),
                str(r["prescription"]).strip(),
            ),
        )

    for item in payload["inventory"]:
        conn.execute(
            "INSERT INTO inventory (id, item, category, stock, min_stock) VALUES (?, ?, ?, ?, ?)",
            (
                int(item["id"]),
                str(item["item"]).strip(),
                str(item["category"]).strip(),
                int(item["stock"]),
                int(item["minStock"]),
            ),
        )


def create_session(conn: sqlite3.Connection, user_id: int) -> str:
    """Crea un token de sesión persistido en SQLite."""
    conn.execute("DELETE FROM sessions WHERE expires_at <= datetime('now', 'localtime')")
    token = secrets.token_urlsafe(32)
    expires_at = (dt.datetime.now() + dt.timedelta(hours=SESSION_TTL_HOURS)).strftime(
        "%Y-%m-%d %H:%M:%S"
    )
    conn.execute(
        "INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)",
        (token, user_id, expires_at),
    )
    return token


def get_session_user(conn: sqlite3.Connection, token: str) -> dict[str, Any] | None:
    """Valida el token de sesión y retorna el usuario activo asociado."""
    if not token:
        return None
    row = conn.execute(
        """
        SELECT u.id, u.name, u.email, u.role, u.active
        FROM sessions s
        JOIN users u ON u.id = s.user_id
        WHERE s.token = ? AND s.expires_at > datetime('now', 'localtime')
        """,
        (token,),
    ).fetchone()
    if not row or not row["active"]:
        return None
    return serialize_user(row)
