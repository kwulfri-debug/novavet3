"""Servidor HTTP local y API REST para novaVet con respaldo en SQLite."""

from __future__ import annotations

import json
import mimetypes
import os
import re
import sqlite3
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import db

BASE_DIR = Path(__file__).resolve().parent
ALLOWED_STATIC = {
    "/": "index.html",
    "/index.html": "index.html",
    "/app.js": "app.js",
    "/styles.css": "styles.css",
}


class ApiError(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


class NovaVetHandler(BaseHTTPRequestHandler):
    server_version = "NovaVetHTTP/1.0"

    def log_message(self, format: str, *args: Any) -> None:
        # Formato limpio en consola
        print(f"[{self.log_date_time_string()}] {self.address_string()} - {format % args}")

    def _send_json(self, status: int, payload: Any) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _send_static(self, rel_name: str) -> None:
        file_path = BASE_DIR / rel_name
        if not file_path.is_file():
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "Archivo no encontrado."})
            return
        content = file_path.read_bytes()
        mime, _ = mimetypes.guess_type(str(file_path))
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", f"{mime or 'application/octet-stream'}; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(content)

    def _read_json_body(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0") or 0)
        if length <= 0 or length > 5 * 1024 * 1024:
            raise ApiError(HTTPStatus.BAD_REQUEST, "Cuerpo JSON inválido o vacío.")
        raw = self.rfile.read(length)
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ApiError(HTTPStatus.BAD_REQUEST, "JSON mal formado.") from exc
        if not isinstance(data, dict):
            raise ApiError(HTTPStatus.BAD_REQUEST, "Se esperaba un objeto JSON.")
        return data

    def _bearer_token(self) -> str:
        header = self.headers.get("Authorization", "")
        if header.startswith("Bearer "):
            return header[7:].strip()
        return ""

    def _require_auth(self, conn: sqlite3.Connection, allowed_roles: tuple[str, ...] | None = None) -> dict[str, Any]:
        user = db.get_session_user(conn, self._bearer_token())
        if not user:
            raise ApiError(HTTPStatus.UNAUTHORIZED, "Sesión inválida o expirada. Inicia sesión nuevamente.")
        if allowed_roles and user["role"] not in allowed_roles:
            raise ApiError(HTTPStatus.FORBIDDEN, "No tienes permisos para esta acción.")
        return user

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path in ALLOWED_STATIC:
            self._send_static(ALLOWED_STATIC[path])
            return

        if not path.startswith("/api/"):
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "Recurso no encontrado."})
            return

        try:
            self._handle_api_get(path)
        except ApiError as err:
            self._send_json(err.status, {"error": err.message})
        except sqlite3.Error as err:
            self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": f"Error de base de datos: {err}"})

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        try:
            self._handle_api_post(path)
        except ApiError as err:
            self._send_json(err.status, {"error": err.message})
        except sqlite3.IntegrityError as err:
            self._send_json(HTTPStatus.CONFLICT, {"error": f"Conflicto de integridad en BD: {err}"})
        except sqlite3.Error as err:
            self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": f"Error de base de datos: {err}"})

    def do_PATCH(self) -> None:
        path = urlparse(self.path).path
        try:
            self._handle_api_patch(path)
        except ApiError as err:
            self._send_json(err.status, {"error": err.message})
        except sqlite3.IntegrityError as err:
            self._send_json(HTTPStatus.CONFLICT, {"error": f"Conflicto de integridad en BD: {err}"})
        except sqlite3.Error as err:
            self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": f"Error de base de datos: {err}"})

    def _handle_api_get(self, path: str) -> None:
        if path == "/api/health":
            self._send_json(HTTPStatus.OK, {"ok": True, "engine": "sqlite", "sqliteVersion": sqlite3.sqlite_version})
            return

        with db.get_connection() as conn:
            if path == "/api/auth/defaults":
                defaults: dict[str, str] = {}
                for role in ("ADMIN", "VET", "RECEP"):
                    row = conn.execute(
                        "SELECT email FROM users WHERE role = ? AND active = 1 ORDER BY id ASC LIMIT 1",
                        (role,),
                    ).fetchone()
                    defaults[role] = row["email"] if row else ""
                self._send_json(HTTPStatus.OK, {"defaults": defaults})
                return

            if path == "/api/auth/me":
                user = self._require_auth(conn)
                self._send_json(HTTPStatus.OK, {"user": user})
                return

            if path == "/api/state":
                self._require_auth(conn)
                self._send_json(HTTPStatus.OK, db.get_full_state(conn))
                return

            if path == "/api/backup/export":
                self._require_auth(conn, ("ADMIN",))
                self._send_json(HTTPStatus.OK, db.export_backup(conn))
                return

        raise ApiError(HTTPStatus.NOT_FOUND, "Endpoint GET no encontrado.")

    def _handle_api_post(self, path: str) -> None:
        body = self._read_json_body() if path != "/api/auth/logout" else {}

        with db.get_connection() as conn:
            if path == "/api/auth/login":
                email = str(body.get("email", "")).strip().lower()
                password = str(body.get("password", ""))
                role = str(body.get("role", "")).strip()
                row = conn.execute(
                    "SELECT id, name, email, password_hash, role, active FROM users WHERE lower(email) = ?",
                    (email,),
                ).fetchone()
                if not row:
                    raise ApiError(HTTPStatus.UNAUTHORIZED, "Correo no registrado en la clínica.")
                if not row["active"]:
                    raise ApiError(HTTPStatus.FORBIDDEN, "Esta cuenta está suspendida.")
                if role and row["role"] != role:
                    raise ApiError(HTTPStatus.FORBIDDEN, f"Este correo pertenece al perfil {row['role']}. Cambia la sección correspondiente.")
                if not db.verify_password(password, row["password_hash"]):
                    raise ApiError(HTTPStatus.UNAUTHORIZED, "Contraseña incorrecta para este rol.")

                token = db.create_session(conn, row["id"])
                conn.commit()
                self._send_json(
                    HTTPStatus.OK,
                    {
                        "token": token,
                        "user": db.serialize_user(row),
                        "state": db.get_full_state(conn),
                    },
                )
                return

            if path == "/api/auth/logout":
                token = self._bearer_token()
                if token:
                    conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
                    conn.commit()
                self._send_json(HTTPStatus.OK, {"ok": True})
                return

            if path == "/api/users":
                self._require_auth(conn, ("ADMIN",))
                name = str(body.get("name", "")).strip()
                email = str(body.get("email", "")).strip().lower()
                password = str(body.get("password", ""))
                role = str(body.get("role", "")).strip()
                if not name or not email or len(password) < 4 or role not in ("ADMIN", "VET", "RECEP"):
                    raise ApiError(HTTPStatus.BAD_REQUEST, "Datos de usuario inválidos (contraseña mínima de 4 caracteres).")
                exists = conn.execute("SELECT 1 FROM users WHERE lower(email) = ?", (email,)).fetchone()
                if exists:
                    raise ApiError(HTTPStatus.CONFLICT, "Este correo ya se encuentra registrado.")
                conn.execute(
                    "INSERT INTO users (name, email, password_hash, role, active) VALUES (?, ?, ?, ?, 1)",
                    (name, email, db.hash_password(password), role),
                )
                conn.commit()
                self._send_json(HTTPStatus.CREATED, {"state": db.get_full_state(conn)})
                return

            if path == "/api/inventory":
                self._require_auth(conn, ("ADMIN",))
                item = str(body.get("item", "")).strip()
                category = str(body.get("category", "")).strip()
                stock = int(body.get("stock", 0))
                min_stock = int(body.get("minStock", 1))
                if not item or not category or stock < 0 or min_stock < 1:
                    raise ApiError(HTTPStatus.BAD_REQUEST, "Datos de inventario inválidos.")
                conn.execute(
                    "INSERT INTO inventory (item, category, stock, min_stock) VALUES (?, ?, ?, ?)",
                    (item, category, stock, min_stock),
                )
                conn.commit()
                self._send_json(HTTPStatus.CREATED, {"state": db.get_full_state(conn)})
                return

            if path == "/api/admissions":
                self._require_auth(conn, ("RECEP", "ADMIN"))
                owner_name = str(body.get("ownerName", "")).strip()
                phone = str(body.get("phone", "")).strip()
                address = str(body.get("address", "")).strip() or "No registrada"
                pet_name = str(body.get("petName", "")).strip()
                species = str(body.get("species", "")).strip()
                breed = str(body.get("breed", "")).strip()
                age = str(body.get("age", "")).strip()
                if not all([owner_name, phone, pet_name, species, breed, age]):
                    raise ApiError(HTTPStatus.BAD_REQUEST, "Todos los campos obligatorios de admisión son requeridos.")

                existing = conn.execute(
                    "SELECT id FROM owners WHERE lower(name) = lower(?)",
                    (owner_name,),
                ).fetchone()
                if existing:
                    owner_id = existing["id"]
                else:
                    cur = conn.execute(
                        "INSERT INTO owners (name, phone, address) VALUES (?, ?, ?)",
                        (owner_name, phone, address),
                    )
                    owner_id = cur.lastrowid

                conn.execute(
                    "INSERT INTO pets (owner_id, name, species, breed, age) VALUES (?, ?, ?, ?, ?)",
                    (owner_id, pet_name, species, breed, age),
                )
                conn.commit()
                self._send_json(HTTPStatus.CREATED, {"state": db.get_full_state(conn)})
                return

            if path == "/api/appointments":
                self._require_auth(conn, ("RECEP", "ADMIN"))
                pet_id = int(body.get("petId", 0))
                vet_name = str(body.get("vetName", "")).strip()
                date = str(body.get("date", "")).strip()
                time = str(body.get("time", "")).strip()
                reason = str(body.get("reason", "")).strip()
                if not pet_id or not vet_name or not date or not time or not reason:
                    raise ApiError(HTTPStatus.BAD_REQUEST, "Faltan datos para agendar la cita.")

                pet = conn.execute("SELECT id FROM pets WHERE id = ?", (pet_id,)).fetchone()
                if not pet:
                    raise ApiError(HTTPStatus.NOT_FOUND, "Paciente no encontrado.")

                conflict = conn.execute(
                    """
                    SELECT 1 FROM appointments
                    WHERE vet_name = ? AND date = ? AND time = ? AND status != 'Cancelada'
                    """,
                    (vet_name, date, time),
                ).fetchone()
                if conflict:
                    raise ApiError(
                        HTTPStatus.CONFLICT,
                        f"Horario ocupado: {vet_name} ya tiene cita el {date} a las {time}.",
                    )

                vet_row = conn.execute(
                    "SELECT id FROM users WHERE name = ? AND role = 'VET' LIMIT 1",
                    (vet_name,),
                ).fetchone()
                vet_id = vet_row["id"] if vet_row else None

                conn.execute(
                    """
                    INSERT INTO appointments (pet_id, vet_id, vet_name, date, time, reason, status)
                    VALUES (?, ?, ?, ?, ?, ?, 'Confirmada')
                    """,
                    (pet_id, vet_id, vet_name, date, time, reason),
                )
                conn.commit()
                self._send_json(HTTPStatus.CREATED, {"state": db.get_full_state(conn)})
                return

            if path == "/api/records":
                user = self._require_auth(conn, ("VET", "ADMIN"))
                pet_id = int(body.get("petId", 0))
                date = str(body.get("date", "")).strip()
                diagnosis = str(body.get("diagnosis", "")).strip()
                prescription = str(body.get("prescription", "")).strip()
                if not pet_id or not date or not diagnosis or not prescription:
                    raise ApiError(HTTPStatus.BAD_REQUEST, "Completa diagnóstico y prescripción.")
                pet = conn.execute("SELECT id FROM pets WHERE id = ?", (pet_id,)).fetchone()
                if not pet:
                    raise ApiError(HTTPStatus.NOT_FOUND, "Paciente no encontrado.")

                conn.execute(
                    """
                    INSERT INTO records (pet_id, vet_id, vet_name, date, diagnosis, prescription)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (pet_id, user["id"], user["name"], date, diagnosis, prescription),
                )
                conn.commit()
                self._send_json(HTTPStatus.CREATED, {"state": db.get_full_state(conn)})
                return

            if path == "/api/backup/import":
                user = self._require_auth(conn, ("ADMIN",))
                try:
                    db.import_backup(conn, body)
                    restored_user = conn.execute(
                        "SELECT id, name, email, role, active FROM users WHERE lower(email) = lower(?) AND active = 1",
                        (user["email"],),
                    ).fetchone() or conn.execute(
                        "SELECT id, name, email, role, active FROM users WHERE role = 'ADMIN' AND active = 1 ORDER BY id ASC LIMIT 1"
                    ).fetchone()
                    if not restored_user:
                        raise ValueError("El respaldo no contiene ningún administrador activo.")
                    token = db.create_session(conn, restored_user["id"])
                    conn.commit()
                except ValueError as exc:
                    raise ApiError(HTTPStatus.BAD_REQUEST, str(exc)) from exc
                self._send_json(
                    HTTPStatus.OK,
                    {
                        "token": token,
                        "user": db.serialize_user(restored_user),
                        "state": db.get_full_state(conn),
                    },
                )
                return

        raise ApiError(HTTPStatus.NOT_FOUND, "Endpoint POST no encontrado.")

    def _handle_api_patch(self, path: str) -> None:
        body = self._read_json_body()

        with db.get_connection() as conn:
            m_user = re.fullmatch(r"/api/users/(\d+)/toggle", path)
            if m_user:
                current = self._require_auth(conn, ("ADMIN",))
                target_id = int(m_user.group(1))
                if target_id == current["id"]:
                    raise ApiError(HTTPStatus.BAD_REQUEST, "No puedes suspender tu propia sesión activa.")
                row = conn.execute("SELECT id, name, active FROM users WHERE id = ?", (target_id,)).fetchone()
                if not row:
                    raise ApiError(HTTPStatus.NOT_FOUND, "Usuario no encontrado.")
                new_active = 0 if row["active"] else 1
                conn.execute("UPDATE users SET active = ? WHERE id = ?", (new_active, target_id))
                if new_active == 0:
                    conn.execute("DELETE FROM sessions WHERE user_id = ?", (target_id,))
                conn.commit()
                self._send_json(HTTPStatus.OK, {"userName": row["name"], "state": db.get_full_state(conn)})
                return

            m_inv = re.fullmatch(r"/api/inventory/(\d+)/adjust", path)
            if m_inv:
                self._require_auth(conn, ("ADMIN",))
                item_id = int(m_inv.group(1))
                delta = int(body.get("delta", 0))
                row = conn.execute("SELECT id, item, stock, min_stock FROM inventory WHERE id = ?", (item_id,)).fetchone()
                if not row:
                    raise ApiError(HTTPStatus.NOT_FOUND, "Producto no encontrado.")
                new_stock = row["stock"] + delta
                if new_stock < 0:
                    raise ApiError(HTTPStatus.BAD_REQUEST, "Existencia insuficiente para descontar.")
                conn.execute(
                    "UPDATE inventory SET stock = ?, updated_at = datetime('now', 'localtime') WHERE id = ?",
                    (new_stock, item_id),
                )
                conn.commit()
                self._send_json(
                    HTTPStatus.OK,
                    {
                        "item": row["item"],
                        "lowStock": new_stock <= row["min_stock"],
                        "state": db.get_full_state(conn),
                    },
                )
                return

            m_shift = re.fullmatch(r"/api/appointments/(\d+)/shift", path)
            if m_shift:
                self._require_auth(conn, ("RECEP", "ADMIN"))
                appt_id = int(m_shift.group(1))
                appt = conn.execute("SELECT * FROM appointments WHERE id = ?", (appt_id,)).fetchone()
                if not appt:
                    raise ApiError(HTTPStatus.NOT_FOUND, "Cita no encontrada.")
                hh, mm = (int(x) for x in appt["time"].split(":"))
                next_time = f"{(hh + 1) % 24:02d}:{mm:02d}"
                conflict = conn.execute(
                    """
                    SELECT 1 FROM appointments
                    WHERE id != ? AND vet_name = ? AND date = ? AND time = ? AND status != 'Cancelada'
                    """,
                    (appt_id, appt["vet_name"], appt["date"], next_time),
                ).fetchone()
                if conflict:
                    raise ApiError(HTTPStatus.CONFLICT, "No se puede reprogramar: ese bloque ya está ocupado.")
                conn.execute("UPDATE appointments SET time = ? WHERE id = ?", (next_time, appt_id))
                conn.commit()
                self._send_json(HTTPStatus.OK, {"nextTime": next_time, "state": db.get_full_state(conn)})
                return

            m_cancel = re.fullmatch(r"/api/appointments/(\d+)/cancel", path)
            if m_cancel:
                self._require_auth(conn, ("RECEP", "ADMIN"))
                appt_id = int(m_cancel.group(1))
                cur = conn.execute("UPDATE appointments SET status = 'Cancelada' WHERE id = ?", (appt_id,))
                if cur.rowcount == 0:
                    raise ApiError(HTTPStatus.NOT_FOUND, "Cita no encontrada.")
                conn.commit()
                self._send_json(HTTPStatus.OK, {"state": db.get_full_state(conn)})
                return

            m_attend = re.fullmatch(r"/api/appointments/(\d+)/attend", path)
            if m_attend:
                self._require_auth(conn, ("VET", "ADMIN"))
                appt_id = int(m_attend.group(1))
                appt = conn.execute("SELECT pet_id FROM appointments WHERE id = ?", (appt_id,)).fetchone()
                if not appt:
                    raise ApiError(HTTPStatus.NOT_FOUND, "Cita no encontrada.")
                conn.execute("UPDATE appointments SET status = 'Atendida' WHERE id = ?", (appt_id,))
                conn.commit()
                self._send_json(HTTPStatus.OK, {"petId": appt["pet_id"], "state": db.get_full_state(conn)})
                return

        raise ApiError(HTTPStatus.NOT_FOUND, "Endpoint PATCH no encontrado.")


def run_server(host: str | None = None, port: int | None = None) -> None:
    db.init_db()
    bind_host = host or os.environ.get("NOVAVET_HOST", "127.0.0.1")
    bind_port = port or int(os.environ.get("NOVAVET_PORT", "8000"))
    server = ThreadingHTTPServer((bind_host, bind_port), NovaVetHandler)
    print(f"novaVet activo en http://{bind_host}:{bind_port} (BD SQLite: {db.DB_PATH})")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServidor detenido.")
    finally:
        server.server_close()


if __name__ == "__main__":
    run_server()
