# 🐾 novaVet — Veterinaria San Francisco de Asís

Sistema de gestión clínica y administrativa para veterinaria, desarrollado con **HTML, CSS y JavaScript** en el frontend, un servidor local en **Python** (sin dependencias externas) y persistencia en base de datos relacional **SQLite**.

---

## ✨ Funcionalidades principales

El acceso está dividido por perfiles con menús y permisos específicos:

- **Dirección / Administrador (`ADMIN`)**
  - Panel de control con indicadores operativos (propietarios, pacientes, citas vigentes y alertas de inventario).
  - Gestión de personal y contraseñas (crear colaboradores, habilitar o suspender cuentas).
  - Inventario general (alta de medicamentos/insumos, ajuste de existencias y alertas de stock mínimo).
  - Reportes, exportación e importación de respaldos en formato `.json` y migración de datos previos desde `localStorage`.

- **Médico Veterinario (`VET`)**
  - Agenda médica de consultas con finalización de atención.
  - Registro de historias clínicas, diagnósticos y prescripciones médicas.
  - Consulta de pacientes e historial clínico.
  - Consulta de disponibilidad de inventario (solo lectura).

- **Recepción y Admisiones (`RECEP`)**
  - Registro de propietarios y pacientes (mascotas).
  - Agendamiento de citas con validación anti-traslape por veterinario, fecha y hora.
  - Control de turnos (reprogramación `+1h` y cancelación).
  - Directorio general con búsqueda rápida por paciente, especie, propietario o teléfono.

---

## 🗂️ Estructura del proyecto

```text
nova/
├── index.html           # Interfaz principal (login y panel interno)
├── styles.css           # Estilos corporativos de novaVet
├── app.js               # Lógica del frontend conectada a la API REST
├── server.py            # Servidor HTTP local y API REST en Python
├── db.py                # Acceso a datos SQLite, hash de claves y respaldos
├── schema.sql           # Esquema relacional de la base de datos
├── iniciar_novavet.bat  # Lanzador rápido para Windows
└── novavet.db           # Base de datos SQLite (se genera automáticamente al iniciar)
```

---

## 🗄️ Base de datos (SQLite)

El esquema definido en `schema.sql` utiliza `PRAGMA foreign_keys = ON` y está compuesto por las siguientes tablas:

- `users`: colaboradores autorizados, rol (`ADMIN`, `VET`, `RECEP`), estado y hash de contraseña (`PBKDF2-HMAC-SHA256`).
- `sessions`: tokens de sesión activos con expiración de 24 horas.
- `owners`: datos de propietarios.
- `pets`: pacientes vinculados a su propietario (`owner_id`).
- `appointments`: citas médicas con índice por `(vet_name, date, time)` para control de traslapes.
- `records`: evoluciones clínicas, diagnósticos y prescripciones asociadas al paciente y veterinario.
- `inventory`: insumos, medicamentos y biológicos con control de stock mínimo.

---

## 🚀 Requisitos e instalación

- **Python 3** (incluye `sqlite3` y `http.server` en la biblioteca estándar; no requiere `pip install`).

### Ejecución en Windows

Haz doble clic en `iniciar_novavet.bat` o ejecuta en la terminal dentro de la carpeta del proyecto:

```powershell
python server.py
```

Luego abre en tu navegador:

```text
http://127.0.0.1:8000
```

> **Nota:** Para cambiar el host o puerto por defecto, define las variables de entorno `NOVAVET_HOST` y `NOVAVET_PORT`.

---

## 🔐 Credenciales iniciales de prueba

Al iniciar por primera vez con la base de datos vacía, se crean automáticamente tres cuentas base:

| Rol | Correo | Contraseña |
| :--- | :--- | :--- |
| Administrador (`ADMIN`) | `admin@sanfrancisco.vet` | `admin123` |
| Veterinario (`VET`) | `vet@sanfrancisco.vet` | `vet123` |
| Recepción (`RECEP`) | `recepcion@sanfrancisco.vet` | `recep123` |

---

## 🔌 Endpoints de la API

- `GET /api/health` — Estado del servidor y versión de SQLite.
- `GET /api/auth/defaults` — Correos activos predeterminados por rol.
- `POST /api/auth/login` — Inicio de sesión y emisión de token Bearer.
- `POST /api/auth/logout` — Cierre de sesión.
- `GET /api/auth/me` — Validación del usuario autenticado.
- `GET /api/state` — Estado operativo completo para la interfaz.
- `POST /api/users`, `PATCH /api/users/{id}/toggle` — Gestión de usuarios (`ADMIN`).
- `POST /api/inventory`, `PATCH /api/inventory/{id}/adjust` — Gestión de inventario (`ADMIN`).
- `POST /api/admissions` — Registro de propietario y paciente (`RECEP`, `ADMIN`).
- `POST /api/appointments`, `PATCH /api/appointments/{id}/shift`, `PATCH /api/appointments/{id}/cancel` — Gestión de citas (`RECEP`, `ADMIN`).
- `PATCH /api/appointments/{id}/attend`, `POST /api/records` — Atención clínica e historias (`VET`, `ADMIN`).
- `GET /api/backup/export`, `POST /api/backup/import` — Exportación y restauración JSON (`ADMIN`).

---

## 📌 Recomendación para Git

Si no deseas versionar tus datos locales ni archivos compilados de Python, añade esto a tu `.gitignore`:

```gitignore
novavet.db
novavet.db-wal
novavet.db-shm
__pycache__/
```
