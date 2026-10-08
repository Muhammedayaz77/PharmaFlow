# PharmaFlow — by Hind HealthCare

PharmaFlow is the multi-tenant pharma wholesale management platform under Hind HealthCare / Hind Tech Group.

## Deployment target

Production hosting:

- cPanel / CloudLinux Passenger
- FastAPI + Python
- MySQL
- Live host: `hindhealthcare.hindtechgroup.co.in`

The repository also supports local development with SQLite.

## Production architecture

```
Browser
  ↓
hindhealthcare.hindtechgroup.co.in
  ↓
cPanel Passenger
  ↓
web/Backend/passenger_wsgi.py
  ↓
FastAPI app in web/Backend/main.py
  ↓
MySQL selected by DATABASE_URL
```

## Canonical backend files

```
web/
├── Backend/
│   ├── main.py
│   ├── database.py
│   ├── passenger_wsgi.py
│   ├── requirements.txt
│   └── Helper/
├── View/
├── View Model/
├── Assets/
└── ...
```

## cPanel Python Application

Use these values when creating the fresh application:

- Application root: `~/pharmaflow/PharmaFlow/web/Backend`
- Startup file: `passenger_wsgi.py`
- Application entry point: `application`
- Python version: use the Python version supported by the hosting account
- Dependencies: install `web/Backend/requirements.txt`

The Passenger app should be created against the **Backend directory**, not the repository root and not the static `web` directory.

## Environment variables

Local:

```
DATABASE_URL=sqlite:///./hind_pharma.db
HIND_PHARMA_ENV=development
HIND_PHARMA_SEED_DEMO_DATA=true
HIND_PHARMA_AUTH_SECRET=<local-secret>
```

Production:

```
DATABASE_URL=mysql+pymysql://<user>:<password>@<mysql-host>:3306/<database>
HIND_PHARMA_ENV=production
HIND_PHARMA_SEED_DEMO_DATA=false
HIND_PHARMA_AUTH_SECRET=<long-random-secret>
```

Never commit the production MySQL password or auth secret.

## Health check

Once Passenger is running:

`GET /api/health`

Expected response includes:

```json
{
  "status": "ok",
  "product": "PharmaFlow",
  "brand": "Hind HealthCare"
}
```

The exact `database` field identifies whether the running process selected SQLite or MySQL.

## Tenant routes

Public tenant route pattern:

`/pharmaflow/{customer-slug}`

Example:

`/pharmaflow/hind-pharma`

Protected application APIs use the authenticated tenant/business relationship; the URL slug is not a permission mechanism.

## Fresh deployment rule

For the new deployment, do not copy the previous cPanel Python environment, `.htaccess`, generated `.pyc`, local SQLite database, or old Passenger process settings.

Deploy the repository into a clean directory, create a new Python application/virtual environment, configure MySQL, install dependencies, then restart Passenger.

GitHub Pages remains a static prototype only; it is not the production FastAPI host.
