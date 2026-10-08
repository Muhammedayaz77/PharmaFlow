from datetime import date, datetime
from typing import Optional
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from database import get_connection, initialize_database

try:
    from Helper.auth import create_token, verify_token
    from Helper.password import hash_password, verify_password
except ModuleNotFoundError:
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from Helper.auth import create_token, verify_token
    from Helper.password import hash_password, verify_password

initialize_database()
app = FastAPI(title='PharmaFlow API', version='2.3.0')
WEB_ROOT = Path(__file__).resolve().parents[1]
FRONTEND_INDEX = WEB_ROOT / 'View' / 'index.html'
app.add_middleware(CORSMiddleware, allow_origins=['*'], allow_credentials=False, allow_methods=['*'], allow_headers=['*'])

ROLES = {'super_admin', 'admin', 'manager', 'employee'}
CALL_COOLDOWN_SECONDS = 10


class LoginInput(BaseModel):
    username: str
    password: str


class AdminInput(BaseModel):
    username: str
    business_name: str
    name: Optional[str] = None
    phone: Optional[str] = None
    email: Optional[str] = None
    address: Optional[str] = None


class UserInput(BaseModel):
    username: str
    role: str = Field(pattern='^(manager|employee)$')
    name: Optional[str] = None
    phone: Optional[str] = None


class MedicalInput(BaseModel):
    name: str
    area: Optional[str] = None
    phone: Optional[str] = None


class ProductInput(BaseModel):
    product_id: Optional[str] = None
    code: Optional[str] = None
    name: str
    unit: Optional[str] = None
    mrp: Optional[float] = None
    formula: Optional[str] = None
    company: Optional[str] = None
    image: Optional[str] = None


class OrderItemInput(BaseModel):
    product_id: int
    quantity: int
    price: Optional[float] = None


class OrderInput(BaseModel):
    medical_id: Optional[int] = None
    items: list[OrderItemInput]


class CallingStatusInput(BaseModel):
    is_pick: Optional[bool] = None


def _principal(authorization: Optional[str] = Header(default=None)):
    if not authorization or not authorization.lower().startswith('bearer '):
        raise HTTPException(401, 'Authentication required')
    try:
        return verify_token(authorization.split(' ', 1)[1].strip())
    except ValueError as exc:
        raise HTTPException(401, str(exc)) from exc


def _require(principal, *roles):
    if principal.get('role') not in roles:
        raise HTTPException(403, 'You do not have permission for this action')


def _admin_id(principal) -> int:
    value = principal.get('admin_id')
    if principal.get('role') == 'admin':
        value = principal.get('id')
    if not value:
        raise HTTPException(403, 'Business account is required')
    return int(value)


def _check_subscription(admin_id: int):
    with get_connection() as db:
        admin = db.execute('SELECT is_active, subscription_expiry FROM admins WHERE id=?', (admin_id,)).fetchone()
    if not admin or not admin['is_active']:
        raise HTTPException(403, 'This admin account is inactive')
    if date.fromisoformat(admin['subscription_expiry']) < date.today():
        raise HTTPException(403, 'Subscription expired. Please renew the subscription.')


def _audit(db, principal, action, entity_type=None, entity_id=None, details=None, admin_id=None):
    actor_type = principal.get('role', 'unknown')
    user_id = principal.get('id') if actor_type in {'manager', 'employee'} else None
    db.execute(
        '''INSERT INTO audit_logs(admin_id,user_id,actor_type,action,entity_type,entity_id,details)
           VALUES(?,?,?,?,?,?,?)''',
        (admin_id, user_id, actor_type, action, entity_type, str(entity_id) if entity_id is not None else None, details),
    )


@app.get('/api/health')
def health():
    from database import database_engine
    return {'status': 'ok', 'product': 'PharmaFlow', 'brand': 'Hind HealthCare', 'database': database_engine(), 'version': '2.3.0'}


@app.post('/api/login')
@app.post('/login')
def login(item: LoginInput):
    username = item.username.strip()
    with get_connection() as db:
        super_admin = db.execute('SELECT * FROM super_admins WHERE lower(username)=lower(?)', (username,)).fetchone()
        if super_admin and super_admin['is_active'] and verify_password(item.password, super_admin['password_hash']):
            return {'id': super_admin['id'], 'username': super_admin['username'], 'role': 'super_admin', 'admin_id': None,
                    'token': create_token(super_admin['id'], super_admin['username'], 'super_admin')}

        admin = db.execute('SELECT * FROM admins WHERE lower(username)=lower(?)', (username,)).fetchone()
        if admin and admin['is_active'] and date.fromisoformat(admin['subscription_expiry']) >= date.today() and verify_password(item.password, admin['password_hash']):
            return {'id': admin['id'], 'username': admin['username'], 'role': 'admin', 'admin_id': admin['id'],
                    'business_name': admin['business_name'], 'subscription_expiry': admin['subscription_expiry'],
                    'token': create_token(admin['id'], admin['username'], 'admin', admin['id'])}

        user = db.execute('SELECT u.*,a.business_name,a.is_active AS admin_active,a.subscription_expiry FROM users u JOIN admins a ON a.id=u.admin_id WHERE lower(u.username)=lower(?)', (username,)).fetchone()
        if user and user['is_active'] and user['admin_active'] and _as_date(user['subscription_expiry']) >= date.today() and verify_password(item.password, user['password_hash']):
            return {'id': user['id'], 'username': user['username'], 'role': user['role'], 'admin_id': user['admin_id'],
                    'business_name': user['business_name'], 'subscription_expiry': user['subscription_expiry'],
                    'token': create_token(user['id'], user['username'], user['role'], user['admin_id'])}
    raise HTTPException(401, 'Invalid username or password')


@app.get('/api/me')
def me(principal=Depends(_principal)):
    if principal['role'] != 'super_admin':
        _check_subscription(_admin_id(principal))
    return principal


@app.get('/api/subscription-warning')
def subscription_warning(principal=Depends(_principal)):
    if principal['role'] == 'super_admin':
        return {'show': False, 'days_remaining': None}
    admin_id = _admin_id(principal)
    with get_connection() as db:
        row = db.execute('SELECT subscription_expiry FROM admins WHERE id=?', (admin_id,)).fetchone()
    expiry = date.fromisoformat(row['subscription_expiry'])
    days = (expiry - date.today()).days
    return {'show': 0 <= days <= 30, 'days_remaining': days, 'expiry': expiry.isoformat()}


@app.get('/api/tenant/{slug}')
def public_tenant(slug: str):
    with get_connection() as db:
        row=db.execute('SELECT id,slug,business_name,subtitle,address,phone,email,dl_20b,dl_21b,fssai,gstin,logo,barcode,upi,is_active FROM superAdminTenants WHERE lower(slug)=lower(?)',(slug,)).fetchone()
    if not row or not row['is_active']:
        raise HTTPException(404,'Shop not found')
    return dict(row)

@app.get('/api/super-admin/shop-applications')
def super_admin_applications(principal=Depends(_principal)):
    _require(principal,'super_admin')
    with get_connection() as db:
        rows=db.execute('''
          SELECT a.id,a.tenant_id,a.admin_username,a.admin_name,a.application_status,
                 t.slug,t.business_name,t.subtitle,t.address,t.phone,t.email,t.logo,t.upi,
                 ad.id AS admin_id,ad.is_active,ad.subscription_expiry,
                 p.amount,p.payment_status,p.transaction_id,p.paid_at
          FROM superAdminApplications a
          LEFT JOIN superAdminTenants t ON t.id=a.tenant_id
          LEFT JOIN admins ad ON ad.tenant_id=t.id
          LEFT JOIN superAdminPayments p ON p.application_id=a.id
          ORDER BY a.id DESC
        ''').fetchall()
    return [dict(r) for r in rows]

# ---------------- Super Admin ----------------
@app.get('/api/super-admin/dashboard')
def super_dashboard(principal=Depends(_principal)):
    _require(principal, 'super_admin')
    with get_connection() as db:
        admins = db.execute('SELECT id,username,name,business_name,is_active,subscription_plan,subscription_start,subscription_expiry FROM admins ORDER BY business_name').fetchall()
    return {'admins': [dict(row) for row in admins], 'count': len(admins)}


@app.post('/api/admins')
def create_admin(item: AdminInput, principal=Depends(_principal)):
    _require(principal, 'super_admin')
    username = item.username.strip(); business = item.business_name.strip()
    if not username or not business:
        raise HTTPException(400, 'Username and business name are required')
    today = date.today()
    try:
        next_year = today.replace(year=today.year + 1)
    except ValueError:
        next_year = today.replace(year=today.year + 1, day=28)
    with get_connection() as db:
        try:
            cursor = db.execute('''INSERT INTO admins(username,password_hash,name,business_name,phone,email,address,subscription_plan,subscription_start,subscription_expiry)
                                  VALUES(?,?,?,?,?,?,?,?,?,?)''',
                                (username, hash_password(f'{username}@123'), item.name, business, item.phone, item.email, item.address, 'YEARLY', today.isoformat(), next_year.isoformat()))
            admin_id = cursor.lastrowid
            _audit(db, principal, 'CREATE_ADMIN', 'admin', admin_id, business, admin_id)
        except Exception as exc:
            raise HTTPException(409, 'Admin username already exists') from exc
    return {'status': 'ok', 'id': admin_id, 'username': username, 'password_reset_rule': f'{username}@123'}


@app.delete('/api/admins/{admin_id}')
def delete_admin(admin_id: int, principal=Depends(_principal)):
    _require(principal, 'super_admin')
    with get_connection() as db:
        admin = db.execute('SELECT id,business_name FROM admins WHERE id=?', (admin_id,)).fetchone()
        if not admin: raise HTTPException(404, 'Admin not found')
        _audit(db, principal, 'DELETE_ADMIN', 'admin', admin_id, admin['business_name'], admin_id)
        db.execute('DELETE FROM admins WHERE id=?', (admin_id,))
    return {'status': 'ok'}


@app.patch('/api/admins/{admin_id}/status')
def set_admin_status(admin_id: int, active: bool, principal=Depends(_principal)):
    _require(principal, 'super_admin')
    with get_connection() as db:
        if not db.execute('SELECT 1 FROM admins WHERE id=?', (admin_id,)).fetchone(): raise HTTPException(404, 'Admin not found')
        db.execute('UPDATE admins SET is_active=?,updated_at=CURRENT_TIMESTAMP WHERE id=?', (int(active), admin_id))
        _audit(db, principal, 'ACTIVATE_ADMIN' if active else 'DEACTIVATE_ADMIN', 'admin', admin_id, None, admin_id)
    return {'status': 'ok', 'is_active': active}


@app.post('/api/admins/{admin_id}/reset-password')
def reset_admin_password(admin_id: int, principal=Depends(_principal)):
    _require(principal, 'super_admin')
    with get_connection() as db:
        admin = db.execute('SELECT username FROM admins WHERE id=?', (admin_id,)).fetchone()
        if not admin: raise HTTPException(404, 'Admin not found')
        db.execute('UPDATE admins SET password_hash=?,updated_at=CURRENT_TIMESTAMP WHERE id=?', (hash_password(f"{admin['username']}@123"), admin_id))
        _audit(db, principal, 'RESET_ADMIN_PASSWORD', 'admin', admin_id, None, admin_id)
    return {'status': 'ok', 'message': 'Password reset to username@123'}


# ---------------- Tenant users ----------------
@app.get('/api/users')
def users(principal=Depends(_principal)):
    _require(principal, 'admin', 'manager')
    admin_id = _admin_id(principal); _check_subscription(admin_id)
    with get_connection() as db:
        rows = db.execute('SELECT id,username,role,name,phone,is_active,created_at,updated_at FROM users WHERE admin_id=? ORDER BY username', (admin_id,)).fetchall()
    return [dict(row) for row in rows]


@app.post('/api/users')
def add_user(item: UserInput, principal=Depends(_principal)):
    _require(principal, 'admin', 'manager')
    admin_id = _admin_id(principal); _check_subscription(admin_id)
    with get_connection() as db:
        if principal['role'] == 'manager' and item.role != 'employee':
            raise HTTPException(403, 'Manager can create employees only')
        try:
            cursor = db.execute('''INSERT INTO users(admin_id,username,password_hash,role,name,phone)
                                  VALUES(?,?,?,?,?,?)''',
                                (admin_id, item.username.strip(), hash_password(f'{item.username.strip()}@123'), item.role, item.name, item.phone))
            _audit(db, principal, 'CREATE_USER', 'user', cursor.lastrowid, item.role, admin_id)
            return dict(db.execute('SELECT id,username,role,name,phone,is_active,created_at,updated_at FROM users WHERE id=?', (cursor.lastrowid,)).fetchone())
        except Exception as exc:
            raise HTTPException(409, 'Username already exists') from exc


@app.delete('/api/users/{user_id}')
def delete_user(user_id: int, principal=Depends(_principal)):
    _require(principal, 'admin')
    admin_id = _admin_id(principal); _check_subscription(admin_id)
    with get_connection() as db:
        row = db.execute('SELECT username,role FROM users WHERE id=? AND admin_id=?', (user_id, admin_id)).fetchone()
        if not row: raise HTTPException(404, 'User not found')
        _audit(db, principal, 'DELETE_USER', 'user', user_id, row['role'], admin_id)
        db.execute('DELETE FROM users WHERE id=? AND admin_id=?', (user_id, admin_id))
    return {'status': 'ok'}


@app.post('/api/users/{user_id}/reset-password')
def reset_user_password(user_id: int, principal=Depends(_principal)):
    _require(principal, 'admin')
    admin_id = _admin_id(principal); _check_subscription(admin_id)
    with get_connection() as db:
        row = db.execute('SELECT username FROM users WHERE id=? AND admin_id=?', (user_id, admin_id)).fetchone()
        if not row: raise HTTPException(404, 'User not found')
        db.execute('UPDATE users SET password_hash=?,updated_at=CURRENT_TIMESTAMP WHERE id=?', (hash_password(f"{row['username']}@123"), user_id))
        _audit(db, principal, 'RESET_USER_PASSWORD', 'user', user_id, None, admin_id)
    return {'status': 'ok'}


# ---------------- Medicals ----------------
@app.get('/api/medicals')
def medicals(search: str = '', principal=Depends(_principal)):
    _require(principal, 'admin', 'manager', 'employee')
    admin_id = _admin_id(principal); _check_subscription(admin_id)
    pattern = f'%{search.strip()}%'
    with get_connection() as db:
        rows = db.execute('SELECT * FROM medicals WHERE admin_id=? AND is_active=1 AND (name LIKE ? OR area LIKE ?) ORDER BY name', (admin_id, pattern, pattern)).fetchall()
    return [dict(row) for row in rows]


@app.post('/api/medicals')
def add_medical(item: MedicalInput, principal=Depends(_principal)):
    _require(principal, 'admin', 'manager')
    admin_id = _admin_id(principal); _check_subscription(admin_id)
    name = item.name.strip()
    if not name: raise HTTPException(400, 'Medical name is required')
    with get_connection() as db:
        try:
            cursor = db.execute('INSERT INTO medicals(admin_id,name,area,phone) VALUES(?,?,?,?)', (admin_id, name, item.area, item.phone))
            return dict(db.execute('SELECT * FROM medicals WHERE id=?', (cursor.lastrowid,)).fetchone())
        except Exception as exc:
            raise HTTPException(409, 'Medical already exists') from exc


@app.put('/api/medicals/{medical_id}')
def edit_medical(medical_id: int, item: MedicalInput, principal=Depends(_principal)):
    _require(principal, 'admin', 'manager')
    admin_id = _admin_id(principal); _check_subscription(admin_id)
    with get_connection() as db:
        cursor = db.execute('UPDATE medicals SET name=?,area=?,phone=?,updated_at=CURRENT_TIMESTAMP WHERE id=? AND admin_id=? AND is_active=1', (item.name.strip(), item.area, item.phone, medical_id, admin_id))
        if cursor.rowcount == 0: raise HTTPException(404, 'Medical not found')
    return {'status': 'ok'}


@app.delete('/api/medicals/{medical_id}')
def delete_medical(medical_id: int, principal=Depends(_principal)):
    _require(principal, 'admin')
    admin_id = _admin_id(principal); _check_subscription(admin_id)
    with get_connection() as db:
        row = db.execute('SELECT name FROM medicals WHERE id=? AND admin_id=?', (medical_id, admin_id)).fetchone()
        if not row: raise HTTPException(404, 'Medical not found')
        db.execute('DELETE FROM medicals WHERE id=? AND admin_id=?', (medical_id, admin_id))
    return {'status': 'ok'}


# ---------------- Daily Calling ----------------
@app.get('/api/calling/today')
def daily_calling_list(principal=Depends(_principal)):
    _require(principal, 'admin', 'manager', 'employee')
    admin_id = _admin_id(principal); _check_subscription(admin_id)
    employee_id = principal['id'] if principal['role'] == 'employee' else None
    today = date.today().isoformat()
    with get_connection() as db:
        if employee_id:
            rows = db.execute('''
                SELECT m.id,m.name,m.phone,m.area,
                       CASE WHEN EXISTS (SELECT 1 FROM calling_logs c WHERE c.medical_id=m.id AND c.employee_id=? AND date(c.called_at)=?) THEN 1 ELSE 0 END AS is_call,
                       (SELECT c.is_pick FROM calling_logs c WHERE c.medical_id=m.id AND c.employee_id=? AND date(c.called_at)=? ORDER BY c.id DESC LIMIT 1) AS is_pick,
                       (SELECT c.is_not_pick FROM calling_logs c WHERE c.medical_id=m.id AND c.employee_id=? AND date(c.called_at)=? ORDER BY c.id DESC LIMIT 1) AS is_not_pick
                FROM medicals m WHERE m.admin_id=? AND m.is_active=1 ORDER BY m.name
            ''', (employee_id,today,employee_id,today,employee_id,today,admin_id)).fetchall()
        else:
            rows = db.execute('''
                SELECT m.id,m.name,m.phone,m.area,
                       CASE WHEN EXISTS (SELECT 1 FROM calling_logs c WHERE c.medical_id=m.id AND date(c.called_at)=?) THEN 1 ELSE 0 END AS is_call,
                       (SELECT c.is_pick FROM calling_logs c WHERE c.medical_id=m.id AND date(c.called_at)=? ORDER BY c.id DESC LIMIT 1) AS is_pick,
                       (SELECT c.is_not_pick FROM calling_logs c WHERE c.medical_id=m.id AND date(c.called_at)=? ORDER BY c.id DESC LIMIT 1) AS is_not_pick
                FROM medicals m WHERE m.admin_id=? AND m.is_active=1 ORDER BY m.name
            ''', (today,today,today,admin_id)).fetchall()
    return [dict(row) for row in rows]


@app.post('/api/calling/{medical_id}/call')
def record_call_click(medical_id: int, principal=Depends(_principal)):
    _require(principal, 'employee')
    admin_id = _admin_id(principal); _check_subscription(admin_id)
    employee_id = principal['id']
    now = datetime.utcnow()
    with get_connection() as db:
        medical = db.execute('SELECT id,name,phone FROM medicals WHERE id=? AND admin_id=? AND is_active=1', (medical_id,admin_id)).fetchone()
        if not medical:
            raise HTTPException(404, 'Medical not found')
        recent = db.execute('SELECT called_at FROM calling_logs WHERE employee_id=? ORDER BY id DESC LIMIT 1', (employee_id,)).fetchone()
        if recent:
            recent_at = datetime.fromisoformat(recent['called_at'].replace('Z',''))
            seconds = (now - recent_at).total_seconds()
            if seconds < CALL_COOLDOWN_SECONDS:
                raise HTTPException(429, f'Please wait {max(1, int(CALL_COOLDOWN_SECONDS - seconds))} seconds before the next call.')
        db.execute('''INSERT INTO calling_logs(admin_id,medical_id,employee_id,called_at,is_call,is_pick,is_not_pick)
                      VALUES(?,?,?,?,1,NULL,NULL)''', (admin_id,medical_id,employee_id,now.isoformat(timespec='seconds')))
    return {'status':'ok','medical_id':medical_id,'is_call':True,'cooldown_seconds':CALL_COOLDOWN_SECONDS}


@app.patch('/api/calling/{medical_id}/status')
def update_call_status(medical_id: int, item: CallingStatusInput, principal=Depends(_principal)):
    _require(principal, 'employee')
    admin_id = _admin_id(principal); employee_id = principal['id']; today = date.today().isoformat()
    if item.is_pick is None:
        raise HTTPException(400, 'Select Picked or Not Picked')
    with get_connection() as db:
        latest = db.execute('''SELECT id FROM calling_logs WHERE medical_id=? AND employee_id=? AND date(called_at)=? ORDER BY id DESC LIMIT 1''', (medical_id,employee_id,today)).fetchone()
        if not latest:
            raise HTTPException(400, 'Call the medical first')
        db.execute('UPDATE calling_logs SET is_pick=?,is_not_pick=? WHERE id=?', (int(item.is_pick), int(not item.is_pick), latest['id']))
    return {'status':'ok','is_pick':item.is_pick,'is_not_pick':not item.is_pick}


@app.get('/api/admin/calling/report')
def admin_calling_report(principal=Depends(_principal)):
    _require(principal, 'admin')
    admin_id = _admin_id(principal); _check_subscription(admin_id); today = date.today().isoformat()
    with get_connection() as db:
        rows = db.execute('''
            SELECT m.id AS medical_id,m.name,m.phone,m.area,
                   COUNT(c.id) AS call_count,
                   MAX(c.called_at) AS last_called_at,
                   MAX(CASE WHEN c.is_pick=1 THEN 1 ELSE 0 END) AS is_pick,
                   MAX(CASE WHEN c.is_not_pick=1 THEN 1 ELSE 0 END) AS is_not_pick,
                   u.username AS employee
            FROM medicals m
            LEFT JOIN calling_logs c ON c.medical_id=m.id AND c.admin_id=? AND date(c.called_at)=?
            LEFT JOIN users u ON u.id=c.employee_id
            WHERE m.admin_id=? AND m.is_active=1
            GROUP BY m.id,m.name,m.phone,m.area,u.username
            ORDER BY m.name,u.username
        ''', (admin_id,today,admin_id)).fetchall()
    return [dict(row) for row in rows]


# ---------------- Products ----------------
@app.get('/api/products')
def products(search: str = '', principal=Depends(_principal)):
    _require(principal, 'admin', 'manager', 'employee')
    admin_id = _admin_id(principal); _check_subscription(admin_id)
    pattern = f'%{search.strip()}%'
    with get_connection() as db:
        rows = db.execute('''SELECT * FROM products WHERE admin_id=? AND is_active=1 AND
          (name LIKE ? OR code LIKE ? OR product_id LIKE ? OR company LIKE ? OR formula LIKE ?) ORDER BY name''',
          (admin_id, pattern, pattern, pattern, pattern, pattern)).fetchall()
    return [dict(row) for row in rows]


@app.post('/api/products')
def add_product(item: ProductInput, principal=Depends(_principal)):
    _require(principal, 'admin', 'manager')
    admin_id = _admin_id(principal); _check_subscription(admin_id)
    with get_connection() as db:
        try:
            cursor = db.execute('''INSERT INTO products(admin_id,product_id,code,name,unit,mrp,formula,company,image)
                                  VALUES(?,?,?,?,?,?,?,?,?)''',
                                (admin_id, item.product_id, item.code, item.name.strip(), item.unit, item.mrp, item.formula, item.company, item.image))
            return dict(db.execute('SELECT * FROM products WHERE id=?', (cursor.lastrowid,)).fetchone())
        except Exception as exc:
            raise HTTPException(409, 'Product with this ID already exists') from exc


@app.put('/api/products/{product_id}')
def edit_product(product_id: int, item: ProductInput, principal=Depends(_principal)):
    _require(principal, 'admin', 'manager')
    admin_id = _admin_id(principal); _check_subscription(admin_id)
    with get_connection() as db:
        cursor = db.execute('''UPDATE products SET product_id=?,code=?,name=?,unit=?,mrp=?,formula=?,company=?,image=?,updated_at=CURRENT_TIMESTAMP
                               WHERE id=? AND admin_id=? AND is_active=1''',
                            (item.product_id, item.code, item.name.strip(), item.unit, item.mrp, item.formula, item.company, item.image, product_id, admin_id))
        if cursor.rowcount == 0: raise HTTPException(404, 'Product not found')
    return {'status': 'ok'}


@app.post('/api/products/bulk')
def add_products(items: list[ProductInput], principal=Depends(_principal)):
    _require(principal, 'admin', 'manager')
    admin_id = _admin_id(principal); _check_subscription(admin_id)
    with get_connection() as db:
        for item in items:
            try:
                db.execute('''INSERT INTO products(admin_id,product_id,code,name,unit,mrp,formula,company,image)
                              VALUES(?,?,?,?,?,?,?,?,?)''',
                           (admin_id, item.product_id, item.code, item.name.strip(), item.unit, item.mrp, item.formula, item.company, item.image))
            except Exception as exc:
                raise HTTPException(409, f'Bulk import failed for product: {item.name}') from exc
    return {'status': 'ok', 'count': len(items)}


@app.delete('/api/products/{product_id}')
def delete_product(product_id: int, principal=Depends(_principal)):
    _require(principal, 'admin')
    admin_id = _admin_id(principal); _check_subscription(admin_id)
    with get_connection() as db:
        if not db.execute('SELECT 1 FROM products WHERE id=? AND admin_id=?', (product_id, admin_id)).fetchone(): raise HTTPException(404, 'Product not found')
        db.execute('DELETE FROM products WHERE id=? AND admin_id=?', (product_id, admin_id))
    return {'status': 'ok'}


# ---------------- Orders ----------------
@app.post('/api/orders')
def create_order(order: OrderInput, principal=Depends(_principal)):
    _require(principal, 'admin', 'manager', 'employee')
    admin_id = _admin_id(principal); _check_subscription(admin_id)
    if not order.items: raise HTTPException(400, 'Order must contain at least one product')
    with get_connection() as db:
        if order.medical_id is not None and not db.execute('SELECT 1 FROM medicals WHERE id=? AND admin_id=? AND is_active=1', (order.medical_id, admin_id)).fetchone():
            raise HTTPException(400, 'Medical does not belong to this business')
        creator_id = principal['id'] if principal['role'] != 'admin' else None
        cursor = db.execute('INSERT INTO orders(admin_id,medical_id,created_by) VALUES(?,?,?)', (admin_id, order.medical_id, creator_id))
        order_id = cursor.lastrowid
        for item in order.items:
            if item.quantity < 1: raise HTTPException(400, 'Quantity must be at least 1')
            product = db.execute('SELECT mrp FROM products WHERE id=? AND admin_id=? AND is_active=1', (item.product_id, admin_id)).fetchone()
            if not product: raise HTTPException(400, 'Product does not belong to this business')
            db.execute('INSERT INTO order_items(order_id,product_id,quantity,price) VALUES(?,?,?,?)', (order_id, item.product_id, item.quantity, item.price if item.price is not None else product['mrp']))
    return {'status': 'ok', 'order_id': order_id}


@app.get('/api/orders')
def get_orders(principal=Depends(_principal)):
    _require(principal, 'admin', 'manager', 'employee')
    admin_id = _admin_id(principal); _check_subscription(admin_id)
    with get_connection() as db:
        orders = [dict(row) for row in db.execute('SELECT * FROM orders WHERE admin_id=? ORDER BY id DESC', (admin_id,)).fetchall()]
        for order in orders:
            order['items'] = [dict(row) for row in db.execute('SELECT * FROM order_items WHERE order_id=?', (order['id'],)).fetchall()]
    return orders


try:
    from .tenant_routes import register as register_tenant_routes
except ImportError:
    from tenant_routes import register as register_tenant_routes

register_tenant_routes(app)

# Public tenant routes use the same shared frontend entry point.
# Tenant identity is validated by the API; the URL slug is only routing context.
FRONTEND_INDEX = WEB_ROOT / 'View' / 'index.html'

if FRONTEND_INDEX.exists():
    @app.get('/pharmaflow', include_in_schema=False)
    @app.get('/pharmaflow/{slug}', include_in_schema=False)
    def pharmaflow_home(slug: str = 'hind-pharma'):
        return FileResponse(FRONTEND_INDEX)

    @app.get('/', include_in_schema=False)
    def frontend_root():
        return FileResponse(FRONTEND_INDEX)

# Serve only the browser-facing web folders. Backend source/database files are not mounted.
for _public_path in ('View', 'View Model', 'Assets', 'API', 'Models', 'Helper', 'temp', 'data'):
    _directory = WEB_ROOT / _public_path
    if _directory.exists():
        app.mount(
            f'/{_public_path}',
            StaticFiles(directory=_directory),
            name=f'frontend_{_public_path.lower().replace(" ", "_")}',
        )

if __name__ == '__main__':
    import uvicorn
    uvicorn.run('main:app', host='127.0.0.1', port=8000, reload=True)
