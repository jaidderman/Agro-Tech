// ============================================================
// AGRO-TECH — Backend Node.js + Express + PostgreSQL
// Archivo: server.js  |  Versión: 9.5 — RBAC Blindado + Parche Automático BD
// ============================================================

const path = require('path');
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
require('dotenv').config();

const JWT_SECRET = 'agro_tech_secret_key_2025';
const app = express();

// ==================== CORS — CONFIGURACIÓN CLOUDFLARE / RENDER ====================
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'cf-skip-browser-warning', 'X-Requested-With', 'Accept', 'Origin']
}));

app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET,POST,PUT,PATCH,DELETE,OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, cf-skip-browser-warning, X-Requested-With, Accept, Origin');
  next();
});

app.use((req, res, next) => {
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

app.use(express.json());
app.use(express.static(__dirname));

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'login.html')));

// ==================== CONEXIÓN CON POSTGRESQL (RENDER) ====================
const pool = new Pool({
  connectionString: 'postgresql://jaidder:uiJDzAIwjTPKtIoZYyEV7ZYmY9cz60xH@dpg-d82b9fmgvqtc73dihc1g-a.ohio-postgres.render.com/agrotech_wk1y',
  ssl: { rejectUnauthorized: false }
});

// ==================== MIDDLEWARES DE AUTENTICACIÓN Y SEGURIDAD ====================
const authMiddleware = async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Acceso denegado: No se proporcionó un token de seguridad JWT.' });
  try { 
    req.user = jwt.verify(token, JWT_SECRET); 
    next(); 
  } catch { 
    return res.status(401).json({ error: 'Sesión inválida o expirada. Por favor, inicia sesión nuevamente.' }); 
  }
};

const adminMiddleware = (req, res, next) => {
  if (!req.user || req.user.rol !== 'admin') {
    return res.status(403).json({ error: 'Acceso restringido: Operación exclusiva para el Administrador del Sistema.' });
  }
  next();
};

// Middleware unificado de Control de Acceso por Roles (RBAC)
const requerirRoles = (...rolesPermitidos) => (req, res, next) => {
  if (!req.user) return res.status(401).json({ error: 'Usuario no autenticado.' });
  if (!rolesPermitidos.includes(req.user.rol)) {
    return res.status(403).json({ error: `Acceso denegado: El rol '${req.user.rol}' no tiene autorización para esta sección.` });
  }
  next();
};

// ============================================================
//  MÓDULO DE AUTENTICACIÓN (LOGIN, REGISTRO, RECUPERACIÓN)
// ============================================================
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM usuarios WHERE email=$1 AND activo=true', [email]);
    if (!result.rows.length) return res.status(401).json({ error: 'Credenciales inválidas' });
    
    const user = result.rows[0];
    if (!await bcrypt.compare(password, user.password_hash)) return res.status(401).json({ error: 'Credenciales inválidas' });
    
    await pool.query('UPDATE usuarios SET ultimo_acceso=NOW() WHERE id=$1', [user.id]);
    const token = jwt.sign({ id: user.id, rol: user.rol, nombre: user.nombre }, JWT_SECRET, { expiresIn: '8h' });
    
    res.json({ token, user: { id: user.id, nombre: user.nombre, apellido: user.apellido, email: user.email, rol: user.rol } });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/auth/register', async (req, res) => {
  const { nombre, apellido, email, password } = req.body;
  if (!nombre || !apellido || !email || !password) return res.status(400).json({ error: 'Campos incompletos' });
  try {
    if ((await pool.query('SELECT id FROM usuarios WHERE email=$1', [email])).rows.length) {
      return res.status(409).json({ error: 'El correo electrónico ya se encuentra registrado.' });
    }
    const hash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      `INSERT INTO usuarios (nombre,apellido,email,password_hash,rol,activo)
       VALUES ($1,$2,$3,$4,'tecnico',true) RETURNING id,nombre,apellido,email,rol`,
      [nombre.trim(), apellido.trim(), email.trim().toLowerCase(), hash]
    );
    res.status(201).json({ message: 'Usuario registrado con éxito', user: result.rows[0] });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/auth/forgot-password', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'El correo electrónico es mandatorio.' });
  try {
    const result = await pool.query('SELECT id, nombre, apellido FROM usuarios WHERE email=$1 AND activo=true', [email]);
    if (!result.rows.length) return res.json({ message: 'Instrucciones enviadas si el registro existe.' });

    const user = result.rows[0];
    const token = crypto.randomBytes(32).toString('hex');
    const expiracion = new Date(Date.now() + 60 * 60 * 1000);

    await pool.query('UPDATE tokens_recuperacion_v9 SET usado=true WHERE usuario_id=$1 AND usado=false', [user.id]);
    await pool.query(`INSERT INTO tokens_recuperacion_v9 (usuario_id, token, fecha_expiracion, usado) VALUES ($1, $2, $3, FALSE)`, [user.id, token, expiracion]);

    console.log(`\n🔑 TOKEN DE RECUPERACIÓN GENERADO: ${token}\n`);
    res.json({ message: 'Instrucciones enviadas con éxito. Revise la terminal/logs del servidor.' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/auth/reset-password', async (req, res) => {
  const { token, nueva_password } = req.body;
  try {
    const result = await pool.query(
      `SELECT rt.*, u.nombre FROM tokens_recuperacion_v9 rt JOIN usuarios u ON rt.usuario_id=u.id
       WHERE rt.token=$1 AND rt.usado=false AND rt.fecha_expiracion > NOW()`
    );
    if (!result.rows.length) return res.status(400).json({ error: 'Token de recuperación inválido o vencido.' });

    const { usuario_id } = result.rows[0];
    const hash = await bcrypt.hash(nueva_password, 10);
    await pool.query('UPDATE usuarios SET password_hash=$1 WHERE id=$2', [hash, usuario_id]);
    await pool.query('UPDATE tokens_recuperacion_v9 SET usado=true WHERE token=$1', [token]);
    res.json({ message: 'Contraseña actualizada con éxito.' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ============================================================
//  ADMINISTRACIÓN DE USUARIOS (EXCLUSIVO ADMIN)
// ============================================================
app.get('/api/usuarios', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    res.json((await pool.query(`SELECT id,nombre,apellido,email,rol,activo,fecha_registro,ultimo_acceso FROM usuarios ORDER BY fecha_registro DESC`)).rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.patch('/api/usuarios/:id/rol', authMiddleware, adminMiddleware, async (req, res) => {
  const { rol } = req.body;
  const rolesValidos = ['admin', 'productor', 'encargado', 'tecnico'];
  if (!rolesValidos.includes(rol)) return res.status(400).json({ error: 'Rol no admitido por el sistema.' });
  try {
    const result = await pool.query('UPDATE usuarios SET rol=$1 WHERE id=$2 RETURNING id,nombre,apellido,email,rol', [rol, req.params.id]);
    res.json(result.rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.patch('/api/usuarios/:id/activo', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const result = await pool.query('UPDATE usuarios SET activo=$1 WHERE id=$2 RETURNING id,nombre,apellido,email,rol,activo', [req.body.activo, req.params.id]);
    res.json(result.rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ============================================================
//  DASHBOARD METRICS
// ============================================================
app.get('/api/dashboard/stats', authMiddleware, async (req, res) => {
  try {
    const [ganado, cultivos, alertas, vacunas, ganadoRec, cultivosRec, ventasMes] = await Promise.all([
      pool.query("SELECT COUNT(*) FROM ganado WHERE estado='activo'"),
      pool.query("SELECT COUNT(*) FROM cultivos WHERE estado NOT IN ('cosechado','perdido')"),
      pool.query("SELECT COUNT(*) FROM alertas WHERE completada=false AND fecha_programada<=CURRENT_DATE"),
      pool.query("SELECT COUNT(*) FROM vacunaciones WHERE fecha_aplicacion>=CURRENT_DATE-30"),
      pool.query(`SELECT g.id,g.numero_arete,g.nombre,g.especie,g.raza,g.sexo,g.peso_inicial,g.peso_actual,g.estado,l.nombre AS lote_nombre FROM ganado g LEFT JOIN lotes l ON g.lote_id=l.id ORDER BY g.fecha_registro DESC LIMIT 5`),
      pool.query(`SELECT c.id,c.nombre_cultivo,c.variedad,c.fecha_siembra,c.fecha_estimada_cosecha,c.estado,l.nombre AS lote_nombre FROM cultivos c LEFT JOIN lotes l ON c.lote_id=l.id WHERE c.estado NOT IN ('cosechado','perdido') ORDER BY c.fecha_registro DESC LIMIT 5`),
      pool.query("SELECT COALESCE(SUM(precio),0) AS total FROM ventas WHERE fecha>=date_trunc('month',CURRENT_DATE)")
    ]);
    res.json({
      total_ganado: parseInt(ganado.rows[0].count),
      cultivos_activos: parseInt(cultivos.rows[0].count),
      alertas_pendientes: parseInt(alertas.rows[0].count),
      vacunas_mes: parseInt(vacunas.rows[0].count),
      ventas_mes: parseFloat(ventasMes.rows[0].total),
      ganado_reciente: ganadoRec.rows,
      cultivos_recientes: cultivosRec.rows
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ============================================================
//  ENDPOINTS POR MÓDULOS CON RUTA RBAC PROTEGIDA
// ============================================================

// --- Módulo Común / Infraestructura (Admin, Productor, Encargado) ---
app.get('/api/lotes', authMiddleware, requerirRoles('admin','productor','encargado'), async (req, res) => {
  try { res.json((await pool.query('SELECT id,nombre FROM lotes WHERE activo=true ORDER BY nombre')).rows); } 
  catch (err) { res.status(500).json({ error: err.message }); }
});

// --- Módulo Pecuario (Admin, Productor, Técnico) ---
app.get('/api/ganado', authMiddleware, requerirRoles('admin','productor','tecnico'), async (req, res) => {
  try { res.json((await pool.query('SELECT g.*,l.nombre AS lote_nombre FROM ganado g LEFT JOIN lotes l ON g.lote_id=l.id ORDER BY g.fecha_registro DESC')).rows); } 
  catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/ganado', authMiddleware, requerirRoles('admin','productor','tecnico'), async (req, res) => {
  const { lote_id,numero_arete,nombre,especie,raza,sexo,fecha_nacimiento,peso_inicial,color,estado,observaciones } = req.body;
  try {
    const r = await pool.query(
      `INSERT INTO ganado (lote_id,numero_arete,nombre,especie,raza,sexo,fecha_nacimiento,peso_inicial,peso_actual,color,estado,observaciones)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING *`,
      [lote_id,numero_arete,nombre,especie,raza,sexo,fecha_nacimiento||null,peso_inicial,peso_inicial,color,estado||'activo',observaciones]
    );
    res.status(201).json(r.rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/ganado/:id', authMiddleware, requerirRoles('admin','productor','tecnico'), async (req, res) => {
  try {
    await pool.query('DELETE FROM ganado WHERE id=$1', [req.params.id]);
    res.json({ message: 'Animal eliminado con éxito.' });
  } catch (err) { res.status(500).json({ error: 'Restricción de integridad: El animal contiene bitácoras clínicas vinculadas.' }); }
});

app.get('/api/catalogo-vacunas', authMiddleware, requerirRoles('admin','productor','tecnico'), async (req, res) => {
  try { res.json((await pool.query('SELECT * FROM catalogo_vacunas WHERE activo=true ORDER BY nombre')).rows); } 
  catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/vacunaciones', authMiddleware, requerirRoles('admin','productor','tecnico'), async (req, res) => {
  try {
    // JOIN robusto tolerante a inserciones directas de texto o ID de catálogo
    res.json((await pool.query(`
      SELECT v.*, g.nombre AS ganado_nombre, g.numero_arete, COALESCE(cv.nombre, v.vacuna_nombre) AS vacuna_nombre
      FROM vacunaciones v
      JOIN ganado g ON v.ganado_id=g.id
      LEFT JOIN catalogo_vacunas cv ON v.vacuna_id=cv.id
      ORDER BY v.fecha_aplicacion DESC`)).rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/vacunaciones', authMiddleware, requerirRoles('admin','productor','tecnico'), async (req, res) => {
  const { ganado_id,vacuna_id,fecha_aplicacion,dosis_aplicada,responsable,proxima_dosis,observaciones } = req.body;
  try {
    const r = await pool.query(
      `INSERT INTO vacunaciones (ganado_id,vacuna_id,fecha_aplicacion,dosis_aplicada,responsable,proxima_dosis,observaciones,registrado_por)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,
      [ganado_id,vacuna_id||null,fecha_aplicacion,dosis_aplicada,responsable,proxima_dosis||null,observaciones,req.user.id]
    );
    res.status(201).json(r.rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/alimentacion', authMiddleware, requerirRoles('admin','productor','tecnico'), async (req, res) => {
  try { res.json((await pool.query('SELECT a.*,l.nombre AS nombre_lote FROM alimentacion a LEFT JOIN lotes l ON a.lote_id=l.id ORDER BY a.fecha DESC')).rows); } 
  catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/alimentacion', authMiddleware, requerirRoles('admin','productor','tecnico'), async (req, res) => {
  const { lote_id,tipo_alimento,cantidad_kg,costo,responsable,observaciones } = req.body;
  try {
    const r = await pool.query(
      `INSERT INTO alimentacion (lote_id,tipo_alimento,cantidad_kg,fecha,costo,responsable,observaciones,registrado_por)
       VALUES ($1,$2,$3,CURRENT_DATE,$4,$5,$6,$7) RETURNING *`,
      [lote_id,tipo_alimento,cantidad_kg,costo,responsable,observaciones||'',req.user.id]
    );
    res.status(201).json(r.rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// --- Módulo Agrícola (Admin, Productor, Encargado) ---
app.get('/api/cultivos', authMiddleware, requerirRoles('admin','productor','encargado'), async (req, res) => {
  try { res.json((await pool.query('SELECT c.*,l.nombre AS lote_nombre FROM cultivos c LEFT JOIN lotes l ON c.lote_id=l.id ORDER BY c.fecha_registro DESC')).rows); } 
  catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/cultivos', authMiddleware, requerirRoles('admin','productor','encargado'), async (req, res) => {
  const { lote_id,nombre_cultivo,variedad,fecha_siembra,fecha_estimada_cosecha,area_sembrada,cantidad_semilla_kg,observaciones } = req.body;
  try {
    const r = await pool.query(
      `INSERT INTO cultivos (lote_id,nombre_cultivo,variedad,fecha_siembra,fecha_estimada_cosecha,area_sembrada,cantidad_semilla_kg,observaciones,registrado_por)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *`,
      [lote_id,nombre_cultivo,variedad,fecha_siembra,fecha_estimada_cosecha||null,area_sembrada,cantidad_semilla_kg,observaciones,req.user.id]
    );
    res.status(201).json(r.rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/abonos', authMiddleware, requerirRoles('admin','productor','encargado'), async (req, res) => {
  try { res.json((await pool.query('SELECT a.*,c.nombre_cultivo AS cultivo_nombre FROM aplicacion_abonos a LEFT JOIN cultivos c ON a.cultivo_id=c.id ORDER BY a.fecha DESC')).rows); } 
  catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/abonos', authMiddleware, requerirRoles('admin','productor','encargado'), async (req, res) => {
  const { cultivo_id,tipo_abono,cantidad_kg,fecha,costo,metodo_aplicacion,proveedor,responsable,observaciones } = req.body;
  try {
    const r = await pool.query(
      `INSERT INTO aplicacion_abonos (cultivo_id,tipo_abono,cantidad_kg,fecha,costo,metodo_aplicacion,proveedor,responsable,observaciones,registrado_por)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *`,
      [cultivo_id,tipo_abono,cantidad_kg,fecha,costo,metodo_aplicacion,proveedor,responsable,observaciones,req.user.id]
    );
    res.status(201).json(r.rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/riegos', authMiddleware, requerirRoles('admin','productor','encargado'), async (req, res) => {
  try { res.json((await pool.query('SELECT r.*,c.nombre_cultivo AS cultivo_nombre FROM riegos r LEFT JOIN cultivos c ON r.cultivo_id=c.id ORDER BY r.fecha DESC')).rows); } 
  catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/riegos', authMiddleware, requerirRoles('admin','productor','encargado'), async (req, res) => {
  const { cultivo_id,fecha,tipo_riego,duracion_horas,litros_agua,costo,observaciones } = req.body;
  try {
    const r = await pool.query(
      `INSERT INTO riegos (cultivo_id,fecha,tipo_riego,duracion_horas,litros_agua,costo,observaciones,registrado_por)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,
      [cultivo_id,fecha,tipo_riego,duracion_horas,litros_agua,costo,observaciones,req.user.id]
    );
    res.status(201).json(r.rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// --- Módulo Comercial / Financiero (Admin, Productor) ---
app.get('/api/ventas', authMiddleware, requerirRoles('admin','productor'), async (req, res) => {
  try {
    res.json((await pool.query(`
      SELECT v.*, g.numero_arete, g.nombre AS ganado_nombre, g.especie, c.nombre_cultivo, c.variedad, u.nombre AS registrado_nombre, u.apellido AS registrado_apellido
      FROM ventas v
      LEFT JOIN ganado g ON v.ganado_id=g.id
      LEFT JOIN cultivos c ON v.cultivo_id=c.id
      LEFT JOIN usuarios u ON v.registrado_por=u.id
      ORDER BY v.fecha DESC`)).rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/ventas', authMiddleware, requerirRoles('admin','productor'), async (req, res) => {
  const { tipo, ganado_id, cultivo_id, comprador, precio, fecha, observaciones } = req.body;
  try {
    const result = await pool.query(
      `INSERT INTO ventas (tipo,ganado_id,cultivo_id,comprador,precio,fecha,observaciones,registrado_por)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,
      [tipo, ganado_id||null, cultivo_id||null, comprador, precio, fecha, observaciones||null, req.user.id]
    );
    if (tipo === 'ganado' && ganado_id) await pool.query("UPDATE ganado SET estado='vendido' WHERE id=$1", [ganado_id]);
    if (tipo === 'cultivo' && cultivo_id) await pool.query("UPDATE cultivos SET estado='cosechado',fecha_cosecha_real=$1 WHERE id=$2", [fecha, cultivo_id]);
    res.status(201).json(result.rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/stats/ventas-mensuales', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT EXTRACT(MONTH FROM fecha) as mes, SUM(precio) as total FROM ventas
      WHERE EXTRACT(YEAR FROM fecha) = EXTRACT(YEAR FROM NOW()) GROUP BY EXTRACT(MONTH FROM fecha) ORDER BY mes`);
    const mesesValores = Array(12).fill(0);
    result.rows.forEach(row => { mesesValores[parseInt(row.mes) - 1] = parseFloat(row.total); });
    res.json({ valores: mesesValores });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// --- Alertas Operativas (Globales de Sesión Abierta) ---
app.get('/api/alertas', authMiddleware, async (req, res) => {
  try { res.json((await pool.query('SELECT * FROM alertas WHERE usuario_id=$1 ORDER BY fecha_programada ASC', [req.user.id])).rows); } 
  catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/alertas', authMiddleware, async (req, res) => {
  const { tipo,titulo,descripcion,fecha_programada,ganado_id,cultivo_id,prioridad } = req.body;
  try {
    const r = await pool.query(
      `INSERT INTO alertas (usuario_id,tipo,titulo,descripcion,fecha_programada,ganado_id,cultivo_id,prioridad)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,
      [req.user.id,tipo,titulo,descripcion,fecha_programada,ganado_id||null,cultivo_id||null,prioridad||'media']
    );
    res.status(201).json(r.rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.patch('/api/alertas/:id/completar', authMiddleware, async (req, res) => {
  try { res.json((await pool.query(`UPDATE alertas SET completada=true,fecha_completada=NOW() WHERE id=$1 RETURNING *`, [req.params.id])).rows[0]); } 
  catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/alertas/:id', authMiddleware, async (req, res) => {
  try { await pool.query('DELETE FROM alertas WHERE id=$1 AND usuario_id=$2', [req.params.id, req.user.id]); res.json({ message: 'Alerta eliminada' }); } 
  catch (err) { res.status(500).json({ error: err.message }); }
});

// ============================================================
//  INICIALIZACIÓN Y PARCHADO DE LA BASE DE DATOS
// ============================================================
async function inicializarDB() {
  try {
    // Parche Estructural para Tablas Vacías e Integridad
    await pool.query(`
      ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS activo BOOLEAN DEFAULT TRUE;
      ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS ultimo_acceso TIMESTAMP WITH TIME ZONE;
      ALTER TABLE ganado ADD COLUMN IF NOT EXISTS peso_inicial DECIMAL(10,2);
      ALTER TABLE vacunaciones ADD COLUMN IF NOT EXISTS vacuna_id UUID;
      ALTER TABLE vacunaciones ADD COLUMN IF NOT EXISTS vacuna_nombre VARCHAR(150);
      
      ALTER TABLE usuarios DROP CONSTRAINT IF EXISTS usuarios_rol_check;
      ALTER TABLE usuarios ADD CONSTRAINT usuarios_rol_check CHECK (rol IN ('admin','productor','encargado','tecnico'));
    `);
    
    await pool.query(`
      CREATE TABLE IF NOT EXISTS tokens_recuperacion_v9 (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        usuario_id UUID REFERENCES usuarios(id) ON DELETE CASCADE,
        token TEXT NOT NULL,
        fecha_expiracion TIMESTAMP NOT NULL,
        usado BOOLEAN DEFAULT FALSE,
        fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
      CREATE TABLE IF NOT EXISTS ventas (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        tipo VARCHAR(20) NOT NULL CHECK (tipo IN ('ganado','cultivo')),
        ganado_id UUID REFERENCES ganado(id) ON DELETE SET NULL,
        cultivo_id UUID REFERENCES cultivos(id) ON DELETE SET NULL,
        comprador VARCHAR(200) NOT NULL,
        precio DECIMAL(12,2) NOT NULL,
        fecha DATE NOT NULL,
        observaciones TEXT,
        registrado_por UUID REFERENCES usuarios(id),
        fecha_registro TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    const hash = await bcrypt.hash('123456', 10);
    const existe = await pool.query('SELECT id FROM usuarios WHERE email=$1', ['admin@agrotech.mx']);
    if (!existe.rows.length) {
      await pool.query(`INSERT INTO usuarios (nombre,apellido,email,password_hash,rol,activo) VALUES ('Christian Dominic','Balán López','admin@agrotech.mx',$1,'admin',TRUE)`, [hash]);
      console.log('✅ [BD] Administrador Christian Dominic configurado con éxito.');
    }
    console.log('✅ [BD] Servidor v9.5 sincronizado correctamente con Render Cloud.');
  } catch (err) { console.error('❌ [BD] Error:', err.message); }
}

inicializarDB();

const PORT = process.env.PORT || 3001;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Servidor en ejecución en el puerto ${PORT}`);
});

module.exports = app;