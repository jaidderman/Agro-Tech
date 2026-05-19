// ============================================================
// AGRO-TECH — Backend Node.js + Express + PostgreSQL
// Archivo: server.js  |  Versión: 8.0 — Registro + Gestión de Roles
// ============================================================
// DEPENDENCIAS: npm install express cors pg bcrypt jsonwebtoken dotenv
// USO:          node server.js
// FRONTEND:     coloca index.html en la misma carpeta que este archivo
// TÚNEL:        cloudflared tunnel --url http://localhost:3001
// ============================================================

const path = require('path');
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();

// ==================== CORS — CLOUDFLARE COMPATIBLE ====================
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: [
    'Content-Type',
    'Authorization',
    'cf-skip-browser-warning',
    'X-Requested-With',
    'Accept',
    'Origin'
  ]
}));

app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET,POST,PUT,PATCH,DELETE,OPTIONS');
  res.header(
    'Access-Control-Allow-Headers',
    'Content-Type, Authorization, cf-skip-browser-warning, X-Requested-With, Accept, Origin'
  );
  next();
});

app.use((req, res, next) => {
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

// ==================== BODY PARSER ====================
app.use(express.json());

// ==================== ARCHIVOS ESTÁTICOS ====================
app.use(express.static(__dirname));

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// ==================== CONEXIÓN POSTGRESQL ====================
const pool = new Pool({
  host: 'localhost',
  port: 5432,
  database: 'agrotech',
  user: 'postgres',
  password: 'kakashi9ine',
  options: '-c search_path=public'
});

const JWT_SECRET = process.env.JWT_SECRET || 'agrotech_secret_key_2025';

// ==================== MIDDLEWARE AUTH ====================
const authMiddleware = async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No autorizado' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Token inválido' });
  }
};

// Middleware exclusivo para admin
const adminMiddleware = (req, res, next) => {
  if (req.user?.rol !== 'admin') {
    return res.status(403).json({ error: 'Acceso denegado. Solo administradores.' });
  }
  next();
};

// ============================================================
//  AUTH — LOGIN
// ============================================================
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await pool.query(
      'SELECT * FROM usuarios WHERE email = $1 AND activo = true',
      [email]
    );
    if (!result.rows.length)
      return res.status(401).json({ error: 'Credenciales incorrectas' });

    const user = result.rows[0];
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid)
      return res.status(401).json({ error: 'Credenciales incorrectas' });

    await pool.query('UPDATE usuarios SET ultimo_acceso = NOW() WHERE id = $1', [user.id]);

    const token = jwt.sign(
      { id: user.id, rol: user.rol, nombre: user.nombre },
      JWT_SECRET,
      { expiresIn: '8h' }
    );
    res.json({
      token,
      user: {
        id: user.id,
        nombre: user.nombre,
        apellido: user.apellido,
        email: user.email,
        rol: user.rol
      }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
//  AUTH — REGISTRO
// ============================================================
app.post('/api/auth/register', async (req, res) => {
  const { nombre, apellido, email, password } = req.body;
  if (!nombre || !apellido || !email || !password) {
    return res.status(400).json({ error: 'Todos los campos son obligatorios' });
  }
  if (password.length < 6) {
    return res.status(400).json({ error: 'La contraseña debe tener al menos 6 caracteres' });
  }
  try {
    const existe = await pool.query('SELECT id FROM usuarios WHERE email = $1', [email]);
    if (existe.rows.length > 0) {
      return res.status(409).json({ error: 'El correo ya está registrado' });
    }
    const hash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      `INSERT INTO usuarios (nombre, apellido, email, password_hash, rol, activo)
       VALUES ($1, $2, $3, $4, 'trabajador', true) RETURNING id, nombre, apellido, email, rol`,
      [nombre.trim(), apellido.trim(), email.trim().toLowerCase(), hash]
    );
    res.status(201).json({ message: 'Usuario registrado correctamente', user: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
//  USUARIOS — SOLO ADMIN
// ============================================================
app.get('/api/usuarios', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, nombre, apellido, email, rol, activo, fecha_registro, ultimo_acceso
       FROM usuarios ORDER BY fecha_registro DESC`
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.patch('/api/usuarios/:id/rol', authMiddleware, adminMiddleware, async (req, res) => {
  const { id } = req.params;
  const { rol } = req.body;
  const rolesValidos = ['admin', 'ganadero', 'veterinario', 'trabajador'];
  if (!rolesValidos.includes(rol)) {
    return res.status(400).json({ error: 'Rol inválido. Roles permitidos: ' + rolesValidos.join(', ') });
  }
  try {
    const result = await pool.query(
      'UPDATE usuarios SET rol = $1 WHERE id = $2 RETURNING id, nombre, apellido, email, rol',
      [rol, id]
    );
    if (!result.rowCount) return res.status(404).json({ error: 'Usuario no encontrado' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.patch('/api/usuarios/:id/activo', authMiddleware, adminMiddleware, async (req, res) => {
  const { id } = req.params;
  const { activo } = req.body;
  try {
    const result = await pool.query(
      'UPDATE usuarios SET activo = $1 WHERE id = $2 RETURNING id, nombre, apellido, email, rol, activo',
      [activo, id]
    );
    if (!result.rowCount) return res.status(404).json({ error: 'Usuario no encontrado' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
//  DASHBOARD STATS
// ============================================================
app.get('/api/dashboard/stats', authMiddleware, async (req, res) => {
  try {
    const [ganado, cultivos, alertas, vacunas, ganadoReciente, cultivosRecientes] =
      await Promise.all([
        pool.query("SELECT COUNT(*) FROM ganado WHERE estado = 'activo'"),
        pool.query("SELECT COUNT(*) FROM cultivos WHERE estado NOT IN ('cosechado','perdido')"),
        pool.query("SELECT COUNT(*) FROM alertas WHERE completada = false AND fecha_programada <= CURRENT_DATE + 7"),
        pool.query("SELECT COUNT(*) FROM vacunaciones WHERE fecha_aplicacion >= CURRENT_DATE - 30"),
        pool.query(`
          SELECT g.id, g.numero_arete, g.nombre, g.especie, g.raza, g.sexo,
                 g.peso_inicial, g.peso_actual, g.estado, l.nombre AS lote_nombre
          FROM ganado g
          LEFT JOIN lotes l ON g.lote_id = l.id
          ORDER BY g.fecha_registro DESC LIMIT 5
        `),
        pool.query(`
          SELECT c.id, c.nombre_cultivo, c.variedad, c.fecha_siembra,
                 c.fecha_estimada_cosecha, c.estado, l.nombre AS lote_nombre
          FROM cultivos c
          LEFT JOIN lotes l ON c.lote_id = l.id
          WHERE c.estado NOT IN ('cosechado','perdido')
          ORDER BY c.fecha_registro DESC LIMIT 5
        `)
      ]);

    res.json({
      total_ganado: parseInt(ganado.rows[0].count),
      cultivos_activos: parseInt(cultivos.rows[0].count),
      alertas_pendientes: parseInt(alertas.rows[0].count),
      vacunas_mes: parseInt(vacunas.rows[0].count),
      ganado_reciente: ganadoReciente.rows,
      cultivos_recientes: cultivosRecientes.rows
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
//  LOTES
// ============================================================
app.get('/api/lotes', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, nombre FROM lotes WHERE activo = true ORDER BY nombre'
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
//  GANADO
// ============================================================
app.get('/api/ganado', authMiddleware, async (req, res) => {
  try {
    const { estado, lote_id } = req.query;
    let query = `SELECT g.*, l.nombre AS lote_nombre FROM ganado g LEFT JOIN lotes l ON g.lote_id = l.id WHERE 1=1`;
    const params = [];
    if (estado) { params.push(estado); query += ` AND g.estado = $${params.length}`; }
    if (lote_id) { params.push(lote_id); query += ` AND g.lote_id = $${params.length}`; }
    query += ' ORDER BY g.fecha_registro DESC';
    res.json((await pool.query(query, params)).rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/ganado', authMiddleware, async (req, res) => {
  const { lote_id, numero_arete, nombre, especie, raza, sexo,
    fecha_nacimiento, peso_inicial, color, estado, observaciones } = req.body;
  try {
    const result = await pool.query(
      `INSERT INTO ganado
         (lote_id, numero_arete, nombre, especie, raza, sexo, fecha_nacimiento,
          peso_inicial, peso_actual, color, estado, observaciones)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING *`,
      [lote_id, numero_arete, nombre, especie, raza, sexo,
        fecha_nacimiento || null, peso_inicial, peso_inicial,
        color, estado || 'activo', observaciones]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/ganado/:id', authMiddleware, async (req, res) => {
  const { id } = req.params;
  const { numero_arete, nombre, raza, sexo, peso_actual, peso_inicial,
    color, estado, observaciones, fecha_nacimiento, lote_id, especie } = req.body;
  try {
    const result = await pool.query(
      `UPDATE ganado
       SET numero_arete=$1, nombre=$2, raza=$3, sexo=$4, peso_actual=$5,
           color=$6, estado=$7, observaciones=$8, fecha_nacimiento=$9,
           lote_id=$10, especie=$11,
           peso_inicial = COALESCE($12, peso_inicial)
       WHERE id=$13 RETURNING *`,
      [numero_arete, nombre, raza, sexo, peso_actual,
        color, estado || 'activo', observaciones,
        fecha_nacimiento || null, lote_id, especie,
        peso_inicial || null, id]
    );
    if (!result.rowCount) return res.status(404).json({ error: 'Animal no encontrado' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/ganado/:id', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query('DELETE FROM ganado WHERE id=$1', [req.params.id]);
    if (!result.rowCount) return res.status(404).json({ error: 'El animal no existe' });
    res.json({ message: 'Animal eliminado permanentemente' });
  } catch (err) {
    res.status(500).json({
      error: 'No se puede eliminar: el animal tiene historial de vacunas o alimentación vinculado. Primero elimina su historial.'
    });
  }
});

// ============================================================
//  CATÁLOGO DE VACUNAS
// ============================================================
app.get('/api/catalogo-vacunas', authMiddleware, async (req, res) => {
  try {
    res.json(
      (await pool.query('SELECT * FROM catalogo_vacunas WHERE activo = true ORDER BY nombre')).rows
    );
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
//  VACUNACIONES
// ============================================================
app.get('/api/vacunaciones', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT v.*, g.nombre AS ganado_nombre, g.numero_arete, cv.nombre AS vacuna_nombre
      FROM vacunaciones v
      JOIN ganado g ON v.ganado_id = g.id
      JOIN catalogo_vacunas cv ON v.vacuna_id = cv.id
      ORDER BY v.fecha_aplicacion DESC LIMIT 100
    `);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/vacunaciones', authMiddleware, async (req, res) => {
  const { ganado_id, vacuna_id, fecha_aplicacion, dosis_aplicada,
    responsable, proxima_dosis, observaciones } = req.body;
  try {
    const result = await pool.query(
      `INSERT INTO vacunaciones
         (ganado_id, vacuna_id, fecha_aplicacion, dosis_aplicada,
          responsable, proxima_dosis, observaciones, registrado_por)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,
      [ganado_id, vacuna_id, fecha_aplicacion, dosis_aplicada,
        responsable, proxima_dosis, observaciones, req.user.id]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/vacunaciones/:id', authMiddleware, async (req, res) => {
  const { id } = req.params;
  const { fecha_aplicacion, dosis_aplicada, responsable, proxima_dosis, observaciones } = req.body;
  try {
    const result = await pool.query(
      `UPDATE vacunaciones
       SET fecha_aplicacion=$1, dosis_aplicada=$2, responsable=$3,
           proxima_dosis=$4, observaciones=$5
       WHERE id=$6 RETURNING *`,
      [fecha_aplicacion, dosis_aplicada, responsable, proxima_dosis || null, observaciones, id]
    );
    if (!result.rowCount) return res.status(404).json({ error: 'Vacunación no encontrada' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/vacunaciones/:id', authMiddleware, async (req, res) => {
  try {
    await pool.query('DELETE FROM vacunaciones WHERE id=$1', [req.params.id]);
    res.json({ message: 'Vacunación eliminada' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
//  CULTIVOS
// ============================================================
app.get('/api/cultivos', authMiddleware, async (req, res) => {
  try {
    res.json(
      (await pool.query(
        `SELECT c.*, l.nombre AS lote_nombre
         FROM cultivos c LEFT JOIN lotes l ON c.lote_id = l.id
         ORDER BY c.fecha_registro DESC`
      )).rows
    );
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/cultivos', authMiddleware, async (req, res) => {
  const { lote_id, nombre_cultivo, variedad, fecha_siembra,
    fecha_estimada_cosecha, area_sembrada, cantidad_semilla_kg, observaciones } = req.body;
  try {
    const result = await pool.query(
      `INSERT INTO cultivos
         (lote_id, nombre_cultivo, variedad, fecha_siembra, fecha_estimada_cosecha,
          area_sembrada, cantidad_semilla_kg, observaciones, registrado_por)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *`,
      [lote_id, nombre_cultivo, variedad, fecha_siembra,
        fecha_estimada_cosecha, area_sembrada, cantidad_semilla_kg, observaciones, req.user.id]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/cultivos/:id', authMiddleware, async (req, res) => {
  const { id } = req.params;
  const { estado, fecha_cosecha_real, rendimiento_ton, observaciones,
    nombre_cultivo, variedad, lote_id, area_sembrada,
    fecha_siembra, fecha_estimada_cosecha } = req.body;
  try {
    const result = await pool.query(
      `UPDATE cultivos
       SET estado=$1, fecha_cosecha_real=$2, rendimiento_ton=$3, observaciones=$4,
           nombre_cultivo        = COALESCE($5,  nombre_cultivo),
           variedad              = COALESCE($6,  variedad),
           lote_id               = COALESCE($7,  lote_id),
           area_sembrada         = COALESCE($8,  area_sembrada),
           fecha_siembra         = COALESCE($9,  fecha_siembra),
           fecha_estimada_cosecha= COALESCE($10, fecha_estimada_cosecha)
       WHERE id=$11 RETURNING *`,
      [estado, fecha_cosecha_real || null, rendimiento_ton || null, observaciones,
        nombre_cultivo || null, variedad || null, lote_id || null,
        area_sembrada || null, fecha_siembra || null, fecha_estimada_cosecha || null, id]
    );
    if (!result.rowCount) return res.status(404).json({ error: 'Cultivo no encontrado' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/cultivos/:id', authMiddleware, async (req, res) => {
  try {
    await pool.query('DELETE FROM cultivos WHERE id=$1', [req.params.id]);
    res.json({ message: 'Cultivo eliminado' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
//  ALERTAS
// ============================================================
app.get('/api/alertas', authMiddleware, async (req, res) => {
  try {
    res.json(
      (await pool.query(
        'SELECT * FROM alertas WHERE usuario_id=$1 ORDER BY fecha_programada ASC',
        [req.user.id]
      )).rows
    );
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/alertas', authMiddleware, async (req, res) => {
  const { tipo, titulo, descripcion, fecha_programada,
    ganado_id, cultivo_id, prioridad } = req.body;
  try {
    const result = await pool.query(
      `INSERT INTO alertas
         (usuario_id, tipo, titulo, descripcion, fecha_programada,
          ganado_id, cultivo_id, prioridad)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,
      [req.user.id, tipo, titulo, descripcion, fecha_programada,
        ganado_id || null, cultivo_id || null, prioridad || 'media']
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/alertas/:id', authMiddleware, async (req, res) => {
  const { id } = req.params;
  const { tipo, titulo, descripcion, fecha_programada,
    ganado_id, cultivo_id, prioridad } = req.body;
  try {
    const result = await pool.query(
      `UPDATE alertas
       SET tipo=$1, titulo=$2, descripcion=$3, fecha_programada=$4,
           ganado_id=$5, cultivo_id=$6, prioridad=$7
       WHERE id=$8 AND usuario_id=$9 RETURNING *`,
      [tipo, titulo, descripcion, fecha_programada,
        ganado_id || null, cultivo_id || null, prioridad || 'media',
        id, req.user.id]
    );
    if (!result.rowCount) return res.status(404).json({ error: 'Alerta no encontrada' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.patch('/api/alertas/:id/completar', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      `UPDATE alertas SET completada=true, fecha_completada=NOW()
       WHERE id=$1 RETURNING *`,
      [req.params.id]
    );
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/alertas/:id', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      'DELETE FROM alertas WHERE id=$1 AND usuario_id=$2',
      [req.params.id, req.user.id]
    );
    if (!result.rowCount)
      return res.status(404).json({ error: 'Alerta no encontrada o sin permiso' });
    res.json({ message: 'Alerta eliminada' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
//  ALIMENTACIÓN
// ============================================================
app.get('/api/alimentacion', authMiddleware, async (req, res) => {
  try {
    res.json(
      (await pool.query(`
        SELECT a.*, l.nombre AS nombre_lote
        FROM alimentacion a LEFT JOIN lotes l ON a.lote_id = l.id
        ORDER BY a.fecha DESC
      `)).rows
    );
  } catch (err) {
    res.status(500).json({ error: 'Error al obtener datos: ' + err.message });
  }
});

app.post('/api/alimentacion', authMiddleware, async (req, res) => {
  const { lote_id, tipo_alimento, cantidad_kg, costo, responsable, observaciones } = req.body;
  try {
    const result = await pool.query(
      `INSERT INTO alimentacion
         (lote_id, tipo_alimento, cantidad_kg, fecha, costo, responsable, observaciones, registrado_por)
       VALUES ($1,$2,$3,CURRENT_DATE,$4,$5,$6,$7) RETURNING *`,
      [lote_id, tipo_alimento, cantidad_kg, costo, responsable, observaciones || '', req.user.id]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Error al guardar: ' + err.message });
  }
});

app.put('/api/alimentacion/:id', authMiddleware, async (req, res) => {
  const { id } = req.params;
  const { tipo_alimento, cantidad_kg, costo, responsable } = req.body;
  try {
    const result = await pool.query(
      `UPDATE alimentacion
       SET tipo_alimento=$1, cantidad_kg=$2, costo=$3, responsable=$4
       WHERE id=$5 RETURNING *`,
      [tipo_alimento, cantidad_kg, costo, responsable, id]
    );
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/alimentacion/:id', authMiddleware, async (req, res) => {
  try {
    await pool.query('DELETE FROM alimentacion WHERE id=$1', [req.params.id]);
    res.json({ message: 'Registro eliminado' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
//  ABONOS
// ============================================================
app.get('/api/abonos', authMiddleware, async (req, res) => {
  try {
    res.json(
      (await pool.query(`
        SELECT a.*, c.nombre_cultivo AS cultivo_nombre
        FROM aplicacion_abonos a LEFT JOIN cultivos c ON a.cultivo_id = c.id
        ORDER BY a.fecha DESC
      `)).rows
    );
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/abonos', authMiddleware, async (req, res) => {
  const { cultivo_id, tipo_abono, cantidad_kg, fecha, costo,
    metodo_aplicacion, proveedor, responsable, observaciones } = req.body;
  try {
    const result = await pool.query(
      `INSERT INTO aplicacion_abonos
         (cultivo_id, tipo_abono, cantidad_kg, fecha, costo,
          metodo_aplicacion, proveedor, responsable, observaciones, registrado_por)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *`,
      [cultivo_id, tipo_abono, cantidad_kg, fecha, costo,
        metodo_aplicacion, proveedor, responsable, observaciones, req.user.id]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/abonos/:id', authMiddleware, async (req, res) => {
  const { id } = req.params;
  const { tipo_abono, cantidad_kg, fecha, costo,
    metodo_aplicacion, responsable, observaciones } = req.body;
  try {
    const result = await pool.query(
      `UPDATE aplicacion_abonos
       SET tipo_abono=$1, cantidad_kg=$2, fecha=$3, costo=$4,
           metodo_aplicacion=$5, responsable=$6, observaciones=$7
       WHERE id=$8 RETURNING *`,
      [tipo_abono, cantidad_kg, fecha, costo,
        metodo_aplicacion, responsable, observaciones, id]
    );
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/abonos/:id', authMiddleware, async (req, res) => {
  try {
    await pool.query('DELETE FROM aplicacion_abonos WHERE id=$1', [req.params.id]);
    res.json({ message: 'Abono eliminado' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
//  RIEGOS
// ============================================================
app.get('/api/riegos', authMiddleware, async (req, res) => {
  try {
    res.json(
      (await pool.query(`
        SELECT r.*, c.nombre_cultivo AS cultivo_nombre
        FROM riegos r LEFT JOIN cultivos c ON r.cultivo_id = c.id
        ORDER BY r.fecha DESC
      `)).rows
    );
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/riegos', authMiddleware, async (req, res) => {
  const { cultivo_id, fecha, tipo_riego, duracion_horas,
    litros_agua, costo, observaciones } = req.body;
  try {
    const result = await pool.query(
      `INSERT INTO riegos
         (cultivo_id, fecha, tipo_riego, duracion_horas,
          litros_agua, costo, observaciones, registrado_por)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,
      [cultivo_id, fecha, tipo_riego, duracion_horas,
        litros_agua, costo, observaciones, req.user.id]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/riegos/:id', authMiddleware, async (req, res) => {
  const { id } = req.params;
  const { tipo_riego, fecha, duracion_horas, litros_agua, costo, observaciones } = req.body;
  try {
    const result = await pool.query(
      `UPDATE riegos
       SET tipo_riego=$1, fecha=$2, duracion_horas=$3,
           litros_agua=$4, costo=$5, observaciones=$6
       WHERE id=$7 RETURNING *`,
      [tipo_riego, fecha, duracion_horas, litros_agua, costo, observaciones, id]
    );
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/riegos/:id', authMiddleware, async (req, res) => {
  try {
    await pool.query('DELETE FROM riegos WHERE id=$1', [req.params.id]);
    res.json({ message: 'Riego eliminado' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
//  INICIALIZACIÓN DE BD
// ============================================================
async function inicializarDB() {
  try {
    // Asegurar columnas necesarias
    await pool.query(`
      ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS activo BOOLEAN DEFAULT TRUE;
      ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS ultimo_acceso TIMESTAMP WITH TIME ZONE;
    `);

    // Actualizar CHECK constraint de roles para incluir nuevos roles
    await pool.query(`
      ALTER TABLE usuarios DROP CONSTRAINT IF EXISTS usuarios_rol_check;
      ALTER TABLE usuarios ADD CONSTRAINT usuarios_rol_check
        CHECK (rol IN ('admin', 'ganadero', 'veterinario', 'trabajador', 'productor', 'encargado', 'tecnico'));
    `);

    const hash = await bcrypt.hash('123456', 10);
    const existe = await pool.query('SELECT id FROM usuarios WHERE email = $1', ['admin@agrotech.mx']);

    if (existe.rows.length === 0) {
      await pool.query(
        `INSERT INTO usuarios (nombre, apellido, email, password_hash, rol, activo)
         VALUES ('Admin', 'Agro-Tech', 'admin@agrotech.mx', $1, 'admin', TRUE)`,
        [hash]
      );
      console.log('✅ [BD] Admin creado — email: admin@agrotech.mx | contraseña: 123456');
    } else {
      console.log('✅ [BD] Admin ya existe, sin cambios.');
    }

    console.log('✅ [BD] Base de datos verificada y lista.');
  } catch (err) {
    console.error('❌ [BD] Error en inicialización:', err.message);
  }
}

inicializarDB();

// ============================================================
//  ARRANQUE DEL SERVIDOR
// ============================================================
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log('');
  console.log('🌱 ========================================');
  console.log(`🌱  Agro-Tech corriendo en :${PORT}`);
  console.log(`🌱  Frontend → http://localhost:${PORT}`);
  console.log(`🌱  API Base → http://localhost:${PORT}/api`);
  console.log('🌱 ========================================');
  console.log('');
});

module.exports = app;
