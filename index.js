const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');

const app = express();
app.use(cors());
app.use(express.json({ limit: '50mb' }));

const dbConfig = {
  host: 'srv469.hstgr.io',
  user: 'u951308636_diego_leon',
  password: 'Le0n2018#',
  database: 'u951308636_factu_facil',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
};

const pool = mysql.createPool(dbConfig);
const JWT_SECRET = 'factufacil_secret_key_2024_muy_segura';

const esActivo = (estado) => estado && estado.toLowerCase() === 'activo';

const verificarToken = (req, res, next) => {
  const token = req.headers['authorization']?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ success: false, mensaje: 'Token requerido' });
  try {
    req.usuario = jwt.verify(token, JWT_SECRET);
    next();
  } catch (error) {
    return res.status(401).json({ success: false, mensaje: 'Token inválido' });
  }
};

// Health Check
app.get('/', (req, res) => {
  res.json({ status: 'ok', mensaje: 'FactuFácil API v2.0', version: '2.0.0' });
});

// Setup inicial
app.post('/api/setup/usuario-empresa', async (req, res) => {
  try {
    const { empresaId, usuario, nombre, email, password, permisos, admin } = req.body;
    const [empresas] = await pool.query('SELECT id FROM empresas WHERE codigo = ?', [empresaId]);
    if (empresas.length === 0) return res.status(400).json({ success: false, mensaje: 'Empresa no encontrada' });
    
    const [existe] = await pool.query('SELECT id FROM usuarios_empresa WHERE usuario = ?', [usuario]);
    if (existe.length > 0) {
      const passwordHash = await bcrypt.hash(password, 10);
      await pool.query('UPDATE usuarios_empresa SET password = ? WHERE usuario = ?', [passwordHash, usuario]);
      return res.json({ success: true, mensaje: 'Password actualizado' });
    }
    
    const passwordHash = await bcrypt.hash(password, 10);
    await pool.query(`INSERT INTO usuarios_empresa (empresa_id, usuario, password, nombre, email, permisos, estado, admin) VALUES (?, ?, ?, ?, ?, ?, 'Activo', ?)`,
      [empresas[0].id, usuario, passwordHash, nombre, email, permisos || 'gestionar', admin === 'Si' ? 1 : 0]);
    res.json({ success: true, mensaje: 'Usuario creado correctamente' });
  } catch (error) {
    res.status(500).json({ success: false, mensaje: error.message });
  }
});

// Catálogos
app.get('/api/catalogos', async (req, res) => {
  try {
    const [regimenes] = await pool.query('SELECT clave, descripcion FROM cat_regimen ORDER BY clave');
    const [usosCfdi] = await pool.query('SELECT clave, descripcion FROM cat_uso_cfdi ORDER BY clave');
    const [empresas] = await pool.query(`SELECT id, codigo, nombre FROM empresas WHERE LOWER(estatus) = 'activo' ORDER BY nombre`);
    res.json({
      success: true,
      regimenes,
      usosCfdi,
      empresas: empresas.map(e => ({ id: e.codigo, nombre: e.nombre }))
    });
  } catch (error) {
    res.status(500).json({ success: false, mensaje: 'Error al obtener catálogos' });
  }
});

// Login Cliente
app.post('/api/auth/login-usuario', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ success: false, mensaje: 'Email y contraseña requeridos' });
    
    const [usuarios] = await pool.query('SELECT * FROM usuarios WHERE email = ?', [email.toLowerCase()]);
    if (usuarios.length === 0) return res.status(401).json({ success: false, mensaje: 'Credenciales inválidas' });
    
    const usuario = usuarios[0];
    const passwordValido = await bcrypt.compare(password, usuario.password);
    if (!passwordValido) return res.status(401).json({ success: false, mensaje: 'Credenciales inválidas' });
    
    // Obtener razones sociales del cliente
    const [razones] = await pool.query('SELECT * FROM clientes_razones WHERE usuario_id = ?', [usuario.id]);
    
    const token = jwt.sign({ id: usuario.id, uuid: usuario.uuid, email: usuario.email, tipo: 'cliente' }, JWT_SECRET, { expiresIn: '7d' });
    
    res.json({
      success: true,
      tipo: 'cliente',
      token,
      usuario: {
        id: usuario.id,
        uuid: usuario.uuid,
        nombre: usuario.nombre,
        email: usuario.email,
        csf: usuario.csf
      },
      razones: razones.map(r => ({
        id: r.id,
        rfc: r.rfc,
        razon: r.razon,
        regimen: r.regimen,
        cp: r.cp,
        uso_cfdi: r.uso_cfdi,
        csf: r.csf,
        predeterminada: r.predeterminada
      }))
    });
  } catch (error) {
    res.status(500).json({ success: false, mensaje: 'Error del servidor' });
  }
});

// Login Empresa
app.post('/api/auth/login-empresa', async (req, res) => {
  try {
    const { usuario, password } = req.body;
    if (!usuario || !password) return res.status(400).json({ success: false, mensaje: 'Usuario y contraseña requeridos' });
    
    const [usuarios] = await pool.query(`
      SELECT ue.*, e.nombre as empresa_nombre, e.codigo as empresa_codigo
      FROM usuarios_empresa ue
      JOIN empresas e ON ue.empresa_id = e.id
      WHERE ue.usuario = ? AND LOWER(e.estatus) = 'activo'
    `, [usuario]);
    
    if (usuarios.length === 0) return res.status(401).json({ success: false, mensaje: 'Usuario no encontrado' });
    
    const user = usuarios[0];
    if (!esActivo(user.estado)) return res.status(401).json({ success: false, mensaje: 'Usuario inactivo' });
    
    const passwordValido = await bcrypt.compare(password, user.password);
    if (!passwordValido) return res.status(401).json({ success: false, mensaje: 'Contraseña incorrecta' });
    
    const token = jwt.sign({
      id: user.id, empresaId: user.empresa_id, usuario: user.usuario,
      tipo: 'empresa', permisos: user.permisos, admin: user.admin
    }, JWT_SECRET, { expiresIn: '7d' });
    
    res.json({
      success: true, tipo: 'empresa', token,
      empresaId: user.empresa_id,
      empresaNombre: user.empresa_nombre,
      empresaAlias: user.empresa_codigo,
      usuario: user.usuario,
      permisos: user.permisos,
      admin: user.admin ? true : false
    });
  } catch (error) {
    res.status(500).json({ success: false, mensaje: 'Error del servidor' });
  }
});

// Registro Cliente
app.post('/api/auth/registro', async (req, res) => {
  try {
    const { nombre, email, password, rfc, razon, regimen, cp, uso_cfdi, csf } = req.body;
    
    if (!email || !password || !rfc || !razon) {
      return res.status(400).json({ success: false, mensaje: 'Campos obligatorios faltantes' });
    }
    
    // Verificar email duplicado
    const [existeEmail] = await pool.query('SELECT id FROM usuarios WHERE email = ?', [email.toLowerCase()]);
    if (existeEmail.length > 0) {
      return res.status(400).json({ success: false, mensaje: 'Este correo ya está registrado' });
    }
    
    // Verificar RFC duplicado en razones
    const [existeRfc] = await pool.query('SELECT id FROM clientes_razones WHERE rfc = ?', [rfc.toUpperCase()]);
    if (existeRfc.length > 0) {
      return res.status(400).json({ success: false, mensaje: 'Este RFC ya está registrado' });
    }
    
    const uuid = uuidv4();
    const passwordHash = await bcrypt.hash(password, 10);
    
    // Crear usuario
    const [resultado] = await pool.query(`
      INSERT INTO usuarios (uuid, nombre, email, password, csf)
      VALUES (?, ?, ?, ?, ?)
    `, [uuid, nombre, email.toLowerCase(), passwordHash, csf || null]);
    
    const usuarioId = resultado.insertId;
    
    // Crear primera razón social
    await pool.query(`
      INSERT INTO clientes_razones (usuario_id, rfc, razon, regimen, cp, uso_cfdi, csf, predeterminada)
      VALUES (?, ?, ?, ?, ?, ?, ?, 1)
    `, [usuarioId, rfc.toUpperCase(), razon, regimen, cp, uso_cfdi, csf || null]);
    
    res.json({ success: true, mensaje: 'Cuenta creada correctamente' });
  } catch (error) {
    console.error('Error registro:', error);
    res.status(500).json({ success: false, mensaje: 'Error del servidor' });
  }
});

// Obtener razones sociales del cliente
app.get('/api/clientes/razones', verificarToken, async (req, res) => {
  try {
    const [razones] = await pool.query('SELECT * FROM clientes_razones WHERE usuario_id = ?', [req.usuario.id]);
    res.json({ success: true, razones });
  } catch (error) {
    res.status(500).json({ success: false, mensaje: 'Error del servidor' });
  }
});

// Agregar razón social
app.post('/api/clientes/razones', verificarToken, async (req, res) => {
  try {
    const { rfc, razon, regimen, cp, uso_cfdi, csf } = req.body;
    
    // Verificar RFC duplicado
    const [existeRfc] = await pool.query('SELECT id FROM clientes_razones WHERE rfc = ?', [rfc.toUpperCase()]);
    if (existeRfc.length > 0) {
      return res.status(400).json({ success: false, mensaje: 'Este RFC ya está registrado' });
    }
    
    await pool.query(`
      INSERT INTO clientes_razones (usuario_id, rfc, razon, regimen, cp, uso_cfdi, csf, predeterminada)
      VALUES (?, ?, ?, ?, ?, ?, ?, 0)
    `, [req.usuario.id, rfc.toUpperCase(), razon, regimen, cp, uso_cfdi, csf || null]);
    
    res.json({ success: true, mensaje: 'Razón social agregada' });
  } catch (error) {
    res.status(500).json({ success: false, mensaje: 'Error del servidor' });
  }
});

// Actualizar razón social
app.put('/api/clientes/razones/:id', verificarToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { rfc, razon, regimen, cp, uso_cfdi, csf } = req.body;
    
    await pool.query(`
      UPDATE clientes_razones SET rfc = ?, razon = ?, regimen = ?, cp = ?, uso_cfdi = ?, csf = ?
      WHERE id = ? AND usuario_id = ?
    `, [rfc.toUpperCase(), razon, regimen, cp, uso_cfdi, csf, id, req.usuario.id]);
    
    res.json({ success: true, mensaje: 'Razón social actualizada' });
  } catch (error) {
    res.status(500).json({ success: false, mensaje: 'Error del servidor' });
  }
});

// Eliminar razón social
app.delete('/api/clientes/razones/:id', verificarToken, async (req, res) => {
  try {
    const { id } = req.params;
    
    // Verificar que no sea la única
    const [count] = await pool.query('SELECT COUNT(*) as total FROM clientes_razones WHERE usuario_id = ?', [req.usuario.id]);
    if (count[0].total <= 1) {
      return res.status(400).json({ success: false, mensaje: 'Debes tener al menos una razón social' });
    }
    
    await pool.query('DELETE FROM clientes_razones WHERE id = ? AND usuario_id = ?', [id, req.usuario.id]);
    res.json({ success: true, mensaje: 'Razón social eliminada' });
  } catch (error) {
    res.status(500).json({ success: false, mensaje: 'Error del servidor' });
  }
});

// Establecer razón predeterminada
app.put('/api/clientes/razones/:id/predeterminada', verificarToken, async (req, res) => {
  try {
    const { id } = req.params;
    await pool.query('UPDATE clientes_razones SET predeterminada = 0 WHERE usuario_id = ?', [req.usuario.id]);
    await pool.query('UPDATE clientes_razones SET predeterminada = 1 WHERE id = ? AND usuario_id = ?', [id, req.usuario.id]);
    res.json({ success: true, mensaje: 'Razón predeterminada actualizada' });
  } catch (error) {
    res.status(500).json({ success: false, mensaje: 'Error del servidor' });
  }
});

// Actualizar perfil cliente
app.put('/api/clientes/perfil', verificarToken, async (req, res) => {
  try {
    const { nombre, password, csf } = req.body;
    
    let query = 'UPDATE usuarios SET nombre = ?';
    let params = [nombre];
    
    if (csf) {
      query += ', csf = ?';
      params.push(csf);
    }
    
    if (password && password.trim() !== '') {
      const passwordHash = await bcrypt.hash(password, 10);
      query += ', password = ?';
      params.push(passwordHash);
    }
    
    query += ' WHERE id = ?';
    params.push(req.usuario.id);
    
    await pool.query(query, params);
    
    const [usuarios] = await pool.query('SELECT * FROM usuarios WHERE id = ?', [req.usuario.id]);
    const [razones] = await pool.query('SELECT * FROM clientes_razones WHERE usuario_id = ?', [req.usuario.id]);
    
    res.json({
      success: true,
      mensaje: 'Perfil actualizado',
      usuario: {
        id: usuarios[0].id,
        nombre: usuarios[0].nombre,
        email: usuarios[0].email,
        csf: usuarios[0].csf
      },
      razones
    });
  } catch (error) {
    res.status(500).json({ success: false, mensaje: 'Error del servidor' });
  }
});

// Dashboard cliente
app.get('/api/clientes/dashboard', verificarToken, async (req, res) => {
  try {
    const [razones] = await pool.query('SELECT id FROM clientes_razones WHERE usuario_id = ?', [req.usuario.id]);
    const razonIds = razones.map(r => r.id);
    
    if (razonIds.length === 0) {
      return res.json({
        success: true,
        stats: { total: 0, pendientes: 0, facturadas: 0, rechazadas: 0 },
        ultimas: []
      });
    }
    
    const [stats] = await pool.query(`
      SELECT 
        COUNT(*) as total,
        SUM(CASE WHEN estatus = 'Pendiente' THEN 1 ELSE 0 END) as pendientes,
        SUM(CASE WHEN estatus = 'Facturado' THEN 1 ELSE 0 END) as facturadas,
        SUM(CASE WHEN estatus = 'Rechazado' THEN 1 ELSE 0 END) as rechazadas
      FROM solicitudes 
      WHERE razon_id IN (?)
    `, [razonIds]);
    
    const [ultimas] = await pool.query(`
      SELECT s.*, e.nombre as tienda, cr.rfc, cr.razon
      FROM solicitudes s
      JOIN empresas e ON s.empresa_id = e.id
      JOIN clientes_razones cr ON s.razon_id = cr.id
      WHERE s.razon_id IN (?)
      ORDER BY s.fecha DESC
      LIMIT 5
    `, [razonIds]);
    
    res.json({
      success: true,
      stats: stats[0],
      ultimas: ultimas.map(s => ({
        id: s.uuid,
        fecha: s.fecha,
        tienda: s.tienda,
        rfc: s.rfc,
        razon: s.razon,
        monto: s.monto,
        estatus: s.estatus
      }))
    });
  } catch (error) {
    res.status(500).json({ success: false, mensaje: 'Error del servidor' });
  }
});

// Buscar RFC
app.get('/api/rfc/:rfc', async (req, res) => {
  try {
    const rfc = req.params.rfc.toUpperCase();
    
    const [razones] = await pool.query('SELECT * FROM clientes_razones WHERE rfc = ?', [rfc]);
    if (razones.length > 0) {
      const r = razones[0];
      return res.json({
        success: true,
        datos: { razon: r.razon, regimen: r.regimen, cp: r.cp, uso_cfdi: r.uso_cfdi, csf: r.csf }
      });
    }
    
    const [solicitudes] = await pool.query('SELECT * FROM solicitudes WHERE rfc = ? ORDER BY fecha DESC LIMIT 1', [rfc]);
    if (solicitudes.length > 0) {
      const s = solicitudes[0];
      return res.json({
        success: true,
        datos: { razon: s.razon, regimen: s.regimen, cp: s.cp, uso_cfdi: s.uso_cfdi }
      });
    }
    
    res.json({ success: false, mensaje: 'RFC no encontrado' });
  } catch (error) {
    res.status(500).json({ success: false, mensaje: 'Error del servidor' });
  }
});

// Crear Solicitud
app.post('/api/solicitudes', async (req, res) => {
  try {
    const { empresa_id, razon_id, rfc, razon, regimen, cp, uso_cfdi, email, monto, folio, notas, ticket, csf } = req.body;
    
    if (!empresa_id || !rfc || !razon || !email) {
      return res.status(400).json({ success: false, mensaje: 'Campos obligatorios faltantes' });
    }
    
    const [empresas] = await pool.query('SELECT id FROM empresas WHERE codigo = ?', [empresa_id]);
    if (empresas.length === 0) {
      return res.status(400).json({ success: false, mensaje: 'Empresa no encontrada' });
    }
    
    const uuid = uuidv4();
    
    await pool.query(`
      INSERT INTO solicitudes (uuid, empresa_id, razon_id, rfc, razon, regimen, cp, uso_cfdi, email, monto, folio, notas, ticket, csf, estatus)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Pendiente')
    `, [uuid, empresas[0].id, razon_id || null, rfc.toUpperCase(), razon, regimen, cp, uso_cfdi, email.toLowerCase(), monto || null, folio, notas, ticket, csf]);
    
    res.json({ success: true, mensaje: 'Solicitud creada correctamente', uuid });
  } catch (error) {
    res.status(500).json({ success: false, mensaje: 'Error del servidor' });
  }
});

// Solicitudes de empresa
app.get('/api/solicitudes/empresa/:empresaId', verificarToken, async (req, res) => {
  try {
    let empresaIdNum = req.params.empresaId;
    if (isNaN(empresaIdNum)) {
      const [empresas] = await pool.query('SELECT id FROM empresas WHERE codigo = ?', [empresaIdNum]);
      if (empresas.length === 0) return res.status(404).json({ success: false, mensaje: 'Empresa no encontrada' });
      empresaIdNum = empresas[0].id;
    }
    
    const [solicitudes] = await pool.query(`
      SELECT s.*, e.nombre as tienda
      FROM solicitudes s
      JOIN empresas e ON s.empresa_id = e.id
      WHERE s.empresa_id = ?
      ORDER BY s.fecha DESC
    `, [empresaIdNum]);
    
    res.json(solicitudes.map(s => ({
      id: s.uuid, fecha: s.fecha, rfc: s.rfc, razon: s.razon, regimen: s.regimen,
      cp: s.cp, uso_cfdi: s.uso_cfdi, email: s.email, monto: s.monto, folio: s.folio,
      notas: s.notas, ticket: s.ticket, csf: s.csf, estatus: s.estatus, tienda: s.tienda
    })));
  } catch (error) {
    res.status(500).json({ success: false, mensaje: 'Error del servidor' });
  }
});

// Mis solicitudes (cliente)
app.get('/api/solicitudes/mis', verificarToken, async (req, res) => {
  try {
    const [razones] = await pool.query('SELECT id FROM clientes_razones WHERE usuario_id = ?', [req.usuario.id]);
    const razonIds = razones.map(r => r.id);
    
    if (razonIds.length === 0) {
      return res.json({ success: true, data: [] });
    }
    
    const [solicitudes] = await pool.query(`
      SELECT s.*, e.nombre as tienda, cr.rfc as razon_rfc, cr.razon as razon_nombre
      FROM solicitudes s
      JOIN empresas e ON s.empresa_id = e.id
      LEFT JOIN clientes_razones cr ON s.razon_id = cr.id
      WHERE s.razon_id IN (?) OR s.email = ?
      ORDER BY s.fecha DESC
    `, [razonIds, req.usuario.email]);
    
    res.json({
      success: true,
      data: solicitudes.map(s => ({
        id: s.uuid, fecha: s.fecha, tienda: s.tienda, rfc: s.rfc, razon: s.razon,
        regimen: s.regimen, cp: s.cp, uso_cfdi: s.uso_cfdi, email: s.email,
        monto: s.monto, folio: s.folio, notas: s.notas, ticket: s.ticket,
        csf: s.csf, estatus: s.estatus
      }))
    });
  } catch (error) {
    res.status(500).json({ success: false, mensaje: 'Error del servidor' });
  }
});

// Detalle solicitud
app.get('/api/solicitudes/:uuid', verificarToken, async (req, res) => {
  try {
    const [solicitudes] = await pool.query(`
      SELECT s.*, e.nombre as tienda
      FROM solicitudes s
      JOIN empresas e ON s.empresa_id = e.id
      WHERE s.uuid = ?
    `, [req.params.uuid]);
    
    if (solicitudes.length === 0) {
      return res.status(404).json({ success: false, mensaje: 'Solicitud no encontrada' });
    }
    
    const s = solicitudes[0];
    res.json({
      success: true,
      solicitud: {
        id: s.uuid, fecha: s.fecha, tienda: s.tienda, rfc: s.rfc, razon: s.razon,
        regimen: s.regimen, cp: s.cp, uso_cfdi: s.uso_cfdi, email: s.email,
        monto: s.monto, folio: s.folio, notas: s.notas, ticket: s.ticket,
        csf: s.csf, estatus: s.estatus
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, mensaje: 'Error del servidor' });
  }
});

// Actualizar estatus solicitud
app.put('/api/solicitudes/:uuid/estatus', verificarToken, async (req, res) => {
  try {
    const { estatus } = req.body;
    if (!['Pendiente', 'Facturado', 'Rechazado'].includes(estatus)) {
      return res.status(400).json({ success: false, mensaje: 'Estatus inválido' });
    }
    await pool.query('UPDATE solicitudes SET estatus = ? WHERE uuid = ?', [estatus, req.params.uuid]);
    res.json({ success: true, mensaje: 'Estatus actualizado' });
  } catch (error) {
    res.status(500).json({ success: false, mensaje: 'Error del servidor' });
  }
});

// Usuarios empresa
app.get('/api/usuarios-empresa/:empresaId', verificarToken, async (req, res) => {
  try {
    let empresaIdNum = req.params.empresaId;
    if (isNaN(empresaIdNum)) {
      const [empresas] = await pool.query('SELECT id FROM empresas WHERE codigo = ?', [empresaIdNum]);
      if (empresas.length === 0) return res.status(404).json({ success: false, mensaje: 'Empresa no encontrada' });
      empresaIdNum = empresas[0].id;
    }
    
    const [usuarios] = await pool.query(`
      SELECT id, usuario as Usuario, nombre as Nombre, email as Email, permisos as Permisos, estado as Estado, admin as Admin
      FROM usuarios_empresa WHERE empresa_id = ? ORDER BY nombre
    `, [empresaIdNum]);
    
    res.json(usuarios);
  } catch (error) {
    res.status(500).json({ success: false, mensaje: 'Error del servidor' });
  }
});

// Crear usuario empresa
app.post('/api/usuarios-empresa', verificarToken, async (req, res) => {
  try {
    const { empresaId, usuario, nombre, email, password, permisos, estado, admin } = req.body;
    if (!empresaId || !usuario || !nombre || !password) {
      return res.status(400).json({ success: false, mensaje: 'Campos obligatorios faltantes' });
    }
    
    let empresaIdNum = empresaId;
    if (isNaN(empresaId)) {
      const [empresas] = await pool.query('SELECT id FROM empresas WHERE codigo = ?', [empresaId]);
      if (empresas.length === 0) return res.status(404).json({ success: false, mensaje: 'Empresa no encontrada' });
      empresaIdNum = empresas[0].id;
    }
    
    // Verificar usuario duplicado
    const [existeUsuario] = await pool.query('SELECT id FROM usuarios_empresa WHERE usuario = ?', [usuario]);
    if (existeUsuario.length > 0) {
      return res.status(400).json({ success: false, mensaje: 'Este usuario ya existe' });
    }
    
    // Verificar email duplicado
    if (email) {
      const [existeEmail] = await pool.query('SELECT id FROM usuarios_empresa WHERE email = ? AND empresa_id = ?', [email, empresaIdNum]);
      if (existeEmail.length > 0) {
        return res.status(400).json({ success: false, mensaje: 'Este correo ya está registrado' });
      }
    }
    
    const passwordHash = await bcrypt.hash(password, 10);
    await pool.query(`
      INSERT INTO usuarios_empresa (empresa_id, usuario, password, nombre, email, permisos, estado, admin)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `, [empresaIdNum, usuario, passwordHash, nombre, email, permisos || 'lectura', estado || 'Activo', admin === 'Si' ? 1 : 0]);
    
    res.json({ success: true, mensaje: 'Usuario creado correctamente' });
  } catch (error) {
    res.status(500).json({ success: false, mensaje: 'Error del servidor' });
  }
});

// Actualizar usuario empresa
app.put('/api/usuarios-empresa/:id', verificarToken, async (req, res) => {
  try {
    const { nombre, email, password, permisos, estado, admin } = req.body;
    
    let query = 'UPDATE usuarios_empresa SET nombre = ?, email = ?, permisos = ?, estado = ?, admin = ?';
    let params = [nombre, email, permisos, estado, admin === 'Si' || admin === true ? 1 : 0];
    
    if (password && password.trim() !== '') {
      query += ', password = ?';
      params.push(await bcrypt.hash(password, 10));
    }
    
    query += ' WHERE id = ?';
    params.push(req.params.id);
    
    await pool.query(query, params);
    res.json({ success: true, mensaje: 'Usuario actualizado correctamente' });
  } catch (error) {
    res.status(500).json({ success: false, mensaje: 'Error del servidor' });
  }
});

// Eliminar usuario empresa
app.delete('/api/usuarios-empresa/:id', verificarToken, async (req, res) => {
  try {
    await pool.query('DELETE FROM usuarios_empresa WHERE id = ?', [req.params.id]);
    res.json({ success: true, mensaje: 'Usuario eliminado correctamente' });
  } catch (error) {
    res.status(500).json({ success: false, mensaje: 'Error del servidor' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 FactuFácil API v2.0 en puerto ${PORT}`));
