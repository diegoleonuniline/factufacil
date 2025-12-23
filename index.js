const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');

const app = express();
app.use(cors());
app.use(express.json({ limit: '50mb' }));

// Configuración de la base de datos
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

// Clave secreta para JWT
const JWT_SECRET = 'factufacil_secret_key_2024_muy_segura';

// ============================================
// MIDDLEWARE: Verificar Token
// ============================================
const verificarToken = (req, res, next) => {
  const token = req.headers['authorization']?.replace('Bearer ', '');
  if (!token) {
    return res.status(401).json({ success: false, mensaje: 'Token requerido' });
  }
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.usuario = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ success: false, mensaje: 'Token inválido' });
  }
};

// ============================================
// RUTA: Health Check
// ============================================
app.get('/', (req, res) => {
  res.json({ status: 'ok', mensaje: 'FactuFácil API funcionando', version: '1.0.0' });
});

// ============================================
// RUTA: Setup inicial (para crear primer usuario)
// ============================================
app.post('/api/setup/usuario-empresa', async (req, res) => {
  try {
    const { empresaId, usuario, nombre, email, password, permisos, admin } = req.body;
    
    const [empresas] = await pool.query('SELECT id FROM empresas WHERE codigo = ?', [empresaId]);
    if (empresas.length === 0) {
      return res.status(400).json({ success: false, mensaje: 'Empresa no encontrada' });
    }
    
    const empresaIdNum = empresas[0].id;
    
    const [existe] = await pool.query('SELECT id FROM usuarios_empresa WHERE usuario = ?', [usuario]);
    if (existe.length > 0) {
      const passwordHash = await bcrypt.hash(password, 10);
      await pool.query('UPDATE usuarios_empresa SET password = ? WHERE usuario = ?', [passwordHash, usuario]);
      return res.json({ success: true, mensaje: 'Password actualizado' });
    }
    
    const passwordHash = await bcrypt.hash(password, 10);
    
    await pool.query(`
      INSERT INTO usuarios_empresa (empresa_id, usuario, password, nombre, email, permisos, estado, admin)
      VALUES (?, ?, ?, ?, ?, ?, 'activo', ?)
    `, [empresaIdNum, usuario, passwordHash, nombre, email, permisos || 'gestionar', admin === 'Si' ? 1 : 0]);
    
    res.json({ success: true, mensaje: 'Usuario creado correctamente' });
  } catch (error) {
    console.error('Error setup:', error);
    res.status(500).json({ success: false, mensaje: error.message });
  }
});

// ============================================
// RUTA: Obtener Catálogos
// ============================================
app.get('/api/catalogos', async (req, res) => {
  try {
    const [regimenes] = await pool.query('SELECT clave, descripcion FROM cat_regimen ORDER BY clave');
    const [usosCfdi] = await pool.query('SELECT clave, descripcion FROM cat_uso_cfdi ORDER BY clave');
    const [empresas] = await pool.query('SELECT id, codigo, nombre FROM empresas WHERE estatus = "activo" ORDER BY nombre');
    
    res.json({
      success: true,
      regimenes: regimenes,
      usosCfdi: usosCfdi,
      empresas: empresas.map(e => ({ id: e.codigo, nombre: e.nombre }))
    });
  } catch (error) {
    console.error('Error catálogos:', error);
    res.status(500).json({ success: false, mensaje: 'Error al obtener catálogos' });
  }
});

// ============================================
// RUTA: Login Usuario (Cliente)
// ============================================
app.post('/api/auth/login-usuario', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ success: false, mensaje: 'Email y contraseña requeridos' });
    }
    
    const [usuarios] = await pool.query('SELECT * FROM usuarios WHERE email = ?', [email.toLowerCase()]);
    
    if (usuarios.length === 0) {
      return res.status(401).json({ success: false, mensaje: 'Credenciales inválidas' });
    }
    
    const usuario = usuarios[0];
    const passwordValido = await bcrypt.compare(password, usuario.password);
    
    if (!passwordValido) {
      return res.status(401).json({ success: false, mensaje: 'Credenciales inválidas' });
    }
    
    const token = jwt.sign(
      { id: usuario.id, uuid: usuario.uuid, email: usuario.email, tipo: 'cliente' },
      JWT_SECRET,
      { expiresIn: '7d' }
    );
    
    res.json({
      success: true,
      tipo: 'cliente',
      token: token,
      usuario: {
        uuid: usuario.uuid,
        nombre: usuario.nombre,
        email: usuario.email,
        rfc: usuario.rfc,
        razon: usuario.razon,
        regimen: usuario.regimen,
        cp: usuario.cp,
        uso_cfdi: usuario.uso_cfdi
      }
    });
  } catch (error) {
    console.error('Error login usuario:', error);
    res.status(500).json({ success: false, mensaje: 'Error del servidor' });
  }
});

// ============================================
// RUTA: Login Empresa
// ============================================
app.post('/api/auth/login-empresa', async (req, res) => {
  try {
    const { usuario, password } = req.body;
    
    if (!usuario || !password) {
      return res.status(400).json({ success: false, mensaje: 'Usuario y contraseña requeridos' });
    }
    
    const [usuarios] = await pool.query(`
      SELECT ue.*, e.nombre as empresa_nombre, e.codigo as empresa_codigo
      FROM usuarios_empresa ue
      JOIN empresas e ON ue.empresa_id = e.id
      WHERE ue.usuario = ? AND e.estatus = 'activo'
    `, [usuario]);
    
    if (usuarios.length === 0) {
      return res.status(401).json({ success: false, mensaje: 'Usuario no encontrado' });
    }
    
    const user = usuarios[0];
    
    // Comparar estado ignorando mayúsculas/minúsculas
    if (user.estado.toLowerCase() !== 'activo') {
      return res.status(401).json({ success: false, mensaje: 'Usuario inactivo' });
    }
    
    const passwordValido = await bcrypt.compare(password, user.password);
    
    if (!passwordValido) {
      return res.status(401).json({ success: false, mensaje: 'Contraseña incorrecta' });
    }
    
    const token = jwt.sign(
      { 
        id: user.id, 
        empresaId: user.empresa_id, 
        usuario: user.usuario, 
        tipo: 'empresa',
        permisos: user.permisos,
        admin: user.admin
      },
      JWT_SECRET,
      { expiresIn: '7d' }
    );
    
    res.json({
      success: true,
      tipo: 'empresa',
      token: token,
      empresaId: user.empresa_id,
      empresaNombre: user.empresa_nombre,
      empresaAlias: user.empresa_codigo,
      usuario: user.usuario,
      permisos: user.permisos,
      admin: user.admin ? true : false
    });
  } catch (error) {
    console.error('Error login empresa:', error);
    res.status(500).json({ success: false, mensaje: 'Error del servidor' });
  }
});

// ============================================
// RUTA: Registrar Usuario (Cliente)
// ============================================
app.post('/api/auth/registro', async (req, res) => {
  try {
    const { nombre, email, password, rfc, razon, regimen, cp, uso_cfdi } = req.body;
    
    if (!email || !password || !rfc || !razon) {
      return res.status(400).json({ success: false, mensaje: 'Campos obligatorios faltantes' });
    }
    
    const [existente] = await pool.query('SELECT id FROM usuarios WHERE email = ?', [email.toLowerCase()]);
    if (existente.length > 0) {
      return res.status(400).json({ success: false, mensaje: 'El email ya está registrado' });
    }
    
    const uuid = uuidv4();
    const passwordHash = await bcrypt.hash(password, 10);
    
    await pool.query(`
      INSERT INTO usuarios (uuid, nombre, email, password, rfc, razon, regimen, cp, uso_cfdi)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `, [uuid, nombre, email.toLowerCase(), passwordHash, rfc.toUpperCase(), razon, regimen, cp, uso_cfdi]);
    
    res.json({ success: true, mensaje: 'Usuario registrado correctamente' });
  } catch (error) {
    console.error('Error registro:', error);
    res.status(500).json({ success: false, mensaje: 'Error del servidor' });
  }
});

// ============================================
// RUTA: Buscar datos por RFC
// ============================================
app.get('/api/rfc/:rfc', async (req, res) => {
  try {
    const rfc = req.params.rfc.toUpperCase();
    
    const [usuarios] = await pool.query('SELECT * FROM usuarios WHERE rfc = ?', [rfc]);
    
    if (usuarios.length > 0) {
      const u = usuarios[0];
      return res.json({
        success: true,
        datos: {
          razon: u.razon,
          regimen: u.regimen,
          cp: u.cp,
          uso_cfdi: u.uso_cfdi,
          email: u.email
        }
      });
    }
    
    const [solicitudes] = await pool.query('SELECT * FROM solicitudes WHERE rfc = ? ORDER BY fecha DESC LIMIT 1', [rfc]);
    
    if (solicitudes.length > 0) {
      const s = solicitudes[0];
      return res.json({
        success: true,
        datos: {
          razon: s.razon,
          regimen: s.regimen,
          cp: s.cp,
          uso_cfdi: s.uso_cfdi,
          email: s.email
        }
      });
    }
    
    res.json({ success: false, mensaje: 'RFC no encontrado' });
  } catch (error) {
    console.error('Error buscar RFC:', error);
    res.status(500).json({ success: false, mensaje: 'Error del servidor' });
  }
});

// ============================================
// RUTA: Crear Solicitud
// ============================================
app.post('/api/solicitudes', async (req, res) => {
  try {
    const { empresa_id, rfc, razon, regimen, cp, uso_cfdi, email, monto, folio, notas, ticket, csf, cc } = req.body;
    
    if (!empresa_id || !rfc || !razon || !email) {
      return res.status(400).json({ success: false, mensaje: 'Campos obligatorios faltantes' });
    }
    
    const [empresas] = await pool.query('SELECT id FROM empresas WHERE codigo = ?', [empresa_id]);
    if (empresas.length === 0) {
      return res.status(400).json({ success: false, mensaje: 'Empresa no encontrada' });
    }
    
    const empresaIdNum = empresas[0].id;
    const uuid = uuidv4();
    
    await pool.query(`
      INSERT INTO solicitudes (uuid, empresa_id, rfc, razon, regimen, cp, uso_cfdi, email, monto, folio, notas, ticket, csf, estatus)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Pendiente')
    `, [uuid, empresaIdNum, rfc.toUpperCase(), razon, regimen, cp, uso_cfdi, email.toLowerCase(), monto || null, folio, notas, ticket, csf]);
    
    res.json({ success: true, mensaje: 'Solicitud creada correctamente', uuid: uuid });
  } catch (error) {
    console.error('Error crear solicitud:', error);
    res.status(500).json({ success: false, mensaje: 'Error del servidor' });
  }
});

// ============================================
// RUTA: Obtener Solicitudes de Empresa
// ============================================
app.get('/api/solicitudes/empresa/:empresaId', verificarToken, async (req, res) => {
  try {
    const empresaId = req.params.empresaId;
    
    let empresaIdNum = empresaId;
    if (isNaN(empresaId)) {
      const [empresas] = await pool.query('SELECT id FROM empresas WHERE codigo = ?', [empresaId]);
      if (empresas.length === 0) {
        return res.status(404).json({ success: false, mensaje: 'Empresa no encontrada' });
      }
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
      id: s.uuid,
      fecha: s.fecha,
      rfc: s.rfc,
      razon: s.razon,
      regimen: s.regimen,
      cp: s.cp,
      uso_cfdi: s.uso_cfdi,
      email: s.email,
      monto: s.monto,
      folio: s.folio,
      notas: s.notas,
      ticket: s.ticket,
      csf: s.csf,
      estatus: s.estatus,
      tienda: s.tienda
    })));
  } catch (error) {
    console.error('Error obtener solicitudes:', error);
    res.status(500).json({ success: false, mensaje: 'Error del servidor' });
  }
});

// ============================================
// RUTA: Obtener Mis Solicitudes (Cliente)
// ============================================
app.get('/api/solicitudes/mis/:email', verificarToken, async (req, res) => {
  try {
    const email = req.params.email.toLowerCase();
    
    const [solicitudes] = await pool.query(`
      SELECT s.*, e.nombre as tienda
      FROM solicitudes s
      JOIN empresas e ON s.empresa_id = e.id
      WHERE s.email = ?
      ORDER BY s.fecha DESC
    `, [email]);
    
    res.json({
      success: true,
      data: solicitudes.map(s => ({
        id: s.uuid,
        fecha: s.fecha,
        rfc: s.rfc,
        razon: s.razon,
        monto: s.monto,
        folio: s.folio,
        ticket: s.ticket,
        csf: s.csf,
        estatus: s.estatus,
        tienda: s.tienda
      }))
    });
  } catch (error) {
    console.error('Error mis solicitudes:', error);
    res.status(500).json({ success: false, mensaje: 'Error del servidor' });
  }
});

// ============================================
// RUTA: Actualizar Estatus Solicitud
// ============================================
app.put('/api/solicitudes/:uuid/estatus', verificarToken, async (req, res) => {
  try {
    const { uuid } = req.params;
    const { estatus } = req.body;
    
    if (!['Pendiente', 'Facturado', 'Rechazado'].includes(estatus)) {
      return res.status(400).json({ success: false, mensaje: 'Estatus inválido' });
    }
    
    await pool.query('UPDATE solicitudes SET estatus = ? WHERE uuid = ?', [estatus, uuid]);
    
    res.json({ success: true, mensaje: 'Estatus actualizado' });
  } catch (error) {
    console.error('Error actualizar estatus:', error);
    res.status(500).json({ success: false, mensaje: 'Error del servidor' });
  }
});

// ============================================
// RUTA: Obtener Usuarios de Empresa
// ============================================
app.get('/api/usuarios-empresa/:empresaId', verificarToken, async (req, res) => {
  try {
    const empresaId = req.params.empresaId;
    
    let empresaIdNum = empresaId;
    if (isNaN(empresaId)) {
      const [empresas] = await pool.query('SELECT id FROM empresas WHERE codigo = ?', [empresaId]);
      if (empresas.length === 0) {
        return res.status(404).json({ success: false, mensaje: 'Empresa no encontrada' });
      }
      empresaIdNum = empresas[0].id;
    }
    
    const [usuarios] = await pool.query(`
      SELECT id, usuario as Usuario, nombre as Nombre, email as Email, permisos as Permisos, estado as Estado, admin as Admin
      FROM usuarios_empresa
      WHERE empresa_id = ?
      ORDER BY nombre
    `, [empresaIdNum]);
    
    res.json(usuarios);
  } catch (error) {
    console.error('Error obtener usuarios:', error);
    res.status(500).json({ success: false, mensaje: 'Error del servidor' });
  }
});

// ============================================
// RUTA: Crear Usuario Empresa
// ============================================
app.post('/api/usuarios-empresa', verificarToken, async (req, res) => {
  try {
    const { empresaId, usuario, nombre, email, password, permisos, estado, admin } = req.body;
    
    if (!empresaId || !usuario || !nombre || !password) {
      return res.status(400).json({ success: false, mensaje: 'Campos obligatorios faltantes' });
    }
    
    let empresaIdNum = empresaId;
    if (isNaN(empresaId)) {
      const [empresas] = await pool.query('SELECT id FROM empresas WHERE codigo = ?', [empresaId]);
      if (empresas.length === 0) {
        return res.status(404).json({ success: false, mensaje: 'Empresa no encontrada' });
      }
      empresaIdNum = empresas[0].id;
    }
    
    const [existente] = await pool.query('SELECT id FROM usuarios_empresa WHERE usuario = ? AND empresa_id = ?', [usuario, empresaIdNum]);
    if (existente.length > 0) {
      return res.status(400).json({ success: false, mensaje: 'El usuario ya existe' });
    }
    
    const passwordHash = await bcrypt.hash(password, 10);
    const esAdmin = admin === 'Si' || admin === true ? 1 : 0;
    
    await pool.query(`
      INSERT INTO usuarios_empresa (empresa_id, usuario, password, nombre, email, permisos, estado, admin)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `, [empresaIdNum, usuario, passwordHash, nombre, email, permisos || 'lectura', estado || 'activo', esAdmin]);
    
    res.json({ success: true, mensaje: 'Usuario creado correctamente' });
  } catch (error) {
    console.error('Error crear usuario:', error);
    res.status(500).json({ success: false, mensaje: 'Error del servidor' });
  }
});

// ============================================
// RUTA: Actualizar Usuario Empresa
// ============================================
app.put('/api/usuarios-empresa/:id', verificarToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { nombre, email, password, permisos, estado, admin } = req.body;
    
    let query = 'UPDATE usuarios_empresa SET nombre = ?, email = ?, permisos = ?, estado = ?, admin = ?';
    let params = [nombre, email, permisos, estado, admin === 'Si' || admin === true ? 1 : 0];
    
    if (password && password.trim() !== '') {
      const passwordHash = await bcrypt.hash(password, 10);
      query += ', password = ?';
      params.push(passwordHash);
    }
    
    query += ' WHERE id = ?';
    params.push(id);
    
    await pool.query(query, params);
    
    res.json({ success: true, mensaje: 'Usuario actualizado correctamente' });
  } catch (error) {
    console.error('Error actualizar usuario:', error);
    res.status(500).json({ success: false, mensaje: 'Error del servidor' });
  }
});

// ============================================
// RUTA: Eliminar Usuario Empresa
// ============================================
app.delete('/api/usuarios-empresa/:id', verificarToken, async (req, res) => {
  try {
    const { id } = req.params;
    
    await pool.query('DELETE FROM usuarios_empresa WHERE id = ?', [id]);
    
    res.json({ success: true, mensaje: 'Usuario eliminado correctamente' });
  } catch (error) {
    console.error('Error eliminar usuario:', error);
    res.status(500).json({ success: false, mensaje: 'Error del servidor' });
  }
});

// ============================================
// RUTA: Actualizar Perfil Usuario
// ============================================
app.put('/api/usuarios/:email', verificarToken, async (req, res) => {
  try {
    const { email } = req.params;
    const { nombre, password, rfc, razon, regimen, cp, uso_cfdi } = req.body;
    
    let query = 'UPDATE usuarios SET nombre = ?, rfc = ?, razon = ?, regimen = ?, cp = ?, uso_cfdi = ?';
    let params = [nombre, rfc, razon, regimen, cp, uso_cfdi];
    
    if (password && password.trim() !== '') {
      const passwordHash = await bcrypt.hash(password, 10);
      query += ', password = ?';
      params.push(passwordHash);
    }
    
    query += ' WHERE email = ?';
    params.push(email.toLowerCase());
    
    await pool.query(query, params);
    
    const [usuarios] = await pool.query('SELECT * FROM usuarios WHERE email = ?', [email.toLowerCase()]);
    
    res.json({
      success: true,
      mensaje: 'Perfil actualizado',
      usuario: usuarios.length > 0 ? {
        nombre: usuarios[0].nombre,
        email: usuarios[0].email,
        rfc: usuarios[0].rfc,
        razon: usuarios[0].razon,
        regimen: usuarios[0].regimen,
        cp: usuarios[0].cp,
        uso_cfdi: usuarios[0].uso_cfdi
      } : null
    });
  } catch (error) {
    console.error('Error actualizar perfil:', error);
    res.status(500).json({ success: false, mensaje: 'Error del servidor' });
  }
});

// ============================================
// INICIAR SERVIDOR
// ============================================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 FactuFácil API corriendo en puerto ${PORT}`);
});
