const express = require('express');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2/promise'); // Cambiamos pg por mysql2
const app = express();
const port = 3000;
const cors = require('cors');

// Configuración de middlewares
app.use(cors());
app.use(express.json());

// Configuración de MySQL (reemplaza la configuración de PostgreSQL)
const pool = mysql.createPool({
    host: 'localhost',
    user: 'root',       // Usuario de MySQL
    password: '',      // Contraseña de MySQL
    database: 'mydb',  // Nombre de la base de datos
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

const JWT_SECRET = 'tu_clave_secreta_super_segura';

// Middleware de autenticación JWT (no cambia)
const authenticateToken = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.sendStatus(401);

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

// Login (adaptado para MySQL)
app.post('/login', async (req, res) => {
    const { nombre, password } = req.body;
    try {
        const [rows] = await pool.query(
            'SELECT * FROM users WHERE nombre = ? AND password = ?',
            [nombre, password]
        );
        if (rows.length === 0) {
            return res.status(401).json({ message: "Credenciales incorrectas" });
        }
        const user = rows[0];
        const token = jwt.sign(
            { id: user.id, nombre: user.nombre },
            JWT_SECRET,
            { expiresIn: '1h' }
        );
        res.json({ token });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// CRUD con MySQL

// Obtener todos los usuarios
app.get('/users', authenticateToken, async (req, res) => {
    try {
        const [rows] = await pool.query('SELECT id, nombre FROM users');
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Obtener un usuario específico
app.get('/users/:id', authenticateToken, async (req, res) => {
    try {
        const [rows] = await pool.query('SELECT id, nombre FROM users WHERE id = ?', [req.params.id]);
        if (rows.length === 0) {
            return res.status(404).json({ message: 'Usuario no encontrado' });
        }
        res.json(rows[0]);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Crear un nuevo usuario
app.post('/users', authenticateToken, async (req, res) => {
    const { nombre, password } = req.body;
    try {
        const [result] = await pool.query(
            'INSERT INTO users (nombre, password) VALUES (?, ?)',
            [nombre, password]
        );
        
        // MySQL no tiene RETURNING, hacemos una consulta adicional
        const [newUser] = await pool.query('SELECT id, nombre FROM users WHERE id = ?', [result.insertId]);
        res.status(201).json(newUser[0]);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Actualizar un usuario
app.put('/users/:id', authenticateToken, async (req, res) => {
    const { nombre } = req.body; // Solo recibimos el nombre
    
    try {
      const [result] = await pool.query(
        'UPDATE users SET nombre = ? WHERE id = ?',
        [nombre, req.params.id]
      );
      
      if (result.affectedRows === 0) {
        return res.status(404).json({ message: 'Usuario no encontrado' });
      }
      
      res.json({ message: 'Nombre de usuario actualizado' });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });
  
// Eliminar un usuario
app.delete('/users/:id', authenticateToken, async (req, res) => {
    try {
        const [result] = await pool.query(
            'DELETE FROM users WHERE id = ?',
            [req.params.id]
        );
        
        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Usuario no encontrado' });
        }
        
        res.status(204).send();
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.listen(port, () => {
    console.log(`Servidor escuchando en http://localhost:${port}`);
});