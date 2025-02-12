require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const db = require('./conexion'); // Importamos la conexión a MySQL

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = process.env.SECRET_KEY || 'tu_clave_secreta';

app.use(bodyParser.json());
app.use(cors());

// 🟢 REGISTRO DE USUARIO
app.post('/register', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ message: "Faltan datos" });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 8);
        const sql = "INSERT INTO usuarios (username, password) VALUES (?, ?)";
        db.query(sql, [username, hashedPassword], (err, result) => {
            if (err) {
                console.error(err);
                return res.status(500).json({ message: "Error en el servidor" });
            }
            res.status(201).json({ message: "Usuario registrado correctamente" });
        });
    } catch (error) {
        res.status(500).json({ message: "Error en el servidor" });
    }
});

// 🟢 LOGIN DE USUARIO
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ message: "Faltan datos" });
    }

    const sql = "SELECT * FROM usuarios WHERE username = ?";
    db.query(sql, [username], async (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ message: "Error en el servidor" });
        }

        if (results.length === 0) {
            return res.status(400).json({ message: "Usuario no encontrado" });
        }

        const user = results[0];
        const validPassword = await bcrypt.compare(password, user.password);
        
        if (!validPassword) {
            return res.status(400).json({ message: "Contraseña incorrecta" });
        }

        const token = jwt.sign({ id: user.id }, SECRET_KEY, { expiresIn: '1h' });
        res.json({ token });
    });
});

// 🟢 RUTA PROTEGIDA
app.get('/protected', (req, res) => {
    const token = req.headers['authorization'];
    
    if (!token) {
        return res.status(401).json({ message: "Acceso denegado" });
    }

    try {
        const verified = jwt.verify(token, SECRET_KEY);
        res.json({ message: "Acceso concedido", user: verified });
    } catch (error) {
        res.status(400).json({ message: "Token inválido" });
    }
});

// 🟢 INICIAR EL SERVIDOR
app.listen(PORT, () => {
    console.log(`Servidor corriendo en http://localhost:${PORT}`);
});
