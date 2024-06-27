const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const http = require('http');
const WebSocket = require('ws');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(bodyParser.json());

// Connect to SQLite database
const dbPath = path.join(__dirname, 'application.db');
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error('Error connecting to SQLite database:', err.message);
    } else {
        console.log('Connected to SQLite database');
        db.run(`CREATE TABLE IF NOT EXISTS users (
            username varchar(250),
            password varchar(250),
            email varchar(250)
        )`);
    }
});

// Serve static files from the "public" directory
app.use(express.static(path.join(__dirname, 'public')));

// Signup endpoint
app.post('/signup', (req, res) => {
    const { username, password, email } = req.body;

    bcrypt.genSalt(10, (err, salt) => {
        bcrypt.hash(password, salt, (err, hash) => {
            if (err) {
                console.error('Error hashing password:', err);
                return res.status(500).json({ message: 'Error registering user' });
            }
            const insertQuery = `INSERT INTO users (username, password, email) VALUES (?, ?, ?)`;
            db.run(insertQuery, [username, hash, email], function(err) {
                if (err) {
                    console.error('Error inserting user into database:', err.message);
                    return res.status(500).json({ message: 'Error registering user' });
                }
                console.log(`User ${username} registered successfully`);
                res.status(201).json({ message: 'User registered successfully' });
            });
        });
    });
});

// Login endpoint
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    db.get(`SELECT * FROM users WHERE username = ?`, [username], (err, row) => {
        if (err) {
            console.error('Error querying database:', err.message);
            return res.status(500).json({ message: 'Error retrieving user' });
        }
        if (!row) {
            return res.status(401).json({ message: 'User not found' });
        }

        bcrypt.compare(password, row.password, (err, result) => {
            if (err || !result) {
                return res.status(401).json({ message: 'Invalid credentials' });
            }
            res.status(200).json({ message: 'Login successful' });
        });
    });
});

// Serve the home page
app.get('/home', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'home.html'));
});

// Serve the login page as the root route
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Serve the signup page
app.get('/signup', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'signup.html'));
});

// Create HTTP server
const server = http.createServer(app);

// Set up WebSocket server
const wss = new WebSocket.Server({ server });

wss.on('connection', (ws) => {
    ws.on('message', (message) => {
        const messageData = JSON.parse(message);
        wss.clients.forEach(client => {
            if (client.readyState === WebSocket.OPEN) {
                client.send(JSON.stringify(messageData));
            }
        });
    });
});

server.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
