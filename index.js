const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const { v4: uuidv4 } = require('uuid');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = 'changeme-secret-key'; // À changer en prod

app.use(cors());
app.use(bodyParser.json());

// Configuration de la base de données
const DB_NAME = 'unchk_db';
const dbConfig = {
  host: 'localhost',
  user: 'root',
  password: '', // pas de mot de passe XAMPP par défaut
  multipleStatements: true,
};

// Création de la base et des tables si elles n'existent pas
async function initDatabase() {
  const connection = await mysql.createConnection(dbConfig);
  await connection.query(`CREATE DATABASE IF NOT EXISTS \`${DB_NAME}\`;`);
  await connection.changeUser({ database: DB_NAME });
  await connection.query(`
    CREATE TABLE IF NOT EXISTS users (
      id VARCHAR(36) PRIMARY KEY,
      username VARCHAR(255),
      email VARCHAR(255) UNIQUE,
      password VARCHAR(255),
      role VARCHAR(50),
      status VARCHAR(50),
      createdAt DATETIME
    );
    CREATE TABLE IF NOT EXISTS questions (
      id VARCHAR(36) PRIMARY KEY,
      text TEXT,
      \`order\` INT
    );
    CREATE TABLE IF NOT EXISTS answers (
      id VARCHAR(36) PRIMARY KEY,
      candidateId VARCHAR(36),
      questionId VARCHAR(36),
      questionText TEXT,
      text TEXT,
      createdAt DATETIME
    );
    CREATE TABLE IF NOT EXISTS videos (
      id VARCHAR(36) PRIMARY KEY,
      candidateId VARCHAR(36),
      url TEXT,
      title VARCHAR(255),
      duration VARCHAR(50),
      createdAt DATETIME
    );
  `);
  await connection.end();
  console.log('Base de données et tables vérifiées/créées.');
}

// Appel de l'initialisation au démarrage du serveur
initDatabase().catch(console.error);

// Helper pour obtenir une connexion à la base
async function getDbConnection() {
  return mysql.createConnection({ ...dbConfig, database: DB_NAME });
}

// Auth: 
//  (DB, bcrypt, JWT)
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const conn = await getDbConnection();
    const [rows] = await conn.execute('SELECT * FROM users WHERE email = ?', [email]);
    await conn.end();
    if (rows.length === 0) return res.status(401).json({ message: 'Invalid credentials' });
    const user = rows[0];
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) return res.status(401).json({ message: 'Invalid credentials' });
    const { password: _, ...userData } = user;
    const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '12h' });
    res.json({ ...userData, token });
  } catch (err) {
    res.status(500).json({ message: 'Erreur serveur', error: err.message });
  }
});

// Auth: Register (DB, hash password)
app.post('/api/register', async (req, res) => {
  const { username, email, password, role } = req.body;
  try {
    const conn = await getDbConnection();
    const [exists] = await conn.execute('SELECT id FROM users WHERE email = ?', [email]);
    if (exists.length > 0) {
      await conn.end();
      return res.status(409).json({ message: 'User already exists' });
    }
    const id = uuidv4();
    const status = 'pending';
    const createdAt = new Date();
    const hashedPassword = await bcrypt.hash(password, 10);
    await conn.execute('INSERT INTO users (id, username, email, password, role, status, createdAt) VALUES (?, ?, ?, ?, ?, ?, ?)', [id, username, email, hashedPassword, role, status, createdAt]);
    await conn.end();
    res.status(201).json({ id, username, email, role, status, createdAt });
  } catch (err) {
    res.status(500).json({ message: 'Erreur serveur', error: err.message });
  }
});

// Get all questions (DB)
app.get('/api/questions', async (req, res) => {
  try {
    const conn = await getDbConnection();
    const [rows] = await conn.execute('SELECT * FROM questions ORDER BY `order` ASC');
    await conn.end();
    res.json(rows);
  } catch (err) {
    res.status(500).json({ message: 'Erreur serveur', error: err.message });
  }
});

// Submit answers (DB)
app.post('/api/answers', async (req, res) => {
  const { candidateId, answers: submittedAnswers } = req.body;
  try {
    const conn = await getDbConnection();
    const savedAnswers = [];
    for (const a of submittedAnswers) {
      const id = uuidv4();
      // On récupère le texte de la question
      const [qRows] = await conn.execute('SELECT text FROM questions WHERE id = ?', [a.questionId]);
      const questionText = qRows[0]?.text || '';
      const createdAt = new Date();
      await conn.execute('INSERT INTO answers (id, candidateId, questionId, questionText, text, createdAt) VALUES (?, ?, ?, ?, ?, ?)', [id, candidateId, a.questionId, questionText, a.text, createdAt]);
      savedAnswers.push({ id, candidateId, questionId: a.questionId, questionText, text: a.text, createdAt });
    }
    await conn.end();
    res.status(201).json(savedAnswers);
  } catch (err) {
    res.status(500).json({ message: 'Erreur serveur', error: err.message });
  }
});

// Get answers for a candidate (DB)
app.get('/api/answers/:candidateId', async (req, res) => {
  const { candidateId } = req.params;
  try {
    const conn = await getDbConnection();
    const [rows] = await conn.execute('SELECT * FROM answers WHERE candidateId = ?', [candidateId]);
    await conn.end();
    res.json(rows);
  } catch (err) {
    res.status(500).json({ message: 'Erreur serveur', error: err.message });
  }
});

// Upload video (DB)
app.post('/api/videos', async (req, res) => {
  const { candidateId, url, title, duration } = req.body;
  try {
    const conn = await getDbConnection();
    const id = uuidv4();
    const createdAt = new Date();
    await conn.execute('INSERT INTO videos (id, candidateId, url, title, duration, createdAt) VALUES (?, ?, ?, ?, ?, ?)', [id, candidateId, url, title, duration, createdAt]);
    await conn.end();
    res.status(201).json({ id, candidateId, url, title, duration, createdAt });
  } catch (err) {
    res.status(500).json({ message: 'Erreur serveur', error: err.message });
  }
});

// Get videos for a candidate (DB)
app.get('/api/videos/:candidateId', async (req, res) => {
  const { candidateId } = req.params;
  try {
    const conn = await getDbConnection();
    const [rows] = await conn.execute('SELECT * FROM videos WHERE candidateId = ?', [candidateId]);
    await conn.end();
    res.json(rows);
  } catch (err) {
    res.status(500).json({ message: 'Erreur serveur', error: err.message });
  }
});

// Get all candidates (DB)
app.get('/api/candidates', async (req, res) => {
  try {
    const conn = await getDbConnection();
    const [users] = await conn.execute('SELECT * FROM users WHERE role = ?', ['candidate']);
    for (const u of users) {
      const [videos] = await conn.execute('SELECT * FROM videos WHERE candidateId = ?', [u.id]);
      const [answers] = await conn.execute('SELECT * FROM answers WHERE candidateId = ?', [u.id]);
      u.videos = videos;
      u.answers = answers;
    }
    await conn.end();
    res.json(users);
  } catch (err) {
    res.status(500).json({ message: 'Erreur serveur', error: err.message });
  }
});

// Ajouter une question (DB)
app.post('/api/questions', async (req, res) => {
  const { text, order } = req.body;
  if (!text || typeof order !== 'number') {
    return res.status(400).json({ message: 'text et order sont requis' });
  }
  try {
    const conn = await getDbConnection();
    const id = uuidv4();
    await conn.execute('INSERT INTO questions (id, text, `order`) VALUES (?, ?, ?)', [id, text, order]);
    await conn.end();
    res.status(201).json({ id, text, order });
  } catch (err) {
    res.status(500).json({ message: 'Erreur serveur', error: err.message });
  }
});

// Get all recruiters (DB)
app.get('/api/recruiters', async (req, res) => {
  try {
    const conn = await getDbConnection();
    const [users] = await conn.execute('SELECT * FROM users WHERE role = ?', ['recruiter']);
    await conn.end();
    res.json(users);
  } catch (err) {
    res.status(500).json({ message: 'Erreur serveur', error: err.message });
  }
});

app.listen(PORT, () => {
  console.log(`API server running on port ${PORT}`);
});