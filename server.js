// server.js (using ES modules)

import 'dotenv/config';
import express from 'express';
import bcrypt from 'bcrypt';
import crypto from 'crypto';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import rateLimit from 'express-rate-limit';
import fetch from 'node-fetch';

const app = express();
const port = 3000;

// AES encryption settings
const algorithm = 'aes-256-cbc';
const key = Buffer.from(process.env.AES_KEY, 'hex');
const iv = Buffer.from(process.env.AES_IV, 'hex');

function encrypt(text) {
  const cipher = crypto.createCipheriv(algorithm, key, iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return encrypted;
}

// In-memory user store
const users = [];

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Rate limiter: max 5 login attempts per 15 minutes per IP
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { error: 'Too many login attempts. Please try again after 15 minutes.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// Verify Google reCAPTCHA token
async function verifyCaptcha(token) {
  if (!token) return false;
  const secretKey = process.env.RECAPTCHA_SECRET_KEY;
  const response = await fetch('https://www.google.com/recaptcha/api/siteverify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `secret=${secretKey}&response=${token}`,
  });
  const data = await response.json();
  return data.success;
}

// Registration route
app.post('/register', async (req, res) => {
  try {
    const { username, email, gender, password, captchaToken } = req.body;

    if (!username || !email || !gender || !password) {
      return res.status(400).json({ error: 'All fields are required.' });
    }

    // Verify CAPTCHA
    if (!captchaToken) {
      return res.status(400).json({ error: 'CAPTCHA token missing.' });
    }
    const captchaValid = await verifyCaptcha(captchaToken);
    if (!captchaValid) {
      return res.status(400).json({ error: 'CAPTCHA verification failed.' });
    }

    // Check for existing user
    if (users.find((u) => u.username === username)) {
      return res.status(409).json({ error: 'Username already exists.' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const encryptedEmail = encrypt(email);

    users.push({ username, email: encryptedEmail, gender, hashedPassword });

    console.log('User registered:', username);

    res.json({ message: 'Data submitted successfully!' });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Server error. Check logs.' });
  }
});

// Login route with rate limiter and CAPTCHA
app.post('/login', loginLimiter, async (req, res) => {
  try {
    const { username, password, captchaToken } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required.' });
    }

    if (!captchaToken) {
      return res.status(400).json({ error: 'CAPTCHA token missing.' });
    }

    const captchaValid = await verifyCaptcha(captchaToken);
    if (!captchaValid) {
      return res.status(400).json({ error: 'CAPTCHA verification failed.' });
    }

    const user = users.find((u) => u.username === username);
    if (!user) {
      return res.status(401).json({ error: 'Invalid username or password.' });
    }

    const isMatch = await bcrypt.compare(password, user.hashedPassword);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid username or password.' });
    }

    // Issue JWT token
    const token = jwt.sign(
      { username: user.username, gender: user.gender },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN }
    );

    res.json({ message: 'Login successful!', token });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Server error. Check logs.' });
  }
});

// JWT middleware
function verifyToken(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return res.status(401).json({ error: 'No token provided.' });
  }

  const token = authHeader.split(' ')[1];
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid token.' });
    }
    req.user = decoded;
    next();
  });
}

// Protected route example
app.get('/protected', verifyToken, (req, res) => {
  res.json({ message: `Hello ${req.user.username}, you accessed a protected route!` });
});

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});