import express from 'express';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';

const app = express();
//sign5
// Middleware setup with more secure CORS options
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS?.split(',') || 'http://localhost:3000',
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Use environment variable for secret key
const secretKey = process.env.JWT_SECRET_KEY || 'your-secret-key-minimum-32-chars-long';

// Generate SHA-256 hash of fingerprint
async function generateSHA256(fingerprint) {
  try {
    const encoder = new TextEncoder();
    const data = encoder.encode(fingerprint);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  } catch (error) {
    console.error('Error generating hash:', error);
    throw new Error('Failed to generate fingerprint hash');
  }
}

// Generate fingerprint from request headers
async function generateFingerprint(req) {
  try {
    const headers = req.headers;
    const fingerprintComponents = [
      headers['sec-ch-ua'] || '',
      headers['user-agent'] || '',
      headers['accept-language'] || '',
      headers['upgrade-insecure-requests'] || '',
      req.ip // Include IP address in fingerprint
    ];
    console.log(fingerprintComponents);
    
    // Filter out empty values and join
    const fingerprint = fingerprintComponents
      .filter(component => component)
      .join('-');
      
    return await generateSHA256(fingerprint);
    
  } catch (error) {
    console.error('Error generating fingerprint:', error);
    throw new Error('Failed to generate fingerprint');
  }
}

// Middleware to verify JWT token
const verifyToken = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith('Bearer ')) {
      return res.status(401).json({ message: 'No token provided' });
    }

    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, secretKey);
    
    // Generate current fingerprint and compare with stored one
    const currentFingerprint = await generateFingerprint(req);
    if (decoded.fingerprint !== currentFingerprint) {
      return res.status(401).json({ message: 'Invalid token fingerprint' });
    }

    req.user = decoded;
    next();
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ message: 'Token expired' });
    }
    return res.status(401).json({ message: 'Invalid token' });
  }
};

// Login route
app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ message: 'Username and password required' });
    }

    // Demo authentication - replace with database lookup
    if (username === 'admin' && password === 'admin') {
      const fingerprint = await generateFingerprint(req);
      const token = jwt.sign(
        { 
          username,
          fingerprint,
          // Add additional claims as needed
          iat: Math.floor(Date.now() / 1000),
        },
        secretKey,
        { 
          expiresIn: '1h',
          algorithm: 'HS256'
        }
      );

      // Set token in HTTP-only cookie for better security
      res.cookie('token', token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 3600000 // 1 hour
      });

      return res.json({ message: 'Login successful' });
    }

    return res.status(401).json({ message: 'Invalid credentials' });
  } catch (error) {
    console.error('Login error:', error);
    return res.status(500).json({ message: 'Internal server error' });
  }
});

// Protected route
app.get('/protected', verifyToken, (req, res) => {
  res.json({ 
    message: 'Protected route accessed',
    user: {
      username: req.user.username,
      fingerprint: req.user.fingerprint
      // Don't send sensitive information back
    }
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ message: 'Something went wrong!' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});