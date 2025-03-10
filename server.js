require('dotenv').config();
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const session = require('express-session');
const { Pool } = require('pg');

const app = express();
app.use(express.json());
app.use(cors());

// ✅ PostgreSQL Connection
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
});

// ✅ Session Middleware (Needed for Google Auth)
app.use(session({
    secret: process.env.SESSION_SECRET || 'supersecret',
    resave: false,
    saveUninitialized: true
}));

// ✅ Initialize Passport
app.use(passport.initialize());
app.use(passport.session());

// ✅ REGISTER USER (Students & Organizations)
app.post('/register', async (req, res) => {
    const { email, password, userType } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);

    try {
        const result = await pool.query(
            'INSERT INTO users (email, password, user_type) VALUES ($1, $2, $3) RETURNING id',
            [email, hashedPassword, userType]
        );
        res.json({ success: true, userId: result.rows[0].id });
    } catch (err) {
        if (err.code === '23505') {
            res.status(400).json({ error: 'Email already exists' });
        } else {
            res.status(500).json({ error: err.message });
        }
    }
});

// ✅ LOGIN USER
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        const user = await pool.query('SELECT * FROM users WHERE email = $1', [email]);

        if (user.rows.length === 0) return res.status(401).json({ error: 'User not found' });

        // Prevent password check if user has NULL password (Google users)
        if (!user.rows[0].password) return res.status(401).json({ error: 'This account was registered with Google. Please log in using Google.' });

        const isMatch = await bcrypt.compare(password, user.rows[0].password);
        if (!isMatch) return res.status(401).json({ error: 'Incorrect password' });

        const token = jwt.sign({ userId: user.rows[0].id }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.json({ token });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ✅ Middleware to Verify Token
function authenticateToken(req, res, next) {
    const token = req.header('Authorization');
    if (!token) return res.status(401).json({ error: 'Access denied' });

    try {
        const verified = jwt.verify(token.split(" ")[1], process.env.JWT_SECRET);
        req.user = verified;
        next();
    } catch (err) {
        res.status(400).json({ error: 'Invalid token' });
    }
}

// ✅ GET PROFILE (Protected Route)
app.get('/profile', authenticateToken, async (req, res) => {
    try {
        const user = await pool.query('SELECT email, user_type FROM users WHERE id = $1', [req.user.userId]);
        res.json(user.rows[0]);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ✅ Google OAuth Strategy (Fixed NULL Password Issue)
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "/auth/google/callback"
}, async (accessToken, refreshToken, profile, done) => {
    try {
        // Check if user exists in DB
        let user = await pool.query('SELECT * FROM users WHERE email = $1', [profile.emails[0].value]);

        if (user.rows.length === 0) {
            // If user doesn't exist, create new user with NULL password
            user = await pool.query(
                'INSERT INTO users (email, password, user_type) VALUES ($1, $2, $3) RETURNING *',
                [profile.emails[0].value, null, 'student'] // Password is NULL for Google users
            );
        }

        return done(null, user.rows[0]);
    } catch (err) {
        return done(err, null);
    }
}));

// ✅ Serialize & Deserialize User
passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
    try {
        const user = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
        done(null, user.rows[0]);
    } catch (err) {
        done(err, null);
    }
});

// ✅ Google OAuth Routes
app.get('/auth/google',
    passport.authenticate('google', { scope: ['profile', 'email'] })
);

app.get('/auth/google/callback',
    passport.authenticate('google', { failureRedirect: '/' }),
    (req, res) => {
        res.send("✅ Google Authentication Successful! You can now use the app.");
    }
);

// ✅ Start Server
app.listen(5000, () => console.log("✅ Server running on port 5000"));
