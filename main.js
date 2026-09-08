require('dotenv').config();

const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const cookieParser = require('cookie-parser');
const User = require('./models/user');
const Note = require('./models/note');
const {
    AUTH_COOKIE_NAME,
    isAuthenticated,
    isAdminAuthenticated,
    setAuthCookie
} = require('./auth');

const app = express();
const PORT = process.env.PORT || 3000;
const DATABASE_URL = process.env.DATABASE_URL;

// Configure Express before defining routes.
app.set('view engine', 'ejs');
app.use(express.static('public'));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
// This makes cookies available as req.cookies in our JWT middleware.
app.use(cookieParser());

app.get('/', (req, res) => {
    res.redirect('/login');
});

// Public routes.
app.get('/register', (req, res) => {
    res.render('register');
});

app.post('/register', async (req, res) => {
        try {
                const { username, password } = req.body;
                const hashedPassword = await bcrypt.hash(password, 10);
                // New accounts are ordinary users by default. Never accept a
                // role from the registration form, or visitors could make
                // themselves admins by editing the submitted HTML.
                const user = new User({
                    username,
                    password: hashedPassword,
                    role: 'user'
                });

                await user.save();
                res.redirect('/login');
        } catch (error) {
                res.status(400).send('Could not create account. The username may already exist.');
        }
});

app.get('/login', (req, res) => {
    res.render('login');
});

app.post('/login', async (req, res) => {
        try {
                const { username, password } = req.body;
                const user = await User.findOne({ username });

                if (!user || !(await bcrypt.compare(password, user.password))) {
                        return res.redirect('/login');
                }

                // Admins use a separate login route and token. This keeps
                // the normal user authentication flow separate from the
                // higher-privilege administration flow.
                if (user.role === 'admin') {
                    return res.redirect('/admin/login');
                }

                // Signing in creates the JWT and sends it to the browser.
                setAuthCookie(res, user);
                res.redirect('/dashboard');
        } catch (error) {
                res.status(500).send('Could not log in. Please try again.');
    }
});

// Separate admin authentication: only a database user whose role is exactly
// "admin" can receive a token for this area.
app.get('/admin/login', (req, res) => {
    res.render('admin-login');
});

app.post('/admin/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const admin = await User.findOne({ username, role: 'admin' });

        if (!admin || !(await bcrypt.compare(password, admin.password))) {
            return res.redirect('/admin/login');
        }

        // The token includes the admin identity, and middleware checks the
        // database role again before every protected admin request.
        setAuthCookie(res, admin);
        res.redirect('/admin/users');
    } catch (error) {
        res.status(500).send('Could not log in as admin. Please try again.');
    }
});

app.post('/logout', (req, res) => {
    // JWTs are stateless, so logging out means removing the browser cookie.
    res.clearCookie(AUTH_COOKIE_NAME);
    res.redirect('/login');
});

// Private routes. Every route below requires a logged-in user.
app.get('/dashboard', isAuthenticated, (req, res) => {
    res.render('dashboard');
});

// This route is protected by authorization, not only authentication.
// The query deliberately selects safe profile fields and excludes password.
app.get('/admin/users', isAdminAuthenticated, async (req, res) => {
    const users = await User.find()
        .select('_id username role createdAt')
        .sort({ createdAt: -1 })
        .lean();

    res.render('admin-users', { admin: req.admin, users });
});

app.get('/home', isAuthenticated, async (req, res) => {
    const notes = await Note.find({ user: req.user.userId }).sort({ createdAt: -1 });
    res.render('home', { notes });
});

app.get('/create', isAuthenticated, (req, res) => {
    res.render('create');
});

app.post('/create', isAuthenticated, async (req, res) => {
    const { title, content } = req.body;
    const note = new Note({ title, content, user: req.user.userId });

    await note.save();
    res.redirect('/home');
});

app.get('/edit/:id', isAuthenticated, async (req, res) => {
    const note = await Note.findOne({ _id: req.params.id, user: req.user.userId });

    if (!note) {
        return res.status(404).send('Note not found');
    }

    res.render('edit', { note });
});

app.post('/edit/:id', isAuthenticated, async (req, res) => {
    const { title, content } = req.body;
    const note = await Note.findOneAndUpdate(
        { _id: req.params.id, user: req.user.userId },
        { title, content },
        { new: true }
    );

    if (!note) {
        return res.status(404).send('Note not found');
    }

    res.redirect('/home');
});

app.post('/delete/:id', isAuthenticated, async (req, res) => {
    await Note.findOneAndDelete({ _id: req.params.id, user: req.user.userId });
    res.redirect('/home');
});

// Start the server only after MongoDB is connected.
async function startServer() {
    try {
        if (!process.env.JWT_SECRET || !DATABASE_URL) {
            throw new Error('DATABASE_URL and JWT_SECRET must be set in .env');
        }

        await mongoose.connect(DATABASE_URL);
        console.log('Connected to MongoDB');

        app.listen(PORT, () => {
            console.log(`Server is running on http://localhost:${PORT}`);
        });
    } catch (error) {
        console.error('Could not connect to MongoDB:', error.message);
        process.exit(1);
    }
}

startServer();
