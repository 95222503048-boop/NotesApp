const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const session = require('express-session');
const User = require('./models/user');
const Note = require('./models/note');
const { isAuthenticated, isAdminAuthenticated } = require('./auth');

const app = express();
const PORT = 3000;
const DATABASE_URL = 'mongodb://localhost:27017/auth-app';

// Configure Express before defining routes.
app.set('view engine', 'ejs');
app.use(express.static('public'));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Sessions remember that a user has logged in.
app.use(session({
    secret: 'WelcomeBuddy',
    resave: false,
    saveUninitialized: false
}));

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

                // Admins use a separate login route and session. This keeps
                // the normal user authentication flow separate from the
                // higher-privilege administration flow.
                if (user.role === 'admin') {
                    return res.redirect('/admin/login');
                }

                req.session.userId = user._id;
                req.session.save((error) => {
                        if (error) {
                                return res.status(500).send('Unable to create session');
                        }

                        res.redirect('/dashboard');
                });
        } catch (error) {
                res.status(500).send('Could not log in. Please try again.');
    }
});

// Separate admin authentication: only a database user whose role is exactly
// "admin" can create an admin session. Being logged in as a normal user does
// not grant permission to enter this area.
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

        // Store the admin identity in a different session property.
        // Authorization middleware will verify this identity again.
        req.session.adminUserId = admin._id;
        req.session.save((error) => {
            if (error) {
                return res.status(500).send('Unable to create admin session');
            }

            res.redirect('/admin/users');
        });
    } catch (error) {
        res.status(500).send('Could not log in as admin. Please try again.');
    }
});

app.post('/logout', (req, res) => {
    req.session.destroy((error) => {
        if (error) {
            return res.status(500).send('Unable to log out');
        }

        res.clearCookie('connect.sid');
        res.redirect('/login');
    });
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
    const notes = await Note.find({ user: req.session.userId }).sort({ createdAt: -1 });
    res.render('home', { notes });
});

app.get('/create', isAuthenticated, (req, res) => {
    res.render('create');
});

app.post('/create', isAuthenticated, async (req, res) => {
    const { title, content } = req.body;
    const note = new Note({ title, content, user: req.session.userId });

    await note.save();
    res.redirect('/home');
});

app.get('/edit/:id', isAuthenticated, async (req, res) => {
    const note = await Note.findOne({ _id: req.params.id, user: req.session.userId });

    if (!note) {
        return res.status(404).send('Note not found');
    }

    res.render('edit', { note });
});

app.post('/edit/:id', isAuthenticated, async (req, res) => {
    const { title, content } = req.body;
    const note = await Note.findOneAndUpdate(
        { _id: req.params.id, user: req.session.userId },
        { title, content },
        { new: true }
    );

    if (!note) {
        return res.status(404).send('Note not found');
    }

    res.redirect('/home');
});

app.post('/delete/:id', isAuthenticated, async (req, res) => {
    await Note.findOneAndDelete({ _id: req.params.id, user: req.session.userId });
    res.redirect('/home');
});

// Start the server only after MongoDB is connected.
async function startServer() {
    try {
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
