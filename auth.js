const User = require('./models/user');
const jwt = require('jsonwebtoken');

// The cookie name is kept in one place so login, middleware, and logout
// always use the same name.
const AUTH_COOKIE_NAME = 'authToken';

// A JWT is a small signed string. It lets the server identify the user
// without storing a login session for every visitor in server memory.
function createToken(user) {
    return jwt.sign(
        { userId: user._id.toString(), role: user.role },
        process.env.JWT_SECRET,
        { expiresIn: process.env.JWT_EXPIRES_IN || '1h' }
    );
}

// Put the token in an HTTP-only cookie. JavaScript in the browser cannot read
// this cookie, which makes it harder for an accidental script to steal it.
function setAuthCookie(res, user) {
    res.cookie(AUTH_COOKIE_NAME, createToken(user), {
        httpOnly: true,
        sameSite: 'lax',
        secure: process.env.NODE_ENV === 'production',
        maxAge: 60 * 60 * 1000
    });
}

// Read the token from the cookie and check its signature and expiration time.
// The decoded data is only trusted after jwt.verify succeeds.
function readToken(req) {
    const token = req.cookies && req.cookies[AUTH_COOKIE_NAME];

    if (!token) {
        return null;
    }

    try {
        return jwt.verify(token, process.env.JWT_SECRET);
    } catch (error) {
        return null;
    }
}

// Authentication answers: "Who is logged in?"
// This middleware protects normal user pages by checking the JWT cookie.
function isAuthenticated(req, res, next) {
    const tokenData = readToken(req);

    if (tokenData && tokenData.userId) {
        req.user = tokenData;
        return next();
    }

    return res.redirect('/login');
}

// Authorization answers: "Is this logged-in person allowed to do this?"
// A token value alone is not enough for an admin check. We look up the current
// database record so a role change takes effect immediately.
async function isAdminAuthenticated(req, res, next) {
    const tokenData = readToken(req);

    if (!tokenData || !tokenData.userId) {
        return res.redirect('/admin/login');
    }

    const admin = await User.findOne({
        _id: tokenData.userId,
        role: 'admin'
    }).select('_id username role').lean();

    if (!admin) {
        return res.clearCookie(AUTH_COOKIE_NAME).redirect('/admin/login');
    }

    req.admin = admin;
    return next();
}

module.exports = {
    AUTH_COOKIE_NAME,
    isAuthenticated,
    isAdminAuthenticated,
    setAuthCookie
};
