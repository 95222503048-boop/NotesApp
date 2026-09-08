const User = require('./models/user');

// Authentication answers: "Who is logged in?"
// This middleware protects normal user pages by checking the user session.
function isAuthenticated(req, res, next) {
    if (req.session && req.session.userId) {
        return next();
    }
    
    return res.redirect('/login');
}

// Authorization answers: "Is this logged-in person allowed to do this?"
// A session value alone is not enough for an admin check. We look up the
// current database record so a user's role can be changed or removed safely.
async function isAdminAuthenticated(req, res, next) {
    if (!req.session || !req.session.adminUserId) {
        return res.redirect('/admin/login');
    }

    const admin = await User.findOne({
        _id: req.session.adminUserId,
        role: 'admin'
    }).select('_id username role').lean();

    if (!admin) {
        return req.session.destroy(() => res.redirect('/admin/login'));
    }

    req.admin = admin;
    return next();
}

module.exports = { isAuthenticated, isAdminAuthenticated };