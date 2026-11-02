
require('dotenv').config();

const session = require('express-session');
const db = require('./config/db');
const express = require('express');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const bcrypt = require('bcryptjs');

const app = express();


// ===============================
// EJS SETUP
// ===============================

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));


// ===============================
// STATIC FILES
// ===============================

app.use(express.static(path.join(__dirname, 'public')));


// ===============================
// FORM DATA
// ===============================

app.use(express.urlencoded({ extended: true }));

app.use(express.json());


// ===============================
// SESSION
// ===============================

app.use(session({

    secret: process.env.SESSION_SECRET || 'virtual-notice-board-secret',

    resave: false,

    saveUninitialized: false

}));


// ===============================
// MULTER FILE UPLOAD SETUP
// ===============================

const uploadFolder = path.join(
    __dirname,
    'public',
    'uploads',
    'notices'
);

fs.mkdirSync(uploadFolder, { recursive: true });


// Storage

const storage = multer.diskStorage({

    destination: function (req, file, cb) {

        cb(null, uploadFolder);

    },

    filename: function (req, file, cb) {

        const uniqueName =
            Date.now() + '-' + path.basename(file.originalname);

        cb(null, uniqueName);

    }

});


// Upload configuration

const upload = multer({

    storage: storage,

    limits: {
        fileSize: 10 * 1024 * 1024
    },

    fileFilter: function (req, file, cb) {

        const allowedTypes = [
            'application/pdf',
            'image/jpeg',
            'image/png',
            'image/gif',
            'image/webp'
        ];

        if (allowedTypes.includes(file.mimetype)) {

            cb(null, true);

        } else {

            cb(new Error(
                'Only PDF, JPG, PNG, GIF, and WEBP files are allowed.'
            ));

        }

    }

});


// ===============================
// LOGIN PAGE
// ===============================

app.get('/login', (req, res) => {

    res.render('login', {
        error: false,
        logout: false
    });

});


// ===============================
// REGISTER PAGE
// ===============================

app.get('/register', (req, res) => {

    res.render('register', {
        error: false
    });

});


// ===============================
// REGISTER USER
// ===============================

app.post('/register', async (req, res) => {

    const name = req.body.name;
    const username = req.body.username;
    const email = req.body.email;
    const password = req.body.password;

    const branch = req.body.branch;
    const academicYear = req.body.academicYear;

    // Password hashing

    const hashedPassword = await bcrypt.hash(password, 10);

    const sql = `
        INSERT INTO users
        (name, username, email, password, branch, academic_year)
        VALUES (?, ?, ?, ?, ?, ?)
    `;

    db.query(
        sql,
        [
            name,
            username,
            email,
            hashedPassword,
            branch,
            academicYear
        ],
        (err) => {

            if (err) {

                console.log(err);

                return res.render('register', {
                    error: "Registration failed. Username or email may already exist."
                });

            }

            res.redirect('/login');

        }

    );

});


// ===============================
// LOGIN USER
// ===============================

app.post('/login', async (req, res) => {

    const username = req.body.username;
    const password = req.body.password;

    const sql = `
        SELECT *
        FROM users
        WHERE username = ?
    `;

    db.query(sql, [username], async (err, result) => {

        if (err) {

            console.log(err);

            return res.send("Database error");

        }

        if (result.length > 0) {

            const storedPassword = result[0].password;

            // Check hashed password

            let isMatch = await bcrypt.compare(
                password,
                storedPassword
            );

            // Support existing plain-text passwords

            if (!isMatch && password === storedPassword) {

                isMatch = true;

                const hashedPassword = await bcrypt.hash(
                    password,
                    10
                );

                db.query(
                    'UPDATE users SET password = ? WHERE id = ?',
                    [hashedPassword, result[0].id]
                );

            }

            if (isMatch) {

                req.session.user = {

                    userId: result[0].id,

                    name: result[0].name,

                    username: result[0].username,

                    email: result[0].email,

                    role: result[0].role,

                    branch: result[0].branch,

                    academicYear: result[0].academic_year

                };

                return res.redirect('/dashboard');

            }

        }

        res.render('login', {
            error: true,
            logout: false
        });

    });

});


// ===============================
// DASHBOARD
// ===============================

app.get('/dashboard', (req, res) => {

    // Check login

    if (!req.session.user) {
        return res.redirect('/login');
    }

    const studentBranch = req.session.user.branch;
    const studentYear = req.session.user.academicYear;

    // Search

    const search = req.query.q || '';
    const searchValue = '%' + search + '%';

    // Filters

    const branch = req.query.branch || '';
    const year = req.query.year || '';
    const category = req.query.category || '';

    // Fetch notices

    const sql = `
        SELECT notices.*,

            CASE
                WHEN notice_reads.user_id IS NOT NULL THEN 1
                ELSE 0
            END AS isRead

        FROM notices

        LEFT JOIN notice_reads
            ON notices.id = notice_reads.notice_id
            AND notice_reads.user_id = ?

        WHERE (

            notices.title LIKE ?
            OR notices.description LIKE ?

        )

        AND (

            notices.deadline IS NULL
            OR notices.deadline >= CURDATE()

        )

        AND (

            ? = ''
            OR notices.target_branch = ?
            OR notices.target_branch = 'ALL'

        )

        AND (

            ? = ''
            OR notices.target_year = ?
            OR notices.target_year = 'ALL'

        )

        AND (

            ? = ''
            OR notices.category = ?

        )

        ORDER BY

            CASE notices.priority
                WHEN 'HIGH' THEN 1
                WHEN 'MEDIUM' THEN 2
                WHEN 'LOW' THEN 3
                ELSE 4
            END,

            CASE
                WHEN notices.deadline BETWEEN CURDATE()
                    AND DATE_ADD(CURDATE(), INTERVAL 7 DAY)
                THEN 1
                ELSE 2
            END,

            notices.deadline ASC,

            CASE

                WHEN notices.target_branch = ?
                    AND notices.target_year = ? THEN 1

                WHEN notices.target_branch = 'ALL'
                    AND notices.target_year = 'ALL' THEN 2

                WHEN notices.target_branch = ? THEN 3

                ELSE 4

            END,

            notices.created_at DESC
    `;

    db.query(
        sql,
        [

            req.session.user.userId,

            searchValue,
            searchValue,

            branch,
            branch,

            year,
            year,

            category,
            category,

            studentBranch,
            studentYear,
            studentBranch

        ],
        (err, result) => {

            if (err) {

                console.log(err);

                return res.send("Error loading notices");

            }

            // Upcoming deadlines

            const upcomingDeadlines = result.filter(n => {

                if (!n.deadline) {
                    return false;
                }

                const deadline = new Date(n.deadline);

                const today = new Date();

                today.setHours(0, 0, 0, 0);

                const next7Days = new Date();

                next7Days.setDate(next7Days.getDate() + 7);

                next7Days.setHours(23, 59, 59, 999);

                return deadline >= today && deadline <= next7Days;

            });

            // Dashboard

            res.render('dashboard', {

                currentUser: {

                    fullName: req.session.user.name,

                    role: req.session.user.role,

                    email: req.session.user.email,

                    branch: req.session.user.branch,

                    academicYear: req.session.user.academicYear

                },

                // ADMIN and SUPERADMIN

                isStaff: ['ADMIN', 'SUPERADMIN'].includes(
                    req.session.user.role
                ),

                // SUPERADMIN only

                isSuperAdmin:
                    req.session.user.role === 'SUPERADMIN',

                notices: result,

                examNotices: [],

                upcomingDeadlines: upcomingDeadlines,

                branches: [],

                examNoticeCount: 0,

                upcomingDeadlineCount: upcomingDeadlines.length,

                unreadCount: 0,

                q: search,

                category: category,

                branch: branch,

                year: year,

                uploadError: false

            });

        }

    );

});


// ===============================
// REQUEST ADMIN ACCESS
// ===============================

app.post('/request-admin', (req, res) => {

    // Check login

    if (!req.session.user) {
        return res.redirect('/login');
    }

    // Admin and Super Admin cannot request access

    if (['ADMIN', 'SUPERADMIN'].includes(req.session.user.role)) {
        return res.redirect('/dashboard');
    }

    const userId = req.session.user.userId;

    // Check pending request

    const checkSql = `
        SELECT *
        FROM admin_requests
        WHERE user_id = ?
        AND status = 'PENDING'
    `;

    db.query(checkSql, [userId], (err, result) => {

        if (err) {

            console.log(err);

            return res.send("Database error");

        }

        // Request already exists

        if (result.length > 0) {
            return res.redirect('/dashboard');
        }

        // Insert request

        const insertSql = `
            INSERT INTO admin_requests (user_id)
            VALUES (?)
        `;

        db.query(insertSql, [userId], (err) => {

            if (err) {

                console.log(err);

                return res.send("Error sending admin request");

            }

            res.redirect('/dashboard');

        });

    });

});


// ===============================
// VIEW ADMIN REQUESTS
// SUPERADMIN ONLY
// ===============================

app.get('/admin-requests', (req, res) => {

    // Check login

    if (!req.session.user) {
        return res.redirect('/login');
    }

    // Only Super Admin

    if (req.session.user.role !== 'SUPERADMIN') {
        return res.send("Access Denied");
    }

    const sql = `
        SELECT
            admin_requests.id,
            admin_requests.user_id,
            admin_requests.status,
            admin_requests.request_date,
            users.name,
            users.email
        FROM admin_requests
        JOIN users
            ON admin_requests.user_id = users.id
        WHERE admin_requests.status = 'PENDING'
        ORDER BY admin_requests.request_date DESC
    `;

    db.query(sql, (err, result) => {

        if (err) {

            console.log(err);

            return res.send("Error loading admin requests");

        }

        res.render('admin-requests', {
            requests: result
        });

    });

});


// ===============================
// APPROVE ADMIN REQUEST
// SUPERADMIN ONLY
// ===============================

app.post('/admin-requests/:id/approve', (req, res) => {

    // Check login

    if (!req.session.user) {
        return res.redirect('/login');
    }

    // Only Super Admin

    if (req.session.user.role !== 'SUPERADMIN') {
        return res.send("Access Denied");
    }

    const requestId = req.params.id;

    // Find request

    const findSql = `
        SELECT user_id
        FROM admin_requests
        WHERE id = ?
        AND status = 'PENDING'
    `;

    db.query(findSql, [requestId], (err, result) => {

        if (err) {

            console.log(err);

            return res.send("Database error");

        }

        if (result.length === 0) {
            return res.redirect('/admin-requests');
        }

        const userId = result[0].user_id;

        // Change user role to ADMIN

        const updateUserSql = `
            UPDATE users
            SET role = 'ADMIN'
            WHERE id = ?
        `;

        db.query(updateUserSql, [userId], (err) => {

            if (err) {

                console.log(err);

                return res.send("Error approving admin");

            }

            // Update request status

            const updateRequestSql = `
                UPDATE admin_requests
                SET status = 'APPROVED'
                WHERE id = ?
            `;

            db.query(updateRequestSql, [requestId], (err) => {

                if (err) {

                    console.log(err);

                    return res.send("Error updating request");

                }

                res.redirect('/admin-requests');

            });

        });

    });

});


// ===============================
// REJECT ADMIN REQUEST
// SUPERADMIN ONLY
// ===============================

app.post('/admin-requests/:id/reject', (req, res) => {

    // Check login

    if (!req.session.user) {
        return res.redirect('/login');
    }

    // Only Super Admin

    if (req.session.user.role !== 'SUPERADMIN') {
        return res.send("Access Denied");
    }

    const requestId = req.params.id;

    const sql = `
        UPDATE admin_requests
        SET status = 'REJECTED'
        WHERE id = ?
        AND status = 'PENDING'
    `;

    db.query(sql, [requestId], (err) => {

        if (err) {

            console.log(err);

            return res.send("Error rejecting request");

        }

        res.redirect('/admin-requests');

    });

});


// ===============================
// MARK NOTICE AS READ
// ===============================

app.post('/notices/:id/read', (req, res) => {

    // Check login

    if (!req.session.user) {
        return res.redirect('/login');
    }

    const noticeId = req.params.id;

    const userId = req.session.user.userId;

    const sql = `
        INSERT INTO notice_reads (notice_id, user_id)
        VALUES (?, ?)
        ON DUPLICATE KEY UPDATE read_at = CURRENT_TIMESTAMP
    `;

    db.query(sql, [noticeId, userId], (err) => {

        if (err) {

            console.log(err);

            return res.send("Error marking notice as read");

        }

        res.redirect('/dashboard');

    });

});


// ===============================
// CREATE NOTICE PAGE
// ADMIN AND SUPERADMIN
// ===============================

app.get('/create-notice', (req, res) => {

    if (!req.session.user) {
        return res.redirect('/login');
    }

    if (!['ADMIN', 'SUPERADMIN'].includes(req.session.user.role)) {
        return res.redirect('/dashboard');
    }

    res.render('create-notice');

});


// ===============================
// CREATE NOTICE
// ADMIN AND SUPERADMIN
// ===============================

app.post('/create-notice', upload.single('attachment'), (req, res) => {

    console.log("BODY:", req.body);

    console.log("FILE:", req.file);

    if (!req.session.user) {
        return res.redirect('/login');
    }

    if (!['ADMIN', 'SUPERADMIN'].includes(req.session.user.role)) {
        return res.redirect('/dashboard');
    }

    const title = req.body.title;

    const description = req.body.description;

    const category = req.body.category;

    const targetBranch = req.body.target_branch;

    const targetYear = req.body.target_year;

    const priority = req.body.priority;

    const deadline = req.body.deadline || null;

    // File attachment

    const attachment = req.file
        ? '/uploads/notices/' + req.file.filename
        : null;

    const createdBy = req.session.user.userId;

    const sql = `
        INSERT INTO notices
        (title, description, category, target_branch,
         target_year, priority, deadline, created_by, attachment)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;

    db.query(
        sql,
        [
            title,
            description,
            category,
            targetBranch,
            targetYear,
            priority,
            deadline,
            createdBy,
            attachment
        ],
        (err) => {

            if (err) {

                console.log(err);

                return res.send("Error while creating notice");

            }

            res.redirect('/dashboard');

        }

    );

});


// ===============================
// DELETE NOTICE
// ADMIN AND SUPERADMIN
// ===============================

app.post('/notices/:id/delete', (req, res) => {

    // Check login

    if (!req.session.user) {
        return res.redirect('/login');
    }

    // Check admin

    if (!['ADMIN', 'SUPERADMIN'].includes(req.session.user.role)) {
        return res.redirect('/dashboard');
    }

    const noticeId = req.params.id;

    // Delete read records first

    const deleteReadsSql = `
        DELETE FROM notice_reads
        WHERE notice_id = ?
    `;

    db.query(deleteReadsSql, [noticeId], (err) => {

        if (err) {

            console.log(err);

            return res.send("Error deleting notice read records");

        }

        // Delete notice

        const deleteNoticeSql = `
            DELETE FROM notices
            WHERE id = ?
        `;

        db.query(deleteNoticeSql, [noticeId], (err, result) => {

            if (err) {

                console.log(err);

                return res.send("Error deleting notice");

            }

            res.redirect('/dashboard');

        });

    });

});


// ===============================
// LOGOUT
// ===============================

app.get('/logout', (req, res) => {

    req.session.destroy((err) => {

        if (err) {

            console.log(err);

            return res.send("Error while logging out");

        }

        res.redirect('/');

    });

});


// ===============================
// HOME PAGE
// ===============================

app.get('/welcome', (req, res) => {

    res.render('welcome');

});

app.get('/', (req, res) => {

    res.redirect('/welcome');

});


// ===============================
// FILE UPLOAD ERROR HANDLING
// ===============================

app.use((err, req, res, next) => {

    console.log(err.message);

    res.status(400).send(
        err.message || 'Attachment upload failed.'
    );

});


// ===============================
// SERVER START
// ===============================

const PORT = 3000;

app.listen(PORT, () => {

    console.log(`Server running at http://localhost:${PORT}`);

});
