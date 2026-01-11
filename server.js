/**
 * XTRADE SERVER - PRODUCTION CORE
 * Version: 2.1.0
 * Features: Multi-Database User Isolation, Admin Management, OTP Auth, Referral System
 */

const express = require("express");
const bodyParser = require("body-parser");
const path = require("path");
const nodemailer = require("nodemailer");
const crypto = require("crypto");
const sqlite = require("sqlite");
const sqlite3 = require("sqlite3");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const fs = require("fs");
const os = require("os");

// -------- INITIALIZATION & GLOBALS -------- //
const app = express();
const PORT = process.env.PORT || 3000;
let db;

// -------- CONFIGURATION CONSTANTS -------- //
const ADMIN_EMAIL = "admin@example.com";
const ADMIN_PASSWORD = "Ezzyair1@";
const DB_PATH = path.join(__dirname, "xtrade.sqlite");
const USERS_DIR = path.join(__dirname, "users");
const LOG_PATH = path.join(__dirname, "server.log");

// Ensure essential directories and files exist
if (!fs.existsSync(USERS_DIR)) {
    console.log("Creating users directory...");
    fs.mkdirSync(USERS_DIR);
}

/**
 * LOGGER UTILITY
 * Records server events to both console and a local log file.
 */
function logger(message, type = "INFO") {
    const timestamp = new Date().toISOString();
    const logEntry = `[${timestamp}] [${type}] ${message}\n`;
    console.log(logEntry.trim());
    fs.appendFileSync(LOG_PATH, logEntry);
}

/**
 * USER DATABASE HANDLER
 * Opens a connection to a specific user's private SQLite file.
 * @param {string} username - The unique username for the database file.
 */
async function openUserDB(username) {
    try {
        const userDbPath = path.join(USERS_DIR, `${username}.sqlite`);
        const userDb = await sqlite.open({
            filename: userDbPath,
            driver: sqlite3.Database
        });

        // --- 1. Ensure user_replies table exists with 'pinned' column ---
        await userDb.exec(`
            CREATE TABLE IF NOT EXISTS user_replies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                reply_text TEXT,
                seen INTEGER DEFAULT 0,
                pinned INTEGER DEFAULT 0,
                date TEXT
            )
        `);

        // --- 2. Fix for "no such column: pinned" in user_replies ---
        // Even if table exists, older versions might miss the 'pinned' column
        try {
            await userDb.exec("ALTER TABLE user_replies ADD COLUMN pinned INTEGER DEFAULT 0");
        } catch (_) {
            // Column already exists
        }

        // --- 3. Ensure profile table exists (Basic Schema) ---
        await userDb.exec(`
            CREATE TABLE IF NOT EXISTS profile (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE,
                pin TEXT DEFAULT NULL
            )
        `);
        await userDb.exec(`
CREATE TABLE IF NOT EXISTS history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT,        -- CALL / PUT / Deposit / Withdrawal
    asset TEXT,
    amount REAL,
    status TEXT,      -- pending / completed
    date TEXT,
    profit REAL DEFAULT 0,     -- Profit/Loss
    percent REAL DEFAULT 0     -- % change
)
`);

await userDb.exec(`
CREATE TABLE IF NOT EXISTS transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT,
    amount REAL,
    date TEXT,
    status TEXT,
    method TEXT
)
`);



// MIGRATION: Add columns if they are missing in old files
try { await userDb.exec("ALTER TABLE history ADD COLUMN profit REAL DEFAULT 0"); } catch(e) {}
try { await userDb.exec("ALTER TABLE history ADD COLUMN percent REAL DEFAULT 0"); } catch(e) {}
try {
    await userDb.exec(`
        ALTER TABLE profile ADD COLUMN plan TEXT DEFAULT 'free'
    `);
} catch (e) {
    // column already exists → ignore
}

// Add 'signal' column if it doesn't exist
try {
    await userDb.exec(`
        ALTER TABLE profile ADD COLUMN signal TEXT DEFAULT 'none'
    `);
} catch (e) {
    // column already exists → ignore
}




        // --- 4. SAFE MIGRATIONS: Financial & System Columns ---
        const migrations = [
            "total_earnings REAL DEFAULT 0.00",
            "total_referral_count INTEGER DEFAULT 0",
            "pending_withdrawal REAL DEFAULT 0.00",
            "total_withdrawal REAL DEFAULT 0.00",
            "last_deposit REAL DEFAULT 0.00",
            "last_withdrawal REAL DEFAULT 0.00",
            "pinned INTEGER DEFAULT 0", // Fixed: Added to profile for UI state
            "pin TEXT DEFAULT NULL"     // Ensures PIN column exists for verification
        ];

        for (const colDef of migrations) {
            try {
                const colName = colDef.split(' ')[0];
                await userDb.exec(`ALTER TABLE profile ADD COLUMN ${colDef}`);
            } catch (_) {
                // Column already exists, ignore error
            }
        }

        return userDb;
    } catch (err) {
        logger(`CRITICAL: Failed to open/migrate DB for user: ${username} - ${err.message}`, "ERROR");
        throw err;
    }
}


// -------- MIDDLEWARE STACK -------- //

// Security & Header Management
app.use((req, res, next) => {
    res.setHeader("X-Powered-By", "Xtrade-Core");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("X-Content-Type-Options", "nosniff");
    next();
});

// CORS Configuration
app.use(cors({
    origin: function (origin, callback) {
        // Allows all origins for development, can be restricted later
        return callback(null, true);
    },
    credentials: true
}));

// Body Parsing & Cookies
app.use(bodyParser.json({ limit: '100mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '100mb' }));
app.use(cookieParser());

// Static File Hosting
app.use(express.static(path.join(__dirname)));
app.use("/Dashboard", express.static(path.join(__dirname, "Dashboard")));
app.use("/admin", express.static(path.join(__dirname, "admin")));
app.use('/profile', express.static(path.join(__dirname, 'profile')));

// -------- VIEW ROUTES -------- //

app.get("/account/register", (req, res) => {
    res.sendFile(path.join(__dirname, "account/register/index.html"));
});

app.get("/account/login", (req, res) => {
    res.sendFile(path.join(__dirname, "account/login/index.html"));
});

app.get("/account/process", (req, res) => {
    res.sendFile(path.join(__dirname, "account/process/index.html"));
});

// -------- EMAIL TRANSPORT -------- //

// -------- REPAIRED EMAIL TRANSPORT -------- //
const transporter = nodemailer.createTransport({
    host: "smtp.gmail.com",
    port: 465,       // Use 465 for a more stable "Secure from start" connection
    secure: true,    // Required for port 465
    auth: {
        user: "john03t4@gmail.com",
        // MUST BE A 16-CHARACTER APP PASSWORD
        pass: "sbcsqmjtzexxaklk" 
    },
    tls: {
        // This prevents the "Socket Disconnected" error in many network environments
        rejectUnauthorized: false,
        servername: "smtp.gmail.com"
    }
});

// Diagnostic check on startup
transporter.verify((error, success) => {
    if (error) {
        logger(`SMTP Diagnostic Failed: ${error.message}`, "ERROR");
        console.log("Check: 1. Is your internet active? 2. Is the App Password correct?");
    } else {
        logger("SMTP Gateway established and verified.", "SUCCESS");
    }
});

/**
 * EMAIL TEMPLATE GENERATOR
 * Returns a styled HTML email for the verification code.
 */
function getVerificationEmailHtml(fname, code) {
    const year = new Date().getFullYear();
    return `
    <div style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; font-size: 15px; color: #333; line-height: 1.8; max-width: 600px; margin: auto; border: 1px solid #eee; padding: 20px;">
        <div style="text-align: center; border-bottom: 2px solid #007bff; padding-bottom: 10px; margin-bottom: 20px;">
            <h1 style="color: #007bff; margin: 0;">Xtrade</h1>
        </div>
        <h2 style="font-size: 20px; color: #000; font-weight: 600;">Account Verification Required</h2>
        <p>Hello <strong>${fname}</strong>,</p>
        <p>
            Welcome to the Xtrade community. To complete your registration and secure your account, 
            please use the verification code provided below.
        </p>
        <div style="background-color: #f8f9fa; border-radius: 8px; padding: 20px; text-align: center; margin: 30px 0;">
            <span style="font-size: 32px; font-weight: bold; letter-spacing: 5px; color: #007bff;">${code}</span>
        </div>
        <p>This code is valid for 60 minutes. If you did not request this, please ignore this email.</p>
        <p>Warm regards,<br><strong>Xtrade Management Team</strong></p>
        <div style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #eee; font-size: 12px; color: #888;">
            <p>
                All materials and services provided in this email are subject to copyright and belong to Xtrade.
                Any unauthorized duplication or violation will be prosecuted under international intellectual property laws.
            </p>
            <p>Copyright &copy; ${year} Xtrade. All rights reserved.</p>
        </div>
    </div>`;
}

// -------- DATABASE INITIALIZATION -------- //

async function initDB() {
    try {
        db = await sqlite.open({
            filename: DB_PATH,
            driver: sqlite3.Database
        });

        logger("Master Oracle Database connected successfully.");

        /* ---------------------------------- */
        /* VERIFIED USERS TABLE               */
        /* ---------------------------------- */
        await db.exec(`
            CREATE TABLE IF NOT EXISTS verified_users (
                email TEXT PRIMARY KEY,
                fname TEXT,
                lname TEXT,
                username TEXT UNIQUE,
                password TEXT,
                status TEXT DEFAULT 'offline',
                last_seen INTEGER,
                mobile TEXT,
                referral TEXT,
                country TEXT,
                address TEXT,
                zip TEXT,
                profile_pic TEXT DEFAULT 'profile/default.png',
                currency TEXT,
                account TEXT,
                registration_date TEXT,
                user_ref_code TEXT UNIQUE,

                reset_token TEXT,
                reset_expires INTEGER,

                pin TEXT,
                pin_reset_code TEXT,
                pin_reset_expiry INTEGER,
                pin_reset_verified INTEGER DEFAULT 0
            )
        `);

        /* ---------------------------------- */
        /* PENDING USERS TABLE                */
        /* ---------------------------------- */
        await db.exec(`
            CREATE TABLE IF NOT EXISTS pending_users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE,
                fname TEXT,
                lname TEXT,
                username TEXT UNIQUE,
                password TEXT,
                mobile TEXT,
                referral TEXT,
                country TEXT,
                address TEXT,
                zip TEXT,
                profile_pic TEXT DEFAULT 'profile/default.png',
                currency TEXT,
                account TEXT,
                code INTEGER,
                expiresAt INTEGER,
                registration_date TEXT,
                user_ref_code TEXT UNIQUE
            )
        `);

        /* ---------------------------------- */
        /* NOTIFICATIONS TABLE                */
        /* ---------------------------------- */
        await db.exec(`
            CREATE TABLE IF NOT EXISTS notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT,
                message TEXT,
                type TEXT DEFAULT 'ADMIN_MESSAGE',
                date TEXT
            )
        `);


        /* ---------------------------------- */
        /* SAFE MIGRATIONS (SQLITE-CORRECT)   */
        /* ---------------------------------- */

        // verified_users migrations (ONE COLUMN PER ALTER)
        try { await db.exec("ALTER TABLE verified_users ADD COLUMN reset_token TEXT"); } catch (_) {}
        try { await db.exec("ALTER TABLE verified_users ADD COLUMN reset_expires INTEGER"); } catch (_) {}
        try { await db.exec("ALTER TABLE verified_users ADD COLUMN pin TEXT"); } catch (_) {}
        try { await db.exec("ALTER TABLE verified_users ADD COLUMN pin_reset_code TEXT"); } catch (_) {}
        try { await db.exec("ALTER TABLE verified_users ADD COLUMN pin_reset_expiry INTEGER"); } catch (_) {}
        try { await db.exec("ALTER TABLE verified_users ADD COLUMN pin_reset_verified INTEGER DEFAULT 0"); } catch (_) {}

        // pending_users migrations
        try {
            await db.exec(
                "ALTER TABLE pending_users ADD COLUMN profile_pic TEXT DEFAULT 'profile/default.png'"
            );
        } catch (_) {}

        /* ---------------------------------- */
        /* USER REPLIES MIGRATIONS            */
        /* ---------------------------------- */
        try {
            await db.exec(
                "ALTER TABLE user_replies ADD COLUMN pinned INTEGER DEFAULT 0"
            );
            logger("Migration applied: user_replies.pinned", "SUCCESS");
        } catch (_) {}

        /* ---------------------------------- */
        /* DATA NORMALIZATION (CRITICAL)      */
        /* ---------------------------------- */

        await db.exec(`
            UPDATE verified_users
            SET profile_pic = 'img/profile/default.png'
            WHERE profile_pic IS NULL OR profile_pic = ''
        `);

        await db.exec(`
            UPDATE pending_users
            SET profile_pic = 'img/profile/default.png'
            WHERE profile_pic IS NULL OR profile_pic = ''
        `);

        /* ---------------------------------- */
        /* START SERVER                       */
        /* ---------------------------------- */
        app.listen(PORT, () => {
            logger(`Xtrade Financial Gateway running on port ${PORT}`, "SUCCESS");
        });

    } catch (err) {
        logger(`Critical System Failure: ${err.message}`, "FATAL");
        process.exit(1);
    }
}


async function getAllUsers() {
    const rows = await db.all(
        "SELECT username FROM verified_users WHERE username IS NOT NULL"
    );
    return rows.map(r => r.username);
}


// -------- AUTHENTICATION LOGIC -------- //

/**
 * REGISTRATION ENDPOINT
 * Handles initial sign-up and triggers verification email.
 */
/**
 * REGISTRATION ENDPOINT
 * Handles initial sign-up and triggers verification email.
 */
app.post("/account/register", async (req, res) => {
    const {
        fname, lname, username, email, mobile,
        referral, password, country, address,
        currency, account
    } = req.body;

    // Validation
    if (!fname || !lname || !username || !email || !password || !country || !mobile) {
        return res.status(400).json({
            success: false,
            message: "Required fields are missing."
        });
    }

    try {
        // Check availability
        const isVerified = await db.get(
            "SELECT 1 FROM verified_users WHERE email=? OR username=?",
            [email, username]
        );

        const isPending = await db.get(
            "SELECT 1 FROM pending_users WHERE email=? OR username=?",
            [email, username]
        );

        if (isVerified || isPending) {
            return res.status(409).json({
                success: false,
                message: "Email or Username already taken."
            });
        }

        // Validate referral
        if (referral) {
            const refCheck = await db.get(
                "SELECT 1 FROM verified_users WHERE username=?",
                [referral]
            );

            if (!refCheck) {
                return res.status(400).json({
                    success: false,
                    message: "The referral code provided is invalid."
                });
            }
        }

        const code = crypto.randomInt(100000, 999999);
        const expiresAt = Date.now() + 60 * 60 * 1000;
        const regDate = new Date().toISOString();

        const accountArray = Array.isArray(account) ? account : [];

        await db.run(
            `INSERT INTO pending_users
            (fname, lname, username, email, mobile, referral, password, country, address, currency, account, code, expiresAt, registration_date, user_ref_code)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
            [
                fname,
                lname,
                username,
                email,
                mobile || "",
                referral || "",
                password,
                country,
                address || "",
                currency || "USD",
                JSON.stringify(accountArray),
                code,
                expiresAt,
                regDate,
                username
            ]
        );

        // Send verification email (non-blocking)
        try {
            await transporter.sendMail({
                from: '"Xtrade Support" <john03t4@gmail.com>',
                to: email,
                subject: "Verify Your Xtrade Account",
                html: getVerificationEmailHtml(fname, code)
            });
        } catch (mailErr) {
            logger(`EMAIL SEND FAILED for ${email}: ${mailErr.message}`, "WARN");
        }

        logger(`New registration: ${username} (${email})`);

        // ✅ SUCCESS RESPONSE (THIS TRIGGERS YOUR POPUP)
        return res.status(200).json({
            success: true,
            email,
            message: "Registration successful. Verification code sent."
        });

    } catch (err) {
        logger(`Register Error: ${err.message}`, "ERROR");
        return res.status(500).json({
            success: false,
            message: "Internal server error."
        });
    }
});



/**
 * UPDATED VERIFICATION (PROCESS) ENDPOINT
 * Fix: Skips referral process if the referral code is empty.
 */
app.post("/account/process", async (req, res) => {
    const { email, evc } = req.body;

    if (!email || !evc) {
        return res.status(400).json({ success: false, message: "Invalid request payload." });
    }

    try {
        // 1️⃣ Fetch pending user
        const user = await db.get("SELECT * FROM pending_users WHERE email=?", [email]);
        if (!user) return res.status(404).json({ success: false, message: "Registration record not found." });
        if (user.code.toString() !== evc.trim()) return res.status(401).json({ success: false, message: "Invalid code." });
        if (Date.now() > user.expiresAt) return res.status(401).json({ success: false, message: "Code has expired." });

        // 2️⃣ Check if username exists in verified_users
        const existingUser = await db.get("SELECT 1 FROM verified_users WHERE username=?", [user.username]);
        if (!existingUser) {
            await db.run(
                `INSERT INTO verified_users 
                (email, fname, lname, username, password, mobile, referral, country, address, currency, account, registration_date, user_ref_code) 
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
                [
                    user.email, user.fname, user.lname, user.username, user.password, user.mobile,
                    user.referral, user.country, user.address, user.currency, user.account, user.registration_date, user.username
                ]
            );
            logger(`User ${user.username} added to verified_users`, "SUCCESS");
        } else {
            logger(`User ${user.username} already exists in verified_users. Skipping insert.`, "INFO");
        }

        // 3️⃣ Handle referral logic
        if (user.referral && user.referral.trim() !== "") {
            const referrer = await db.get(
                "SELECT username FROM verified_users WHERE username = ?",
                [user.referral]
            );
            if (referrer) {
                try {
                    const refDb = await openUserDB(referrer.username);
                    
                    // Increment referral count
                    await refDb.run(
                        "UPDATE profile SET total_referral_count = total_referral_count + 1, total_balance = total_balance + 10 WHERE username = ?",
                        [referrer.username]
                    );

                    // Send Notification
                    await refDb.exec(`CREATE TABLE IF NOT EXISTS notifications (id INTEGER PRIMARY KEY AUTOINCREMENT, msg TEXT, type TEXT, seen INTEGER DEFAULT 0, date TEXT)`);
                    
                    await refDb.run(
                        "INSERT INTO notifications (msg, type, seen, date) VALUES (?, ?, 0, ?)",
                        ["You just invited a friend $10", "success", new Date().toISOString()]
                    );

                    await refDb.close();
                    logger(`Referral count updated for: ${referrer.username}`, "SUCCESS");
                } catch (refErr) {
                    logger(`Failed to update referral count for ${referrer.username}: ${refErr.message}`, "ERROR");
                }
            } else {
                logger(`Referral code ${user.referral} invalid. Skipping referral update.`, "INFO");
            }
        } else {
            logger(`No referral code provided for user: ${user.username}. Skipping referral update.`, "INFO");
        }

        // 4️⃣ Initialize private user DB
        const userDb = await openUserDB(user.username);

        // 4a️⃣ Ensure profile table exists
        await userDb.exec(`
            CREATE TABLE IF NOT EXISTS profile (
                id INTEGER PRIMARY KEY AUTOINCREMENT
            )
        `);

        // 4b️⃣ Add missing columns safely
        const columns = [
            "fname TEXT",
            "lname TEXT",
            "username TEXT",
            "email TEXT",
            "mobile TEXT",
            "country TEXT",
            "address TEXT",
            "zip TEXT",
            "profile_pic TEXT DEFAULT 'profile/default.png'",
            "referral TEXT",
            "currency TEXT",
            "account TEXT",
            "password TEXT",
            "pin TEXT DEFAULT NULL",
            "reg_date TEXT",
            "total_balance REAL DEFAULT 0.00",
            "total_bonus REAL DEFAULT 55.00",
            "investment REAL DEFAULT 0.00",
            "total_earnings REAL DEFAULT 0.00",
            "total_referral_count INTEGER DEFAULT 0",
            "pending_withdrawal REAL DEFAULT 0.00",
            "total_withdrawal REAL DEFAULT 0.00",
            "last_deposit REAL DEFAULT 0.00",
            "last_withdrawal REAL DEFAULT 0.00"
        ];

        for (const colDef of columns) {
            const colName = colDef.split(' ')[0];
            try {
                await userDb.exec(`ALTER TABLE profile ADD COLUMN ${colDef}`);
                logger(`Migrated profile column [${colName}] for: ${user.username}`, "SUCCESS");
            } catch (_) {
                // Column already exists → ignore
            }
        }

        // 4c️⃣ Insert user profile safely
        await userDb.run(
            `INSERT OR IGNORE INTO profile 
            (fname, lname, username, email, mobile, country, address, referral, currency, account, password, reg_date) 
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
            [user.fname, user.lname, user.username, user.email, user.mobile, user.country, user.address, user.referral, user.currency, user.account, user.password, user.registration_date]
        );

        // 4d️⃣ Notifications table
        await userDb.exec(`
            CREATE TABLE IF NOT EXISTS notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                msg TEXT,
                type TEXT,
                seen INTEGER DEFAULT 0,
                date TEXT
            )
        `);
        await userDb.run(
            "INSERT INTO notifications (msg, type, date) VALUES (?, ?, ?)",
            ["Welcome to Xtrade!", "success", new Date().toISOString()]
        );

        await userDb.close();

        // 5️⃣ Delete pending record
        await db.run("DELETE FROM pending_users WHERE email=?", [email]);

        logger(`Database initialized for: ${user.username}`, "SUCCESS");
        res.json({ success: true, message: "Account successfully verified." });

    } catch (err) {
        logger(`Process Error: ${err.message}`, "ERROR");
        res.status(500).json({ success: false, message: "Error during verification." });
    }
});

/**
 * RESEND VERIFICATION CODE ENDPOINT
 * Regenerates a code for a pending user and sends it via email.
 */
app.post("/account/resend-code", async (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({ success: false, message: "Email is required." });
    }

    try {
        // 1. Check if the user is actually in the pending table
        const user = await db.get("SELECT fname, email FROM pending_users WHERE email = ?", [email]);

        if (!user) {
            // Check if they are already verified
            const isVerified = await db.get("SELECT 1 FROM verified_users WHERE email = ?", [email]);
            if (isVerified) {
                return res.status(400).json({ success: false, message: "Account is already verified. Please login." });
            }
            return res.status(404).json({ success: false, message: "No pending registration found for this email." });
        }

        // 2. Generate new code and expiry (1 hour from now)
        const newCode = crypto.randomInt(100000, 999999);
        const newExpiresAt = Date.now() + (60 * 60 * 1000);

        // 3. Update the pending_users table
        await db.run(
            "UPDATE pending_users SET code = ?, expiresAt = ? WHERE email = ?",
            [newCode, newExpiresAt, email]
        );

        // 4. Send the email with the new code
        await transporter.sendMail({
            from: '"Xtrade Support" <john03t4@gmail.com>',
            to: email,
            subject: "Your New Verification Code",
            html: getVerificationEmailHtml(user.fname, newCode)
        });

        logger(`Resent verification code to: ${email}`);
        res.json({ success: true, message: "A new verification code has been sent to your email." });

    } catch (err) {
        logger(`Resend Code Error: ${err.message}`, "ERROR");
        res.status(500).json({ success: false, message: "Failed to resend code. Please try again later." });
    }
});

/**
 * UPDATED LOGIN ENDPOINT
 */
app.post("/account/login", async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) return res.status(400).json({ success: false, message: "Credentials required." });

    try {
        // Step 1: Find the user in the Main Verified Table to get their unique Username
        const identity = await db.get("SELECT username, email, status FROM verified_users WHERE email=? OR username=?", [username, username]);

        if (identity) {
            // Check if suspended
            if (identity.status === 'suspended') {
                return res.status(405).json({ success: false, message: "Account suspended." });
            }

            // Step 2: Open the specific user database (e.g., users/cenz.sqlite)
            const userDb = await openUserDB(identity.username);
            
            // Step 3: Check if the password matches in the private database
            const userProfile = await userDb.get("SELECT password FROM profile WHERE password=?", [password]);
            await userDb.close();

            if (userProfile) {
                // Update presence in main DB
                await db.run("UPDATE verified_users SET status = 'online', last_seen = ? WHERE email = ?", [Date.now(), identity.email]);
                
                logger(`Login successful via private DB: ${identity.username}`);
                return res.json({ 
                    success: true, 
                    verified: true, 
                    email: identity.email, 
                    username: identity.username 
                });
            } else {
                return res.status(401).json({ success: false, message: "Invalid password." });
            }
        }

        // Step 4: Fallback to Pending Users (if not yet verified)
        const pendingUser = await db.get("SELECT * FROM pending_users WHERE (email=? OR username=?) AND password=?", [username, username, password]);
        if (pendingUser) {
            return res.status(403).json({
                success: false,
                verified: false,
                message: "Account not verified.",
                email: pendingUser.email
            });
        }

        return res.status(404).json({ success: false, message: "User not found." });

    } catch (err) {
        logger(`Login Error: ${err.message}`, "ERROR");
        res.status(500).json({ success: false, message: "Server error during login." });
    }
});

// -------- CONTACT FORM ROUTE -------- //
// -------- FIXED CONTACT FORM ROUTE -------- //
app.post("/api/contact", async (req, res) => {
    const { name, email, subject, message } = req.body;

    // 1. Validation: Ensures all fields are present
    if (!name || !email || !subject || !message) {
        return res.status(400).json({ success: false, message: "All fields are required." });
    }

    // 2. Setup Mail Options: Matches the logic used in /account/register
    const mailOptions = {
        // Use the authenticated email address to prevent SMTP rejection
        from: '"Xtrade Contact System" <john03t4@gmail.com>', 
        to: "john03t4@gmail.com", 
        // Sets the user's email as the Reply-To so you can respond directly to them
        replyTo: email, 
        subject: `New Contact Form Submission: ${subject}`,
        html: `
            <div style="font-family: Arial, sans-serif; padding: 20px; border: 1px solid #253978; max-width: 600px;">
                <h2 style="color: #253978; border-bottom: 2px solid #253978; padding-bottom: 10px;">New Message from ${name}</h2>
                <p><strong>User Email:</strong> ${email}</p>
                <p><strong>Subject:</strong> ${subject}</p>
                <div style="background-color: #f4f4f4; padding: 15px; border-radius: 5px; margin-top: 15px;">
                    <p style="white-space: pre-wrap; color: #333;">${message}</p>
                </div>
                <p style="font-size: 11px; color: #888; margin-top: 20px;">
                    This email was generated by the Xtrade Server Contact API.
                </p>
            </div>`
    };

    try {
        // 3. Send via the verified transporter
        await transporter.sendMail(mailOptions);
        
        logger(`Contact email sent successfully from: ${email}`, "SUCCESS");
        res.json({ success: true, message: "Email sent successfully." });
    } catch (err) {
        // 4. Detailed error logging for debugging
        logger(`Failed to send contact email: ${err.message}`, "ERROR");
        res.status(500).json({ 
            success: false, 
            message: "Internal server error.",
            error: err.message 
        });
    }
});

app.post("/account/forgot-password", async (req, res) => {
    const { email } = req.body;
    try {
        const user = await db.get("SELECT fname, username, reset_expires FROM verified_users WHERE email = ?", [email]);
        
        if (!user) {
            return res.status(404).json({ 
                success: false, 
                message: "This email is not registered in our records." 
            });
        }

        // --- UPDATED BLOCK START ---
        // Allow a new email to be sent if the last one was sent more than 30 seconds ago
        // The original logic checked for the full 30-minute expiry (reset_expires > Date.now())
        // We calculate 'sentAt' by subtracting the 30-minute duration from the expiry timestamp
        const sentAt = user.reset_expires ? (user.reset_expires - (30 * 60 * 1000)) : 0;
        const secondsSinceLastEmail = (Date.now() - sentAt) / 1000;

        if (user.reset_expires && secondsSinceLastEmail < 30) {
            return res.status(406).json({
                success: false,
                message: `Please wait ${Math.ceil(30 - secondsSinceLastEmail)} seconds before requesting another link.`
            });
        }
        // --- UPDATED BLOCK END ---

        const resetCode = crypto.randomBytes(20).toString('hex');
        const expiresAt = Date.now() + (30 * 60 * 1000); // 30 minutes valid link duration

        await db.run(
            "UPDATE verified_users SET reset_token = ?, reset_expires = ? WHERE email = ?", 
            [resetCode, expiresAt, email]
        );

        // Logic for sending the email remains the same...
        const resetLink = `http://127.0.0.1:5500/account/reset?Y76D=${resetCode}`;

        await transporter.sendMail({
            from: '"Xtrade Support" <john03t4@gmail.com>',
            to: email,
            subject: "Password Reset Request",
            html: `
                <div style="font-family: Arial, sans-serif; padding: 25px; border: 1px solid #e2e8f0; border-radius: 10px; max-width: 600px; margin: auto;">
                    <div style="text-align: center; margin-bottom: 20px;">
                        <h2 style="color: #253978; margin-bottom: 10px;">Secure Password Reset</h2>
                        <p style="color: #64748b;">Hello ${user.fname}, click the button below to update your security credentials.</p>
                    </div>
                    <div style="text-align: center; margin: 35px 0;">
                        <a href="${resetLink}" style="background-color: #253978; color: #ffffff; padding: 14px 30px; text-decoration: none; border-radius: 8px; font-weight: bold; font-size: 16px; display: inline-block;">Update Password Now</a>
                    </div>
                    <p style="font-size: 12px; color: #94a3b8; text-align: center;">This link expires in 30 minutes.</p>
                </div>`
        });

        logger(`Reset Link Sent to: ${email}`);
        return res.status(200).json({ 
            success: true, 
            message: "A secure reset link has been sent to your email." 
        });

    } catch (err) {
        console.error("Forgot Password Error:", err);
        return res.status(500).json({ success: false, message: "Internal delivery failure." });
    }
});



/* --- VERIFY RESET LINK --- */
app.get("/account/verify-reset-link", async (req, res) => {
    const { code } = req.query;
    if (!code) return res.status(400).json({ success: false, message: "Missing reset token." });

    try {
        const user = await db.get(
            "SELECT email, reset_expires FROM verified_users WHERE reset_token = ?",
            [code]
        );

        if (!user) return res.status(401).json({ success: false, message: "Invalid reset link." });
        if (Date.now() > user.reset_expires) return res.status(401).json({ success: false, message: "Reset link has expired." });

        res.json({ success: true, message: "Reset link verified." });
    } catch (err) {
        console.error("Verify link error:", err);
        res.status(500).json({ success: false, message: "Server verification error." });
    }
});

/* --- RESET PASSWORD --- */
/* --- RESET PASSWORD --- */
app.post("/account/reset-password", async (req, res) => {
    const { code, newPassword } = req.body;

    if (!code || !newPassword) {
        return res.status(400).json({ success: false, message: "Invalid request." });
    }

    try {
        // 1️⃣ Get user by token
        const user = await db.get(
            "SELECT email, username, password, reset_expires FROM verified_users WHERE reset_token = ?",
            [code]
        );

        if (!user) {
            return res.status(401).json({ success: false, message: "Invalid or expired reset session." });
        }

        if (Date.now() > user.reset_expires) {
            return res.status(401).json({ success: false, message: "Reset session expired." });
        }

        // 2️⃣ Check if new password is the same as current password
        if (newPassword === user.password) {
            return res.json({ success: false, info: true, message: "New password cannot be the same as your current password." });
        }

        // 3️⃣ Update password directly (plain text)
        await db.run(
            "UPDATE verified_users SET password = ?, reset_token = NULL, reset_expires = NULL WHERE email = ?",
            [newPassword, user.email]
        );

        // 4️⃣ Sync with user DB if needed
        if (user.username) {
            const userDb = await openUserDB(user.username);
            await userDb.run("UPDATE profile SET password = ? WHERE email = ?", [newPassword, user.email]);
            await userDb.close();
        }

        res.json({ success: true, message: "Password updated successfully." });

    } catch (err) {
        console.error("Reset password error:", err);
        res.status(500).json({ success: false, message: "Server error or sync failed." });
    }
});




/**
 * PRESENCE UPDATER
 * Updates the user's online/offline status.
 */
app.post("/account/status", async (req, res) => {
    const { email, status } = req.body;
    if (!email) return res.status(400).send("Identifier missing");

    try {
        await db.run(
            "UPDATE verified_users SET status = ?, last_seen = ? WHERE email = ?",
            [status || 'offline', Date.now(), email]
        );
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ success: false });
    }
});

// -------- DASHBOARD OPERATIONS -------- //

// -------- UPDATED DASHBOARD DATA ENDPOINT -------- //
app.post("/Dashboard/data", async (req, res) => {
    const { email } = req.body;
    
    if (!email) {
        return res.status(400).json({ success: false, message: "Email identifier missing" });
    }

    try {
        // 1. Fetch user status and username from the main table
        const userRef = await db.get("SELECT username, status FROM verified_users WHERE email=?", [email]);
        
        // 2. Account Existence Check
        if (!userRef) {
            logger(`Dashboard Access Denied: Unregistered email (${email})`, "WARN");
            return res.status(200).json({ success: false, message: "Account not registered on server" });
        }

        // 3. SUSPENSION CHECK
        if (userRef.status && userRef.status.toLowerCase() === 'suspended') {
            logger(`Dashboard Access Blocked: Suspended account (${email})`, "INFO");
            return res.json({ 
                success: true, 
                data: { status: 'suspended' } 
            });
        }

        // 4. Open private DB based on verified username
        const userDb = await openUserDB(userRef.username);
        const privateData = await userDb.get("SELECT * FROM profile");
        await userDb.close();

        // Check if profile exists in the private DB
        if (!privateData) {
            logger(`Dashboard Error: Profile row missing for ${userRef.username}`, "ERROR");
            return res.status(404).json({ success: false, message: "Profile data missing" });
        }

        /**
         * FIX: ENSURE EARNINGS IS DEFINED
         * We check for 'total_earnings' and 'earnings' (in case of naming mismatch)
         * and force the result to be a valid number.
         */
        privateData.total_earnings = parseFloat(privateData.total_earnings || privateData.earnings || 0);

        // 5. Merge status and other required fields
        privateData.status = userRef.status;

        // Final safety check for all numeric fields to prevent frontend 'NaN' or 'undefined'
        const numericFields = ['total_balance', 'total_bonus', 'investment', 'pending_withdrawal', 'total_withdrawal'];
        numericFields.forEach(field => {
            privateData[field] = parseFloat(privateData[field] || 0);
        });

        res.json({ success: true, data: privateData });
    } catch (err) {
        logger(`Dashboard Data Error: ${err.message}`, "ERROR");
        res.status(500).json({ success: false, message: "Internal Server Error" });
    }
});


// --- NEW: CHANGE PASSWORD ---
app.post("/api/change-password", async (req, res) => {
    const { email, oldPassword, newPassword } = req.body;

    if (!email || !oldPassword || !newPassword) {
        return res.status(400).json({ success: false, message: "Required fields missing." });
    }

    try {
        // 1. Fetch the user's current password and username from the Master Database
        const masterUser = await db.get("SELECT username, password FROM verified_users WHERE email = ?", [email]);

        if (!masterUser) {
            return res.status(404).json({ success: false, message: "Account not found." });
        }

        // 2. Validate the old password
        if (masterUser.password !== oldPassword) {
            return res.status(401).json({ success: false, message: "The current password provided is incorrect." });
        }

        // 3. Update the Master Database (xtrade.sqlite)
        await db.run("UPDATE verified_users SET password = ? WHERE email = ?", [newPassword, email]);
        
        // 4. Update the Private User Database (e.g., users/username.sqlite)
        // We use your openUserDB utility to access the isolated file
        const userDb = await openUserDB(masterUser.username);
        
        // Update the password inside the private profile table
        await userDb.run("UPDATE profile SET password = ? WHERE email = ?", [newPassword, email]);
        
        // Close the connection to avoid file locking
        await userDb.close();

        logger(`Password sync completed for: ${masterUser.username}`, "SUCCESS");
        res.json({ success: true, message: "Password updated in all records." });

    } catch (err) {
        logger(`Sync Error: ${err.message}`, "ERROR");
        res.status(500).json({ success: false, message: "Failed to sync password across databases." });
    }
});

// --- NEW: CHANGE PROFILE IMAGE ---
// 2. Updated Route
app.post("/api/change-profile-pic", async (req, res) => {
    const { email, imageBase64 } = req.body;

    // HARD GUARD
    if (!email || !imageBase64 || !imageBase64.startsWith("data:image")) {
        return res.status(400).json({
            success: false,
            message: "Invalid image upload"
        });
    }

    try {
        const user = await db.get(
            "SELECT username FROM verified_users WHERE email = ?",
            [email]
        );

        if (!user) {
            return res.status(404).json({ success: false, message: "User not found" });
        }

        const username = user.username;
        const profileDir = path.join(__dirname, "profile");

        if (!fs.existsSync(profileDir)) {
            fs.mkdirSync(profileDir);
        }

        // Convert Base64 → File
        const base64Data = imageBase64.replace(/^data:image\/\w+;base64,/, "");
        const buffer = Buffer.from(base64Data, "base64");

        const fileName = `${username}.png`;
        const filePath = path.join(profileDir, fileName);
        fs.writeFileSync(filePath, buffer);

        // Cache-busted public URL
        const publicUrl = `/profile/${fileName}?v=${Date.now()}`;

        // Update BOTH databases
        await db.run(
            "UPDATE verified_users SET profile_pic = ? WHERE email = ?",
            [publicUrl, email]
        );

        const userDb = await openUserDB(username);
        await userDb.run(
            "UPDATE profile SET profile_pic = ? WHERE email = ?",
            [publicUrl, email]
        );
        await userDb.close();

        res.json({ success: true, url: publicUrl });

    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: "Server error" });
    }
});
// -------- ADMIN PANEL CONTROLS -------- //

/**
 * ADMIN LOGIN
 */
app.post("/admin/login", (req, res) => {
    const { email, password } = req.body;
    if (email === ADMIN_EMAIL && password === ADMIN_PASSWORD) {
        logger("Admin access granted.");
        return res.json({ success: true });
    }
    logger("Unauthorized admin login attempt!", "WARN");
    res.status(401).json({ success: false, message: "Invalid admin credentials." });
});

/**
 * ADMIN DATA FEED
 * Fetches user profile + pending bank wire withdrawals (with IDs)
 */
app.post("/admin/data", async (req, res) => {
    const { email } = req.body;
    if (email !== ADMIN_EMAIL) {
        return res.status(401).json({ success: false });
    }

    try {
        const allUsers = await db.all(
            "SELECT * FROM verified_users ORDER BY registration_date ASC"
        );

        const enhancedUsers = await Promise.all(
            allUsers.map(async (user) => {
                try {
                    const userDb = await openUserDB(user.username);

                    // 🔹 PROFILE FINANCES
                    const finances = await userDb.get(`
                        SELECT
                            total_balance,
                            total_bonus,
                            investment,
                            total_earnings,
                            total_referral_count,
                            pending_withdrawal,
                            total_withdrawal,
                            last_deposit,
                            last_withdrawal
                        FROM profile
                        LIMIT 1
                    `);

                    // 🔹 PENDING BANK WIRE TRANSACTIONS (IMPORTANT)
                    const pendingWithdrawals = await userDb.all(`
                        SELECT
                            id,
                            ABS(amount) AS amount,
                            date,
                            method,
                            status
                        FROM transactions
                        WHERE type = 'Withdrawal'
                          AND status = 'pending'
                          AND method = 'Bank Wire'
                        ORDER BY date DESC
                    `);

                    await userDb.close();

                    return {
                        ...user,
                        account: JSON.parse(user.account || "[]"),
                        ...finances,
                        pending_withdrawals: pendingWithdrawals // 👈 THIS IS NEW
                    };

                } catch (err) {
                    return {
                        ...user,
                        total_balance: 0,
                        total_bonus: 0,
                        investment: 0,
                        total_earnings: 0,
                        total_referral_count: 0,
                        pending_withdrawal: 0,
                        total_withdrawal: 0,
                        last_deposit: 0,
                        last_withdrawal: 0,
                        pending_withdrawals: []
                    };
                }
            })
        );

        res.json({
            success: true,
            verifiedUsers: enhancedUsers
        });

    } catch (err) {
        logger(`Admin Data Error: ${err.message}`, "ERROR");
        res.status(500).json({ success: false });
    }
});


/**
 * FIXED: UPDATE USER FINANCES
 */
/**
 * ADMIN: DYNAMIC UPDATE FINANCES
 * This ensures only the fields edited in the admin panel are changed.
 * If a field is not sent, the database keeps its current value.
 */
app.post("/admin/update-finances", async (req, res) => {
    const { adminEmail, userEmail, username } = req.body;

    if (adminEmail !== ADMIN_EMAIL) return res.status(401).send("Unauthorized");

    try {
        const userDb = await openUserDB(username);

        // 1. Map incoming frontend names to Database column names
        const fieldMapping = {
            balance: "total_balance",
            bonus: "total_bonus",
            investment: "investment",
            earning: "total_earnings",
            total_earnings: "total_earnings",
            referral_count: "total_referral_count",
            pwithdrawal: "pending_withdrawal",
            twithdrawal: "total_withdrawal",
            total_withdrawal: "total_withdrawal",
            ldeposit: "last_deposit",
            lwithdrawal: "last_withdrawal",
            last_withdrawal: "last_withdrawal"
        };

        let updateFields = [];
        let queryValues = [];

        // 2. Loop through the request body and only add items that are NOT undefined/null
        for (const [key, value] of Object.entries(req.body)) {
            if (fieldMapping[key] && value !== undefined && value !== "") {
                updateFields.push(`${fieldMapping[key]} = ?`);
                queryValues.push(value);
            }
        }

        // 3. If no fields were provided to update, stop here
        if (updateFields.length === 0) {
            await userDb.close();
            return res.json({ success: true, message: "No changes detected." });
        }

        // 4. Construct the dynamic SQL query
        // Example result: UPDATE profile SET total_balance = ?, total_earnings = ? WHERE email = ?
        const sql = `UPDATE profile SET ${updateFields.join(", ")} WHERE email = ?`;
        queryValues.push(userEmail);

        await userDb.run(sql, queryValues);
        await userDb.close();

        logger(`Admin updated ${updateFields.length} fields for ${username}.`);
        
        res.json({ 
            success: true, 
            message: `Updated ${updateFields.length} fields successfully. Other values remained unchanged.` 
        });

    } catch (err) {
        logger(`Finance Update Error: ${err.message}`, "ERROR");
        res.status(500).json({ success: false, message: err.message });
    }
});
/**
 * DELETE USER
 */
/**
 * DELETE USER
 * Removes user from master database and deletes their private SQLite file.
 */
app.post("/admin/delete-user", async (req, res) => {
    const { adminEmail, userEmail } = req.body;

    // Security Check
    if (adminEmail !== ADMIN_EMAIL) {
        return res.status(401).send("Unauthorized");
    }

    try {
        // 1. Get the username first to locate the specific database file
        const userInfo = await db.get("SELECT username FROM verified_users WHERE email=?", [userEmail]);

        // 2. Delete the user from the Master Database
        await db.run("DELETE FROM verified_users WHERE email = ?", [userEmail]);

        // 3. Delete the Private User Database File
        if (userInfo && userInfo.username) {
            const userDbFile = path.join(USERS_DIR, `${userInfo.username}.sqlite`);
            
            if (fs.existsSync(userDbFile)) {
                fs.unlinkSync(userDbFile); // This deletes the .sqlite file
                logger(`Deleted DB file for ${userInfo.username}`, "SUCCESS");
            } else {
                logger(`DB file for ${userInfo.username} not found, skipping file deletion.`, "WARN");
            }
        }

        logger(`Admin deleted user: ${userEmail}`);
        res.json({ success: true, message: "User and all associated data purged." });

    } catch (err) {
        logger(`Error deleting user: ${err.message}`, "ERROR");
        res.status(500).json({ success: false, message: "Server error during deletion." });
    }
});

/**
 * SUSPEND USER
 */
app.post("/admin/suspend-user", async (req, res) => {
    const { adminEmail, userEmail } = req.body;
    if (adminEmail !== ADMIN_EMAIL) return res.status(401).send("Unauthorized");

    try {
        await db.run("UPDATE verified_users SET status = 'suspended' WHERE email = ?", [userEmail]);
        logger(`Suspended user: ${userEmail}`);
        res.json({ success: true, message: "User status set to Suspended." });
    } catch (err) {
        res.status(500).json({ success: false });
    }
});

/**
 * ACTIVATE USER
 */
app.post("/admin/activate-user", async (req, res) => {
    const { adminEmail, userEmail } = req.body;
    if (adminEmail !== ADMIN_EMAIL) return res.status(401).send("Unauthorized");

    try {
        await db.run("UPDATE verified_users SET status = 'offline' WHERE email = ?", [userEmail]);
        logger(`Activated user: ${userEmail}`);
        res.json({ success: true, message: "User status set to Active." });
    } catch (err) {
        res.status(500).json({ success: false });
    }
});

// -------- SYSTEM MAINTENANCE ROUTES -------- //

/**
 * PIN MANAGEMENT
 * Saves or updates the 4-digit transaction PIN in the master database.
 */
app.post('/account/update-pin', async (req, res) => {
    const { email, pin, password } = req.body;

    if (!email || !/^\d{4}$/.test(pin) || !password) {
        return res.json({ success: false, message: "Invalid request" });
    }

    try {
        // Step 1: Get username
        const user = await db.get("SELECT username FROM verified_users WHERE email = ?", [email]);
        if (!user) return res.json({ success: false, message: "User not found" });

        // Step 2: Open private user DB
        const userDb = await openUserDB(user.username);

        // Step 3: Verify password in profile table
        const profile = await userDb.get("SELECT password FROM profile WHERE password = ?", [password]);
        if (!profile) {
            await userDb.close();
            return res.json({ success: false, message: "Incorrect password" });
        }

        // Step 4: Save PIN directly (no email verification needed)
        await userDb.run("UPDATE profile SET pin = ?", [pin]);
        await userDb.close();

        return res.json({ success: true, message: "PIN updated successfully" });

    } catch (err) {
        logger(`PIN update error: ${err.message}`, "ERROR");
        res.status(500).json({ success: false, message: "PIN update failed" });
    }
});



app.post('/account/request-pin-reset', async (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({ success: false, message: "Email required" });
    }

    // Generate 6-digit code
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    const expiry = Date.now() + (10 * 60 * 1000); // 10 minutes

    try {
        const user = await db.get(
            `SELECT username FROM verified_users WHERE email = ?`,
            [email]
        );

        if (!user) {
            return res.json({ success: false, message: "User not found" });
        }

        await db.run(
            `UPDATE verified_users
             SET pin_reset_code = ?, pin_reset_expiry = ?, pin_reset_verified = 0
             WHERE email = ?`,
            [code, expiry, email]
        );

        await transporter.sendMail({
            from: '"Xtrade Security" <john03t4@gmail.com>',
            to: email,
            subject: 'Transaction PIN Reset Code',
            html: `
                <div style="font-family:Arial;padding:20px;border:1px solid #eee">
                    <h3>Transaction PIN Reset</h3>
                    <p>Your verification code is:</p>
                    <h1 style="letter-spacing:4px;color:#007bff">${code}</h1>
                    <p>Expires in <b>10 minutes</b></p>
                </div>
            `
        });

        res.json({ success: true });

    } catch (err) {
        logger(`PIN reset request error: ${err.message}`, "ERROR");
        res.status(500).json({ success: false, message: "Failed to send code" });
    }
});

app.post('/account/verify-pin-reset-code', async (req, res) => {
    const { email, code } = req.body;

    if (!email || !/^\d{6}$/.test(code)) {
        return res.json({ success: false, message: "Invalid request" });
    }

    try {
        const user = await db.get(
            `SELECT pin_reset_code, pin_reset_expiry
             FROM verified_users
             WHERE email = ?`,
            [email]
        );

        if (!user || user.pin_reset_code !== code) {
            return res.json({ success: false, message: "Invalid verification code" });
        }

        if (Date.now() > user.pin_reset_expiry) {
            return res.json({ success: false, message: "Verification code expired" });
        }

        await db.run(
            `UPDATE verified_users
             SET pin_reset_verified = 1
             WHERE email = ?`,
            [email]
        );

        res.json({ success: true });

    } catch (err) {
        logger(`PIN verify error: ${err.message}`, "ERROR");
        res.status(500).json({ success: false, message: "Verification failed" });
    }
});

// GET PIN status
app.get('/account/pin-status', async (req, res) => {
    const { email } = req.query;
    if (!email) return res.json({ success: false });

    try {
        const user = await db.get(
            "SELECT username FROM verified_users WHERE email = ?",
            [email]
        );
        if (!user) return res.json({ success: false });

        const userDb = await openUserDB(user.username);
        const row = await userDb.get("SELECT pin FROM profile LIMIT 1");
        await userDb.close();

        res.json({
            success: true,
            hasPin: !!row?.pin
        });

    } catch (err) {
        logger(`PIN status error: ${err.message}`, "ERROR");
        res.status(500).json({ success: false });
    }
});


/**
 * VERIFY ACCOUNT PASSWORD (for PIN setup)
 * Checks if the password entered by the user matches their account
 */
app.post('/api/verify-password', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ success: false, message: "Email and password required" });
    }

    try {
        // Step 1: Get main verified user record
        const user = await db.get(
            "SELECT username FROM verified_users WHERE email = ?",
            [email]
        );

        if (!user) {
            return res.status(404).json({ success: false, message: "User not found" });
        }

        // Step 2: Open the user-specific database
        const userDb = await openUserDB(user.username);

        // Step 3: Check password in the profile table
        const profile = await userDb.get(
            "SELECT password FROM profile WHERE password = ?",
            [password]
        );

        await userDb.close();

        if (!profile) {
            return res.status(401).json({ success: false, message: "Incorrect password" });
        }

        // Step 4: Password verified
        return res.json({ success: true, message: "Password verified" });

    } catch (err) {
        logger(`Password verify error: ${err.message}`, "ERROR");
        return res.status(500).json({ success: false, message: "Server error during password verification" });
    }
});



/**
 * UNIFIED WITHDRAWAL ROUTE
 * Handles both Crypto (auto) and Bank Wire (pending) withdrawals
 */
app.post("/account/withdraw", async (req, res) => {
    const { amount, method, details, email } = req.body;

    if (!email) {
        return res.status(401).json({
            success: false,
            message: "User session expired."
        });
    }

    if (!amount) {
        return res.json({
            success: false,
            message: "Invalid withdrawal request."
        });
    }

    try {
        // 1️⃣ VERIFY USER
        const mainUser = await db.get(
            "SELECT username FROM verified_users WHERE email = ?",
            [email]
        );

        if (!mainUser) {
            return res.status(404).json({
                success: false,
                message: "User not found."
            });
        }

        // 2️⃣ OPEN PRIVATE DB
        const userDb = await openUserDB(mainUser.username);

        // 3️⃣ FETCH BALANCE INFO
        const profile = await userDb.get(
            "SELECT total_balance, total_bonus, pending_withdrawal, total_withdrawal FROM profile LIMIT 1"
        );

        const withdrawAmt = parseFloat(amount);
        const fee = withdrawAmt * 0.02;
        const total = withdrawAmt + fee;

        if (withdrawAmt < 500 || withdrawAmt > 100000) {
            await userDb.close();
            return res.json({
                success: false,
                message: "Withdrawal amount out of bounds."
            });
        }

        let currentBonus = parseFloat(profile?.total_bonus || 0);
        let currentBalance = parseFloat(profile?.total_balance || 0);
        
        let deductionFromBonus = 0;
        let deductionFromBalance = total;

        if (currentBonus > 0) {
            if (currentBonus >= total) {
                deductionFromBonus = total;
                deductionFromBalance = 0;
            } else {
                deductionFromBonus = currentBonus;
                deductionFromBalance = total - currentBonus;
            }
        }

        if (!profile || currentBalance < deductionFromBalance) {
            await userDb.close();
            return res.json({
                success: false,
                message: "Insufficient balance."
            });
        }

        // 4️⃣ METHOD VALIDATION
        if (method === "Crypto") {
            if (!details?.wallet || !details?.address) {
                await userDb.close();
                return res.json({ success: false, message: "Incomplete crypto details." });
            }
        } else if (method === "Bank Wire") {
            if (!details?.bank || !details?.number) {
                await userDb.close();
                return res.json({ success: false, message: "Incomplete bank details." });
            }
        } else {
            await userDb.close();
            return res.json({ success: false, message: "Unsupported withdrawal method." });
        }

        // 5️⃣ UPDATE PROFILE BALANCES
        const newBalance = currentBalance - deductionFromBalance;
        const newBonus = currentBonus - deductionFromBonus;

        // For Bank Wire: add to pending only, crypto updates total & last withdrawal immediately
        let newPending = profile.pending_withdrawal || 0;
        let newTotalWithdrawal = profile.total_withdrawal || 0;
        let lastWithdrawal = 0;
        let txStatus = "completed";

        if (method === "Crypto") {
            newTotalWithdrawal += withdrawAmt;
            lastWithdrawal = withdrawAmt;
        } else if (method === "Bank Wire") {
            newPending += withdrawAmt;
            txStatus = "pending"; // waiting admin approval
        }

        await userDb.run(
            `UPDATE profile SET 
                total_balance = ?, 
                total_bonus = ?,
                pending_withdrawal = ?, 
                last_withdrawal = ?, 
                total_withdrawal = ?`,
            [newBalance, newBonus, newPending, lastWithdrawal, newTotalWithdrawal]
        );

        // 6️⃣ LOG TRANSACTION
        await userDb.run(
            `INSERT INTO transactions (type, amount, date, status, method) VALUES (?, ?, ?, ?, ?)`,
            ["Withdrawal", -total, new Date().toISOString(), txStatus]
        );

        // 6️⃣ LOG TRANSACTION
const txResult = await userDb.run(
    `INSERT INTO transactions (type, amount, date, status, method)
     VALUES (?, ?, ?, ?, ?)`,
    ["Withdrawal", -total, new Date().toISOString(), txStatus, method]
);

// 🔔 IF BANK WIRE → PUSH INTO USER_REPLIES
if (method === "Bank Wire") {
    await userDb.run(
        `INSERT INTO user_replies (reply_text, seen, pinned, date)
         VALUES (?, 0, 0, ?)`,
        [
            `🏦 Bank Wire Withdrawal Request
Amount: $${withdrawAmt.toLocaleString()}
Transaction ID: ${txResult.lastID}
Status: Pending Admin Approval`,
            new Date().toISOString()
        ]
    );
}


        // 7️⃣ NOTIFICATION
        await userDb.run(
            "INSERT INTO notifications (msg, type, date) VALUES (?, ?, ?)",
            [
                method === "Bank Wire"
                    ? `Bank Wire withdrawal of $${withdrawAmt.toLocaleString()} submitted. Pending admin approval.`
                    : `Withdrawal of $${withdrawAmt.toLocaleString()} via ${method} submitted.`,
                "info",
                new Date().toISOString()
            ]
        );

        await userDb.close();

        // 8️⃣ EMAIL HANDLING
        if (method === "Crypto") {
            try {
                await transporter.sendMail({
                    from: '"Xtrade Support" <john03t4@gmail.com>',
                    to: email,
                    subject: `Withdrawal of $${withdrawAmt.toLocaleString()} Submitted`,
                    html: `
                        <div style="font-family:Arial, sans-serif; padding:20px; border:1px solid #eee;">
                            <h3>Withdrawal Confirmation</h3>
                            <p>Dear ${mainUser.username},</p>
                            <p>Your withdrawal of <b>$${withdrawAmt.toLocaleString()}</b> via <b>${method}</b> has been successfully submitted.</p>
                            <p>Fee applied: <b>$${fee.toFixed(2)}</b></p>
                            <p>Total deducted from your account: <b>$${total.toFixed(2)}</b></p>
                            <p>New available balance: <b>$${newBalance.toFixed(2)}</b></p>
                            <p>If you did not authorize this withdrawal, please contact support immediately.</p>
                        </div>
                    `
                });
            } catch (emailErr) {
                logger(`Withdrawal email error: ${emailErr.message}`, "ERROR");
            }
        } else if (method === "Bank Wire") {
            try {
                await transporter.sendMail({
                    from: '"Xtrade System" <no-reply@xtrade.com>',
                    to: "john03t4@gmail.com",
                    subject: `Bank Wire Withdrawal Request from ${mainUser.username}`,
                    html: `
                        <div style="font-family:Arial, sans-serif; padding:20px; border:1px solid #eee;">
                            <h3>Bank Wire Withdrawal Pending Approval</h3>
                            <p>User: <b>${mainUser.username}</b> (${email})</p>
                            <p>Amount Requested: <b>$${withdrawAmt.toLocaleString()}</b></p>
                            <p>Bank Name: <b>${details.bank}</b></p>
                            <p>Account Number: <b>${details.number}</b></p>
                            <p>Fee: <b>$${fee.toFixed(2)}</b></p>
                            <p>Total Deducted From Balance: <b>$${total.toFixed(2)}</b></p>
                            <p>Please approve this withdrawal within 3-5 business days.</p>
                        </div>
                    `
                });
            } catch (emailErr) {
                logger(`Admin email error: ${emailErr.message}`, "ERROR");
            }
        }

        logger(`WITHDRAWAL ${method === "Bank Wire" ? "PENDING" : "SUCCESS"}: ${mainUser.username}`, "INFO");

        res.json({
            success: true,
            message: method === "Bank Wire"
                ? "Bank Wire withdrawal submitted. Pending admin approval within 3-5 business days."
                : "Withdrawal submitted successfully. Confirmation email sent.",
            newBalance
        });

    } catch (err) {
        logger(`WITHDRAWAL ERROR: ${err.message}`, "ERROR");
        res.status(500).json({
            success: false,
            message: "Withdrawal gateway error."
        });
    }
});


/**
 * ADMIN APPROVE BANK WIRE FROM USER_REPLIES
 * Approves pending Bank Wire withdrawals and notifies the user via email
 */
app.post("/admin/approve-bank-wire", async (req, res) => {
    const { username, withdrawId, replyId } = req.body;

    if (!username || !withdrawId) {
        return res.json({ success: false, message: "Invalid request." });
    }

    try {
        // 1️⃣ Get user email from main DB
        const user = await db.get(
            `SELECT email, fname FROM verified_users WHERE username = ?`,
            [username]
        );

        if (!user) {
            return res.json({ success: false, message: "User not found." });
        }

        const userEmail = user.email;

        // 2️⃣ Open user's private DB
        const userDb = await openUserDB(username);

        // 3️⃣ Get pending transaction
        const tx = await userDb.get(
            `SELECT id, amount FROM transactions
             WHERE id = ? AND status = 'pending' AND method = 'Bank Wire'`,
            [withdrawId]
        );

        if (!tx) {
            await userDb.close();
            return res.json({ success: false, message: "Pending withdrawal not found." });
        }

        const withdrawAmt = Math.abs(tx.amount);

        // 4️⃣ Update profile balances
        const profile = await userDb.get(
            `SELECT pending_withdrawal, total_withdrawal FROM profile`
        );

        await userDb.run(
            `UPDATE profile
             SET pending_withdrawal = ?,
                 total_withdrawal = ?,
                 last_withdrawal = ?`,
            [
                Math.max(0, (profile.pending_withdrawal || 0) - withdrawAmt),
                (profile.total_withdrawal || 0) + withdrawAmt,
                withdrawAmt
            ]
        );

        // 5️⃣ Complete transaction
        await userDb.run(
            `UPDATE transactions SET status = 'completed' WHERE id = ?`,
            [withdrawId]
        );

        // 6️⃣ Mark user_replies as seen
        if (replyId) {
            await userDb.run(
                `UPDATE user_replies SET seen = 1 WHERE id = ?`,
                [replyId]
            );
        }

        await userDb.close();

        // 7️⃣ Send email notification to user
        try {
            await transporter.sendMail({
                from: '"Xtrade Support" <no-reply@xtrade.com>',
                to: userEmail,
                subject: `Bank Wire Withdrawal Approved`,
                html: `
                    <div style="font-family:Arial,sans-serif; padding:20px; border:1px solid #eee;">
                        <h3>Withdrawal Approved</h3>
                        <p>Dear ${user.fname || username},</p>
                        <p>Your bank wire withdrawal of <b>$${withdrawAmt.toLocaleString()}</b> has been approved and processed successfully.</p>
                        <p>Transaction ID: <b>${withdrawId}</b></p>
                        <p>Funds should reflect in your bank account within 3-5 business days.</p>
                        <hr>
                        <p style="font-size:12px; color:#888;">If you did not request this withdrawal, contact support immediately.</p>
                    </div>
                `
            });
        } catch (emailErr) {
            logger(`Email error sending withdrawal approval: ${emailErr.message}`, "ERROR");
        }

        // 8️⃣ Respond to admin
        res.json({
            success: true,
            message: "Bank wire withdrawal approved and user notified via email."
        });

    } catch (err) {
        logger(`BANK APPROVAL ERROR: ${err.message}`, "ERROR");
        res.status(500).json({ success: false, message: "Approval failed." });
    }
});






/**
 * DEPOSIT CONFIRMATION ROUTE
 * Credits ONLY the deposited amount (NO FEES)
 */
app.post("/account/deposit", async (req, res) => {
    const { email, amount, txHash, method } = req.body;

    if (!email || !amount) {
        return res.status(400).json({
            success: false,
            message: "Invalid deposit request"
        });
    }

    const depositAmount = parseFloat(amount);
    if (isNaN(depositAmount) || depositAmount <= 0) {
        return res.json({
            success: false,
            message: "Invalid deposit amount"
        });
    }

    try {
        // 1️⃣ Get verified user
        const user = await db.get(
            "SELECT username FROM verified_users WHERE email = ?",
            [email]
        );

        if (!user) {
            return res.status(404).json({
                success: false,
                message: "User not found"
            });
        }

        // 2️⃣ Open user's private DB
        const userDb = await openUserDB(user.username);

        // 3️⃣ Get current balance
        const profile = await userDb.get(
            "SELECT total_balance FROM profile LIMIT 1"
        );

        const currentBalance = parseFloat(profile?.total_balance || 0);
        const newBalance = currentBalance + depositAmount;

        // 4️⃣ Update balance & last deposit
        await userDb.run(
            `UPDATE profile 
             SET total_balance = ?, last_deposit = ?`,
            [newBalance, depositAmount]
        );

        // 5️⃣ Log transaction (NO FEES)
        await userDb.run(
            `INSERT INTO transactions 
             (type, amount, date, status)
             VALUES (?, ?, ?, ?)`,
            [
                "Deposit",
                depositAmount,
                new Date().toISOString(),
                "completed"
            ]
        );

        // 6️⃣ Notify user
        await userDb.run(
            `INSERT INTO notifications 
             (msg, type, date)
             VALUES (?, ?, ?)`,
            [
                `Deposit of $${depositAmount.toLocaleString()} confirmed.`,
                "success",
                new Date().toISOString()
            ]
        );

        await userDb.close();

        logger(`DEPOSIT SUCCESS: ${user.username} +${depositAmount}`, "SUCCESS");

        res.json({
            success: true,
            message: "Deposit credited successfully",
            amount: depositAmount,
            newBalance
        });

    } catch (err) {
        logger(`DEPOSIT ERROR: ${err.message}`, "ERROR");
        res.status(500).json({
            success: false,
            message: "Deposit processing failed"
        });
    }
});



/**
 * VERIFY TRANSACTION PIN
 * Checks if the 4-digit PIN entered by the user matches the one in their profile.
 */
app.post('/account/verify-pin', async (req, res) => {
    const { email, pin } = req.body;

    if (!email) return res.status(400).json({ success: false, message: "Email required" });
    if (!pin || !/^\d{4}$/.test(pin)) return res.status(400).json({ success: false, message: "Invalid PIN format. Must be 4 digits." });

    try {
        const user = await db.get("SELECT username FROM verified_users WHERE email = ?", [email]);
        if (!user) return res.status(404).json({ success: false, message: "User not found" });

        const userDb = await openUserDB(user.username);
        const profile = await userDb.get("SELECT pin FROM profile LIMIT 1");
        await userDb.close();

        if (!profile?.pin) return res.json({ success: false, message: "Transaction PIN not set." });
        if (profile.pin !== pin) return res.json({ success: false, message: "Incorrect PIN." });

        return res.json({ success: true, message: "PIN verified successfully." });
    } catch (err) {
        logger(`PIN verification error: ${err.message}`, "ERROR");
        return res.status(500).json({ success: false, message: "Server error while verifying PIN." });
    }
});




/**
 * AUDIT LOG ENDPOINT
 * Records user activity, validation failures, and transaction attempts.
 */
app.post("/account/audit-log", async (req, res) => {
    const { email, action, details, timestamp } = req.body;

    if (!email) {
        return res.status(400).json({ success: false, message: "Email required for logging." });
    }

    try {
        // 1. Identify the user to find their private DB
        const userRef = await db.get("SELECT username FROM verified_users WHERE email=?", [email]);
        
        if (userRef) {
            // 2. Open private DB to log the action
            const userDb = await openUserDB(userRef.username);
            
            // Create logs table if it doesn't exist
            await userDb.exec(`
                CREATE TABLE IF NOT EXISTS activity_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    action TEXT,
                    details TEXT,
                    timestamp TEXT,
                    ip_address TEXT
                )
            `);

            // 3. Insert the log entry
            await userDb.run(
                "INSERT INTO activity_logs (action, details, timestamp, ip_address) VALUES (?, ?, ?, ?)",
                [
                    action, 
                    JSON.stringify(details || {}), 
                    timestamp || new Date().toISOString(),
                    req.ip
                ]
            );
            
            await userDb.close();
        }

        // Also record to the main server log file for admin monitoring
        logger(`[AUDIT] User: ${email} | Action: ${action} | Details: ${JSON.stringify(details)}`);

        res.json({ success: true });
    } catch (err) {
        logger(`Audit Log Error: ${err.message}`, "ERROR");
        res.status(500).json({ success: false });
    }
});

/**
 * CLIENT: UPDATE PROFILE INFORMATION
 * Handles profile updates from the user dashboard.
 */
app.post("/api/update-profile", async (req, res) => {
    const { email, firstName, lastName, address, zip } = req.body;

    // 1. Validation
    if (!email) {
        return res.status(400).json({ success: false, message: "User session expired. Please log in again." });
    }

    try {
        // 2. Locate the user to find their unique username (required to open their private DB)
        const userRef = await db.get("SELECT username FROM verified_users WHERE email = ?", [email]);

        if (!userRef) {
            return res.status(404).json({ success: false, message: "User record not found." });
        }

        // 3. Open the user's private database
        const userDb = await openUserDB(userRef.username);

        /**
         * 4. Perform Dynamic Update
         * This logic only updates fields that were actually provided in the request body.
         * Mapping: Frontend names -> Database column names
         */
        const updates = [];
        const params = [];

        if (firstName !== undefined) { updates.push("fname = ?"); params.push(firstName); }
        if (lastName !== undefined)  { updates.push("lname = ?"); params.push(lastName); }
        if (address !== undefined)   { updates.push("address = ?"); params.push(address); }
        if (zip !== undefined)       { updates.push("zip = ?"); params.push(zip); }

        if (updates.length === 0) {
            await userDb.close();
            return res.json({ success: true, message: "No changes detected." });
        }

        // Add the email for the WHERE clause
        params.push(email);

        const sql = `UPDATE profile SET ${updates.join(", ")} WHERE email = ?`;
        
        await userDb.run(sql, params);
        await userDb.close();

        // 5. Success Handling
        logger(`Profile updated for user: ${userRef.username} (${email})`);
        
        res.json({ 
            success: true, 
            message: "Profile updated successfully." 
        });

    } catch (err) {
        logger(`Profile Update Error: ${err.message}`, "ERROR");
        res.status(500).json({ 
            success: false, 
            message: "Internal server error during update." 
        });
    }
});

// --- ADMIN EXTENDED ACCESS ---

/**
 * ADMIN: INJECT TRADE HISTORY
 * Adds a trade directly to a user's history table and updates finances
 */
app.post("/admin/inject-trade", async (req, res) => {
    const { adminEmail, userEmail, tradeData } = req.body;

    if (!tradeData) return res.status(400).json({ message: "Trade data missing" });

    try {
        const user = await db.get("SELECT username FROM verified_users WHERE email=?", [userEmail]);
        if (!user) return res.status(404).json({ message: "User not found" });

        const userDb = await openUserDB(user.username);

        // --- SAFETY: Parse all numbers and provide defaults ---
        const tradeAmount = parseFloat(tradeData.amount || 0);
        const tradeProfit = parseFloat(tradeData.profit || 0);
        const tradePercent = parseFloat(tradeData.percent || 0);

        // 1️⃣ Insert trade into history
        await userDb.run(
            `INSERT INTO history 
             (type, asset, amount, status, date, profit, percent) 
             VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [
                tradeData.type,
                tradeData.asset,
                tradeAmount,
                tradeData.status || "completed",
                tradeData.date || new Date().toISOString(),
                tradeProfit,
                tradePercent
            ]
        );

        // 2️⃣ Fetch current finances
        const profile = await userDb.get("SELECT total_earnings, total_balance FROM profile");
        
        let currentEarnings = parseFloat(profile?.total_earnings || 0);
        let currentInvestment = parseFloat(profile?.total_earnings || 0);
        let currentBalance = parseFloat(profile?.total_balance || 0);

        currentInvestment += tradeAmount;

        // 3️⃣ Update finances based on specific logic
        let updatedEarnings = currentEarnings;
        let updatedBalance = currentBalance;

        const type = tradeData.type.toLowerCase();

        if (type === "call") {
            // LOGIC: Deduct amount from balance, add profit to earnings
            updatedBalance = currentBalance - tradeAmount;
            updatedEarnings = currentEarnings + tradeProfit;
        } else if (type === "pull" || type === "put") {
            // Standard Logic: Add profit to both
            updatedEarnings += tradeProfit;
            updatedBalance += tradeProfit;
        } else {
            // Default Fallback
            updatedEarnings += tradeProfit;
            updatedBalance += tradeProfit;
        }

        // 4️⃣ Ensure values are not negative and round to 2 decimals
        updatedEarnings = Math.max(0, Math.round(updatedEarnings * 100) / 100);
        updatedBalance = Math.max(0, Math.round(updatedBalance * 100) / 100);
        currentInvestment = Math.max(0, Math.round(currentInvestment * 100) / 100);

        // 5️⃣ Update the profile table
        await userDb.run(
            `UPDATE profile SET total_earnings = ?, total_balance = ?, investment = ?`,
            [updatedEarnings, updatedBalance, currentInvestment]
        );

        await userDb.close();

        logger(`Admin injected trade for ${userEmail}. Balance: ${updatedBalance}, Earnings: ${updatedEarnings}`);
        
        res.json({ 
            success: true, 
            message: "Trade injected. Balance deducted and earnings increased.",
            newEarnings: updatedEarnings,
            newBalance: updatedBalance
        });
    } catch (err) {
        logger(`Trade Injection Error: ${err.message}`, "ERROR");
        res.status(500).json({ error: err.message });
    }
});

/**
 * GET USER TRADE HISTORY
 */
app.get("/account/trade-history", async (req, res) => {
    const { email } = req.query;

    if (!email) return res.status(400).json({ success: false, message: "Email required" });

    try {
        const user = await db.get("SELECT username FROM verified_users WHERE email = ?", [email]);

        if (!user) return res.status(404).json({ success: false, message: "User not found" });

        const userDb = await openUserDB(user.username);

        // Fetch trade history (latest first)
        const trades = await userDb.all(
            `SELECT id, type, asset, amount, profit, percent, status, date
             FROM history
             ORDER BY date DESC`
        );

        await userDb.close();

        res.json({
            success: true,
            trades: trades || [] // Ensure it's at least an empty array
        });

    } catch (err) {
        logger(`TRADE HISTORY ERROR: ${err.message}`, "ERROR");
        res.status(500).json({ success: false, message: "Failed to load trade history" });
    }
});


app.get("/account/activity", async (req, res) => {
    const { email } = req.query;
    if (!email) return res.json({ success: false });

    try {
        const user = await db.get(
            "SELECT username FROM verified_users WHERE email = ?",
            [email]
        );
        if (!user) return res.json({ success: false });

        const userDb = await openUserDB(user.username);

        const trades = await userDb.all(`
            SELECT 
                'TRADE' as source,
                type,
                asset,
                amount,
                profit,
                percent,
                status,
                date
            FROM history
        `);

        const transactions = await userDb.all(`
            SELECT 
                'TRANSACTION' as source,
                type,
                NULL as asset,
                amount,
                NULL as profit,
                NULL as percent,
                status,
                date
            FROM transactions
        `);

        await userDb.close();

        const activity = [...trades, ...transactions]
            .sort((a, b) => new Date(b.date) - new Date(a.date));

        res.json({ success: true, activity });
    } catch (e) {
        res.status(500).json({ success: false });
    }
});




/**
 * PURCHASE HANDLER (Signal or Package)
 */
app.post("/account/purchase", async (req, res) => {
    const { email, amount, itemName, type } = req.body;

    if (!email || !amount || !itemName || !type) {
        return res.status(400).json({ success: false, message: "Invalid request" });
    }

    try {
        // 1️⃣ Get user
        const mainUser = await db.get(
            "SELECT username FROM verified_users WHERE email = ?",
            [email]
        );
        if (!mainUser) return res.status(404).json({ success: false, message: "User not found" });

        // 2️⃣ Open private DB
        const userDb = await openUserDB(mainUser.username);

        // 3️⃣ Fetch current plan or signal
        const profile = await userDb.get("SELECT plan, signal, total_balance FROM profile LIMIT 1");
        if (!profile) {
            await userDb.close();
            return res.status(404).json({ success: false, message: "User profile not found" });
        }

        // 4️⃣ Check if already subscribed
        if (type === "plan" && profile.plan === itemName) {
            await userDb.close();
            return res.json({ success: false, message: "You are already on this plan." });
        }
        if (type === "signal" && profile.signal === itemName) {
            await userDb.close();
            return res.json({ success: false, message: "You are already on this signal." });
        }

        // 5️⃣ Check balance
        const currentBalance = parseFloat(profile.total_balance || 0);
        const cost = parseFloat(amount);
        if (currentBalance < cost) {
            await userDb.close();
            return res.json({ success: false, reason: "insufficient_balance", message: "Insufficient balance." });
        }

        // 6️⃣ Deduct balance and update plan/signal
        const newBalance = currentBalance - cost;
        if (type === "plan") {
            await userDb.run(`UPDATE profile SET total_balance = ?, plan = ?`, [newBalance, itemName]);
        } else {
            await userDb.run(`UPDATE profile SET total_balance = ?, signal = ?`, [newBalance, itemName]);
        }

        // 7️⃣ Log transaction
        await userDb.run(`INSERT INTO transactions (type, amount, date, status) VALUES (?, ?, ?, ?)`,
            ['PURCHASE', -cost, new Date().toISOString(), 'completed']
        );

        await userDb.close();

        res.json({ success: true, message: `${itemName} activated!`, newBalance });
    } catch (err) {
        logger(`PURCHASE ERROR: ${err.message}`, "ERROR");
        res.status(500).json({ success: false, message: "Internal server error" });
    }
});






/**
 * ADMIN: SEND NOTIFICATION
 * Injects a message into the user's notification/settings alert area
 */
// -------- NOTIFICATION SYSTEM -------- //

/**
 * ADMIN SEND NOTIFICATION
 * Sends a message to a specific user's isolated database.
 */
app.post("/admin/send-notification", async (req, res) => {
    const { userEmail, message, type } = req.body; // type: 'info', 'warning', 'success'

    try {
        const user = await db.get("SELECT username FROM verified_users WHERE email=?", [userEmail]);
        if (!user) return res.status(404).json({ success: false, message: "User not found." });

        const userDb = await openUserDB(user.username);
        
        await userDb.exec("CREATE TABLE IF NOT EXISTS notifications (id INTEGER PRIMARY KEY, msg TEXT, type TEXT, seen INT, date TEXT)");
        await userDb.run("INSERT INTO notifications (msg, type, seen, date) VALUES (?, ?, 0, ?)", 
            [message, type, new Date().toISOString()]);
        
        await userDb.close();
        logger(`Admin sent ${type} notification to ${userEmail}`, "ADMIN_ACTION");
        res.json({ success: true });
    } catch (err) { 
        logger(`Send Notification Error: ${err.message}`, "ERROR");
        res.status(500).send(err.message); 
    }
});

// 1. Route to get a count of all unread replies from all users
app.get("/admin/unread-replies-count", async (req, res) => {
    try {
        const users = await getAllUsers(); // however you already do this

        let totalUnread = 0;
        let usersWithUnread = [];

        for (const username of users) {
            const userDb = await openUserDB(username);

            const row = await userDb.get(`
                SELECT COUNT(*) AS cnt
                FROM user_replies
                WHERE seen = 0
            `);

            if (row.cnt > 0) {
                totalUnread += row.cnt;
                usersWithUnread.push(username);
            }

            await userDb.close();
        }

        res.json({
            success: true,
            count: totalUnread,
            users: usersWithUnread
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false });
    }
});


app.post("/admin/mark-user-replies-read", async (req, res) => {
    const { username } = req.body;
    if (!username) {
        return res.json({ success: false });
    }

    try {
        const userDb = await openUserDB(username);

        await userDb.run(`
            UPDATE user_replies
            SET seen = 1
            WHERE seen = 0
        `);

        await userDb.close();
        res.json({ success: true });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false });
    }
});



// 2. Route to get replies for a specific user and mark them as read
app.get("/admin/get-user-replies", async (req, res) => {
    const { username } = req.query;
    if (!username) {
        return res.json({ success: false });
    }

    try {
        const userDb = await openUserDB(username);

        const replies = await userDb.all(`
            SELECT id, reply_text, date, seen, pinned
            FROM user_replies
            ORDER BY pinned DESC, id DESC
        `);

        await userDb.close();
        res.json({ success: true, replies });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false });
    }
});

app.post("/admin/pin-reply", async (req, res) => {
    const { username, id } = req.body;
    if (!username || !id) {
        return res.json({ success: false });
    }

    try {
        const userDb = await openUserDB(username);

        await userDb.run(`
            UPDATE user_replies
            SET pinned = CASE WHEN pinned = 1 THEN 0 ELSE 1 END
            WHERE id = ?
        `, [id]);

        await userDb.close();
        res.json({ success: true });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false });
    }
});

app.post("/admin/delete-reply", async (req, res) => {
    const { username, id } = req.body;
    if (!username || !id) {
        return res.json({ success: false });
    }

    try {
        const userDb = await openUserDB(username);

        await userDb.run(`
            DELETE FROM user_replies
            WHERE id = ?
        `, [id]);

        await userDb.close();
        res.json({ success: true });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false });
    }
});



// FIXED: Fetch notifications from the PRIVATE user database
// REPLACE your existing app.get("/api/notifications") with this:
app.get("/api/notifications", async (req, res) => {
    const { email } = req.query;
    if (!email) return res.status(400).json({ success: false, message: "Email required." });

    try {
        const identity = await db.get("SELECT username FROM verified_users WHERE email=?", [email]);
        if (!identity) return res.json({ success: false, message: "User not found." });

        const userDb = await openUserDB(identity.username);

        // Ensure table exists
        await userDb.exec("CREATE TABLE IF NOT EXISTS notifications (id INTEGER PRIMARY KEY AUTOINCREMENT, msg TEXT, type TEXT, seen INT, date TEXT)");

        // FIX: Fetch ALL rows (not just one) and include the ID
        const rows = await userDb.all("SELECT id, msg FROM notifications ORDER BY id ASC");
        await userDb.close();

        if (rows && rows.length > 0) {
            // Send the full array of objects [{id: 1, msg: 'hi'}, {id: 2, msg: 'bro'}]
            res.json({ success: true, messages: rows });
        } else {
            res.json({ success: false, messages: [], message: "No notifications." });
        }
    } catch (err) {
        logger(`Fetch Notification Error: ${err.message}`, "ERROR");
        res.status(500).json({ success: false, messages: [] });
    }
});

app.post("/api/delete-notification", async (req, res) => {
    const { email, id } = req.body;
    try {
        const user = await db.get("SELECT username FROM verified_users WHERE email=?", [email]);
        const userDb = await openUserDB(user.username);
        await userDb.run("DELETE FROM notifications WHERE id = ?", [id]);
        await userDb.close();
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ success: false });
    }
});

/**
 * REPLY NOTIFICATION ENDPOINT
 * Receives support replies from users and logs them for Admin review.
 */
app.post("/api/reply-notification", async (req, res) => {
    const { email, message } = req.body;
    try {
        const identity = await db.get("SELECT username FROM verified_users WHERE email=?", [email]);
        const userDb = await openUserDB(identity.username);

        await userDb.exec(`
            CREATE TABLE IF NOT EXISTS user_replies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                reply_text TEXT,
                pinned INTEGER DEFAULT 0,
                seen INTEGER DEFAULT 0,
                date TEXT
            )
        `);

        const now = new Date().toLocaleString();
        await userDb.run("INSERT INTO user_replies (reply_text, seen, date) VALUES (?, 0, ?)", [message, now]);
        
        await userDb.close();
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ success: false });
    }
});

/**
 * SYSTEM STATS
 * For internal monitoring.
 */
app.get("/system/stats", async (req, res) => {
    try {
        const vCount = await db.get("SELECT COUNT(*) as count FROM verified_users");
        const pCount = await db.get("SELECT COUNT(*) as count FROM pending_users");
        const activeToday = await db.get("SELECT COUNT(*) as count FROM verified_users WHERE last_seen > ?", [Date.now() - 86400000]);

        res.json({
            uptime: process.uptime(),
            verified_users: vCount.count,
            pending_users: pCount.count,
            active_24h: activeToday.count,
            memory: process.memoryUsage()
        });
    } catch (err) {
        res.status(500).send("Error fetching stats");
    }
});

/**
 * LOG RETRIEVAL
 */
app.get("/system/logs", (req, res) => {
    // Basic protection (password in query string for example)
    if (req.query.pass !== ADMIN_PASSWORD) return res.status(401).send("Forbidden");
    
    if (fs.existsSync(LOG_PATH)) {
        const logs = fs.readFileSync(LOG_PATH, 'utf8');
        res.header("Content-Type", "text/plain");
        res.send(logs);
    } else {
        res.send("No logs found.");
    }
});

/**
 * ADMIN: DATABASE BACKUP
 * Creates a timestamped copy of the main xtrade.sqlite file
 */
app.post("/admin/backup-db", async (req, res) => {
    const { adminEmail } = req.body;
    if (adminEmail !== ADMIN_EMAIL) return res.status(401).send("Unauthorized");

    try {
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        const backupName = `backup-xtrade-${timestamp}.sqlite`;
        const backupPath = path.join(__dirname, "backups", backupName);

        // Ensure backup directory exists
        if (!fs.existsSync(path.join(__dirname, "backups"))) {
            fs.mkdirSync(path.join(__dirname, "backups"));
        }

        fs.copyFileSync(DB_PATH, backupPath);
        
        logger(`Database backup created: ${backupName}`, "SUCCESS");
        res.json({ success: true, message: `Backup created: ${backupName}` });
    } catch (err) {
        logger(`Backup failed: ${err.message}`, "ERROR");
        res.status(500).json({ success: false, message: "Backup protocol failed." });
    }
});

/**
 * ADMIN: CLEAR LOGS
 * Wipes the server.log file and starts fresh
 */
app.post("/admin/clear-logs", async (req, res) => {
    const { adminEmail } = req.body;
    if (adminEmail !== ADMIN_EMAIL) return res.status(401).send("Unauthorized");

    try {
        fs.writeFileSync(LOG_PATH, `[${new Date().toISOString()}] [INFO] Log file reset by Admin.\n`);
        logger("Server logs cleared.", "SUCCESS");
        res.json({ success: true, message: "Logs rotated successfully." });
    } catch (err) {
        res.status(500).json({ success: false });
    }
});

// -------- ERROR HANDLING & CLEANUP -------- //

// 404 Handler
app.use((req, res) => {
    res.status(404).json({ success: false, message: "Resource not found on Xtrade server." });
});

// Global Exception Catcher
process.on("uncaughtException", (err) => {
    logger(`CRITICAL UNCAUGHT EXCEPTION: ${err.message}`, "FATAL");
    // Consider restarting or notifying admin
});

process.on("unhandledRejection", (reason, promise) => {
    logger(`Unhandled Rejection at: ${promise} reason: ${reason}`, "FATAL");
});

/**
 * GRACEFUL SHUTDOWN
 * Ensures database connections are closed before the process exits.
 */
async function shutdown() {
    logger("Server shutting down...");
    if (db) {
        await db.close();
        logger("Main database connection closed.");
    }
    process.exit(0);
}

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);

// Execute Initialization
initDB();

/**
 * FOOTER COMMENT BLOCK
 * ---------------------------------------------------------
 * This server logic is designed to facilitate high-security 
 * financial trading operations. Individual user databases 
 * ensure that in the event of a single user's data compromise, 
 * the integrity of the remaining user base is maintained.
 * ---------------------------------------------------------
 */