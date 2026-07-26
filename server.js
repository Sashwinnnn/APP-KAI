import express from 'express';
import crypto from 'crypto';
import webpush from 'web-push';
import { initDatabase, getDbConnection } from './database.js';
import { analyzeImageForJSON, generateTextJSON } from './ai.js';
import 'dotenv/config';

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: '12mb' }));
app.use(express.static('public'));

if (process.env.PUBLIC_VAPID_KEY && process.env.PRIVATE_VAPID_KEY) {
    try {
        webpush.setVapidDetails(
            process.env.VAPID_SUBJECT || 'mailto:support@kai.app',
            process.env.PUBLIC_VAPID_KEY,
            process.env.PRIVATE_VAPID_KEY
        );
        console.log("🔔 Web Push VAPID keys configured successfully.");
    } catch (err) {
        console.warn("⚠️ Failed to configure Web Push VAPID details:", err.message);
    }
}

if (!process.env.GEMINI_API_KEY && !process.env.OPENROUTER_API_KEY && !process.env.GROQ_API_KEY) {
    console.warn("⚠️ Neither GEMINI_API_KEY, OPENROUTER_API_KEY nor GROQ_API_KEY is set — AI features (scan, chat, macros) will fail until at least one is configured.");
}

/* ===================== AUTH: sessions & password hashing =====================
   Self-contained (no new npm packages) so this can't break `npm install` on deploy.
   Sessions are a signed cookie: base64url(json).signature — verified with HMAC,
   never trusted blindly. Passwords are hashed with scrypt (Node built-in), never
   stored in plain text. */

const SESSION_SECRET = process.env.SESSION_SECRET || "kai-dev-secret-change-me";
if (!process.env.SESSION_SECRET) {
    console.warn("⚠️ SESSION_SECRET is not set — using an insecure default. Set SESSION_SECRET in your environment before real users sign up.");
}
const SESSION_MAX_AGE_MS = 365 * 24 * 60 * 60 * 1000; // 1 year (365 days)

function base64url(input) {
    return Buffer.from(input).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function base64urlDecode(input) {
    input = input.replace(/-/g, '+').replace(/_/g, '/');
    while (input.length % 4) input += '=';
    return Buffer.from(input, 'base64').toString('utf8');
}

function signSession(userId) {
    const payload = JSON.stringify({ uid: userId, exp: Date.now() + SESSION_MAX_AGE_MS });
    const encodedPayload = base64url(payload);
    const signature = crypto.createHmac('sha256', SESSION_SECRET).update(encodedPayload).digest('hex');
    return `${encodedPayload}.${signature}`;
}

function verifySession(token) {
    if (!token || typeof token !== 'string' || !token.includes('.')) return null;
    const [encodedPayload, signature] = token.split('.');
    const expectedSignature = crypto.createHmac('sha256', SESSION_SECRET).update(encodedPayload).digest('hex');
    try {
        const sigBuf = Buffer.from(signature, 'hex');
        const expectedBuf = Buffer.from(expectedSignature, 'hex');
        if (sigBuf.length !== expectedBuf.length || !crypto.timingSafeEqual(sigBuf, expectedBuf)) return null;
    } catch {
        return null;
    }
    try {
        const payload = JSON.parse(base64urlDecode(encodedPayload));
        if (!payload.uid || !payload.exp || Date.now() > payload.exp) return null;
        return payload.uid;
    } catch {
        return null;
    }
}

function parseCookies(req) {
    const header = req.headers.cookie;
    const cookies = {};
    if (!header) return cookies;
    header.split(';').forEach(pair => {
        const idx = pair.indexOf('=');
        if (idx === -1) return;
        const key = pair.slice(0, idx).trim();
        const val = pair.slice(idx + 1).trim();
        cookies[key] = decodeURIComponent(val);
    });
    return cookies;
}

function setSessionCookie(res, token) {
    const secureFlag = process.env.NODE_ENV === 'production' ? '; Secure' : '';
    res.setHeader('Set-Cookie', `kai_session=${encodeURIComponent(token)}; HttpOnly; Path=/; Max-Age=${Math.floor(SESSION_MAX_AGE_MS / 1000)}; SameSite=Lax${secureFlag}`);
}

function clearSessionCookie(res) {
    const secureFlag = process.env.NODE_ENV === 'production' ? '; Secure' : '';
    res.setHeader('Set-Cookie', `kai_session=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax${secureFlag}`);
}

function hashPassword(password, salt) {
    return crypto.scryptSync(password, salt, 64).toString('hex');
}

function verifyPassword(password, salt, hash) {
    const attempt = hashPassword(password, salt);
    try {
        const attemptBuf = Buffer.from(attempt, 'hex');
        const hashBuf = Buffer.from(hash, 'hex');
        return attemptBuf.length === hashBuf.length && crypto.timingSafeEqual(attemptBuf, hashBuf);
    } catch {
        return false;
    }
}

// Attaches req.userId if a valid session cookie or Bearer token is present.
function attachUser(req, res, next) {
    const cookies = parseCookies(req);
    let token = cookies.kai_session;
    if (!token && req.headers.authorization && req.headers.authorization.startsWith('Bearer ')) {
        token = req.headers.authorization.split(' ')[1];
    }
    const uid = verifySession(token);
    req.userId = uid || null;
    next();
}

// Blocks the request entirely if there's no valid logged-in user.
function requireAuth(req, res, next) {
    if (!req.userId) {
        return res.status(401).json({ error: "Not logged in." });
    }
    next();
}

app.use(attachUser);

/* ===================== DAILY AI USAGE CAP (dynamic, real-time split) =====================
   Gemini's free tier is a single shared pool across your whole app (not
   per-user) — roughly 1,500 requests/day. Rather than a fixed per-user
   number, each person's daily allowance is computed live as:
       SHARED_DAILY_AI_BUDGET / (current total registered users)
   So 5 users each get a generous share; 5,000 users each get almost
   nothing — which is an honest signal that free tier has been outgrown
   and it's time to move to billed usage, not a UX choice to fudge. */
const SHARED_DAILY_AI_BUDGET = Number(process.env.SHARED_DAILY_AI_BUDGET) || 1400;

async function checkDailyLimitOnly(req, res, next) {
    try {
        const db = await getDbConnection();
        const today = new Date().toISOString().split('T')[0];

        const userCountRow = await db.get(`SELECT COUNT(*) as count FROM users`);
        const totalUsers = Math.max(userCountRow?.count || 1, 1);
        const perUserLimitToday = Math.max(1, Math.floor(SHARED_DAILY_AI_BUDGET / totalUsers));

        const row = await db.get(
            `SELECT count FROM daily_usage WHERE user_id = ? AND usage_date = ?`,
            [req.userId, today]
        );

        if (row && row.count >= perUserLimitToday) {
            return res.status(429).json({
                error: `You've hit today's AI usage limit (${perUserLimitToday} requests — your even share of today's shared quota across ${totalUsers} user${totalUsers === 1 ? '' : 's'}). This resets tomorrow.`
            });
        }
        next();
    } catch (err) {
        console.error("⚠️ Daily usage check failed, allowing request through:", err.message);
        next(); // fail open — a broken counter shouldn't take down the whole app
    }
}

// Call this AFTER the real work, with the actual number of Gemini calls made —
// so a request that internally retried 3 models costs 3, and a request that
// made zero AI calls (e.g. trim with all prices already user-entered) costs 0.
async function recordAiUsage(userId, callCount) {
    if (!callCount || callCount <= 0) return;
    try {
        const db = await getDbConnection();
        const today = new Date().toISOString().split('T')[0];
        await db.run(
            `INSERT INTO daily_usage (user_id, usage_date, count) VALUES (?, ?, ?)
             ON CONFLICT(user_id, usage_date) DO UPDATE SET count = count + ?`,
            [userId, today, callCount, callCount]
        );
    } catch (err) {
        console.error("⚠️ Failed to record AI usage:", err.message);
    }
}

initDatabase().then(async () => {
    console.log("📂 Local SQLite kitchen database ready.");
    const db = await getDbConnection();

    // Users table for per-person accounts.
    try {
        await db.run(`
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                password_salt TEXT NOT NULL,
                created_at TEXT
            )
        `);
    } catch (usersErr) {
        console.warn("⚠️ Could not ensure users table exists:", usersErr.message);
    }

    // Per-user daily AI usage counter, to cap shared free-tier consumption.
    try {
        await db.run(`
            CREATE TABLE IF NOT EXISTS daily_usage (
                user_id INTEGER NOT NULL,
                usage_date TEXT NOT NULL,
                count INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (user_id, usage_date)
            )
        `);
    } catch (usageErr) {
        console.warn("⚠️ Could not ensure daily_usage table exists:", usageErr.message);
    }

    // Recipe step logs (Cook Again) and daily macro/nutrition logs — both
    // were referenced throughout the API but never created anywhere, which
    // broke signup, meal logging, and the entire Macros tab.
    try {
        await db.run(`
            CREATE TABLE IF NOT EXISTS recipe_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                recipe_name TEXT NOT NULL,
                recipe_steps TEXT,
                ingredients_used TEXT,
                time_taken_minutes INTEGER,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                user_id INTEGER
            )
        `);
        await db.run(`
            CREATE TABLE IF NOT EXISTS daily_macros (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                log_date DATE DEFAULT CURRENT_DATE,
                food_name TEXT NOT NULL,
                calories INTEGER DEFAULT 0,
                protein_g REAL DEFAULT 0,
                carbs_g REAL DEFAULT 0,
                fat_g REAL DEFAULT 0
            )
        `);
        await db.run(`
            CREATE TABLE IF NOT EXISTS push_subscriptions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                endpoint TEXT UNIQUE NOT NULL,
                p256dh TEXT NOT NULL,
                auth TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        `);
    } catch (extraTablesErr) {
        console.warn("⚠️ Could not ensure recipe_logs/daily_macros tables exist:", extraTablesErr.message);
    }

    // Lightweight migrations — wrapped individually so one failure doesn't block the rest.
    // SQLite throws "duplicate column" if a column already exists, which we treat as a no-op.
    const migrations = [
        `ALTER TABLE pantry ADD COLUMN storage TEXT DEFAULT 'Pantry'`,
        `ALTER TABLE pantry ADD COLUMN user_id INTEGER`,
        `ALTER TABLE history ADD COLUMN user_id INTEGER`,
        `ALTER TABLE recipe_logs ADD COLUMN user_id INTEGER`,
        `ALTER TABLE shopping_list ADD COLUMN is_checked INTEGER DEFAULT 0`,
        `ALTER TABLE shopping_list ADD COLUMN category TEXT DEFAULT 'Custom Items'`,
        `ALTER TABLE shopping_list ADD COLUMN is_essential INTEGER DEFAULT 0`,
        `ALTER TABLE shopping_list ADD COLUMN price REAL`,
        `ALTER TABLE shopping_list ADD COLUMN user_id INTEGER`,
        `ALTER TABLE users ADD COLUMN target_calories INTEGER DEFAULT 2000`,
        `ALTER TABLE users ADD COLUMN target_protein_g REAL DEFAULT 150`,
        `ALTER TABLE users ADD COLUMN target_carbs_g REAL DEFAULT 200`,
        `ALTER TABLE users ADD COLUMN target_fat_g REAL DEFAULT 65`
    ];
    for (const sql of migrations) {
        try {
            await db.run(sql);
            console.log(`🧾 Migration applied: ${sql}`);
        } catch (migrationErr) {
            if (!/duplicate column/i.test(migrationErr.message)) {
                console.warn(`⚠️ Migration skipped (${sql}):`, migrationErr.message);
            }
        }
    }
}).catch(err => {
    console.error("❌ Error initializing kitchen DB:", err);
});

// ===================== AUTH ENDPOINTS =====================

// Lightweight in-memory throttle: since the AI budget is split by total user
// count, unlimited signups would let anyone dilute everyone else's daily
// quota to nothing just by scripting fake accounts. Caps signups per IP.
const signupAttempts = new Map(); // ip -> [timestamps]
const SIGNUP_MAX_PER_WINDOW = 5;
const SIGNUP_WINDOW_MS = 60 * 60 * 1000; // 1 hour

function isSignupRateLimited(ip) {
    const now = Date.now();
    const attempts = (signupAttempts.get(ip) || []).filter(t => now - t < SIGNUP_WINDOW_MS);
    attempts.push(now);
    signupAttempts.set(ip, attempts);
    return attempts.length > SIGNUP_MAX_PER_WINDOW;
}

app.post('/api/auth/signup', async (req, res) => {
    try {
        const clientIp = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress || 'unknown';
        if (isSignupRateLimited(clientIp)) {
            return res.status(429).json({ error: "Too many accounts created recently. Please try again later." });
        }

        const { username, password } = req.body;
        if (!username || !password || username.trim().length < 2 || password.length < 6) {
            return res.status(400).json({ error: "Username (2+ chars) and password (6+ chars) are required." });
        }
        const cleanUsername = username.trim();

        // Ensure database tables exist before querying
        await initDatabase();

        const db = await getDbConnection();
        const existing = await db.get("SELECT id FROM users WHERE username = ? COLLATE NOCASE", [cleanUsername]);
        if (existing) {
            return res.status(409).json({ error: "That username is already taken." });
        }

        const salt = crypto.randomBytes(16).toString('hex');
        const hash = hashPassword(password, salt);
        const result = await db.run(
            "INSERT INTO users (username, password_hash, password_salt, created_at) VALUES (?, ?, ?, ?)",
            [cleanUsername, hash, salt, new Date().toISOString()]
        );
        const newUserId = result.lastID;

        // Claim any pre-existing data (added before accounts existed)
        const primaryOwner = process.env.PRIMARY_OWNER_USERNAME;
        const isDesignatedOwner = primaryOwner && cleanUsername.toLowerCase() === primaryOwner.trim().toLowerCase();

        let userCount = { count: 1 };
        try {
            userCount = await db.get("SELECT COUNT(*) as count FROM users") || { count: 1 };
        } catch (e) {}

        const isFirstAccountEver = userCount && userCount.count === 1;

        if (isDesignatedOwner || (!primaryOwner && isFirstAccountEver)) {
            const tables = ['pantry', 'shopping_list', 'history', 'recipe_logs'];
            for (const tbl of tables) {
                try {
                    await db.run(`UPDATE ${tbl} SET user_id = ? WHERE user_id IS NULL`, [newUserId]);
                } catch (e) {
                    console.warn(`Notice claiming ${tbl}:`, e.message);
                }
            }
            console.log(`📦 Claimed pre-existing data for account: ${cleanUsername}`);
        }

        const token = signSession(newUserId);
        setSessionCookie(res, token);
        res.status(201).json({ id: newUserId, username: cleanUsername, token });
    } catch (err) {
        console.error("❌ Error signing up:", err);
        res.status(500).json({ error: "Signup error: " + err.message });
    }
});

const loginAttempts = new Map(); // ip -> [timestamps]
const LOGIN_MAX_PER_WINDOW = 15;
const LOGIN_WINDOW_MS = 15 * 60 * 1000; // 15 minutes

function recordFailedLogin(ip) {
    const now = Date.now();
    const attempts = (loginAttempts.get(ip) || []).filter(t => now - t < LOGIN_WINDOW_MS);
    attempts.push(now);
    loginAttempts.set(ip, attempts);
}

function isLoginRateLimited(ip) {
    const now = Date.now();
    const attempts = (loginAttempts.get(ip) || []).filter(t => now - t < LOGIN_WINDOW_MS);
    return attempts.length >= LOGIN_MAX_PER_WINDOW;
}

app.post('/api/auth/login', async (req, res) => {
    try {
        const clientIp = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress || 'unknown';
        if (isLoginRateLimited(clientIp)) {
            return res.status(429).json({ error: "Too many failed attempts. Please wait a few minutes." });
        }

        const { username, password } = req.body;
        if (!username || !password) {
            return res.status(400).json({ error: "Username and password are required." });
        }

        const db = await getDbConnection();
        const user = await db.get("SELECT * FROM users WHERE username = ? COLLATE NOCASE", [username.trim()]);
        if (!user) {
            recordFailedLogin(clientIp);
            return res.status(404).json({ error: "ACCOUNT_NOT_FOUND", message: `No account found for "${username.trim()}".` });
        }

        if (!verifyPassword(password, user.password_salt, user.password_hash)) {
            recordFailedLogin(clientIp);
            return res.status(401).json({ error: "Incorrect password. Please try again." });
        }

        const token = signSession(user.id);
        setSessionCookie(res, token);
        res.json({ id: user.id, username: user.username, token });
    } catch (err) {
        console.error("❌ Error logging in:", err);
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/auth/logout', (req, res) => {
    clearSessionCookie(res);
    res.json({ success: true });
});

app.get('/api/auth/me', async (req, res) => {
    if (!req.userId) return res.status(401).json({ error: "Not logged in." });
    try {
        const db = await getDbConnection();
        const user = await db.get("SELECT id, username FROM users WHERE id = ?", [req.userId]);
        if (!user) return res.status(401).json({ error: "Not logged in." });
        res.json(user);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});


// GET: All pantry inventory
app.get('/api/pantry', requireAuth, async (req, res) => {
    try {
        const db = await getDbConnection();
        const items = await db.all("SELECT * FROM pantry WHERE user_id = ? ORDER BY expiry_date ASC", [req.userId]);
        res.json(items);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// POST: Log a new food item
app.post('/api/pantry', requireAuth, async (req, res) => {
    const { name, quantity, expiry_date, added_date, storage } = req.body;
    
    if (!name || !expiry_date) {
        return res.status(400).json({ error: "Missing product name or expiry target." });
    }
    
    try {
        const db = await getDbConnection();
        await db.run(
            `INSERT INTO pantry (name, quantity, expiry_date, added_date, storage, user_id) 
             VALUES (?, ?, ?, ?, ?, ?)`,
            [
                name, 
                quantity || '1 count', 
                expiry_date, 
                added_date || new Date().toISOString().split('T')[0], 
                storage || 'Fridge',
                req.userId
            ]
        );
        res.status(201).json({ message: "Successfully logged item." });
    } catch (error) {
        try {
            const db = await getDbConnection();
            await db.run(
                "INSERT INTO pantry (name, quantity, expiry_date, user_id) VALUES (?, ?, ?, ?)",
                [name, quantity || '1 count', expiry_date, req.userId]
            );
            res.status(201).json({ message: "Successfully logged item (legacy columns fallback)." });
        } catch (fallbackError) {
            res.status(500).json({ error: fallbackError.message });
        }
    }
});

// 📸 POST: Analyze image with AI (Food/Pantry Scan)
app.post('/api/pantry/scan', requireAuth, checkDailyLimitOnly, async (req, res) => {
    const { image } = req.body;
    if (!image) {
        return res.status(400).json({ error: "No image payload received." });
    }

    try {
        const base64Data = image.replace(/^data:image\/\w+;base64,/, "");
        console.log("🤖 Sending image to AI for food analysis...");

        const prompt = `You are KAI, an advanced kitchen assistant. Analyze this kitchen camera shot.
Identify:
1. The name of the grocery or raw food item.
2. The approximate quantity or pack volume.
3. The expiration date.

CRITICAL INSTRUCTION: If no expiration date is physically printed or visible, estimate a highly realistic date counting forward from today's date (${new Date().toISOString().split('T')[0]}). For example, milk expires in ~10 days, avocados in ~5 days, chicken in ~3 days.

Return a JSON object with EXACTLY these fields: "name" (string), "quantity" (string), "expiry_date" (string, YYYY-MM-DD), "storage" (string: "Fridge", "Freezer", or "Pantry"). Return a SINGLE JSON object, not an array, not wrapped in markdown.`;

        const { parsed: scannedItem, callsMade } = await analyzeImageForJSON({ imageBase64: base64Data, mimeType: 'image/jpeg', prompt });
        await recordAiUsage(req.userId, callsMade);

        if (!scannedItem || !scannedItem.name) {
            throw new Error("AI did not return a recognizable item.");
        }

        res.json({ success: true, item: scannedItem });
    } catch (error) {
        await recordAiUsage(req.userId, 1); // the call was still made (and billed) even though it errored
        console.error("AI Scan Error:", error);
        res.status(500).json({ error: "Failed to process image with AI: " + error.message });
    }
});

// 💬 POST: Chat with Contextual AI Agent (Multi-Provider Fallback Edition)
app.post('/api/chat', requireAuth, checkDailyLimitOnly, async (req, res) => {
    try {
        const { message, history, pantry } = req.body;

        let pantryContext = "The user's pantry is currently completely empty.";
        if (pantry && pantry.length > 0) {
            pantryContext = "The user has the following items in their pantry right now:\n" +
                pantry.map(item => `- ${item.name} (Quantity: ${item.quantity || 1}, Expires: ${item.expiry_date || 'N/A'}, ID: ${item.id})`).join('\n');
        }

        const systemInstruction = `You are KAI, a helpful, witty, and highly knowledgeable AI kitchen companion ("Kitchen AI").

CRITICAL CONVERSATIONAL RULES:
- Keep the "reply" brief, snappy, text-style, and match the user's energy.
- NEVER ask the user what ingredients they have. You have live database access.

MODE GATING — decide this FIRST, before anything else:
- Set "wantsRecipe" to true ONLY if the user is explicitly asking for a recipe, a meal/dish idea, "what should I cook/eat", to use up pantry items, or a similar food-preparation request.
- Set "wantsRecipe" to false for everything else — greetings, small talk, storage tips, nutrition questions, general questions about an ingredient, thanks/goodbyes, or anything that isn't a request to cook or get a dish idea. Just reply conversationally like a normal chat assistant would; do not mention checking or scanning the pantry, and do not invent a recipe nobody asked for.
- When "wantsRecipe" is false: "isRecipe" must be false, and "ingredients", "steps", "missingIngredients" must all be empty arrays, and "pantryAlternative" must be omitted/null. Do not run pantry-availability logic at all for these messages.

CRITICAL RECIPE STEP GENERATION RULES (only apply when "wantsRecipe" is true; apply to BOTH "steps" and "pantryAlternative.steps" every single time — no exceptions):
- ALWAYS populate "ingredients" with the FULL array of required ingredients for the recipe, each with a real quantity (e.g. "2 boneless chicken thighs", "1 tbsp olive oil", "1/2 tsp smoked paprika"). Never list a bare item name with no amount.
- If items are missing from the user's pantry, list those exact item names inside "missingIngredients".
- When "isRecipe" is false (because ingredients are missing), you MUST still generate a full, cookable "pantryAlternative" using ONLY items already in the user's pantry (plus common staples like salt, pepper, oil, water). It MUST include "pantryAlternative.title", "pantryAlternative.ingredients" (with quantities), AND "pantryAlternative.steps" — never leave any of these empty.
- EVERY recipe (main or alternative) needs a MINIMUM of 4 steps, each a real, actionable, chronological cooking instruction with specifics: actual cook times ("6-7 minutes"), temperatures ("medium-high heat", "375°F"), techniques ("sear", "simmer", "dice finely"), and doneness cues ("until golden and internal temp reaches 165°F").
- BANNED phrases — never output these or anything equivalent, in "steps" or "pantryAlternative.steps": "cook as desired", "heat and serve", "combine ingredients according to taste", "prepare as you like", "serve fresh and enjoy" as a stand-in for real instructions, "follow standard preparation". If you catch yourself about to write something this vague, replace it with the actual technique and timing instead.
- The "pantryAlternative" must be just as rigorous as the main recipe — it is a real recipe made from what's on hand, not a placeholder. Treat "cook with what you have" the same as any other requested dish.

STRICT DEDUPLICATION:
- Return all required ingredients for the requested dish in the "ingredients" array.
- If ingredients are missing from the user's pantry, include those missing item names in the "missingIngredients" array.

REQUIRED JSON OUTPUT SHAPE (always return exactly this shape, no extra fields):
{
  "reply": string,
  "wantsRecipe": boolean,
  "isRecipe": boolean,
  "recipeTitle": string,
  "ingredients": string[],
  "steps": string[],
  "missingIngredients": string[],
  "pantryAlternative": { "title": string, "ingredients": string[], "steps": string[] } | null
}`;

        const contextualizedUserMessage = `[SYSTEM NOTE: Live pantry database supplied]\n${pantryContext}\n\nUser's message: ${message}`;

        const chatMessages = [];
        if (history && history.length > 0) {
            const recentHistory = history.slice(-4);
            recentHistory.forEach(turn => {
                let contentText = "";
                if (typeof turn.content === 'string') {
                    contentText = turn.content;
                } else if (turn.content && turn.content.reply) {
                    contentText = turn.content.reply;
                } else {
                    contentText = JSON.stringify(turn.content);
                }
                chatMessages.push({
                    role: turn.role === "assistant" ? "assistant" : "user",
                    content: contentText
                });
            });
        }
        chatMessages.push({ role: "user", content: contextualizedUserMessage });

        // Guards against empty or "heat and serve"-style placeholder instructions slipping through.
        const BANNED_STEP_PHRASES = [
            'cook as desired', 'heat and serve', 'combine ingredients according to taste',
            'prepare as you like', 'follow standard preparation', 'serve fresh and enjoy'
        ];
        const isVagueStep = (step) => {
            const s = String(step).toLowerCase();
            return BANNED_STEP_PHRASES.some(phrase => s.includes(phrase));
        };
        const isQualityResponse = (parsed) => {
            if (!parsed) return false;
            if (parsed.wantsRecipe) {
                if (parsed.isRecipe) {
                    if (!Array.isArray(parsed.ingredients) || parsed.ingredients.length === 0) return false;
                    if (!Array.isArray(parsed.steps) || parsed.steps.length < 4) return false;
                    if (parsed.steps.some(isVagueStep)) return false;
                } else if (parsed.pantryAlternative) {
                    const alt = parsed.pantryAlternative;
                    if (!Array.isArray(alt.ingredients) || alt.ingredients.length === 0) return false;
                    if (!Array.isArray(alt.steps) || alt.steps.length < 4) return false;
                    if (alt.steps.some(isVagueStep)) return false;
                } else {
                    // Asked for a recipe but got neither a full recipe nor an alternative — not acceptable.
                    return false;
                }
            }
            return true;
        };

        const { parsed: parsedResult, callsMade } = await generateTextJSON({
            systemPrompt: systemInstruction,
            messages: chatMessages,
            temperature: 0.3,
            validate: isQualityResponse
        });

        await recordAiUsage(req.userId, callsMade);

        const uniqueIngredients = Array.from(new Set(
            (parsedResult.ingredients || []).map(i => i.trim().toLowerCase())
        )).map(i => {
            const original = (parsedResult.ingredients || []).find(orig => orig.trim().toLowerCase() === i);
            return original ? original.trim() : i;
        });

        const updatedHistory = [
            ...(history || []).slice(-4),
            { role: 'user', content: message },
            { role: 'assistant', content: parsedResult.reply || "Recipe loaded!" }
        ];

        res.json({
            reply: parsedResult.reply || "Here is what I found!",
            wantsRecipe: parsedResult.wantsRecipe || false,
            isRecipe: parsedResult.isRecipe || false,
            recipeTitle: parsedResult.recipeTitle || '',
            ingredients: uniqueIngredients,
            steps: parsedResult.steps && parsedResult.steps.length > 0 ? parsedResult.steps : [],
            missingIngredients: parsedResult.missingIngredients || [],
            pantryAlternative: parsedResult.pantryAlternative || null,
            history: updatedHistory
        });

    } catch (error) {
        console.error("❌ BACKEND CRASH ERROR LOG:", error.stack || error);

        const isQuotaError = (
            (error && error.message && error.message.toLowerCase().includes('quota')) ||
            (error && error.message && error.message.toLowerCase().includes('rate limit')) ||
            (error && error.message && error.message.includes('429'))
        );

        if (isQuotaError) {
            return res.status(429).json({ error: 'AI quota exceeded across all fallback models. Please try again in a minute.' });
        }

        res.status(503).json({ error: `Service temporarily unavailable. Error: ${error.message}` });
    }
});

// Helper functions for quantity parsing and deduction
function parseQuantityAndUnit(str) {
    if (!str || typeof str !== 'string') return { amount: 1, unit: 'count', baseAmount: 1, category: 'count', raw: str };

    let target = str.trim();
    const parenMatch = target.match(/\(([^)]+)\)/);
    if (parenMatch && parenMatch[1]) {
        const inner = parseQuantityAndUnit(parenMatch[1]);
        if (inner && inner.unit !== 'count' && inner.category !== 'count') {
            return inner;
        }
    }

    let cleanStr = target.toLowerCase()
        .replace(/(\d+)\s+(\d+)\/(\d+)/g, (m, g1, g2, g3) => (Number(g1) + Number(g2)/Number(g3)).toString())
        .replace(/(\d+)\/(\d+)/g, (m, g1, g2) => (Number(g1)/Number(g2)).toString());

    const numMatch = cleanStr.match(/([0-9.]+)\s*([a-zA-Z\s]+)?/);
    if (!numMatch) return { amount: 1, unit: 'count', baseAmount: 1, category: 'count', raw: str };

    const amount = parseFloat(numMatch[1]) || 1;
    let unitRaw = (numMatch[2] || '').trim();
    const unitToken = unitRaw.split(/\s+/)[0] || '';
    const u = unitToken.toLowerCase();

    // Volume (Base unit: tsp)
    if (/^(tsp|teaspoon|teaspoons|t)$/.test(u)) return { amount, unit: 'tsp', baseAmount: amount, category: 'volume' };
    if (/^(tbsp|tablespoon|tablespoons|tbs|tb)$/.test(u)) return { amount, unit: 'tbsp', baseAmount: amount * 3, category: 'volume' };
    if (/^(fl\s*oz|floz|fluid\s*oz)$/.test(u)) return { amount, unit: 'fl oz', baseAmount: amount * 6, category: 'volume' };
    if (/^(cup|cups|c)$/.test(u)) return { amount, unit: 'cup', baseAmount: amount * 48, category: 'volume' };
    if (/^(pt|pint|pints)$/.test(u)) return { amount, unit: 'pint', baseAmount: amount * 96, category: 'volume' };
    if (/^(qt|quart|quarts)$/.test(u)) return { amount, unit: 'quart', baseAmount: amount * 192, category: 'volume' };
    if (/^(gal|gallon|gallons)$/.test(u)) return { amount, unit: 'gallon', baseAmount: amount * 768, category: 'volume' };
    if (/^(ml|milliliter|milliliters)$/.test(u)) return { amount, unit: 'ml', baseAmount: amount * 0.202884, category: 'volume' };
    if (/^(l|liter|liters)$/.test(u)) return { amount, unit: 'l', baseAmount: amount * 202.884, category: 'volume' };

    // Weight (Base unit: g)
    if (/^(g|gram|grams)$/.test(u)) return { amount, unit: 'g', baseAmount: amount, category: 'weight' };
    if (/^(kg|kilogram|kilograms)$/.test(u)) return { amount, unit: 'kg', baseAmount: amount * 1000, category: 'weight' };
    if (/^(oz|ounce|ounces)$/.test(u)) return { amount, unit: 'oz', baseAmount: amount * 28.3495, category: 'weight' };
    if (/^(lb|lbs|pound|pounds)$/.test(u)) return { amount, unit: 'lb', baseAmount: amount * 453.592, category: 'weight' };

    // Common containers (map to base volume/weight so deducting tsp/tbsp/cups/grams works accurately without throwing out the jar)
    if (/^(jar|jars)$/.test(u)) return { amount, unit: 'jar', baseAmount: amount * 96, category: 'volume' }; // 1 jar = 96 tsp (~2 cups / 16 oz)
    if (/^(bottle|bottles)$/.test(u)) return { amount, unit: 'bottle', baseAmount: amount * 96, category: 'volume' };
    if (/^(can|cans)$/.test(u)) return { amount, unit: 'can', baseAmount: amount * 96, category: 'volume' };
    if (/^(tub|tubs)$/.test(u)) return { amount, unit: 'tub', baseAmount: amount * 96, category: 'volume' };
    if (/^(carton|cartons)$/.test(u)) return { amount, unit: 'carton', baseAmount: amount * 192, category: 'volume' }; // 1 carton = 192 tsp (4 cups / 32 fl oz)
    if (/^(container|containers)$/.test(u)) return { amount, unit: 'container', baseAmount: amount * 96, category: 'volume' };
    if (/^(box|boxes)$/.test(u)) return { amount, unit: 'box', baseAmount: amount * 450, category: 'weight' };
    if (/^(bag|bags|pack|packs|packet|packets|package|packages)$/.test(u)) return { amount, unit: 'pack', baseAmount: amount * 450, category: 'weight' };
    if (/^(stick|sticks)$/.test(u)) return { amount, unit: 'stick', baseAmount: amount * 24, category: 'volume' }; // 1 stick butter = 24 tsp

    return { amount, unit: u || 'count', baseAmount: amount, category: 'count' };
}

function formatRemainingQuantity(baseAmount, category, originalUnit) {
    if (baseAmount <= 0.05) return null;

    if (category === 'volume') {
        if (originalUnit === 'jar' || originalUnit === 'bottle' || originalUnit === 'can' || originalUnit === 'tub' || originalUnit === 'carton' || originalUnit === 'container') {
            const initialBase = (originalUnit === 'carton' ? 192 : 96);
            const ratio = baseAmount / initialBase;
            if (ratio >= 0.85) {
                const cups = (baseAmount / 48).toFixed(1).replace(/\.0$/, '');
                return `${cups} cups (~${ratio.toFixed(1)} ${originalUnit})`;
            }
        }

        if (baseAmount >= 48) {
            const cups = (baseAmount / 48).toFixed(1).replace(/\.0$/, '');
            return `${cups} cup${cups === '1' ? '' : 's'}`;
        }
        if (baseAmount >= 3) {
            const tbsp = (baseAmount / 3).toFixed(1).replace(/\.0$/, '');
            return `${tbsp} tbsp`;
        }
        const tsp = baseAmount.toFixed(1).replace(/\.0$/, '');
        return `${tsp} tsp`;
    }

    if (category === 'weight') {
        if (originalUnit === 'oz' || originalUnit === 'lb') {
            const oz = (baseAmount / 28.3495).toFixed(1).replace(/\.0$/, '');
            return `${oz} oz`;
        }
        if (baseAmount >= 1000) {
            const kg = (baseAmount / 1000).toFixed(1).replace(/\.0$/, '');
            return `${kg} kg`;
        }
        const g = Math.round(baseAmount);
        return `${g}g`;
    }

    const rounded = (Math.round(baseAmount * 10) / 10).toString();
    if (originalUnit && originalUnit !== 'count') {
        return `${rounded} ${originalUnit}`;
    }
    return `${rounded} count`;
}

// PUT: Update single pantry item
app.put('/api/pantry/:id', requireAuth, async (req, res) => {
    const { id } = req.params;
    const { name, quantity, expiry_date, storage } = req.body;
    try {
        const db = await getDbConnection();
        const updateFields = [];
        const values = [];

        if (name !== undefined) { updateFields.push("name = ?"); values.push(name); }
        if (quantity !== undefined) { updateFields.push("quantity = ?"); values.push(quantity); }
        if (expiry_date !== undefined) { updateFields.push("expiry_date = ?"); values.push(expiry_date); }
        if (storage !== undefined) { updateFields.push("storage = ?"); values.push(storage); }

        if (updateFields.length === 0) {
            return res.status(400).json({ error: "No fields to update." });
        }

        values.push(id, req.userId);
        await db.run(`UPDATE pantry SET ${updateFields.join(', ')} WHERE id = ? AND user_id = ?`, values);
        res.json({ success: true, message: "Pantry item updated." });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// POST: Intelligent partial quantity deduction for recipe ingredients
app.post('/api/pantry/deduct', requireAuth, async (req, res) => {
    const { ingredients } = req.body;
    if (!ingredients || !Array.isArray(ingredients) || ingredients.length === 0) {
        return res.json({ success: true, deductions: [] });
    }

    try {
        const db = await getDbConnection();
        const pantryItems = await db.all("SELECT * FROM pantry WHERE user_id = ? ORDER BY expiry_date ASC", [req.userId]);

        const deductions = [];

        for (let rawIng of ingredients) {
            let ingString = "";
            if (typeof rawIng === 'string') {
                ingString = rawIng;
            } else if (rawIng && typeof rawIng === 'object') {
                ingString = `${rawIng.quantity || rawIng.amount || ''} ${rawIng.name || rawIng.ingredient || ''}`.trim();
            }
            if (!ingString) continue;

            const ingParsed = parseQuantityAndUnit(ingString);
            
            // Clean name for matching
            const ingNameClean = ingString.toLowerCase()
                .replace(/^[\d\/\.\s]+/, '')
                .replace(/^(tsp|tbsp|cup|cups|oz|g|kg|lb|lbs|fl oz|teaspoon|teaspoons|tablespoon|tablespoons|carton|jar|bottle|slice|slices|piece|pieces|boneless|skinless|fresh|organic|raw|frozen|clove|cloves|of|a|an|some)\s+/gi, '')
                .trim();

            if (!ingNameClean) continue;

            // Match item in pantry
            const matchedItem = pantryItems.find(p => {
                const pName = p.name.toLowerCase();
                const pClean = pName.replace(/organic|fresh|raw|frozen|boneless|skinless/gi, '').trim();
                const ingClean = ingNameClean.replace(/organic|fresh|raw|frozen|boneless|skinless/gi, '').trim();

                return pName.includes(ingNameClean) || ingNameClean.includes(pName) ||
                       (pClean && ingClean && (pClean.includes(ingClean) || ingClean.includes(pClean)));
            });

            if (matchedItem) {
                let pantryParsed = parseQuantityAndUnit(matchedItem.quantity);

                let pCategory = pantryParsed.category;
                let pBaseAmount = pantryParsed.baseAmount;
                let pUnit = pantryParsed.unit;

                // If pantry item category is 'count' or unit mismatch, convert safely so deduction works accurately
                if (pCategory !== ingParsed.category) {
                    if (ingParsed.category === 'volume') {
                        pCategory = 'volume';
                        pBaseAmount = (pUnit === 'carton' ? 192 : 96) * (pantryParsed.amount || 1);
                    } else if (ingParsed.category === 'weight') {
                        pCategory = 'weight';
                        pBaseAmount = 450 * (pantryParsed.amount || 1);
                    }
                }

                const remainingBase = pBaseAmount - ingParsed.baseAmount;
                const newQuantityStr = formatRemainingQuantity(remainingBase, pCategory, pUnit);

                if (!newQuantityStr || remainingBase <= 0) {
                    await db.run("DELETE FROM pantry WHERE id = ? AND user_id = ?", [matchedItem.id, req.userId]);
                    deductions.push({
                        name: matchedItem.name,
                        deducted: ingString,
                        previous: matchedItem.quantity,
                        remaining: 'Finished',
                        action: 'deleted'
                    });
                } else {
                    await db.run("UPDATE pantry SET quantity = ? WHERE id = ? AND user_id = ?", [newQuantityStr, matchedItem.id, req.userId]);
                    matchedItem.quantity = newQuantityStr;
                    deductions.push({
                        name: matchedItem.name,
                        deducted: ingString,
                        previous: matchedItem.quantity,
                        remaining: newQuantityStr,
                        action: 'updated'
                    });
                }
            }
        }

        res.json({ success: true, deductions });
    } catch (err) {
        console.error("❌ Error deducting pantry items:", err);
        res.status(500).json({ error: err.message });
    }
});

// DELETE: Remove single item
app.delete('/api/pantry/:id', requireAuth, async (req, res) => {
    const { id } = req.params;
    try {
        const db = await getDbConnection();
        await db.run("DELETE FROM pantry WHERE id = ? AND user_id = ?", [id, req.userId]);
        res.json({ message: "Item removed from system." });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// BATCH-DELETE: Remove multiple items used in a recipe
app.post('/api/pantry/batch-delete', requireAuth, async (req, res) => {
    const { ids } = req.body; 
    if (!ids || !Array.isArray(ids)) {
        return res.status(400).json({ error: "Invalid or missing item IDs array." });
    }
    try {
        const db = await getDbConnection();
        for (const id of ids) {
            await db.run("DELETE FROM pantry WHERE id = ? AND user_id = ?", [id, req.userId]);
        }
        res.json({ success: true, message: "Used ingredients cleared from inventory." });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// GET: All recipe history
app.get('/api/history', requireAuth, async (req, res) => {
    try {
        const db = await getDbConnection();
        const rows = await db.all("SELECT * FROM history WHERE user_id = ? ORDER BY cooked_date DESC, id DESC", [req.userId]);
        res.json(rows);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// POST: Log history of a completed meal (with recipe logs)
app.post('/api/history', requireAuth, async (req, res) => {
    const { recipe_name, ingredients_used, recipe_steps, time_taken_minutes } = req.body;
    if (!recipe_name) return res.status(400).json({ error: "Missing recipe name." });
    
    try {
        const db = await getDbConnection();
        
        await db.run(
            "INSERT INTO history (recipe_name, ingredients_used, user_id) VALUES (?, ?, ?)",
            [recipe_name, ingredients_used || '', req.userId]
        );
        
        await db.run(
            "INSERT INTO recipe_logs (recipe_name, recipe_steps, ingredients_used, time_taken_minutes, user_id) VALUES (?, ?, ?, ?, ?)",
            [recipe_name, recipe_steps || '', ingredients_used || '', time_taken_minutes || 0, req.userId]
        );
        
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// DELETE: Remove a history record
app.delete('/api/history/:id', requireAuth, async (req, res) => {
    const { id } = req.params;
    try {
        const db = await getDbConnection();
        await db.run("DELETE FROM history WHERE id = ? AND user_id = ?", [id, req.userId]);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// 🥗 DAILY MACROS & NUTRITION ENDPOINTS

// GET: Fetch today's logged macros, totals & user target goals
app.get('/api/macros/today', requireAuth, async (req, res) => {
    try {
        const db = await getDbConnection();
        const today = new Date().toISOString().split('T')[0];
        const rows = await db.all(
            "SELECT * FROM daily_macros WHERE user_id = ? AND log_date = ? ORDER BY id DESC",
            [req.userId, today]
        );

        const user = await db.get(
            "SELECT target_calories, target_protein_g, target_carbs_g, target_fat_g FROM users WHERE id = ?",
            [req.userId]
        );
        
        const goals = {
            target_calories: user?.target_calories || 2000,
            target_protein_g: user?.target_protein_g || 150,
            target_carbs_g: user?.target_carbs_g || 200,
            target_fat_g: user?.target_fat_g || 65
        };
        
        const totals = rows.reduce((acc, curr) => {
            acc.calories += Number(curr.calories) || 0;
            acc.protein += Number(curr.protein_g) || 0;
            acc.carbs += Number(curr.carbs_g) || 0;
            acc.fat += Number(curr.fat_g) || 0;
            return acc;
        }, { calories: 0, protein: 0, carbs: 0, fat: 0 });

        res.json({ date: today, items: rows, totals, goals });
    } catch (err) {
        console.error("❌ Error fetching daily macros:", err);
        res.status(500).json({ error: err.message });
    }
});

// POST: Update user custom daily macro targets
app.post('/api/macros/goals', requireAuth, async (req, res) => {
    try {
        const { target_calories, target_protein_g, target_carbs_g, target_fat_g } = req.body;
        const db = await getDbConnection();
        await db.run(
            `UPDATE users SET target_calories = ?, target_protein_g = ?, target_carbs_g = ?, target_fat_g = ? WHERE id = ?`,
            [
                Math.max(500, Math.min(10000, Number(target_calories) || 2000)),
                Math.max(10, Math.min(500, Number(target_protein_g) || 150)),
                Math.max(10, Math.min(1000, Number(target_carbs_g) || 200)),
                Math.max(5, Math.min(300, Number(target_fat_g) || 65)),
                req.userId
            ]
        );
        res.json({ success: true });
    } catch (err) {
        console.error("❌ Error updating macro goals:", err);
        res.status(500).json({ error: err.message });
    }
});

// POST: Add a new macro entry for today
app.post('/api/macros', requireAuth, async (req, res) => {
    try {
        const { food_name, calories, protein_g, carbs_g, fat_g, log_date } = req.body;
        if (!food_name) return res.status(400).json({ error: "Food name is required" });

        const db = await getDbConnection();
        const today = log_date || new Date().toISOString().split('T')[0];

        const result = await db.run(
            `INSERT INTO daily_macros (user_id, log_date, food_name, calories, protein_g, carbs_g, fat_g)
             VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [
                req.userId,
                today,
                food_name.trim(),
                Math.round(Number(calories) || 0),
                Math.round((Number(protein_g) || 0) * 10) / 10,
                Math.round((Number(carbs_g) || 0) * 10) / 10,
                Math.round((Number(fat_g) || 0) * 10) / 10
            ]
        );

        res.status(201).json({ success: true, id: result.lastID });
    } catch (err) {
        console.error("❌ Error adding macro entry:", err);
        res.status(500).json({ error: err.message });
    }
});

// POST: AI Macro estimation helper
app.post('/api/macros/estimate', requireAuth, checkDailyLimitOnly, async (req, res) => {
    try {
        const { food_name } = req.body;
        if (!food_name) return res.status(400).json({ error: "Food name is required" });

        const { parsed: estimates, callsMade } = await generateTextJSON({
            systemPrompt: `You are a nutrition estimation engine. Given a food item or meal description, estimate its typical nutritional macros. Return realistic values.

REQUIRED JSON OUTPUT SHAPE (always return exactly this shape, no extra fields):
{ "calories": integer, "protein_g": number, "carbs_g": number, "fat_g": number }`,
            messages: [{ role: 'user', content: `Estimate typical nutritional macros for this food item or meal: "${food_name}".` }],
            temperature: 0.2
        });
        await recordAiUsage(req.userId, callsMade);
        res.json({ success: true, estimates });
    } catch (err) {
        await recordAiUsage(req.userId, 1);
        console.error("❌ Error estimating macros with AI:", err);
        res.status(500).json({ error: err.message });
    }
});

// DELETE: Remove a macro entry
app.delete('/api/macros/:id', requireAuth, async (req, res) => {
    try {
        const db = await getDbConnection();
        await db.run("DELETE FROM daily_macros WHERE id = ? AND user_id = ?", [req.params.id, req.userId]);
        res.json({ success: true });
    } catch (err) {
        console.error("❌ Error removing macro entry:", err);
        res.status(500).json({ error: err.message });
    }
});

// 🛒 SHOPPING LIST ENDPOINTS

// GET: Fetch all shopping list items (organized by category)
app.get('/api/shopping-list', requireAuth, async (req, res) => {
    try {
        const db = await getDbConnection();
        const rows = await db.all(`SELECT * FROM shopping_list WHERE user_id = ? ORDER BY category, added_date DESC`, [req.userId]);
        res.json(rows);
    } catch (err) {
        console.error("❌ Error fetching shopping list:", err);
        res.status(500).json({ error: err.message });
    }
});

// POST: Manually add single item to shopping list
app.post('/api/shopping-list', requireAuth, async (req, res) => {
    try {
        const { name, quantity, category, is_essential, price } = req.body;
        if (!name) return res.status(400).json({ error: "Item name is required" });

        const db = await getDbConnection();
        const result = await db.run(
            `INSERT INTO shopping_list (name, quantity, category, is_essential, price, user_id) VALUES (?, ?, ?, ?, ?, ?)`,
            [name, quantity || '1', category || 'Custom Items', is_essential ? 1 : 0, (price !== undefined && price !== '' && price !== null) ? Number(price) : null, req.userId]
        );
        
        res.json({ id: result.lastID, name, quantity: quantity || '1', category: category || 'Custom Items', is_essential: is_essential ? 1 : 0, price: price || null });
    } catch (err) {
        console.error("❌ Error adding item:", err);
        res.status(500).json({ error: err.message });
    }
});

// POST: Batch add missing ingredients from chat
app.post('/api/shopping-list/batch', requireAuth, async (req, res) => {
    try {
        const { items } = req.body; 
        
        if (!items || !Array.isArray(items) || items.length === 0) {
            return res.status(400).json({ error: "No items provided to add" });
        }

        const db = await getDbConnection();
        let addedCount = 0;
        
        for (const rawItem of items) {
            let name = "";
            let quantity = "1";

            if (typeof rawItem === 'string') {
                const parsed = parseQuantityAndUnit(rawItem);
                name = rawItem
                    .replace(/^[\d\/\.\s]+/, '')
                    .replace(/^(tsp|tbsp|cup|cups|oz|g|kg|lb|lbs|fl oz|teaspoon|teaspoons|tablespoon|tablespoons|carton|jar|bottle|slice|slices|piece|pieces|boneless|skinless|fresh|organic|raw|frozen|clove|cloves|of|a|an|some)\s+/gi, '')
                    .trim();
                if (!name) name = rawItem.trim();

                if (parsed.amount && parsed.unit && parsed.unit !== 'count') {
                    quantity = `${parsed.amount} ${parsed.unit}`;
                } else if (parsed.amount && parsed.amount !== 1) {
                    quantity = `${parsed.amount}`;
                }
            } else if (rawItem && typeof rawItem === 'object') {
                name = rawItem.name || rawItem.ingredient || String(rawItem);
                quantity = rawItem.quantity || rawItem.amount || '1';
            }

            if (!name) continue;

            await db.run(
                `INSERT INTO shopping_list (name, quantity, category, is_essential, user_id) VALUES (?, ?, ?, ?, ?)`,
                [name, quantity, 'Recipe Essentials', 1, req.userId]
            );
            addedCount++;
        }
        
        res.json({ success: true, message: `Added ${addedCount} items to your shopping list.` });
    } catch (err) {
        console.error("❌ Error batch-adding items:", err);
        res.status(500).json({ error: err.message });
    }
});

// PUT: Update shopping list item
app.put('/api/shopping-list/:id', requireAuth, async (req, res) => {
    try {
        const { id } = req.params;
        const { is_checked, is_essential, quantity, price } = req.body;
        const db = await getDbConnection();

        let updateFields = [];
        let values = [];

        if (is_checked !== undefined) {
            updateFields.push("is_checked = ?");
            values.push(is_checked ? 1 : 0);
        }
        if (is_essential !== undefined) {
            updateFields.push("is_essential = ?");
            values.push(is_essential ? 1 : 0);
        }
        if (quantity !== undefined) {
            updateFields.push("quantity = ?");
            values.push(quantity);
        }
        if (price !== undefined) {
            updateFields.push("price = ?");
            values.push(price === '' || price === null ? null : Number(price));
        }

        if (updateFields.length === 0) {
            return res.status(400).json({ error: "No fields to update" });
        }

        values.push(id, req.userId);
        await db.run(
            `UPDATE shopping_list SET ${updateFields.join(", ")} WHERE id = ? AND user_id = ?`,
            values
        );

        res.json({ success: true, message: "Item updated" });
    } catch (err) {
        console.error("❌ Error updating item:", err);
        res.status(500).json({ error: err.message });
    }
});

// DELETE: Remove shopping list item
app.delete('/api/shopping-list/:id', requireAuth, async (req, res) => {
    try {
        const { id } = req.params;
        const db = await getDbConnection();
        
        await db.run(`DELETE FROM shopping_list WHERE id = ? AND user_id = ?`, [id, req.userId]);
        res.json({ message: "Item removed from shopping list", id });
    } catch (err) {
        console.error("❌ Error removing shopping list item:", err);
        res.status(500).json({ error: err.message });
    }
});

// POST: Move checked items from shopping list to pantry
app.post('/api/shopping-list/checkout', requireAuth, async (req, res) => {
    try {
        const db = await getDbConnection();

        const allItems = await db.all("SELECT * FROM shopping_list WHERE user_id = ?", [req.userId]);
        // Filter in JS instead of relying on a SQL "= 1" comparison, since the
        // checked flag can come back as 1, true, or "1" depending on driver/schema.
        const checkedItems = allItems.filter(item => {
            const v = item.is_checked;
            return v === 1 || v === true || v === '1' || v === 'true';
        });

        if (checkedItems.length === 0) {
            return res.json({ success: true, message: "No checked items to move.", movedCount: 0 });
        }

        const today = new Date().toISOString().split('T')[0];
        const futureDate = new Date();
        futureDate.setDate(futureDate.getDate() + 14);
        const expiryDate = futureDate.toISOString().split('T')[0];

        const movedIds = [];
        const failedItems = [];

        for (const item of checkedItems) {
            try {
                await db.run(
                    `INSERT INTO pantry (name, quantity, expiry_date, added_date, storage, user_id) VALUES (?, ?, ?, ?, ?, ?)`,
                    [item.name, item.quantity || '1', expiryDate, today, 'Pantry', req.userId]
                );
                movedIds.push(item.id);
            } catch (insertErr) {
                // Legacy schema fallback — mirrors the fallback used in POST /api/pantry.
                try {
                    await db.run(
                        "INSERT INTO pantry (name, quantity, expiry_date, user_id) VALUES (?, ?, ?, ?)",
                        [item.name, item.quantity || '1', expiryDate, req.userId]
                    );
                    movedIds.push(item.id);
                } catch (fallbackErr) {
                    console.error(`❌ Failed to move "${item.name}" to pantry:`, fallbackErr.message);
                    failedItems.push(item.name);
                }
            }
        }

        // Only clear the items that actually made it into the pantry.
        for (const id of movedIds) {
            await db.run("DELETE FROM shopping_list WHERE id = ? AND user_id = ?", [id, req.userId]);
        }

        res.json({
            success: true,
            message: failedItems.length > 0
                ? `Moved ${movedIds.length} items to pantry. Failed: ${failedItems.join(', ')}`
                : `Moved ${movedIds.length} items to pantry`,
            movedCount: movedIds.length,
            failedItems
        });
    } catch (err) {
        console.error("❌ Error checking out items:", err);
        res.status(500).json({ error: err.message });
    }
});

// 📸 POST: Multi-modal Receipt Scan parsing
app.post('/api/pantry/scan-receipt', requireAuth, checkDailyLimitOnly, async (req, res) => {
    try {
        const { imageBase64 } = req.body; 
        if (!imageBase64) return res.status(400).json({ error: "No receipt image data received." });

        const rawBase64 = imageBase64.split(",")[1] || imageBase64;

        const prompt = `You are a high-speed store receipt data extraction engine. 
        Analyze this receipt image and extract all identifiable food items, ingredients, or groceries.
        
        CRITICAL PARSING RULES:
        1. Decode store text abbreviations into clean names (e.g., convert 'ORG BNN' to 'Organic Banana').
        2. Cleanly ignore non-food items entirely (like bags, taxes, structural codes).
        3. Guess a realistic, conservative 'days_until_expiry' integer based on typical ingredient decay cycles.
        
        Return a JSON object with an array called 'items' matching this exact format:
        {
          "items": [
             { "name": "Organic Banana", "quantity": "1 bunch", "days_until_expiry": 5 },
             { "name": "2% Milk", "quantity": "1 carton", "days_until_expiry": 10 }
          ]
        }`;

        const { parsed: parsedData, callsMade } = await analyzeImageForJSON({ imageBase64: rawBase64, mimeType: 'image/jpeg', prompt });
        await recordAiUsage(req.userId, callsMade);

        res.json({ items: parsedData.items || [] });

    } catch (error) {
        await recordAiUsage(req.userId, 1);
        console.error("❌ Receipt scan breakdown:", error);
        res.status(500).json({ error: "Failed to accurately parse the receipt snapshot." });
    }
});

// POST: Budget trimmer - figures out what fits in budget using real (or estimated) prices
app.post('/api/shopping-list/trim', requireAuth, checkDailyLimitOnly, async (req, res) => {
    try {
        const { budget, items } = req.body;
        const budgetNum = Number(budget);
        if (!budgetNum || budgetNum <= 0 || !items || items.length === 0) {
            return res.status(400).json({ error: "A positive budget and at least one item are required" });
        }

        // Items the user already priced don't need AI involvement at all.
        const pricedItems = items.filter(i => i.price !== null && i.price !== undefined && i.price !== '' && !isNaN(Number(i.price)));
        const unpricedItems = items.filter(i => !pricedItems.includes(i));

        let estimates = {}; // name -> { estimatedPrice, essential }

        if (unpricedItems.length > 0) {
            const itemsList = unpricedItems.map(i => `- ${i.name} (qty: ${i.quantity || '1'})`).join('\n');
            const { parsed, callsMade } = await generateTextJSON({
                systemPrompt: `You are a grocery pricing assistant. For each item given, provide your best realistic estimate of its typical US grocery store price for the given quantity, and whether it's a kitchen essential (staple, protein, core ingredient) vs a nice-to-have/optional item. Be realistic and specific with prices — no rounding to guesses like $5 for everything.

REQUIRED JSON OUTPUT SHAPE (always return exactly this shape, no extra fields):
{ "items": [ { "name": string, "estimatedPrice": number, "essential": boolean } ] }`,
                messages: [{ role: 'user', content: itemsList }],
                temperature: 0.2
            });

            await recordAiUsage(req.userId, callsMade);
            (parsed.items || []).forEach(i => {
                estimates[i.name.trim().toLowerCase()] = { estimatedPrice: i.estimatedPrice, essential: !!i.essential };
            });
        }

        // Build a single priced list combining user-entered prices and AI estimates.
        const fullList = items.map(item => {
            const userPrice = pricedItems.includes(item) ? Number(item.price) : null;
            const est = estimates[item.name.trim().toLowerCase()];
            return {
                name: item.name,
                quantity: item.quantity || '1',
                price: userPrice !== null ? userPrice : (est ? est.estimatedPrice : 0),
                priceIsEstimate: userPrice === null,
                essential: item.is_essential ? true : (est ? est.essential : false)
            };
        });

        // Deterministic keep/cut logic — always correct math, never left to the model to add up.
        const essentials = fullList.filter(i => i.essential);
        const optional = fullList.filter(i => !i.essential).sort((a, b) => a.price - b.price);

        const essentialsCost = essentials.reduce((sum, i) => sum + i.price, 0);
        const keep = [...essentials];
        const cut = [];
        let runningTotal = essentialsCost;

        for (const item of optional) {
            if (runningTotal + item.price <= budgetNum) {
                keep.push(item);
                runningTotal += item.price;
            } else {
                cut.push(item);
            }
        }

        res.json({
            budget: budgetNum,
            estimatedTotal: Math.round(runningTotal * 100) / 100,
            fullListTotal: Math.round(fullList.reduce((s, i) => s + i.price, 0) * 100) / 100,
            overBudgetWithEssentialsAlone: essentialsCost > budgetNum,
            keep,
            cut
        });
    } catch (err) {
        console.error("❌ Error trimming list:", err);
        res.status(500).json({ error: err.message });
    }
});

// 🔔 WEB PUSH NOTIFICATION ENDPOINTS

// GET: Fetch public VAPID key
app.get('/api/push/vapid-key', (req, res) => {
    res.json({ publicKey: process.env.PUBLIC_VAPID_KEY || null });
});

// POST: Save push subscription for logged in user
app.post('/api/push/subscribe', requireAuth, async (req, res) => {
    try {
        const { subscription } = req.body;
        if (!subscription || !subscription.endpoint || !subscription.keys) {
            return res.status(400).json({ error: "Invalid subscription object" });
        }
        const db = await getDbConnection();
        await db.run(
            `INSERT INTO push_subscriptions (user_id, endpoint, p256dh, auth) VALUES (?, ?, ?, ?)
             ON CONFLICT(endpoint) DO UPDATE SET user_id = ?, p256dh = ?, auth = ?`,
            [req.userId, subscription.endpoint, subscription.keys.p256dh, subscription.keys.auth,
             req.userId, subscription.keys.p256dh, subscription.keys.auth]
        );
        res.json({ success: true, message: "Push subscription saved" });
    } catch (err) {
        console.error("❌ Error saving push subscription:", err);
        res.status(500).json({ error: err.message });
    }
});

// POST: Trigger a test push notification
app.post('/api/push/send-test', requireAuth, async (req, res) => {
    try {
        if (!process.env.PUBLIC_VAPID_KEY || !process.env.PRIVATE_VAPID_KEY) {
            return res.status(400).json({ error: "VAPID keys are not configured in environment variables." });
        }
        const db = await getDbConnection();
        const subs = await db.all("SELECT * FROM push_subscriptions WHERE user_id = ?", [req.userId]);
        if (!subs || subs.length === 0) {
            return res.status(404).json({ error: "No push subscriptions found for this account. Enable notifications first." });
        }

        const payload = JSON.stringify({
            title: "KAI Notification Test",
            body: "Your smart kitchen push notifications are working perfectly!",
            recipeId: ""
        });

        let sentCount = 0;
        for (const sub of subs) {
            try {
                const pushSub = {
                    endpoint: sub.endpoint,
                    keys: { p256dh: sub.p256dh, auth: sub.auth }
                };
                await webpush.sendNotification(pushSub, payload);
                sentCount++;
            } catch (pushErr) {
                console.warn(`⚠️ Failed to send push to endpoint ${sub.endpoint}:`, pushErr.message);
                if (pushErr.statusCode === 410 || pushErr.statusCode === 404) {
                    await db.run("DELETE FROM push_subscriptions WHERE id = ?", [sub.id]);
                }
            }
        }

        res.json({ success: true, sentCount });
    } catch (err) {
        console.error("❌ Error sending test push notification:", err);
        res.status(500).json({ error: err.message });
    }
});

// Listener Setup
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Server running on port ${PORT}`);
});
