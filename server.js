import express from 'express';
import crypto from 'crypto';
import { GoogleGenAI, Type } from '@google/genai';
import { initDatabase, getDbConnection } from './database.js';
import 'dotenv/config';

const app = express();
const PORT = process.env.PORT || 4000;

app.use(express.json({ limit: '12mb' }));
app.use(express.static('public'));

const apiKey = process.env.GEMINI_API_KEY || "";
console.log(`🔑 Checking API Key: Starts with: ${apiKey.slice(0, 6)}...`);

const ai = new GoogleGenAI({ apiKey: apiKey });

/* ===================== AUTH: sessions & password hashing =====================
   Self-contained (no new npm packages) so this can't break `npm install` on deploy.
   Sessions are a signed cookie: base64url(json).signature — verified with HMAC,
   never trusted blindly. Passwords are hashed with scrypt (Node built-in), never
   stored in plain text. */

const SESSION_SECRET = process.env.SESSION_SECRET || "kai-dev-secret-change-me";
if (!process.env.SESSION_SECRET) {
    console.warn("⚠️ SESSION_SECRET is not set — using an insecure default. Set SESSION_SECRET in your environment before real users sign up.");
}
const SESSION_MAX_AGE_MS = 30 * 24 * 60 * 60 * 1000; // 30 days

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

// Attaches req.userId if a valid session cookie is present, without blocking the request.
function attachUser(req, res, next) {
    const cookies = parseCookies(req);
    const uid = verifySession(cookies.kai_session);
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

async function enforceDailyAiLimit(req, res, next) {
    try {
        const db = await getDbConnection();
        const today = new Date().toISOString().split('T')[0];

        const userCountRow = await db.get(`SELECT COUNT(*) as count FROM users`);
        const totalUsers = Math.max(userCountRow?.count || 1, 1);
        const perUserLimitToday = Math.max(1, Math.floor(SHARED_DAILY_AI_BUDGET / totalUsers));

        await db.run(
            `INSERT INTO daily_usage (user_id, usage_date, count) VALUES (?, ?, 1)
             ON CONFLICT(user_id, usage_date) DO UPDATE SET count = count + 1`,
            [req.userId, today]
        );
        const row = await db.get(
            `SELECT count FROM daily_usage WHERE user_id = ? AND usage_date = ?`,
            [req.userId, today]
        );

        if (row && row.count > perUserLimitToday) {
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

    // Lightweight migrations — wrapped individually so one failure doesn't block the rest.
    // SQLite throws "duplicate column" if a column already exists, which we treat as a no-op.
    const migrations = [
        `ALTER TABLE shopping_list ADD COLUMN price REAL`,
        `ALTER TABLE pantry ADD COLUMN user_id INTEGER`,
        `ALTER TABLE shopping_list ADD COLUMN user_id INTEGER`,
        `ALTER TABLE history ADD COLUMN user_id INTEGER`,
        `ALTER TABLE recipe_logs ADD COLUMN user_id INTEGER`
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

app.post('/api/auth/signup', async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password || username.trim().length < 2 || password.length < 6) {
            return res.status(400).json({ error: "Username (2+ chars) and password (6+ chars) are required." });
        }
        const cleanUsername = username.trim();

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

        // Claim any pre-existing data (added before accounts existed) so it isn't
        // orphaned. Deterministic by username (set PRIMARY_OWNER_USERNAME in your
        // environment) so it's always the same person's account regardless of
        // signup order — not just "whoever happened to sign up first."
        const primaryOwner = process.env.PRIMARY_OWNER_USERNAME;
        const isDesignatedOwner = primaryOwner && cleanUsername.toLowerCase() === primaryOwner.trim().toLowerCase();

        const userCount = await db.get("SELECT COUNT(*) as count FROM users");
        const isFirstAccountEver = userCount && userCount.count === 1;

        if (isDesignatedOwner || (!primaryOwner && isFirstAccountEver)) {
            await db.run("UPDATE pantry SET user_id = ? WHERE user_id IS NULL", [newUserId]);
            await db.run("UPDATE shopping_list SET user_id = ? WHERE user_id IS NULL", [newUserId]);
            await db.run("UPDATE history SET user_id = ? WHERE user_id IS NULL", [newUserId]);
            await db.run("UPDATE recipe_logs SET user_id = ? WHERE user_id IS NULL", [newUserId]);
            console.log(`📦 Claimed pre-existing data for account: ${cleanUsername}`);
        }

        setSessionCookie(res, signSession(newUserId));
        res.status(201).json({ id: newUserId, username: cleanUsername });
    } catch (err) {
        console.error("❌ Error signing up:", err);
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password) {
            return res.status(400).json({ error: "Username and password are required." });
        }

        const db = await getDbConnection();
        const user = await db.get("SELECT * FROM users WHERE username = ? COLLATE NOCASE", [username.trim()]);
        if (!user || !verifyPassword(password, user.password_salt, user.password_hash)) {
            return res.status(401).json({ error: "Incorrect username or password." });
        }

        setSessionCookie(res, signSession(user.id));
        res.json({ id: user.id, username: user.username });
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

// 📸 POST: Analyze image with Gemini (Food/Pantry Scan)
app.post('/api/pantry/scan', requireAuth, enforceDailyAiLimit, async (req, res) => {
    const { image } = req.body;
    if (!image) {
        return res.status(400).json({ error: "No image payload received." });
    }

    try {
        const base64Data = image.replace(/^data:image\/\w+;base64,/, "");
        console.log("🤖 Sending image to Gemini for food analysis...");

        const response = await ai.models.generateContent({
            model: 'gemini-3.5-flash',
            contents: [
                {
                    inlineData: {
                        mimeType: 'image/jpeg',
                        data: base64Data
                    }
                },
                `You are KAI, an advanced kitchen assistant. Analyze this kitchen camera shot. 
                Identify:
                1. The name of the grocery or raw food item.
                2. The approximate quantity or pack volume.
                3. The expiration date. 
                
                CRITICAL INSTRUCTION: If no expiration date is physically printed or visible, estimate a highly realistic date counting forward from today's date (${new Date().toISOString().split('T')[0]}). For example, milk expires in ~10 days, avocados in ~5 days, chicken in ~3 days.
                
                Return a JSON object with fields: name, quantity, expiry_date, storage (Fridge/Freezer/Pantry). Return as a SINGLE object, not an array.`,
            ],
            config: {
                responseMimeType: "application/json",
                responseSchema: {
                    type: Type.OBJECT,
                    properties: {
                        name: { type: Type.STRING },
                        quantity: { type: Type.STRING },
                        expiry_date: { type: Type.STRING },
                        storage: { type: Type.STRING }
                    },
                    required: ["name", "quantity", "expiry_date"]
                }
            }
        });

        const scannedItem = JSON.parse(response.text);
        res.json({ success: true, item: scannedItem });
    } catch (error) {
        console.error("AI Scan Error:", error);
        res.status(500).json({ error: "Failed to process image with AI: " + error.message });
    }
});

// 💬 POST: Chat with Contextual AI Agent (Multi-Tier Fallback Edition)
app.post('/api/chat', requireAuth, enforceDailyAiLimit, async (req, res) => {
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
- If ingredients are missing from the user's pantry, include those missing item names in the "missingIngredients" array.`;

        const contextualizedUserMessage = `[SYSTEM NOTE: Live pantry database supplied]\n${pantryContext}\n\nUser's message: ${message}`;

        const contents = [];
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

                contents.push({
                    role: turn.role === "assistant" ? "model" : "user",
                    parts: [{ text: contentText }]
                });
            });
        }
        
        contents.push({ role: "user", parts: [{ text: contextualizedUserMessage }] });

        const modelsToTry = [
            "gemini-3.5-flash",
            "gemini-3.1-flash-lite",
            "gemini-2.5-flash",
            "gemini-flash-latest"
        ];

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

        let response = null;
        let lastError = null;

        for (const modelName of modelsToTry) {
            try {
                console.log(`📡 Attempting API call with model: ${modelName}...`);
                response = await ai.models.generateContent({
                    model: modelName,
                    contents: contents,
                    config: {
                     systemInstruction: systemInstruction, 
                    temperature: 0.2, 
                    responseMimeType: "application/json",
                    responseSchema: {
                        type: Type.OBJECT,
                        properties: {
                            reply: { type: Type.STRING },
                            wantsRecipe: {
                                type: Type.BOOLEAN,
                                description: "True only if the user is explicitly asking for a recipe, meal idea, or what to cook. False for casual chat, questions, or anything else."
                            },
                            isRecipe: { type: Type.BOOLEAN },
                            recipeTitle: { type: Type.STRING },
                            ingredients: {
                                type: Type.ARRAY,
                                items: { type: Type.STRING },
                                description: "Full list of ingredients needed for the primary recipe."
                            },
                            steps: {
                                type: Type.ARRAY,
                                items: { type: Type.STRING },
                                description: "At least 4 explicit, chronological cooking instructions for the primary recipe."
                            },
                            missingIngredients: {
                                type: Type.ARRAY,
                                items: { type: Type.STRING },
                                description: "List of ingredients missing from pantry."
                            },
                            pantryAlternative: {
                                type: Type.OBJECT,
                                properties: {
                                    title: { type: Type.STRING },
                                    ingredients: {
                                        type: Type.ARRAY,
                                        items: { type: Type.STRING },
                                        description: "Ingredients needed for alternative recipe using on-hand items, each with a real quantity. Never empty."
                                    },
                                    steps: {
                                        type: Type.ARRAY,
                                        items: { type: Type.STRING },
                                        description: "At least 4 explicit, specific, chronological cooking instructions (real times/temps/techniques) for the alternative recipe. Never empty, never vague."
                                    }
                                },
                                required: ["title", "ingredients", "steps"]
                            }
                        },
                        required: ["reply", "wantsRecipe", "isRecipe", "ingredients", "steps", "missingIngredients"]
                    }
                }
            });

            if (response && response.text) {
                    let candidateParsed;
                    try {
                        candidateParsed = JSON.parse(response.text);
                    } catch (parseErr) {
                        console.warn(`⚠️ Model ${modelName} returned unparseable JSON. Trying next option...`);
                        response = null;
                        lastError = parseErr;
                        continue;
                    }

                    if (!isQualityResponse(candidateParsed)) {
                        console.warn(`⚠️ Model ${modelName} returned empty/vague recipe content. Trying next option...`);
                        response = null;
                        lastError = new Error(`Model ${modelName} returned low-quality recipe content.`);
                        continue;
                    }

                    console.log(`✅ Success with model: ${modelName}`);
                    break;
                }
            } catch (err) {
                console.warn(`⚠️ Model ${modelName} failed or busy. Trying next option... (Error: ${err.message})`);
                lastError = err;
            }
        }

        if (!response || !response.text) {
            throw lastError || new Error("All Gemini models failed to respond.");
        }

        const parsedResult = JSON.parse(response.text);
        
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
            (error && (error.code === 429 || (error.error && error.error.code === 429))) ||
            (error && (error.status === 'RESOURCE_EXHAUSTED')) ||
            (error && error.message && error.message.toLowerCase().includes('quota'))
        );

        if (isQuotaError) {
            return res.status(429).json({ error: { message: 'AI quota exceeded across all fallback models. Please try again in a minute.' } });
        }

        res.status(503).json({ error: { message: `Service temporarily unavailable. Error: ${error.message}` } });
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
        
        for (const item of items) {
            await db.run(
                `INSERT INTO shopping_list (name, quantity, category, is_essential, user_id) VALUES (?, ?, ?, ?, ?)`,
                [item, '1', 'Recipe Essentials', 1, req.userId]
            );
        }
        
        res.json({ success: true, message: `Added ${items.length} items to your shopping list.` });
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
app.post('/api/pantry/scan-receipt', requireAuth, enforceDailyAiLimit, async (req, res) => {
    try {
        const { imageBase64 } = req.body; 
        if (!imageBase64) return res.status(400).json({ error: "No receipt image data received." });

        const imagePart = {
            inlineData: {
                data: imageBase64.split(",")[1] || imageBase64,
                mimeType: "image/jpeg"
            }
        };

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

        const response = await ai.models.generateContent({
            model: "gemini-3.5-flash", 
            contents: [prompt, imagePart],
            config: { responseMimeType: "application/json" }
        });

        const parsedData = JSON.parse(response.text);
        res.json({ items: parsedData.items || [] });

    } catch (error) {
        console.error("❌ Receipt scan breakdown:", error);
        res.status(500).json({ error: "Failed to accurately parse the receipt snapshot." });
    }
});

// POST: Budget trimmer - figures out what fits in budget using real (or estimated) prices
app.post('/api/shopping-list/trim', requireAuth, enforceDailyAiLimit, async (req, res) => {
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
            const response = await ai.models.generateContent({
                model: "gemini-3.5-flash",
                contents: [{
                    text: `You are a grocery pricing assistant. For each item below, give your best realistic estimate of its typical US grocery store price for the given quantity, and whether it's a kitchen essential (staple, protein, core ingredient) vs a nice-to-have/optional item.\n\n${itemsList}\n\nBe realistic and specific with prices — no rounding to guesses like $5 for everything.`
                }],
                config: {
                    responseMimeType: "application/json",
                    responseSchema: {
                        type: Type.OBJECT,
                        properties: {
                            items: {
                                type: Type.ARRAY,
                                items: {
                                    type: Type.OBJECT,
                                    properties: {
                                        name: { type: Type.STRING },
                                        estimatedPrice: { type: Type.NUMBER, description: "Realistic USD price estimate for this item at the given quantity." },
                                        essential: { type: Type.BOOLEAN }
                                    },
                                    required: ["name", "estimatedPrice", "essential"]
                                }
                            }
                        },
                        required: ["items"]
                    }
                }
            });

            const parsed = JSON.parse(response.text);
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

// Listener Setup
app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
});
