import { createClient } from '@libsql/client';
import 'dotenv/config';

/* ===================== TURSO (libSQL) =====================
   Replaces local SQLite so data survives Render's ephemeral filesystem —
   Render wipes any local file (like the old kai_kitchen.db) on every
   redeploy, restart, or free-tier spin-down. Turso is SQLite-compatible
   but lives on Turso's servers instead of your app's disk, and its free
   tier doesn't expire.

   Setup (one time):
     1. npm install -g turso-cli   (or use the Turso web dashboard instead)
     2. turso auth signup
     3. turso db create kai-kitchen
     4. turso db show kai-kitchen --url          -> TURSO_DATABASE_URL
     5. turso db tokens create kai-kitchen        -> TURSO_AUTH_TOKEN
     6. Put both in your .env (and in Render's Environment settings).

   If TURSO_DATABASE_URL isn't set, this falls back to a local file named
   kai_kitchen.db — handy for local development, but remember that will
   NOT persist on Render's free tier. Always set the Turso env vars for
   anything you deploy.
============================================================== */

let clientInstance = null;

function getClient() {
    if (!clientInstance) {
        const url = process.env.TURSO_DATABASE_URL || 'file:./kai_kitchen.db';
        const authToken = process.env.TURSO_AUTH_TOKEN || undefined;

        if (url.startsWith('file:')) {
            console.warn("⚠️ TURSO_DATABASE_URL is not set — using a local SQLite file. This will NOT persist on Render's free tier. Set TURSO_DATABASE_URL and TURSO_AUTH_TOKEN in your .env for production.");
        }

        clientInstance = createClient({ url, authToken });
    }
    return clientInstance;
}

/**
 * Thin wrapper that mimics the old `sqlite` package's db.get/all/run/exec
 * API, backed by @libsql/client. This is the only reason server.js didn't
 * need to be rewritten when swapping databases.
 */
function wrapClient(client) {
    return {
        async get(sql, params = []) {
            const result = await client.execute({ sql, args: params });
            return result.rows[0] || undefined;
        },
        async all(sql, params = []) {
            const result = await client.execute({ sql, args: params });
            return result.rows;
        },
        async run(sql, params = []) {
            const result = await client.execute({ sql, args: params });
            return {
                lastID: result.lastInsertRowid !== undefined && result.lastInsertRowid !== null
                    ? Number(result.lastInsertRowid)
                    : undefined,
                changes: result.rowsAffected
            };
        },
        async exec(sql) {
            // Handles either a single statement or several separated by ';'.
            await client.executeMultiple(sql);
        }
    };
}

export async function getDbConnection() {
    return wrapClient(getClient());
}

export async function initDatabase() {
    const db = await getDbConnection();

    // 0. Users table — required for multi-user accounts. Missing this table
    //    (or any of the ones below) is what made signup crash with
    //    "no such table: ..." errors.
    await db.exec(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            password_salt TEXT NOT NULL,
            created_at TEXT,
            target_calories INTEGER DEFAULT 2000,
            target_protein_g REAL DEFAULT 150,
            target_carbs_g REAL DEFAULT 200,
            target_fat_g REAL DEFAULT 65
        )
    `);

    // 1. Pantry table (storage + user_id included so fresh installs don't
    //    need the ALTER TABLE migrations at all)
    await db.exec(`
        CREATE TABLE IF NOT EXISTS pantry (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            quantity TEXT DEFAULT '1',
            expiry_date DATE NOT NULL,
            added_date DATE DEFAULT CURRENT_DATE,
            storage TEXT DEFAULT 'Pantry',
            user_id INTEGER
        )
    `);

    // 2. Recipe History Table
    await db.exec(`
        CREATE TABLE IF NOT EXISTS history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            recipe_name TEXT NOT NULL,
            cooked_date DATE DEFAULT CURRENT_DATE,
            ingredients_used TEXT,
            user_id INTEGER
        )
    `);

    // 3. Recipe step logs — used by "Cook Again" / the flashcard cooking modal.
    await db.exec(`
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

    // 3b. Daily macro/nutrition log — the Macros tab (log food, AI estimate, goals).
    await db.exec(`
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

    // 4. Shopping List Table
    await db.exec(`
        CREATE TABLE IF NOT EXISTS shopping_list (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            quantity TEXT DEFAULT '1',
            category TEXT DEFAULT 'Custom Items',
            is_essential INTEGER DEFAULT 0,
            is_checked INTEGER DEFAULT 0,
            price REAL,
            added_date DATE DEFAULT CURRENT_DATE,
            user_id INTEGER
        )
    `);

    // 5. Per-user daily AI usage counter (shared free-tier budget split).
    await db.exec(`
        CREATE TABLE IF NOT EXISTS daily_usage (
            user_id INTEGER NOT NULL,
            usage_date TEXT NOT NULL,
            count INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (user_id, usage_date)
        )
    `);

    // Seed demo values if database is fresh
    const countResult = await db.get("SELECT COUNT(*) as count FROM pantry");
    if (Number(countResult.count) === 0) {
        const today = new Date();

        const expiredDate = new Date();
        expiredDate.setDate(today.getDate() - 2);

        const soonDate = new Date();
        soonDate.setDate(today.getDate() + 2);

        const freshDate = new Date();
        freshDate.setDate(today.getDate() + 12);

        await db.run(
            "INSERT INTO pantry (name, quantity, expiry_date) VALUES (?, ?, ?)",
            ['Organic Whole Milk', '1 carton', expiredDate.toISOString().split('T')[0]]
        );
        await db.run(
            "INSERT INTO pantry (name, quantity, expiry_date) VALUES (?, ?, ?)",
            ['Fresh Avocado', '2 count', soonDate.toISOString().split('T')[0]]
        );
        await db.run(
            "INSERT INTO pantry (name, quantity, expiry_date) VALUES (?, ?, ?)",
            ['Boneless Chicken Breast', '500g', freshDate.toISOString().split('T')[0]]
        );
        console.log("🌱 Database seeded with mock pantry items.");
    }
}
