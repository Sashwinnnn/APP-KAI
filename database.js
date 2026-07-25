import sqlite3 from 'sqlite3';
import { open } from 'sqlite';

export async function getDbConnection() {
    return open({
        filename: './kai_kitchen.db',
        driver: sqlite3.Database
    });
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

    // 1. Create Pantry table (storage + user_id included so fresh installs
    //    don't need the ALTER TABLE migrations at all)
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

    // 2. Create Recipe History Table
    await db.exec(`
        CREATE TABLE IF NOT EXISTS history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            recipe_name TEXT NOT NULL,
            cooked_date DATE DEFAULT CURRENT_DATE,
            ingredients_used TEXT,
            user_id INTEGER
        )
    `);

    // 3. Recipe step logs — used by "Cook Again" / the flashcard cooking
    //    modal. This table was never created anywhere, which crashed both
    //    /api/history (finishing a recipe) and signup (which tries to claim
    //    pre-existing rows in every table, including this one).
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

    // 3b. Daily macro/nutrition log — the entire Macros tab (log food, AI
    //     estimate, goals) reads/writes this table, but it was never created.
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

    // 🛒 4. Shopping List Table — category/is_essential/is_checked/price were
    //    referenced throughout server.js but never actually existed as
    //    columns, so every insert/update against them failed silently.
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
    if (countResult.count === 0) {
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
