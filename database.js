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
    
    try {
        await db.exec(`PRAGMA busy_timeout = 5000;`);
    } catch (e) {}

    // 1. Create Pantry table
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

    // 3. Create Recipe Logs Table
    await db.exec(`
        CREATE TABLE IF NOT EXISTS recipe_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            recipe_name TEXT NOT NULL,
            recipe_steps TEXT,
            ingredients_used TEXT,
            time_taken_minutes INTEGER DEFAULT 0,
            user_id INTEGER,
            created_at DATE DEFAULT CURRENT_DATE
        )
    `);

    // 4. Create Shopping List Table
    await db.exec(`
        CREATE TABLE IF NOT EXISTS shopping_list (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            quantity TEXT DEFAULT '1',
            is_checked INTEGER DEFAULT 0,
            category TEXT DEFAULT 'Custom Items',
            is_essential INTEGER DEFAULT 0,
            price REAL,
            user_id INTEGER,
            added_date DATE DEFAULT CURRENT_DATE
        )
    `);

    // 5. Create Users Table
    await db.exec(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            password_salt TEXT NOT NULL,
            created_at TEXT
        )
    `);

    // 6. Create Daily Usage Table
    await db.exec(`
        CREATE TABLE IF NOT EXISTS daily_usage (
            user_id INTEGER NOT NULL,
            usage_date TEXT NOT NULL,
            count INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (user_id, usage_date)
        )
    `);

    // Seed demo values if database is fresh
    try {
        const countResult = await db.get("SELECT COUNT(*) as count FROM pantry");
        if (countResult && countResult.count === 0) {
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
    } catch (seedErr) {
        console.warn("Notice seeding database:", seedErr.message);
    }
}
