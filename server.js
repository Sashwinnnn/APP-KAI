import express from 'express';
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

initDatabase().then(() => {
    console.log("📂 Local SQLite kitchen database ready.");
}).catch(err => {
    console.error("❌ Error initializing kitchen DB:", err);
});

// GET: All pantry inventory
app.get('/api/pantry', async (req, res) => {
    try {
        const db = await getDbConnection();
        const items = await db.all("SELECT * FROM pantry ORDER BY expiry_date ASC");
        res.json(items);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// POST: Log a new food item
app.post('/api/pantry', async (req, res) => {
    const { name, quantity, expiry_date, added_date, storage } = req.body;
    
    if (!name || !expiry_date) {
        return res.status(400).json({ error: "Missing product name or expiry target." });
    }
    
    try {
        const db = await getDbConnection();
        await db.run(
            `INSERT INTO pantry (name, quantity, expiry_date, added_date, storage) 
             VALUES (?, ?, ?, ?, ?)`,
            [
                name, 
                quantity || '1 count', 
                expiry_date, 
                added_date || new Date().toISOString().split('T')[0], 
                storage || 'Fridge'
            ]
        );
        res.status(201).json({ message: "Successfully logged item." });
    } catch (error) {
        try {
            const db = await getDbConnection();
            await db.run(
                "INSERT INTO pantry (name, quantity, expiry_date) VALUES (?, ?, ?)",
                [name, quantity || '1 count', expiry_date]
            );
            res.status(201).json({ message: "Successfully logged item (legacy columns fallback)." });
        } catch (fallbackError) {
            res.status(500).json({ error: fallbackError.message });
        }
    }
});

// 📸 POST: Analyze image with Gemini (Food/Pantry Scan)
app.post('/api/pantry/scan', async (req, res) => {
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
app.post('/api/chat', async (req, res) => {
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
app.delete('/api/pantry/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const db = await getDbConnection();
        await db.run("DELETE FROM pantry WHERE id = ?", [id]);
        res.json({ message: "Item removed from system." });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// BATCH-DELETE: Remove multiple items used in a recipe
app.post('/api/pantry/batch-delete', async (req, res) => {
    const { ids } = req.body; 
    if (!ids || !Array.isArray(ids)) {
        return res.status(400).json({ error: "Invalid or missing item IDs array." });
    }
    try {
        const db = await getDbConnection();
        for (const id of ids) {
            await db.run("DELETE FROM pantry WHERE id = ?", [id]);
        }
        res.json({ success: true, message: "Used ingredients cleared from inventory." });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// GET: All recipe history
app.get('/api/history', async (req, res) => {
    try {
        const db = await getDbConnection();
        const rows = await db.all("SELECT * FROM history ORDER BY cooked_date DESC, id DESC");
        res.json(rows);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// POST: Log history of a completed meal (with recipe logs)
app.post('/api/history', async (req, res) => {
    const { recipe_name, ingredients_used, recipe_steps, time_taken_minutes } = req.body;
    if (!recipe_name) return res.status(400).json({ error: "Missing recipe name." });
    
    try {
        const db = await getDbConnection();
        
        await db.run(
            "INSERT INTO history (recipe_name, ingredients_used) VALUES (?, ?)",
            [recipe_name, ingredients_used || '']
        );
        
        await db.run(
            "INSERT INTO recipe_logs (recipe_name, recipe_steps, ingredients_used, time_taken_minutes) VALUES (?, ?, ?, ?)",
            [recipe_name, recipe_steps || '', ingredients_used || '', time_taken_minutes || 0]
        );
        
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// DELETE: Remove a history record
app.delete('/api/history/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const db = await getDbConnection();
        await db.run("DELETE FROM history WHERE id = ?", [id]);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// 🛒 SHOPPING LIST ENDPOINTS

// GET: Fetch all shopping list items (organized by category)
app.get('/api/shopping-list', async (req, res) => {
    try {
        const db = await getDbConnection();
        const rows = await db.all(`SELECT * FROM shopping_list ORDER BY category, added_date DESC`);
        res.json(rows);
    } catch (err) {
        console.error("❌ Error fetching shopping list:", err);
        res.status(500).json({ error: err.message });
    }
});

// POST: Manually add single item to shopping list
app.post('/api/shopping-list', async (req, res) => {
    try {
        const { name, quantity, category, is_essential } = req.body;
        if (!name) return res.status(400).json({ error: "Item name is required" });

        const db = await getDbConnection();
        const result = await db.run(
            `INSERT INTO shopping_list (name, quantity, category, is_essential) VALUES (?, ?, ?, ?)`,
            [name, quantity || '1', category || 'Custom Items', is_essential ? 1 : 0]
        );
        
        res.json({ id: result.lastID, name, quantity: quantity || '1', category: category || 'Custom Items', is_essential: is_essential ? 1 : 0 });
    } catch (err) {
        console.error("❌ Error adding item:", err);
        res.status(500).json({ error: err.message });
    }
});

// POST: Batch add missing ingredients from chat
app.post('/api/shopping-list/batch', async (req, res) => {
    try {
        const { items } = req.body; 
        
        if (!items || !Array.isArray(items) || items.length === 0) {
            return res.status(400).json({ error: "No items provided to add" });
        }

        const db = await getDbConnection();
        
        for (const item of items) {
            await db.run(
                `INSERT INTO shopping_list (name, quantity, category, is_essential) VALUES (?, ?, ?, ?)`,
                [item, '1', 'Recipe Essentials', 1]
            );
        }
        
        res.json({ success: true, message: `Added ${items.length} items to your shopping list.` });
    } catch (err) {
        console.error("❌ Error batch-adding items:", err);
        res.status(500).json({ error: err.message });
    }
});

// PUT: Update shopping list item
app.put('/api/shopping-list/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const { is_checked, is_essential, quantity } = req.body;
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

        if (updateFields.length === 0) {
            return res.status(400).json({ error: "No fields to update" });
        }

        values.push(id);
        await db.run(
            `UPDATE shopping_list SET ${updateFields.join(", ")} WHERE id = ?`,
            values
        );

        res.json({ success: true, message: "Item updated" });
    } catch (err) {
        console.error("❌ Error updating item:", err);
        res.status(500).json({ error: err.message });
    }
});

// DELETE: Remove shopping list item
app.delete('/api/shopping-list/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const db = await getDbConnection();
        
        await db.run(`DELETE FROM shopping_list WHERE id = ?`, [id]);
        res.json({ message: "Item removed from shopping list", id });
    } catch (err) {
        console.error("❌ Error removing shopping list item:", err);
        res.status(500).json({ error: err.message });
    }
});

// POST: Move checked items from shopping list to pantry
app.post('/api/shopping-list/checkout', async (req, res) => {
    try {
        const db = await getDbConnection();

        const allItems = await db.all("SELECT * FROM shopping_list");
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
                    `INSERT INTO pantry (name, quantity, expiry_date, added_date, storage) VALUES (?, ?, ?, ?, ?)`,
                    [item.name, item.quantity || '1', expiryDate, today, 'Pantry']
                );
                movedIds.push(item.id);
            } catch (insertErr) {
                // Legacy schema fallback — mirrors the fallback used in POST /api/pantry.
                try {
                    await db.run(
                        "INSERT INTO pantry (name, quantity, expiry_date) VALUES (?, ?, ?)",
                        [item.name, item.quantity || '1', expiryDate]
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
            await db.run("DELETE FROM shopping_list WHERE id = ?", [id]);
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
app.post('/api/pantry/scan-receipt', async (req, res) => {
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

// POST: Budget trimmer - ask KAI to trim shopping list
app.post('/api/shopping-list/trim', async (req, res) => {
    try {
        const { budget, items } = req.body;
        if (!budget || !items || items.length === 0) {
            return res.status(400).json({ error: "Budget and items required" });
        }

        const itemsList = items.map(i => `- ${i.name} (${i.quantity})`).join('\n');
        
        const response = await ai.models.generateContent({
            model: "gemini-3.5-flash",
            contents: [{
                text: `You are a smart shopping budget advisor. The user has a budget of $${budget} and wants to buy these items:\n\n${itemsList}\n\nWhich items are ESSENTIAL and which can be skipped to stay under budget? Return a JSON object with "essential" and "optional" arrays of item names.`
            }],
            config: { responseMimeType: "application/json" }
        });

        const advice = JSON.parse(response.text);
        res.json(advice);
    } catch (err) {
        console.error("❌ Error trimming list:", err);
        res.status(500).json({ error: err.message });
    }
});

// Listener Setup
app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
});
