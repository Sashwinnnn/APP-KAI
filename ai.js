import 'dotenv/config';

/* ===================== FREE AI PROVIDERS =====================
   Replaces Gemini entirely. Two free providers, used for different jobs:

   - OpenRouter: used for image analysis (pantry scan, receipt scan) via a
     free vision-capable model, and as a text fallback.
   - Groq: used first for text-only jobs (chat, macro estimates, price
     estimates) since it's fast and has a more generous free tier — Groq's
     vision models are still "preview" and not reliable for production, so
     they're deliberately not used here.

   Both are OpenAI-compatible /chat/completions APIs, so this file is the
   only place that needs to change if you swap providers or models later.

   IMPORTANT: free model IDs on OpenRouter change/get retired over time.
   If scanning or chat suddenly starts failing with a 404/"model not found"
   error, check https://openrouter.ai/models?max_price=0 for current free
   vision models and update OPENROUTER_VISION_MODEL below (or in your .env).

   By default this uses OpenRouter's "openrouter/free" auto-router, which
   picks whichever free model is currently live instead of one hardcoded
   model ID — this avoids the app breaking every time a specific :free
   model gets retired (which happens without much notice).
================================================================= */

const OPENROUTER_API_KEY = process.env.OPENROUTER_API_KEY || '';
const OPENROUTER_URL = 'https://openrouter.ai/api/v1/chat/completions';
const GROQ_API_KEY = process.env.GROQ_API_KEY || '';
const GROQ_URL = 'https://api.groq.com/openai/v1/chat/completions';

const VISION_MODEL = process.env.OPENROUTER_VISION_MODEL || 'openrouter/free';

// Text models to try in order. Each entry is skipped automatically if its
// API key isn't set, so this works fine with only one of the two keys
// configured.
const TEXT_MODEL_CHAIN = [
    { provider: 'groq', url: GROQ_URL, apiKey: GROQ_API_KEY, model: process.env.GROQ_TEXT_MODEL || 'llama-3.3-70b-versatile' },
    { provider: 'openrouter', url: OPENROUTER_URL, apiKey: OPENROUTER_API_KEY, model: process.env.OPENROUTER_TEXT_MODEL || 'openrouter/free' },
    { provider: 'openrouter', url: OPENROUTER_URL, apiKey: OPENROUTER_API_KEY, model: process.env.OPENROUTER_TEXT_MODEL_2 || 'deepseek/deepseek-chat-v3.1:free' }
];

function extractJSON(text) {
    if (!text) return null;
    // Models sometimes wrap JSON in markdown fences even when told not to.
    const cleaned = text.replace(/```json/gi, '').replace(/```/g, '').trim();
    try {
        return JSON.parse(cleaned);
    } catch {
        // Last resort: grab the first {...} or [...] block in the text.
        const match = cleaned.match(/\{[\s\S]*\}|\[[\s\S]*\]/);
        if (match) {
            try { return JSON.parse(match[0]); } catch { /* give up below */ }
        }
        return null;
    }
}

async function callChatCompletions({ url, apiKey, model, messages, temperature }) {
    const headers = {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${apiKey}`
    };
    if (url === OPENROUTER_URL) {
        // OpenRouter asks for these but doesn't require them; harmless either way.
        headers['HTTP-Referer'] = process.env.APP_URL || 'https://kai-kitchen.local';
        headers['X-Title'] = 'KAI Kitchen AI';
    }

    const response = await fetch(url, {
        method: 'POST',
        headers,
        body: JSON.stringify({ model, messages, temperature })
    });

    if (!response.ok) {
        const errBody = await response.text().catch(() => '');
        const err = new Error(`AI request failed (${response.status}): ${errBody.slice(0, 300)}`);
        err.status = response.status;
        throw err;
    }

    const data = await response.json();
    const text = data?.choices?.[0]?.message?.content;
    if (!text) throw new Error('AI response had no content.');
    return text;
}

/**
 * Analyze an image (pantry item photo or receipt) and return parsed JSON.
 * Always goes through OpenRouter's free vision model — requires
 * OPENROUTER_API_KEY to be set.
 */
export async function analyzeImageForJSON({ imageBase64, mimeType = 'image/jpeg', prompt }) {
    if (!OPENROUTER_API_KEY) {
        throw new Error('OPENROUTER_API_KEY is not set. Add it to your .env to enable AI image scanning.');
    }

    const messages = [
        {
            role: 'user',
            content: [
                { type: 'text', text: `${prompt}\n\nRespond with ONLY a raw JSON object — no markdown, no code fences, no explanation before or after it.` },
                { type: 'image_url', image_url: { url: `data:${mimeType};base64,${imageBase64}` } }
            ]
        }
    ];

    const text = await callChatCompletions({
        url: OPENROUTER_URL,
        apiKey: OPENROUTER_API_KEY,
        model: VISION_MODEL,
        messages,
        temperature: 0.2
    });

    const parsed = extractJSON(text);
    if (!parsed) throw new Error('AI returned unparseable JSON for the image analysis.');
    return { parsed, callsMade: 1, modelUsed: `openrouter:${VISION_MODEL}` };
}

/**
 * Text/JSON completion with automatic fallback across free providers.
 * Tries Groq first (fast, generous limits), then OpenRouter free models.
 *
 * @param {object} opts
 * @param {string} opts.systemPrompt - instructions + required JSON shape
 * @param {Array<{role: string, content: string}>} opts.messages - conversation turns
 * @param {number} [opts.temperature]
 * @param {(parsed: any) => boolean} [opts.validate] - optional quality check;
 *        if it returns false, the next model in the chain is tried instead
 *        of accepting a low-quality response.
 */
export async function generateTextJSON({ systemPrompt, messages, temperature = 0.3, validate }) {
    let lastError = null;
    let callsMade = 0;
    let attemptedAny = false;

    for (const { provider, url, apiKey, model } of TEXT_MODEL_CHAIN) {
        if (!apiKey) continue; // this provider isn't configured — skip it
        attemptedAny = true;

        try {
            callsMade++;
            const fullMessages = [
                { role: 'system', content: `${systemPrompt}\n\nRespond with ONLY a raw JSON object — no markdown, no code fences, no explanation before or after it.` },
                ...messages
            ];
            const text = await callChatCompletions({ url, apiKey, model, messages: fullMessages, temperature });
            const parsed = extractJSON(text);

            if (!parsed) {
                console.warn(`⚠️ AI model ${provider}:${model} returned unparseable JSON. Trying next option...`);
                lastError = new Error(`Model ${provider}:${model} returned unparseable JSON.`);
                continue;
            }
            if (validate && !validate(parsed)) {
                console.warn(`⚠️ AI model ${provider}:${model} returned low-quality content. Trying next option...`);
                lastError = new Error(`Model ${provider}:${model} returned low-quality content.`);
                continue;
            }

            return { parsed, callsMade, modelUsed: `${provider}:${model}` };
        } catch (err) {
            console.warn(`⚠️ AI model ${provider}:${model} failed: ${err.message}`);
            lastError = err;
        }
    }

    if (!attemptedAny) {
        throw new Error('No AI provider is configured. Set GROQ_API_KEY and/or OPENROUTER_API_KEY in your .env.');
    }
    throw lastError || new Error('All configured AI providers failed to respond.');
}
