import 'dotenv/config';
import { GoogleGenAI } from '@google/genai';

/* ===================== AI PROVIDERS =====================
   Supports Gemini via @google/genai as primary provider when
   GEMINI_API_KEY is present, with fallback to Groq and OpenRouter.
   ======================================================== */

const GEMINI_API_KEY = process.env.GEMINI_API_KEY || '';
const OPENROUTER_API_KEY = process.env.OPENROUTER_API_KEY || '';
const OPENROUTER_URL = 'https://openrouter.ai/api/v1/chat/completions';
const GROQ_API_KEY = process.env.GROQ_API_KEY || '';
const GROQ_URL = 'https://api.groq.com/openai/v1/chat/completions';

const VISION_MODEL = process.env.OPENROUTER_VISION_MODEL || 'openrouter/free';

let geminiClient = null;
function getGeminiClient() {
    if (!geminiClient && GEMINI_API_KEY) {
        geminiClient = new GoogleGenAI({
            apiKey: GEMINI_API_KEY,
            httpOptions: {
                headers: {
                    'User-Agent': 'aistudio-build'
                }
            }
        });
    }
    return geminiClient;
}

function extractJSON(text) {
    if (!text) return null;
    const cleaned = text.replace(/```json/gi, '').replace(/```/g, '').trim();
    try {
        return JSON.parse(cleaned);
    } catch {
        const match = cleaned.match(/\{[\s\S]*\}|\[[\s\S]*\]/);
        if (match) {
            try { return JSON.parse(match[0]); } catch { /* ignore */ }
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
 */
export async function analyzeImageForJSON({ imageBase64, mimeType = 'image/jpeg', prompt }) {
    if (process.env.GEMINI_API_KEY) {
        try {
            const ai = getGeminiClient();
            const response = await ai.models.generateContent({
                model: 'gemini-3.6-flash',
                contents: [
                    {
                        role: 'user',
                        parts: [
                            { text: `${prompt}\n\nRespond with ONLY a raw JSON object — no markdown, no code fences, no explanation before or after it.` },
                            { inlineData: { mimeType, data: imageBase64 } }
                        ]
                    }
                ],
                config: { temperature: 0.2, responseMimeType: 'application/json' }
            });
            const text = response.text;
            const parsed = extractJSON(text);
            if (parsed) {
                return { parsed, callsMade: 1, modelUsed: 'gemini:gemini-3.6-flash' };
            }
        } catch (err) {
            console.warn(`⚠️ Gemini image analysis failed: ${err.message}. Trying OpenRouter...`);
        }
    }

    if (!OPENROUTER_API_KEY) {
        throw new Error('Neither GEMINI_API_KEY nor OPENROUTER_API_KEY is configured for AI image scanning.');
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
 * Text/JSON completion with automatic fallback across Gemini, Groq, and OpenRouter.
 */
export async function generateTextJSON({ systemPrompt, messages, temperature = 0.3, validate }) {
    let lastError = null;
    let callsMade = 0;

    // 1. Try Gemini first if key exists
    if (process.env.GEMINI_API_KEY) {
        try {
            callsMade++;
            const ai = getGeminiClient();

            // Convert conversation messages format to prompt/history or combined prompt for Gemini
            let formattedPrompt = `${systemPrompt}\n\nRespond with ONLY a raw JSON object — no markdown, no code fences, no explanation before or after it.\n\n`;
            for (const msg of messages) {
                formattedPrompt += `[${msg.role.toUpperCase()}]: ${msg.content}\n`;
            }

            const response = await ai.models.generateContent({
                model: 'gemini-3.6-flash',
                contents: formattedPrompt,
                config: { temperature, responseMimeType: 'application/json' }
            });

            const parsed = extractJSON(response.text);
            if (parsed && (!validate || validate(parsed))) {
                return { parsed, callsMade, modelUsed: 'gemini:gemini-3.6-flash' };
            }
            if (parsed && validate && !validate(parsed)) {
                console.warn(`⚠️ Gemini returned low-quality content. Trying next provider...`);
            }
        } catch (err) {
            console.warn(`⚠️ Gemini text generation failed: ${err.message}. Trying next provider...`);
            lastError = err;
        }
    }

    // 2. Fall back to Groq and OpenRouter
    const textChain = [
        { provider: 'groq', url: GROQ_URL, apiKey: GROQ_API_KEY, model: process.env.GROQ_TEXT_MODEL || 'llama-3.3-70b-versatile' },
        { provider: 'openrouter', url: OPENROUTER_URL, apiKey: OPENROUTER_API_KEY, model: process.env.OPENROUTER_TEXT_MODEL || 'openrouter/free' },
        { provider: 'openrouter', url: OPENROUTER_URL, apiKey: OPENROUTER_API_KEY, model: process.env.OPENROUTER_TEXT_MODEL_2 || 'deepseek/deepseek-chat-v3.1:free' }
    ];

    for (const { provider, url, apiKey, model } of textChain) {
        if (!apiKey) continue;

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

    if (!process.env.GEMINI_API_KEY && !GROQ_API_KEY && !OPENROUTER_API_KEY) {
        throw new Error('No AI provider is configured. Set GEMINI_API_KEY, GROQ_API_KEY, or OPENROUTER_API_KEY in your environment.');
    }
    throw lastError || new Error('All configured AI providers failed to respond.');
}
