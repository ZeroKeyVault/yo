/**
 * RedRabbit Relay Server v2.3
 *
 * Security model:
 *   - Server stores ONLY opaque AES-GCM encrypted blobs.
 *   - No access to vault keys, user identity keys, or plaintext.
 *   - Cannot decrypt messages or link them to real-world identities.
 *   - Vault IDs are opaque random tokens.
 *   - User IDs are SHA-256(Ed25519_public_key) — unlinkable without the key.
 *
 * What the server sees per message:
 *   { id, vaultId, blob: "<opaque b64 ciphertext>", timestamp, acknowledged: Set<userId> }
 *
 * The blob is a fully opaque string — NEVER parsed.
 *
 * v2.3 changes:
 *   - Rate limiters applied as route-level middleware arrays — fixes the inline
 *     callback pattern that could silently misfire with express-rate-limit v7 async.
 *   - Dedicated sub-routes (/api/vault_create, /api/message, etc.) each with the
 *     correct limiter tier, plus a /api shim for backward compat.
 *   - Pre-parse body-size guard to reject huge requests before JSON parsing.
 *   - Stricter input validation with regex guards.
 *   - All v2.2 semantics preserved: permanent participants, ack-deletion, 7-day TTL,
 *     private vault 2-person cap, eager ack-based deletion.
 *
 * Production notes:
 *   - Replace in-memory Maps with Redis/PostgreSQL.
 *   - Add TLS. Without HTTPS the blobs are visible in transit.
 *   - Guard /admin/stats with auth.
 */

'use strict';

const express   = require('express');
const cors      = require('cors');
const rateLimit = require('express-rate-limit');
const helmet    = require('helmet');

const app = express();

// ── Core Security Middleware ───────────────────────────────────

app.use(helmet({ crossOriginResourcePolicy: false }));

app.use(cors({
    origin: '*',
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type'],
}));

// Reject oversized bodies BEFORE JSON parsing (cheap DDoS guard).
app.use((req, res, next) => {
    const len = parseInt(req.headers['content-length'] || '0', 10);
    if (len > 2 * 1024 * 1024) {
        return res.status(413).json({ success: false, error: 'Request body too large' });
    }
    next();
});

app.use(express.json({ limit: '2mb' }));

// ── Rate Limiters ──────────────────────────────────────────────
//
// Layered defence: every /api request hits the global limiter first,
// then the operation-specific limiter for its route.

// Tier 1 — Global: all /api routes, 300 req/min per IP.
const globalLimiter = rateLimit({
    windowMs:        60 * 1000,
    max:             300,
    standardHeaders: true,
    legacyHeaders:   false,
    message:         { success: false, error: 'Too many requests — please slow down.' },
    skip:            (req) => req.method === 'OPTIONS',
});

// Tier 2 — Writes: vault_create + message + nuke, 60 req/min per IP.
const writeLimiter = rateLimit({
    windowMs:        60 * 1000,
    max:             60,
    standardHeaders: true,
    legacyHeaders:   false,
    message:         { success: false, error: 'Too many write requests — please slow down.' },
});

// Tier 3 — Vault creation specifically, 10 per min per IP.
const vaultCreateLimiter = rateLimit({
    windowMs:        60 * 1000,
    max:             10,
    standardHeaders: true,
    legacyHeaders:   false,
    message:         { success: false, error: 'Too many vault creation requests.' },
});

// Tier 4 — Nuke, 3 per min per IP (should almost never happen).
const nukeLimiter = rateLimit({
    windowMs:        60 * 1000,
    max:             3,
    standardHeaders: true,
    legacyHeaders:   false,
    message:         { success: false, error: 'Too many nuke requests.' },
});

// Tier 5 — Polling reads, 600 per min per IP
// (1 client at 5-second interval = 12/min → 600 supports ~50 concurrent clients per IP).
const readLimiter = rateLimit({
    windowMs:        60 * 1000,
    max:             600,
    standardHeaders: true,
    legacyHeaders:   false,
    message:         { success: false, error: 'Too many read requests — please slow down.' },
});

// Apply global limiter to all /api/* traffic.
app.use('/api', globalLimiter);

// ── Input Validation ───────────────────────────────────────────

function isValidId(s) {
    // Printable ASCII, 8–512 chars.
    return typeof s === 'string' &&
           s.length >= 8 && s.length <= 512 &&
           /^[\x20-\x7E]+$/.test(s);
}

function isValidUserId(s) {
    // base64url, 16–128 chars.
    return typeof s === 'string' &&
           s.length >= 16 && s.length <= 128 &&
           /^[A-Za-z0-9+/=_-]+$/.test(s);
}

// ── In-Memory Store ────────────────────────────────────────────

/**
 * vaults: Map<vaultId, {
 *   createdAt:       number,
 *   type:            'private' | 'public',
 *   participants:    Set<userId>,   // PERMANENT — never shrinks on leave
 *   maxParticipants: number,
 * }>
 *
 * DESIGN NOTE: participants is a permanent set of every userId that has EVER
 * successfully joined. We do NOT remove users on vault_leave because doing so
 * would cause premature ack-based message deletion when a user is temporarily
 * offline. The 7-day TTL handles the case where someone never returns.
 */
const vaults   = new Map();

/**
 * messages: Map<vaultId, Array<{
 *   id, vaultId, blob, timestamp, acknowledged: Set<userId>
 * }>>
 */
const messages = new Map();

const MAX_MESSAGES_PER_VAULT = 2000;
const MESSAGE_TTL_MS         = 7 * 24 * 60 * 60 * 1000; // 7 days

function getVaultMsgs(vaultId) {
    if (!messages.has(vaultId)) messages.set(vaultId, []);
    return messages.get(vaultId);
}

// ── Hourly Cleanup ─────────────────────────────────────────────
//
// Message is deleted when EITHER:
//   (a) Older than 7 days — TTL expired, member never came online.
//   (b) Every permanent participant has acknowledged receipt.

setInterval(() => {
    const cutoff = Date.now() - MESSAGE_TTL_MS;

    for (const [vaultId, msgs] of messages) {
        const vault            = vaults.get(vaultId);
        const participantCount = vault ? vault.participants.size : 0;

        const pruned = msgs.filter(m => {
            if (m.timestamp < cutoff) return false;                                           // (a)
            if (participantCount > 0 && m.acknowledged.size >= participantCount) return false; // (b)
            return true;
        });

        if (pruned.length !== msgs.length) messages.set(vaultId, pruned);

        if (pruned.length === 0 && (!vault || vault.participants.size === 0)) {
            messages.delete(vaultId);
            vaults.delete(vaultId);
        }
    }
}, 60 * 60 * 1000);

// ── Route Handlers ─────────────────────────────────────────────
//
// Each operation has its own route with the correct rate-limiter tier.
// The /api POST shim below provides backward compatibility.

// vault_create — registers a new vault. No key material, just the ID + type.
app.post('/api/vault_create', [writeLimiter, vaultCreateLimiter], (req, res) => {
    const { vaultId, vaultType } = req.body || {};

    if (!isValidId(vaultId)) {
        return res.status(400).json({ success: false, error: 'invalid vaultId' });
    }

    if (!vaults.has(vaultId)) {
        const t = vaultType === 'private' ? 'private' : 'public';
        vaults.set(vaultId, {
            createdAt:       Date.now(),
            type:            t,
            participants:    new Set(),
            maxParticipants: t === 'private' ? 2 : Infinity,
        });
        messages.set(vaultId, []);
    }

    return res.json({ success: true });
});

// vault_join — adds userId to permanent participant set. Enforces private cap.
app.post('/api/vault_join', (req, res) => {
    const { vaultId, userId } = req.body || {};

    if (!isValidId(vaultId) || !isValidUserId(userId)) {
        return res.status(400).json({ success: false, error: 'invalid vaultId or userId' });
    }

    if (!vaults.has(vaultId)) {
        // Auto-stub: vault was registered before a server restart.
        vaults.set(vaultId, {
            createdAt:       Date.now(),
            type:            'public',
            participants:    new Set(),
            maxParticipants: Infinity,
        });
        messages.set(vaultId, []);
    }

    const vault = vaults.get(vaultId);

    if (
        vault.type === 'private' &&
        vault.participants.size >= vault.maxParticipants &&
        !vault.participants.has(userId)
    ) {
        return res.status(403).json({
            success: false,
            error:   'Private vault is full (max 2 participants).',
        });
    }

    vault.participants.add(userId);
    getVaultMsgs(vaultId);

    return res.json({
        success:          true,
        participantCount: vault.participants.size,
        vaultType:        vault.type,
    });
});

// vault_leave — intentional no-op for membership tracking.
app.post('/api/vault_leave', (req, res) => {
    return res.json({ success: true });
});

// message — stores opaque blob. Server NEVER parses blob content.
app.post('/api/message', writeLimiter, (req, res) => {
    const { id, vaultId, blob } = req.body || {};

    if (!isValidId(id) || !isValidId(vaultId)) {
        return res.status(400).json({ success: false, error: 'invalid id or vaultId' });
    }
    if (typeof blob !== 'string' || blob.length === 0) {
        return res.status(400).json({ success: false, error: 'blob must be a non-empty string' });
    }
    if (blob.length > 1_000_000) {
        return res.status(413).json({ success: false, error: 'blob exceeds 1 MB limit' });
    }

    const list = getVaultMsgs(vaultId);

    if (list.some(m => m.id === id)) {
        return res.json({ success: true, timestamp: Date.now() });
    }

    const timestamp = Date.now();
    list.push({ id, vaultId, blob, timestamp, acknowledged: new Set() });

    if (list.length > MAX_MESSAGES_PER_VAULT) {
        list.splice(0, list.length - MAX_MESSAGES_PER_VAULT);
    }

    return res.json({ success: true, timestamp });
});

// get_messages — returns blobs since a given timestamp.
app.post('/api/get_messages', readLimiter, (req, res) => {
    const { vaultId, since } = req.body || {};

    if (!isValidId(vaultId)) {
        return res.status(400).json({ success: false, error: 'invalid vaultId' });
    }

    const list   = getVaultMsgs(vaultId);
    const cutoff = (typeof since === 'number' && since > 0) ? since : 0;

    const serialized = list
        .filter(m => m.timestamp > cutoff)
        .map(m => ({ id: m.id, vaultId: m.vaultId, blob: m.blob, timestamp: m.timestamp }));

    const vault            = vaults.get(vaultId);
    const participantCount = vault ? vault.participants.size : 0;

    return res.json({ success: true, data: serialized, participantCount });
});

// ack_messages — records delivery. Eagerly deletes fully-delivered messages.
app.post('/api/ack_messages', (req, res) => {
    const { vaultId, messageIds, userId } = req.body || {};

    if (!isValidId(vaultId) || !Array.isArray(messageIds) || !isValidUserId(userId)) {
        return res.status(400).json({ success: false, error: 'invalid parameters' });
    }
    if (messageIds.length > 500) {
        return res.status(400).json({ success: false, error: 'too many messageIds (max 500)' });
    }

    const list             = getVaultMsgs(vaultId);
    const vault            = vaults.get(vaultId);
    const participantCount = vault ? vault.participants.size : 0;
    const toDelete         = new Set();

    for (const msgId of messageIds) {
        if (typeof msgId !== 'string') continue;
        const msg = list.find(m => m.id === msgId);
        if (!msg) continue;
        msg.acknowledged.add(userId);
        if (participantCount > 0 && msg.acknowledged.size >= participantCount) {
            toDelete.add(msgId);
        }
    }

    if (toDelete.size > 0) {
        messages.set(vaultId, list.filter(m => !toDelete.has(m.id)));
    }

    return res.json({ success: true });
});

// get_participant_count — returns permanent participant count.
app.post('/api/get_participant_count', readLimiter, (req, res) => {
    const { vaultId } = req.body || {};

    if (!isValidId(vaultId)) {
        return res.status(400).json({ success: false, error: 'invalid vaultId' });
    }

    const vault            = vaults.get(vaultId);
    const participantCount = vault ? vault.participants.size : 0;

    return res.json({ success: true, participantCount });
});

// nuke_user — wipes specified vaults from server entirely.
app.post('/api/nuke_user', nukeLimiter, (req, res) => {
    const { vaultIds } = req.body || {};

    if (Array.isArray(vaultIds)) {
        for (const vid of vaultIds) {
            if (typeof vid === 'string') {
                messages.delete(vid);
                vaults.delete(vid);
            }
        }
    }

    return res.json({ success: true });
});

// ── /api POST shim — backward compatibility ────────────────────
//
// Clients from v2.2 POST to /api with { type, ...fields }.
// This middleware rewrites the URL and re-dispatches to the dedicated route.
// MUST be placed AFTER all /api/<type> routes so it only fires for unmatched POSTs.

app.post('/api', (req, res, next) => {
    const { type } = req.body || {};
    if (!type || typeof type !== 'string') {
        return res.status(400).json({ success: false, error: 'missing type' });
    }

    const allowed = [
        'vault_create', 'vault_join', 'vault_leave',
        'message', 'get_messages', 'ack_messages',
        'get_participant_count', 'nuke_user',
    ];

    if (!allowed.includes(type)) {
        return res.status(400).json({ success: false, error: `unknown type: ${type}` });
    }

    // Rewrite and re-dispatch.
    req.url = `/api/${type}`;
    app.handle(req, res, next);
});

// ── Health & Stats ─────────────────────────────────────────────

app.get('/health', (_req, res) => {
    res.json({ status: 'ok', ts: Date.now() });
});

app.get('/admin/stats', (_req, res) => {
    let totalMessages     = 0;
    let totalParticipants = 0;
    let privateVaults     = 0;
    let publicVaults      = 0;

    for (const msgs of messages.values()) totalMessages += msgs.length;
    for (const v of vaults.values()) {
        totalParticipants += v.participants.size;
        v.type === 'private' ? privateVaults++ : publicVaults++;
    }

    res.json({
        vaults: vaults.size, privateVaults, publicVaults,
        messages: totalMessages, totalParticipants,
        uptime: Math.floor(process.uptime()),
    });
});

// ── 404 catch-all ──────────────────────────────────────────────

app.use((_req, res) => {
    res.status(404).json({ success: false, error: 'not found' });
});

// ── Start ──────────────────────────────────────────────────────

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`\nRedRabbit relay v2.3  port=${PORT}`);
    console.log('Blobs:  opaque AES-GCM only — server is blind to all content.');
    console.log('Limits: global 300/min | write 60/min | create 10/min | nuke 3/min | read 600/min');
    console.log('TTL:    messages auto-deleted on full-ack OR after 7 days.\n');
});
