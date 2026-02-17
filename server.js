/**
 * RedRabbit Relay Server v2.1
 *
 * Security model:
 *   - The server stores ONLY opaque encrypted blobs.
 *   - It has no access to vault keys, user identity keys, or plaintext.
 *   - It cannot decrypt messages or link messages to real-world identities.
 *   - Vault IDs are random tokens with no semantic meaning to the server.
 *   - User IDs are SHA-256(Ed25519_public_key) — unlinkable without the key.
 *
 * What the server sees per message:
 *   { id, vaultId, blob: "<opaque AES-GCM ciphertext>", timestamp, acknowledged: Set<userId> }
 *
 * The blob field is a JSON string containing:
 *   { v, eph, iv, ct, sig, spk } — all base64-encoded crypto material.
 *   The server treats this as a fully opaque string and never parses it.
 *
 * New features in v2.1:
 *   - Participant tracking (blind - just counts userIds)
 *   - Private vault enforcement (max 2 participants)
 *   - Message acknowledgment tracking (for auto-deletion)
 *   - Auto-delete messages after ALL participants acknowledge receipt
 *   - 7-day TTL for undelivered messages
 *   - Robust rate limiting and DDoS protection
 *
 * Production notes:
 *   - Replace in-memory Maps with Redis or a persistent DB.
 *   - Add TLS (HTTPS). Without it, blobs are visible in transit to the network.
 *   - The /admin/stats endpoint should be behind authentication in production.
 */

'use strict';

const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');

const app = express();

// ── Security Middleware ────────────────────────────────────────

app.use(helmet());
app.use(cors());
app.use(express.json({ limit: '2mb' }));

// DDoS Protection: Global rate limiter
const globalLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1 minute
    max: 200, // 200 requests per minute per IP
    message: { success: false, error: 'Too many requests, please slow down' },
    standardHeaders: true,
    legacyHeaders: false,
});

// Aggressive rate limiter for write operations
const writeLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1 minute
    max: 60, // 60 writes per minute per IP
    message: { success: false, error: 'Too many write requests, please slow down' },
    standardHeaders: true,
    legacyHeaders: false,
});

app.use('/api', globalLimiter);

// ── In-memory store ────────────────────────────────────────────
// Replace with Redis / SQLite / Postgres for production.

// vaults: Map<vaultId, { createdAt, type: 'private'|'public', participants: Set<userId>, maxParticipants }>
const vaults = new Map();

// messages: Map<vaultId, Array<{ id, vaultId, blob, timestamp, acknowledged: Set<userId> }>>
const messages = new Map();

const MAX_MESSAGES_PER_VAULT = 2000; // ring-buffer cap
const MESSAGE_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

// ── Helper: get or create vault message list ──────────────────

function getVaultMsgs(vaultId) {
    if (!messages.has(vaultId)) messages.set(vaultId, []);
    return messages.get(vaultId);
}

function getVault(vaultId) {
    if (!vaults.has(vaultId)) {
        vaults.set(vaultId, {
            createdAt: Date.now(),
            type: 'public',
            participants: new Set(),
            maxParticipants: Infinity,
        });
    }
    return vaults.get(vaultId);
}

// ── Cleanup: TTL pruner + auto-delete acknowledged messages ────

setInterval(() => {
    const cutoff = Date.now() - MESSAGE_TTL_MS;
    
    for (const [vaultId, msgs] of messages) {
        const vault = vaults.get(vaultId);
        const participantCount = vault ? vault.participants.size : 0;
        
        // Filter messages:
        // 1. Keep if not expired (< 7 days old)
        // 2. Keep if not all participants have acknowledged
        const pruned = msgs.filter(m => {
            // Delete if older than 7 days
            if (m.timestamp < cutoff) return false;
            
            // Delete if all participants have acknowledged
            if (participantCount > 0 && m.acknowledged.size >= participantCount) {
                return false;
            }
            
            return true;
        });
        
        if (pruned.length !== msgs.length) {
            messages.set(vaultId, pruned);
        }
        
        // Remove empty vault slots
        if (pruned.length === 0 && (!vault || vault.participants.size === 0)) {
            messages.delete(vaultId);
            vaults.delete(vaultId);
        }
    }
}, 60 * 60 * 1000); // Run every hour

// ── API ────────────────────────────────────────────────────────

app.post('/api', (req, res) => {
    const { type, ...data } = req.body || {};

    if (!type) return res.status(400).json({ success: false, error: 'missing type' });

    switch (type) {

        // ── vault_create ───────────────────────────────────────
        // Client tells server a vault ID now exists.
        // No key material is ever sent.
        case 'vault_create': {
            writeLimiter(req, res, () => {
                const { vaultId, vaultType } = data;
                if (!vaultId || typeof vaultId !== 'string') {
                    return res.status(400).json({ success: false, error: 'invalid vaultId' });
                }
                
                const type = vaultType === 'private' ? 'private' : 'public';
                
                if (!vaults.has(vaultId)) {
                    vaults.set(vaultId, {
                        createdAt: Date.now(),
                        type: type,
                        participants: new Set(),
                        maxParticipants: type === 'private' ? 2 : Infinity,
                    });
                    messages.set(vaultId, []);
                }
                
                return res.json({ success: true });
            });
            break;
        }

        // ── vault_join ─────────────────────────────────────────
        // Client announces presence. Server tracks participant count.
        case 'vault_join': {
            const { vaultId, userId } = data;
            if (!vaultId || !userId) {
                return res.status(400).json({ success: false, error: 'invalid vaultId or userId' });
            }
            
            const vault = getVault(vaultId);
            
            // Check if vault is full (for private vaults)
            if (vault.type === 'private' && vault.participants.size >= vault.maxParticipants && !vault.participants.has(userId)) {
                return res.status(403).json({ 
                    success: false, 
                    error: 'Private vault is full (max 2 participants)' 
                });
            }
            
            vault.participants.add(userId);
            getVaultMsgs(vaultId); // Ensure message list exists
            
            return res.json({ 
                success: true, 
                participantCount: vault.participants.size,
                vaultType: vault.type 
            });
        }

        // ── vault_leave ────────────────────────────────────────
        case 'vault_leave': {
            const { vaultId, userId } = data;
            if (vaultId && userId && vaults.has(vaultId)) {
                const vault = vaults.get(vaultId);
                vault.participants.delete(userId);
            }
            return res.json({ success: true });
        }

        // ── message ────────────────────────────────────────────
        // Client posts an encrypted blob. The server stores it verbatim.
        // Server never parses or inspects `blob`.
        case 'message': {
            writeLimiter(req, res, () => {
                const { id, vaultId, blob } = data;

                if (!id || !vaultId || !blob) {
                    return res.status(400).json({ success: false, error: 'missing fields' });
                }
                if (typeof blob !== 'string') {
                    return res.status(400).json({ success: false, error: 'blob must be a string' });
                }
                if (blob.length > 1_000_000) {
                    return res.status(413).json({ success: false, error: 'blob too large' });
                }

                const list = getVaultMsgs(vaultId);

                // Idempotent — ignore duplicate IDs
                if (list.some(m => m.id === id)) {
                    return res.json({ success: true, timestamp: Date.now() });
                }

                const timestamp = Date.now();
                list.push({ 
                    id, 
                    vaultId, 
                    blob, 
                    timestamp,
                    acknowledged: new Set() // Track who has received this message
                });

                // Ring buffer: drop oldest when over cap
                if (list.length > MAX_MESSAGES_PER_VAULT) {
                    list.splice(0, list.length - MAX_MESSAGES_PER_VAULT);
                }

                return res.json({ success: true, timestamp });
            });
            break;
        }

        // ── get_messages ───────────────────────────────────────
        // Returns encrypted blobs since a given timestamp.
        // Also returns current participant count for UI display.
        case 'get_messages': {
            const { vaultId, since } = data;
            if (!vaultId) return res.status(400).json({ success: false, error: 'missing vaultId' });

            const list = getVaultMsgs(vaultId);
            const cutoff = typeof since === 'number' ? since : 0;
            const result = list.filter(m => m.timestamp >= cutoff);
            
            // Convert Set to Array for JSON serialization (acknowledged field)
            const serialized = result.map(m => ({
                id: m.id,
                vaultId: m.vaultId,
                blob: m.blob,
                timestamp: m.timestamp,
                // Server doesn't expose who acknowledged, just the count
            }));
            
            const vault = vaults.get(vaultId);
            const participantCount = vault ? vault.participants.size : 1;

            return res.json({ 
                success: true, 
                data: serialized,
                participantCount: participantCount 
            });
        }

        // ── ack_messages ───────────────────────────────────────
        // Client acknowledges receipt of messages.
        // When all participants acknowledge, message is auto-deleted.
        case 'ack_messages': {
            const { vaultId, messageIds, userId } = data;
            if (!vaultId || !Array.isArray(messageIds) || !userId) {
                return res.status(400).json({ success: false, error: 'invalid parameters' });
            }

            const list = getVaultMsgs(vaultId);
            
            for (const msgId of messageIds) {
                const msg = list.find(m => m.id === msgId);
                if (msg) {
                    msg.acknowledged.add(userId);
                }
            }

            return res.json({ success: true });
        }

        // ── get_participant_count ──────────────────────────────
        // Returns current participant count for a vault
        case 'get_participant_count': {
            const { vaultId } = data;
            if (!vaultId) return res.status(400).json({ success: false, error: 'missing vaultId' });
            
            const vault = vaults.get(vaultId);
            const count = vault ? vault.participants.size : 0;
            
            return res.json({ success: true, participantCount: count });
        }

        // ── nuke_user ──────────────────────────────────────────
        // Wipes all vault data for the specified vaults.
        // Server cannot identify user messages, so client must specify vaultIds.
        case 'nuke_user': {
            writeLimiter(req, res, () => {
                const { vaultIds } = data;
                
                // Opt-in vault wipe (client must explicitly pass vaultIds)
                if (Array.isArray(vaultIds)) {
                    for (const vid of vaultIds) {
                        messages.delete(vid);
                        vaults.delete(vid);
                    }
                }
                
                return res.json({ success: true });
            });
            break;
        }

        default:
            return res.status(400).json({ success: false, error: `unknown type: ${type}` });
    }
});

// ── Health / stats (no sensitive data exposed) ─────────────────

app.get('/health', (_req, res) => {
    res.json({ status: 'ok', ts: Date.now() });
});

app.get('/admin/stats', (_req, res) => {
    let totalMessages = 0;
    let totalParticipants = 0;
    
    for (const msgs of messages.values()) totalMessages += msgs.length;
    for (const vault of vaults.values()) totalParticipants += vault.participants.size;
    
    res.json({
        vaults: vaults.size,
        messages: totalMessages,
        totalParticipants: totalParticipants,
        uptime: process.uptime(),
    });
});

// ── Start ──────────────────────────────────────────────────────

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`RedRabbit relay v2.1 listening on :${PORT}`);
    console.log('Security: server stores encrypted blobs only — no plaintext, no key material.');
    console.log('Features: participant tracking, message acknowledgment, auto-deletion');
    console.log('Rate limits: 200 req/min global, 60 writes/min');
});
