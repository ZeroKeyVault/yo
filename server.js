/**
 * RedRabbit Relay Server v2.0
 *
 * Security model:
 *   - The server stores ONLY opaque encrypted blobs.
 *   - It has no access to vault keys, user identity keys, or plaintext.
 *   - It cannot decrypt messages or link messages to real-world identities.
 *   - Vault IDs are random tokens with no semantic meaning to the server.
 *   - User IDs are SHA-256(Ed25519_public_key) — unlinkable without the key.
 *
 * New features:
 *   - Server-controlled timestamps (clients cannot manipulate time)
 *   - Rate limiting & DoS protection
 *   - SQLite persistent database with auto-backups
 *   - Message acknowledgment system (messages deleted after relay)
 *   - Two-person limit for private vaults
 *   - Input validation & schema enforcement
 *   - Horizontal scaling ready (use Redis for distributed rate limiting)
 */

'use strict';

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const Database = require('better-sqlite3');
const Joi = require('joi');
const fs = require('fs');
const path = require('path');

const app = express();

// ── Configuration ──────────────────────────────────────────────────

const MAX_MESSAGES_PER_VAULT = 2000;
const MESSAGE_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 days
const MAX_VAULT_MEMBERS = 2; // Limit for private vaults
const DB_PATH = process.env.DB_PATH || './redrabbit.db';
const BACKUP_DIR = process.env.BACKUP_DIR || './backups';
const BACKUP_INTERVAL_MS = 60 * 60 * 1000; // 1 hour

// ── Database Setup ─────────────────────────────────────────────────

let db;
let queries;

function initDatabase() {
    db = new Database(DB_PATH);
    db.pragma('journal_mode = WAL');
    db.pragma('synchronous = NORMAL');

    // Vaults table
    db.exec(`
        CREATE TABLE IF NOT EXISTS vaults (
            id TEXT PRIMARY KEY,
            type TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            member_count INTEGER DEFAULT 0
        )
    `);

    // Messages table
    db.exec(`
        CREATE TABLE IF NOT EXISTS messages (
            id TEXT PRIMARY KEY,
            vault_id TEXT NOT NULL,
            blob TEXT NOT NULL,
            timestamp INTEGER NOT NULL,
            created_at INTEGER NOT NULL,
            FOREIGN KEY (vault_id) REFERENCES vaults(id)
        )
    `);

    // Message acknowledgments (track who received what)
    db.exec(`
        CREATE TABLE IF NOT EXISTS message_acks (
            message_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            acked_at INTEGER NOT NULL,
            PRIMARY KEY (message_id, user_id),
            FOREIGN KEY (message_id) REFERENCES messages(id)
        )
    `);

    // Vault members tracking
    db.exec(`
        CREATE TABLE IF NOT EXISTS vault_members (
            vault_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            joined_at INTEGER NOT NULL,
            PRIMARY KEY (vault_id, user_id),
            FOREIGN KEY (vault_id) REFERENCES vaults(id)
        )
    `);

    // Indexes for performance
    db.exec(`CREATE INDEX IF NOT EXISTS idx_messages_vault_time ON messages(vault_id, timestamp)`);
    db.exec(`CREATE INDEX IF NOT EXISTS idx_messages_created ON messages(created_at)`);
    db.exec(`CREATE INDEX IF NOT EXISTS idx_vault_members ON vault_members(vault_id)`);

    console.log('✓ Database initialized');
    
    // Prepare queries after database is initialized
    prepareQueries();
}

function prepareQueries() {
    queries = {
        createVault: db.prepare(`
            INSERT OR IGNORE INTO vaults (id, type, created_at, member_count)
            VALUES (?, ?, ?, 0)
        `),

        getVault: db.prepare(`SELECT * FROM vaults WHERE id = ?`),

        incrementMemberCount: db.prepare(`
            UPDATE vaults SET member_count = member_count + 1 WHERE id = ?
        `),

        decrementMemberCount: db.prepare(`
            UPDATE vaults SET member_count = CASE WHEN member_count > 0 THEN member_count - 1 ELSE 0 END WHERE id = ?
        `),

        addMember: db.prepare(`
            INSERT OR IGNORE INTO vault_members (vault_id, user_id, joined_at)
            VALUES (?, ?, ?)
        `),

        removeMember: db.prepare(`
            DELETE FROM vault_members WHERE vault_id = ? AND user_id = ?
        `),

        getMemberCount: db.prepare(`
            SELECT COUNT(*) as count FROM vault_members WHERE vault_id = ?
        `),

        insertMessage: db.prepare(`
            INSERT OR IGNORE INTO messages (id, vault_id, blob, timestamp, created_at)
            VALUES (?, ?, ?, ?, ?)
        `),

        getMessages: db.prepare(`
            SELECT id, vault_id, blob, timestamp
            FROM messages
            WHERE vault_id = ? AND timestamp >= ?
            ORDER BY timestamp ASC
            LIMIT 500
        `),

        ackMessage: db.prepare(`
            INSERT OR IGNORE INTO message_acks (message_id, user_id, acked_at)
            VALUES (?, ?, ?)
        `),

        getMessageAckCount: db.prepare(`
            SELECT COUNT(*) as count FROM message_acks WHERE message_id = ?
        `),

        deleteMessage: db.prepare(`DELETE FROM messages WHERE id = ?`),

        deleteMessageAcks: db.prepare(`DELETE FROM message_acks WHERE message_id = ?`),

        getVaultMessages: db.prepare(`
            SELECT COUNT(*) as count FROM messages WHERE vault_id = ?
        `),

        getOldestMessages: db.prepare(`
            SELECT id FROM messages WHERE vault_id = ? ORDER BY timestamp ASC LIMIT ?
        `),

        deleteVault: db.prepare(`DELETE FROM vaults WHERE id = ?`),

        deleteVaultMessages: db.prepare(`DELETE FROM messages WHERE vault_id = ?`),

        deleteVaultMembers: db.prepare(`DELETE FROM vault_members WHERE vault_id = ?`),

        pruneOldMessages: db.prepare(`
            DELETE FROM messages WHERE created_at < ?
        `),
    };
}

// ── Backup System ──────────────────────────────────────────────────

function createBackup() {
    try {
        if (!fs.existsSync(BACKUP_DIR)) {
            fs.mkdirSync(BACKUP_DIR, { recursive: true });
        }

        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        const backupPath = path.join(BACKUP_DIR, `redrabbit-${timestamp}.db`);
        
        db.backup(backupPath);
        console.log(`✓ Backup created: ${backupPath}`);

        // Clean old backups (keep last 24)
        const backups = fs.readdirSync(BACKUP_DIR)
            .filter(f => f.startsWith('redrabbit-') && f.endsWith('.db'))
            .sort()
            .reverse();

        backups.slice(24).forEach(old => {
            fs.unlinkSync(path.join(BACKUP_DIR, old));
        });
    } catch (e) {
        console.error('Backup error:', e);
    }
}

// ── Input Validation Schemas ───────────────────────────────────────

const schemas = {
    vaultId: Joi.string().min(10).max(100).required(),
    userId: Joi.string().min(10).max(100).required(),
    messageId: Joi.string().min(10).max(100).required(),
    blob: Joi.string().min(1).max(1000000).required(),
    timestamp: Joi.number().integer().positive().optional(),
    since: Joi.number().integer().min(0).optional(),
    vaultIds: Joi.array().items(Joi.string()).max(100).optional(),
    type: Joi.string().valid('vault_create', 'vault_join', 'vault_leave', 
                             'message', 'get_messages', 'ack_messages', 'nuke_user').required(),
    vaultType: Joi.string().valid('private', 'public').optional(),
};

function validate(data, schema) {
    const { error, value } = schema.validate(data, { stripUnknown: true });
    if (error) throw new Error(`Validation: ${error.message}`);
    return value;
}

// ── Rate Limiting & DoS Protection ─────────────────────────────────

const generalLimiter = rateLimit({
    windowMs: 60 * 1000, // 1 minute
    max: 100, // 100 requests per minute
    message: { success: false, error: 'Too many requests' },
    standardHeaders: true,
    legacyHeaders: false,
});

const messageLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 30, // 30 messages per minute
    message: { success: false, error: 'Message rate limit exceeded' },
    keyGenerator: (req) => {
        // Rate limit per user+vault combination
        const body = req.body || {};
        return `${req.ip}-${body.vaultId || ''}-${body.userId || ''}`;
    },
});

const vaultLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 10, // 10 vault creates per hour
    message: { success: false, error: 'Vault creation rate limit exceeded' },
});

// ── Middleware ─────────────────────────────────────────────────────

app.use(helmet({
    contentSecurityPolicy: false, // Allow CORS
}));
app.use(cors());
app.use(express.json({ limit: '2mb' }));
app.use(generalLimiter);

// Request logging for debugging
app.use((req, res, next) => {
    const start = Date.now();
    res.on('finish', () => {
        const duration = Date.now() - start;
        if (duration > 1000) {
            console.log(`⚠ Slow request: ${req.method} ${req.path} ${duration}ms`);
        }
    });
    next();
});

// ── TTL Pruner (runs every hour) ───────────────────────────────────

function pruneOldMessages() {
    const cutoff = Date.now() - MESSAGE_TTL_MS;
    const result = queries.pruneOldMessages.run(cutoff);
    if (result.changes > 0) {
        console.log(`✓ Pruned ${result.changes} old messages`);
    }

    // Clean up empty vaults
    const emptyVaults = db.prepare(`
        SELECT id FROM vaults WHERE id NOT IN (SELECT DISTINCT vault_id FROM messages)
        AND member_count = 0
    `).all();

    emptyVaults.forEach(v => {
        queries.deleteVault.run(v.id);
    });

    if (emptyVaults.length > 0) {
        console.log(`✓ Cleaned ${emptyVaults.length} empty vaults`);
    }
}

// ── API Routes ─────────────────────────────────────────────────────

app.post('/api', async (req, res) => {
    try {
        const { type, ...data } = req.body || {};

        // Validate type
        const validatedType = validate({ type }, Joi.object({ type: schemas.type }));

        switch (validatedType.type) {

            // ── vault_create ───────────────────────────────────────
            case 'vault_create': {
                await vaultLimiter(req, res, async () => {
                    const { vaultId, vaultType = 'private' } = validate(data, Joi.object({
                        vaultId: schemas.vaultId,
                        vaultType: schemas.vaultType,
                    }));

                    const timestamp = Date.now(); // SERVER-CONTROLLED
                    queries.createVault.run(vaultId, vaultType, timestamp);

                    res.json({ success: true, timestamp });
                });
                break;
            }

            // ── vault_join ─────────────────────────────────────────
            case 'vault_join': {
                const { vaultId, userId } = validate(data, Joi.object({
                    vaultId: schemas.vaultId,
                    userId: schemas.userId,
                }));

                const vault = queries.getVault.get(vaultId);
                
                if (!vault) {
                    // Auto-create vault if it doesn't exist
                    const timestamp = Date.now();
                    queries.createVault.run(vaultId, 'private', timestamp);
                }

                // Check member limit for private vaults
                const memberCheck = queries.getMemberCount.get(vaultId);
                const currentMembers = memberCheck.count;

                if (vault && vault.type === 'private' && currentMembers >= MAX_VAULT_MEMBERS) {
                    // Check if user is already a member
                    const existingMember = db.prepare(
                        `SELECT 1 FROM vault_members WHERE vault_id = ? AND user_id = ?`
                    ).get(vaultId, userId);

                    if (!existingMember) {
                        return res.status(403).json({ 
                            success: false, 
                            error: `Private vault full (max ${MAX_VAULT_MEMBERS} members)` 
                        });
                    }
                }

                const timestamp = Date.now();
                queries.addMember.run(vaultId, userId, timestamp);
                queries.incrementMemberCount.run(vaultId);

                res.json({ success: true, timestamp });
                break;
            }

            // ── vault_leave ────────────────────────────────────────
            case 'vault_leave': {
                const { vaultId, userId } = validate(data, Joi.object({
                    vaultId: schemas.vaultId,
                    userId: schemas.userId,
                }));

                queries.removeMember.run(vaultId, userId);
                queries.decrementMemberCount.run(vaultId);

                res.json({ success: true, timestamp: Date.now() });
                break;
            }

            // ── message ────────────────────────────────────────────
            case 'message': {
                await messageLimiter(req, res, async () => {
                    const { id, vaultId, blob } = validate(data, Joi.object({
                        id: schemas.messageId,
                        vaultId: schemas.vaultId,
                        blob: schemas.blob,
                    }));

                    const timestamp = Date.now(); // SERVER-CONTROLLED TIMESTAMP
                    
                    try {
                        queries.insertMessage.run(id, vaultId, blob, timestamp, timestamp);
                    } catch (e) {
                        // Ignore duplicate message IDs (idempotent)
                        if (!e.message.includes('UNIQUE constraint')) {
                            throw e;
                        }
                    }

                    // Ring buffer: enforce message limit per vault
                    const msgCount = queries.getVaultMessages.get(vaultId);
                    if (msgCount.count > MAX_MESSAGES_PER_VAULT) {
                        const toDelete = msgCount.count - MAX_MESSAGES_PER_VAULT;
                        const oldMessages = queries.getOldestMessages.all(vaultId, toDelete);
                        
                        oldMessages.forEach(m => {
                            queries.deleteMessageAcks.run(m.id);
                            queries.deleteMessage.run(m.id);
                        });
                    }

                    res.json({ success: true, timestamp });
                });
                break;
            }

            // ── get_messages ───────────────────────────────────────
            case 'get_messages': {
                const { vaultId, since = 0 } = validate(data, Joi.object({
                    vaultId: schemas.vaultId,
                    since: schemas.since,
                }));

                const messages = queries.getMessages.all(vaultId, since);
                
                res.json({ 
                    success: true, 
                    data: messages,
                    serverTime: Date.now() // Help client sync
                });
                break;
            }

            // ── ack_messages ───────────────────────────────────────
            // Client acknowledges receipt of messages
            // Server deletes messages once all vault members have acked
            case 'ack_messages': {
                const { messageIds, userId } = validate(data, Joi.object({
                    messageIds: Joi.array().items(schemas.messageId).required(),
                    userId: schemas.userId,
                }));

                const timestamp = Date.now();

                for (const msgId of messageIds) {
                    queries.ackMessage.run(msgId, userId, timestamp);

                    // Check if all vault members have acked
                    const message = db.prepare(`SELECT vault_id FROM messages WHERE id = ?`).get(msgId);
                    if (!message) continue;

                    const memberCount = queries.getMemberCount.get(message.vault_id);
                    const ackCount = queries.getMessageAckCount.get(msgId);

                    // Delete message if all members have acked (or vault has no members)
                    if (memberCount.count > 0 && ackCount.count >= memberCount.count) {
                        queries.deleteMessageAcks.run(msgId);
                        queries.deleteMessage.run(msgId);
                    }
                }

                res.json({ success: true });
                break;
            }

            // ── nuke_user ──────────────────────────────────────────
            case 'nuke_user': {
                const { vaultIds } = validate(data, Joi.object({
                    vaultIds: schemas.vaultIds,
                }));

                // Wipe specified vaults (user's own vaults)
                if (Array.isArray(vaultIds)) {
                    for (const vid of vaultIds) {
                        queries.deleteVaultMessages.run(vid);
                        queries.deleteVaultMembers.run(vid);
                        queries.deleteVault.run(vid);
                    }
                }

                res.json({ success: true });
                break;
            }

            default:
                res.status(400).json({ success: false, error: `unknown type: ${type}` });
        }
    } catch (error) {
        console.error('API error:', error);
        res.status(400).json({ 
            success: false, 
            error: error.message || 'Invalid request' 
        });
    }
});

// ── Health / Stats ─────────────────────────────────────────────────

app.get('/health', (_req, res) => {
    res.json({ 
        status: 'ok', 
        ts: Date.now(),
        version: '2.0.0'
    });
});

app.get('/admin/stats', (_req, res) => {
    try {
        const vaultCount = db.prepare(`SELECT COUNT(*) as count FROM vaults`).get();
        const messageCount = db.prepare(`SELECT COUNT(*) as count FROM messages`).get();
        const memberCount = db.prepare(`SELECT COUNT(*) as count FROM vault_members`).get();
        
        res.json({
            vaults: vaultCount.count,
            messages: messageCount.count,
            members: memberCount.count,
            uptime: process.uptime(),
            dbSize: fs.existsSync(DB_PATH) ? fs.statSync(DB_PATH).size : 0,
        });
    } catch (e) {
        res.status(500).json({ error: 'Stats unavailable' });
    }
});

// ── Graceful Shutdown ──────────────────────────────────────────────

function shutdown() {
    console.log('\nShutting down gracefully...');
    createBackup();
    if (db) db.close();
    process.exit(0);
}

process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);

// ── Start Server ───────────────────────────────────────────────────

const PORT = process.env.PORT || 3000;

initDatabase();

// Auto-backup on startup
createBackup();

// Schedule periodic tasks
setInterval(pruneOldMessages, 60 * 60 * 1000); // Every hour
setInterval(createBackup, BACKUP_INTERVAL_MS); // Hourly backups

app.listen(PORT, () => {
    console.log(`
╔════════════════════════════════════════════════════════════╗
║  RedRabbit Relay v2.0                                      ║
║  Port: ${PORT.toString().padEnd(50)}║
║  Database: ${DB_PATH.padEnd(44)}║
║  Backups: ${BACKUP_DIR.padEnd(45)}║
╠════════════════════════════════════════════════════════════╣
║  ✓ Server-controlled timestamps                            ║
║  ✓ Rate limiting & DoS protection                          ║
║  ✓ Persistent SQLite database                              ║
║  ✓ Auto-backups every hour                                 ║
║  ✓ Message acknowledgment system                           ║
║  ✓ Two-person vault limit                                  ║
║  ✓ Input validation & schema enforcement                   ║
╚════════════════════════════════════════════════════════════╝
    `);
    console.log('Security: server stores encrypted blobs only — no plaintext, no key material.\n');
});
