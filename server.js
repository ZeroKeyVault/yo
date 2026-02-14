/**
 * RedRabbit Relay Server v2
 *
 * Security model:
 *   - The server stores ONLY opaque encrypted blobs.
 *   - It has no access to vault keys, user identity keys, or plaintext.
 *   - It cannot decrypt messages or link messages to real-world identities.
 *   - Vault IDs are random tokens with no semantic meaning to the server.
 *   - User IDs are SHA-256(Ed25519_public_key) — unlinkable without the key.
 *
 * What the server sees per message:
 *   { id, vaultId, blob: "<opaque AES-GCM ciphertext>", timestamp }
 *
 * Changes in v2:
 *   - SQLite persistence via better-sqlite3 (WAL mode for crash safety)
 *   - Server-assigned timestamps — client timestamp is ignored entirely
 *   - Rate limiting via express-rate-limit (DoS protection)
 *   - Private vault 2-person member cap enforced server-side
 *   - Input validation & schema enforcement on all endpoints
 *   - ack_messages endpoint: server deletes a message once every vault
 *     member has acknowledged receipt (true relay — no permanent storage)
 *   - nuke_user fully wipes vault data from the DB
 *   - vault_create now accepts vaultType ('private' | 'public')
 *   - vault_join tracks members and returns memberCount to caller
 *
 * Production notes:
 *   - Add TLS (HTTPS / Nginx / Cloudflare). Without it blobs are visible in transit.
 *   - Nginx config example:
 *       location /api { proxy_pass http://127.0.0.1:3000; }
 *   - Cloudflare: enable proxying for DDoS protection + automatic TLS.
 *   - For horizontal scaling: replace better-sqlite3 with Postgres + pgBouncer,
 *     and use a Redis pub/sub queue for cross-node message delivery.
 *   - Backups: SQLite WAL is crash-safe. Add a cron job to copy the .db file
 *     to object storage (S3/R2) hourly: cp redrabbit.db redrabbit.db.bak
 *   - The /admin/stats endpoint should be behind authentication in production.
 */

'use strict';

const express   = require('express');
const cors      = require('cors');
const rateLimit = require('express-rate-limit');
const path      = require('path');
const fs        = require('fs');

// ── Database setup ───────────────────────────────────────────────────────────
// WAL mode: concurrent readers + crash-safe writes. Data survives restarts.
//
// better-sqlite3 is a native C++ addon. If it failed to compile during
// `npm install` (missing node-gyp / Python / build tools), the require()
// call below will throw. Run:
//
//   npm install                       # standard install
//   # if that fails on native build:
//   npm install --build-from-source   # force recompile
//   # or install build tools first:
//   # macOS:  xcode-select --install
//   # Ubuntu: sudo apt install build-essential python3
//   # Windows: npm install --global windows-build-tools

const DB_DIR  = process.env.DB_DIR  || path.join(__dirname, 'data');
const DB_PATH = process.env.DB_PATH || path.join(DB_DIR, 'redrabbit.db');

let db;
let usingMemoryFallback = false;

try {
    const Database = require('better-sqlite3');
    fs.mkdirSync(DB_DIR, { recursive: true });
    db = new Database(DB_PATH);
    db.pragma('journal_mode = WAL');
    db.pragma('synchronous    = NORMAL');
    db.pragma('foreign_keys   = ON');
    db.pragma('cache_size     = -32000');
    console.log(`Database: ${DB_PATH} (SQLite WAL mode — crash-safe, survives restarts)`);
} catch (dbErr) {
    console.error('');
    console.error('════════════════════════════════════════════════════════════');
    console.error('  WARNING: SQLite (better-sqlite3) failed to load!');
    console.error('  Reason:', dbErr.message);
    console.error('');
    console.error('  To fix: run one of the following:');
    console.error('    npm install');
    console.error('    npm install --build-from-source');
    console.error('');
    console.error('  Falling back to IN-MEMORY storage.');
    console.error('  Messages WILL BE LOST when the server restarts!');
    console.error('════════════════════════════════════════════════════════════');
    console.error('');
    usingMemoryFallback = true;
}

// ── In-memory fallback (used when better-sqlite3 is unavailable) ─────────────

function createMemoryStore() {
    const _vaults  = new Map();
    const _members = new Map();
    const _msgs    = new Map();
    const _acks    = new Map();
    return {
        insertVault:     { run: (id,type,ca)     => { if(!_vaults.has(id)) _vaults.set(id,{id,type,created_at:ca}); return {changes:1}; } },
        getVault:        { get: (id)              => _vaults.get(id)||null },
        memberCount:     { get: (vid)             => ({ c:[..._members.keys()].filter(k=>k.startsWith(vid+':')).length }) },
        isMember:        { get: (vid,uid)         => _members.has(`${vid}:${uid}`)?{1:1}:null },
        insertMember:    { run: (vid,uid,ja)      => { const k=`${vid}:${uid}`; if(!_members.has(k)) _members.set(k,{vault_id:vid,user_id:uid,joined_at:ja}); return {changes:1}; } },
        deleteMember:    { run: (vid,uid)         => { _members.delete(`${vid}:${uid}`); return {changes:1}; } },
        msgCount:        { get: (vid)             => ({ c:[..._msgs.values()].filter(m=>m.vault_id===vid).length }) },
        oldestMsg:       { get: (vid)             => { const r=[..._msgs.values()].filter(m=>m.vault_id===vid).sort((a,b)=>a.timestamp-b.timestamp); return r.length?{id:r[0].id}:null; } },
        insertMsg:       { run: (id,vid,blob,ts)  => { _msgs.set(id,{id,vault_id:vid,blob,timestamp:ts}); return {changes:1}; } },
        existsMsg:       { get: (id)              => _msgs.has(id)?{id}:null },
        getMsgs:         { all: (vid,cutoff)      => [..._msgs.values()].filter(m=>m.vault_id===vid&&m.timestamp>=cutoff).sort((a,b)=>a.timestamp-b.timestamp).map(m=>({id:m.id,vaultId:m.vault_id,blob:m.blob,timestamp:m.timestamp})) },
        deleteMsg:       { run: (id)              => { _msgs.delete(id); return {changes:1}; } },
        insertAck:       { run: (mid,uid)         => { _acks.set(`${mid}:${uid}`,true); return {changes:1}; } },
        ackCount:        { get: (mid)             => ({ c:[..._acks.keys()].filter(k=>k.startsWith(mid+':')).length }) },
        deleteAcks:      { run: (mid)             => { for(const k of [..._acks.keys()]) if(k.startsWith(mid+':')) _acks.delete(k); return {changes:1}; } },
        deleteVaultMsgs: { run: (vid)             => { for(const [id,m] of _msgs) if(m.vault_id===vid) _msgs.delete(id); return {changes:1}; } },
        deleteMembers:   { run: (vid)             => { for(const k of [..._members.keys()]) if(k.startsWith(vid+':')) _members.delete(k); return {changes:1}; } },
        deleteVault:     { run: (id)              => { _vaults.delete(id); return {changes:1}; } },
        pruneOldMsgs:    { run: (cutoff)          => { let c=0; for(const [id,m] of _msgs) if(m.timestamp<cutoff){_msgs.delete(id);c++;} return {changes:c}; } },
        pruneEmptyVaults:{ run: (cutoff)          => { let c=0; const used=new Set([..._msgs.values()].map(m=>m.vault_id)); for(const [id,v] of _vaults) if(v.created_at<cutoff&&!used.has(id)){_vaults.delete(id);c++;} return {changes:c}; } },
        // For /admin/stats inline queries
        _counts: () => ({ vaults:_vaults.size, members:_members.size, messages:_msgs.size, acks:_acks.size }),
    };
}

// ── Schema + Statements ───────────────────────────────────────────────────────

let stmt;
let inTransaction; // wraps a fn in a SQLite transaction, or calls it directly

if (usingMemoryFallback) {
    stmt          = createMemoryStore();
    inTransaction = (fn) => fn;
} else {
    db.exec(`
      CREATE TABLE IF NOT EXISTS vaults (
        id         TEXT    PRIMARY KEY,
        type       TEXT    NOT NULL DEFAULT 'public'
                           CHECK (type IN ('public','private')),
        created_at INTEGER NOT NULL
      );

      CREATE TABLE IF NOT EXISTS vault_members (
        vault_id  TEXT    NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
        user_id   TEXT    NOT NULL,
        joined_at INTEGER NOT NULL,
        PRIMARY KEY (vault_id, user_id)
      );

      CREATE TABLE IF NOT EXISTS messages (
        id         TEXT    PRIMARY KEY,
        vault_id   TEXT    NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
        blob       TEXT    NOT NULL,
        timestamp  INTEGER NOT NULL
      );

      CREATE INDEX IF NOT EXISTS idx_messages_vault_ts
        ON messages(vault_id, timestamp);

      CREATE TABLE IF NOT EXISTS message_acks (
        message_id TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
        user_id    TEXT NOT NULL,
        PRIMARY KEY (message_id, user_id)
      );
    `);

    stmt = {
        insertVault:     db.prepare('INSERT OR IGNORE INTO vaults (id, type, created_at) VALUES (?, ?, ?)'),
        getVault:        db.prepare('SELECT id, type FROM vaults WHERE id = ?'),
        memberCount:     db.prepare('SELECT COUNT(*) AS c FROM vault_members WHERE vault_id = ?'),
        isMember:        db.prepare('SELECT 1 FROM vault_members WHERE vault_id = ? AND user_id = ?'),
        insertMember:    db.prepare('INSERT OR IGNORE INTO vault_members (vault_id, user_id, joined_at) VALUES (?, ?, ?)'),
        deleteMember:    db.prepare('DELETE FROM vault_members WHERE vault_id = ? AND user_id = ?'),
        msgCount:        db.prepare('SELECT COUNT(*) AS c FROM messages WHERE vault_id = ?'),
        oldestMsg:       db.prepare('SELECT id FROM messages WHERE vault_id = ? ORDER BY timestamp ASC LIMIT 1'),
        insertMsg:       db.prepare('INSERT INTO messages (id, vault_id, blob, timestamp) VALUES (?, ?, ?, ?)'),
        existsMsg:       db.prepare('SELECT id FROM messages WHERE id = ?'),
        getMsgs:         db.prepare('SELECT id, vault_id AS vaultId, blob, timestamp FROM messages WHERE vault_id = ? AND timestamp >= ? ORDER BY timestamp ASC'),
        deleteMsg:       db.prepare('DELETE FROM messages WHERE id = ?'),
        insertAck:       db.prepare('INSERT OR IGNORE INTO message_acks (message_id, user_id) VALUES (?, ?)'),
        ackCount:        db.prepare('SELECT COUNT(*) AS c FROM message_acks WHERE message_id = ?'),
        deleteAcks:      db.prepare('DELETE FROM message_acks WHERE message_id = ?'),
        deleteVaultMsgs: db.prepare('DELETE FROM messages WHERE vault_id = ?'),
        deleteMembers:   db.prepare('DELETE FROM vault_members WHERE vault_id = ?'),
        deleteVault:     db.prepare('DELETE FROM vaults WHERE id = ?'),
        pruneOldMsgs:    db.prepare('DELETE FROM messages WHERE timestamp < ?'),
        pruneEmptyVaults:db.prepare(`
            DELETE FROM vaults
            WHERE created_at < ?
              AND id NOT IN (SELECT DISTINCT vault_id FROM messages)
        `),
    };

    inTransaction = (fn) => db.transaction(fn);
}

// ── Express app ──────────────────────────────────────────────────────────────

const app = express();

// Trust X-Forwarded-For from Nginx / Cloudflare so rate-limiting uses real IP
app.set('trust proxy', 1);

app.use(cors());
app.use(express.json({ limit: '2mb' }));

// ── Rate limiting ────────────────────────────────────────────────────────────
// 120 API calls per minute per IP. Covers 5-second polling (12/min) plus normal
// messaging with plenty of headroom. Adjust MAX_REQUESTS_PER_MIN via env var.

const MAX_RPM = parseInt(process.env.MAX_RPM || '120', 10);

const limiter = rateLimit({
    windowMs:        60 * 1000,
    max:             MAX_RPM,
    standardHeaders: true,
    legacyHeaders:   false,
    message:         { success: false, error: 'Rate limit exceeded. Slow down.' },
});

app.use('/api', limiter);

// ── Input validation ─────────────────────────────────────────────────────────

// Vault IDs: 'v' + alphanumeric (generated by client as 'v' + base36 + random)
const VAULT_ID_RE = /^[A-Za-z0-9_\-]{4,80}$/;
// User IDs: base64url-encoded SHA-256 hashes (43 chars, no padding)
const USER_ID_RE  = /^[A-Za-z0-9_\-]{20,100}$/;
// Message IDs: 'msg_' + timestamp + random
const MSG_ID_RE   = /^[A-Za-z0-9_\-]{4,100}$/;

const ok = {
    vaultId: (id) => typeof id === 'string' && VAULT_ID_RE.test(id),
    userId:  (id) => typeof id === 'string' && USER_ID_RE.test(id),
    msgId:   (id) => typeof id === 'string' && MSG_ID_RE.test(id),
};

// ── Constants ────────────────────────────────────────────────────────────────

const MAX_MESSAGES_PER_VAULT = 2000;
const MESSAGE_TTL_MS         = 7 * 24 * 60 * 60 * 1000; // 7 days
const PRIVATE_VAULT_MAX      = 2;
const MAX_BLOB_BYTES         = 500_000; // 500 KB per message blob
const MAX_ACK_BATCH          = 200;     // max message IDs in one ack call

// ── TTL pruner — runs every hour ─────────────────────────────────────────────

setInterval(() => {
    const cutoff = Date.now() - MESSAGE_TTL_MS;
    const r1 = stmt.pruneOldMsgs.run(cutoff);
    const r2 = stmt.pruneEmptyVaults.run(cutoff);
    if (r1.changes || r2.changes) {
        console.log(`[pruner] removed ${r1.changes} expired messages, ${r2.changes} empty vaults`);
    }
}, 60 * 60 * 1000);

// ── API ───────────────────────────────────────────────────────────────────────

app.post('/api', (req, res) => {
    const { type, ...data } = req.body || {};
    if (!type) return res.status(400).json({ success: false, error: 'missing type' });

    switch (type) {

        // ── vault_create ──────────────────────────────────────────────────────
        // Registers a new vault on the server. No key material ever sent.
        case 'vault_create': {
            const { vaultId, vaultType = 'public' } = data;

            if (!ok.vaultId(vaultId)) {
                return res.status(400).json({ success: false, error: 'invalid vaultId' });
            }
            if (!['public', 'private'].includes(vaultType)) {
                return res.status(400).json({ success: false, error: 'invalid vaultType' });
            }

            stmt.insertVault.run(vaultId, vaultType, Date.now());
            return res.json({ success: true });
        }

        // ── vault_join ────────────────────────────────────────────────────────
        // Registers a user as a member of a vault.
        // Private vaults are capped at PRIVATE_VAULT_MAX members.
        case 'vault_join': {
            const { vaultId, userId } = data;

            if (!ok.vaultId(vaultId)) {
                return res.status(400).json({ success: false, error: 'invalid vaultId' });
            }
            if (!ok.userId(userId)) {
                return res.status(400).json({ success: false, error: 'invalid userId' });
            }

            // Create vault entry if the joiner is the first (creator may not have called vault_create)
            stmt.insertVault.run(vaultId, 'public', Date.now());

            const vault = stmt.getVault.get(vaultId);

            // Enforce private vault member cap
            if (vault && vault.type === 'private') {
                const alreadyIn = stmt.isMember.get(vaultId, userId);
                if (!alreadyIn) {
                    const { c } = stmt.memberCount.get(vaultId);
                    if (c >= PRIVATE_VAULT_MAX) {
                        return res.status(403).json({
                            success: false,
                            error:   `Private vault is full (${PRIVATE_VAULT_MAX} person max)`,
                        });
                    }
                }
            }

            stmt.insertMember.run(vaultId, userId, Date.now());

            const { c: memberCount } = stmt.memberCount.get(vaultId);
            return res.json({ success: true, memberCount, vaultType: vault ? vault.type : 'public' });
        }

        // ── vault_leave ───────────────────────────────────────────────────────
        case 'vault_leave': {
            const { vaultId, userId } = data;
            if (ok.vaultId(vaultId) && ok.userId(userId)) {
                stmt.deleteMember.run(vaultId, userId);
            }
            return res.json({ success: true });
        }

        // ── message ───────────────────────────────────────────────────────────
        // Client posts an encrypted blob. Server assigns the timestamp.
        // The `timestamp` field from the client is intentionally ignored.
        case 'message': {
            const { id, vaultId, blob } = data;
            // Client may send a timestamp field but we never trust it.

            if (!ok.msgId(id)) {
                return res.status(400).json({ success: false, error: 'invalid message id' });
            }
            if (!ok.vaultId(vaultId)) {
                return res.status(400).json({ success: false, error: 'invalid vaultId' });
            }
            if (typeof blob !== 'string' || blob.length === 0) {
                return res.status(400).json({ success: false, error: 'blob must be a non-empty string' });
            }
            if (blob.length > MAX_BLOB_BYTES) {
                return res.status(413).json({ success: false, error: 'blob too large (max 500 KB)' });
            }

            // Idempotent — silently ignore duplicate IDs
            if (stmt.existsMsg.get(id)) return res.json({ success: true });

            // Ring buffer: evict oldest when vault is full
            const { c } = stmt.msgCount.get(vaultId);
            if (c >= MAX_MESSAGES_PER_VAULT) {
                const oldest = stmt.oldestMsg.get(vaultId);
                if (oldest) {
                    stmt.deleteAcks.run(oldest.id);
                    stmt.deleteMsg.run(oldest.id);
                }
            }

            // Server-assigned timestamp — the authoritative time
            const serverTimestamp = Date.now();
            stmt.insertMsg.run(id, vaultId, blob, serverTimestamp);

            return res.json({ success: true, timestamp: serverTimestamp });
        }

        // ── get_messages ──────────────────────────────────────────────────────
        // Returns encrypted blobs since a given server timestamp.
        // Caller decrypts locally — server never touches blob content.
        case 'get_messages': {
            const { vaultId, since } = data;

            if (!ok.vaultId(vaultId)) {
                return res.status(400).json({ success: false, error: 'invalid vaultId' });
            }

            const cutoff = (typeof since === 'number' && since > 0) ? since : 0;
            const rows   = stmt.getMsgs.all(vaultId, cutoff);

            return res.json({ success: true, data: rows });
        }

        // ── ack_messages ──────────────────────────────────────────────────────
        // Client acknowledges receipt of a list of message IDs.
        // Once every vault member has acked a message, the server deletes it.
        // This is the "true relay" behaviour — no long-term server storage.
        case 'ack_messages': {
            const { vaultId, userId, messageIds } = data;

            if (!ok.vaultId(vaultId)) {
                return res.status(400).json({ success: false, error: 'invalid vaultId' });
            }
            if (!ok.userId(userId)) {
                return res.status(400).json({ success: false, error: 'invalid userId' });
            }
            if (!Array.isArray(messageIds)) {
                return res.status(400).json({ success: false, error: 'messageIds must be an array' });
            }

            const { c: memberCount } = stmt.memberCount.get(vaultId);
            // Need at least 1 member to ACK (self). If 0 members tracked, keep messages.
            const threshold = Math.max(memberCount, 1);

            const processAcks = inTransaction((ids) => {
                for (const msgId of ids.slice(0, MAX_ACK_BATCH)) {
                    if (!ok.msgId(msgId)) continue;
                    stmt.insertAck.run(msgId, userId);
                    const { c: ackCount } = stmt.ackCount.get(msgId);
                    if (ackCount >= threshold) {
                        // All current members received it — delete from relay
                        stmt.deleteAcks.run(msgId);
                        stmt.deleteMsg.run(msgId);
                    }
                }
            });

            processAcks(messageIds);
            return res.json({ success: true });
        }

        // ── nuke_user ─────────────────────────────────────────────────────────
        // Wipes all data for the given vaults (private) or removes membership
        // (public). Client must pass its vault IDs for the wipe to take effect.
        case 'nuke_user': {
            const { vaultIds, userId } = data;

            if (!Array.isArray(vaultIds)) {
                return res.json({ success: true }); // nothing to do
            }

            const nukeVault = inTransaction((vids) => {
                for (const vid of vids) {
                    if (!ok.vaultId(vid)) continue;

                    const vault = stmt.getVault.get(vid);
                    if (!vault) continue;

                    if (vault.type === 'private') {
                        // Private vault: full wipe (only 2 people ever, both nuking means no data left)
                        stmt.deleteVaultMsgs.run(vid);
                        stmt.deleteMembers.run(vid);
                        stmt.deleteVault.run(vid);
                    } else if (ok.userId(userId)) {
                        // Public vault: remove user's membership only
                        stmt.deleteMember.run(vid, userId);
                    }
                }
            });

            nukeVault(vaultIds);
            return res.json({ success: true });
        }

        default:
            return res.status(400).json({ success: false, error: `unknown type: ${type}` });
    }
});

// ── Health / Stats ────────────────────────────────────────────────────────────

app.get('/health', (_req, res) => {
    res.json({ status: 'ok', ts: Date.now() });
});

// NOTE: Lock this endpoint behind authentication in production!
app.get('/admin/stats', (_req, res) => {
    let counts;
    if (usingMemoryFallback) {
        counts = stmt._counts();
    } else {
        counts = {
            vaults:   db.prepare('SELECT COUNT(*) AS c FROM vaults').get().c,
            members:  db.prepare('SELECT COUNT(*) AS c FROM vault_members').get().c,
            messages: db.prepare('SELECT COUNT(*) AS c FROM messages').get().c,
            acks:     db.prepare('SELECT COUNT(*) AS c FROM message_acks').get().c,
        };
    }
    res.json({
        ...counts,
        uptime:  process.uptime(),
        storage: usingMemoryFallback ? 'in-memory (no persistence)' : DB_PATH,
    });
});

// ── Start ─────────────────────────────────────────────────────────────────────

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`RedRabbit relay v2 listening on :${PORT}`);
    if (usingMemoryFallback) {
        console.log('Storage: IN-MEMORY (messages lost on restart — install better-sqlite3 for persistence)');
    }
    console.log('Security: server stores encrypted blobs only — no plaintext, no key material.');
});
