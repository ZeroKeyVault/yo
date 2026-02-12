    /**
     * RedRabbit Relay Server
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
     * The blob field is a JSON string containing:
     *   { v, eph, iv, ct, sig, spk } — all base64-encoded crypto material.
     *   The server treats this as a fully opaque string and never parses it.
     *
     * Production notes:
     *   - Replace in-memory Maps with Redis or a persistent DB.
     *   - Add TLS (HTTPS). Without it, blobs are visible in transit to the network.
     *   - Add rate limiting (express-rate-limit) to prevent spam.
     *   - Consider message TTL (auto-delete after N days).
     *   - The /admin/stats endpoint should be behind authentication in production.
     */

    'use strict';

    const express = require('express');
    const cors    = require('cors');

    const app = express();

    // ── Middleware ────────────────────────────────────────────────

    app.use(cors());
    app.use(express.json({ limit: '2mb' }));

    // ── In-memory store ───────────────────────────────────────────
    // Replace with Redis / SQLite / Postgres for production.

    // vaults: Map<vaultId, { createdAt: number }>
    const vaults = new Map();

    // messages: Map<vaultId, Array<{ id, vaultId, blob, timestamp }>>
    const messages = new Map();

    const MAX_MESSAGES_PER_VAULT = 2000;  // ring-buffer cap
    const MESSAGE_TTL_MS         = 7 * 24 * 60 * 60 * 1000; // 7 days

    // ── Helper: get or create vault message list ──────────────────

    function getVaultMsgs(vaultId) {
        if (!messages.has(vaultId)) messages.set(vaultId, []);
        return messages.get(vaultId);
    }

    // ── TTL pruner (runs every hour) ──────────────────────────────

    setInterval(() => {
        const cutoff = Date.now() - MESSAGE_TTL_MS;
        for (const [vaultId, msgs] of messages) {
            const pruned = msgs.filter(m => m.timestamp >= cutoff);
            if (pruned.length !== msgs.length) {
                messages.set(vaultId, pruned);
            }
            // Remove empty vault slots
            if (pruned.length === 0) {
                messages.delete(vaultId);
                vaults.delete(vaultId);
            }
        }
    }, 60 * 60 * 1000);

    // ── API ───────────────────────────────────────────────────────

    app.post('/api', (req, res) => {
        const { type, ...data } = req.body || {};

        if (!type) return res.status(400).json({ success: false, error: 'missing type' });

        switch (type) {

            // ── vault_create ──────────────────────────────────────
            // Client tells server a vault ID now exists.
            // No key material is ever sent.
            case 'vault_create': {
                const { vaultId } = data;
                if (!vaultId || typeof vaultId !== 'string') {
                    return res.status(400).json({ success: false, error: 'invalid vaultId' });
                }
                if (!vaults.has(vaultId)) {
                    vaults.set(vaultId, { createdAt: Date.now() });
                    messages.set(vaultId, []);
                }
                return res.json({ success: true });
            }

            // ── vault_join ────────────────────────────────────────
            // Client announces presence. Server only stores the userId
            // (which is SHA-256 of their Ed25519 pub key — no plaintext identity).
            case 'vault_join': {
                const { vaultId } = data;
                if (!vaultId) return res.status(400).json({ success: false, error: 'invalid vaultId' });
                // Ensure message list exists even if creator didn't call vault_create
                getVaultMsgs(vaultId);
                if (!vaults.has(vaultId)) vaults.set(vaultId, { createdAt: Date.now() });
                return res.json({ success: true });
            }

            // ── vault_leave ───────────────────────────────────────
            case 'vault_leave': {
                return res.json({ success: true });
            }

            // ── message ───────────────────────────────────────────
            // Client posts an encrypted blob. The server stores it verbatim.
            // Server never parses or inspects `blob`.
            case 'message': {
                const { id, vaultId, blob, timestamp } = data;

                if (!id || !vaultId || !blob || !timestamp) {
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
                if (list.some(m => m.id === id)) return res.json({ success: true });

                list.push({ id, vaultId, blob, timestamp });

                // Ring buffer: drop oldest when over cap
                if (list.length > MAX_MESSAGES_PER_VAULT) {
                    list.splice(0, list.length - MAX_MESSAGES_PER_VAULT);
                }

                return res.json({ success: true });
            }

            // ── get_messages ──────────────────────────────────────
            // Returns encrypted blobs since a given timestamp.
            // Caller decrypts locally — server never touches blob content.
            case 'get_messages': {
                const { vaultId, since } = data;
                if (!vaultId) return res.status(400).json({ success: false, error: 'missing vaultId' });

                const list   = getVaultMsgs(vaultId);
                const cutoff = typeof since === 'number' ? since : 0;
                const result = list.filter(m => m.timestamp >= cutoff);

                return res.json({ success: true, data: result });
            }

            // ── nuke_user ─────────────────────────────────────────
            // Because blobs are opaque, the server cannot identify which
            // messages belong to a given user. The primary nuke action is
            // the client clearing its own keys / IndexedDB.
            // If the user sends their vault IDs, we can optionally wipe those.
            // NOTE: In a shared vault this removes OTHER users' history too.
            //       Disabled by default; enable only if you want full vault wipes.
            case 'nuke_user': {
                const { vaultIds } = data;
                // Opt-in vault wipe (client must explicitly pass vaultIds)
                if (Array.isArray(vaultIds)) {
                    for (const vid of vaultIds) {
                        messages.delete(vid);
                        vaults.delete(vid);
                    }
                }
                return res.json({ success: true });
            }

            default:
                return res.status(400).json({ success: false, error: `unknown type: ${type}` });
        }
    });

    // ── Health / stats (no sensitive data exposed) ────────────────

    app.get('/health', (_req, res) => {
        res.json({ status: 'ok', ts: Date.now() });
    });

    app.get('/admin/stats', (_req, res) => {
        let totalMessages = 0;
        for (const msgs of messages.values()) totalMessages += msgs.length;
        res.json({
            vaults:   vaults.size,
            messages: totalMessages,
            uptime:   process.uptime(),
        });
    });

    // ── Start ─────────────────────────────────────────────────────

    const PORT = process.env.PORT || 3000;
    app.listen(PORT, () => {
        console.log(`RedRabbit relay listening on :${PORT}`);
        console.log('Security: server stores encrypted blobs only — no plaintext, no key material.');
    });
