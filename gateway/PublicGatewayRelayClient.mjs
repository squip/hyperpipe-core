import { EventEmitter } from 'node:events';
import b4a from 'b4a';
import Hyperbee from 'hyperbee';

import { openHyperbeeReplicationChannel } from '@squip/hyperpipe-bridge/public-gateway/hyperbeeReplicationChannel';

import { getCorestore } from '../hyperdrive-manager.mjs';

class PublicGatewayRelayClient extends EventEmitter {
  constructor({ logger = console } = {}) {
    super();
    this.logger = logger;
    this.store = null;
    this.core = null;
    this.db = null;
    this.replications = new Map();
    this.protocolReplicationChannels = new WeakMap();
    this.hyperbeeKey = null;
    this.discoveryKey = null;
    this.lastDownloaded = 0;
    this.lastLength = 0;
    this.lastReplicationLog = 0;
    this.lastReplicaUpdateAt = 0;
    this.replicaSnapshot = {
      length: 0,
      contiguousLength: 0,
      lag: 0,
      version: 0,
      updatedAt: 0
    };
    this._ensureSyncPromise = null;
  }

  async configure(options = {}) {
    const hyperbeeKey = options.hyperbeeKey || options.key;
    if (!hyperbeeKey || typeof hyperbeeKey !== 'string') {
      throw new Error('hyperbeeKey is required to configure relay client');
    }
    if (this.hyperbeeKey === hyperbeeKey && this.core) {
      return;
    }

    await this.close();

    const store = getCorestore();
    const key = b4a.from(hyperbeeKey, 'hex');
    this.logger?.info?.('[PublicGatewayRelayClient] Opening hypercore for public gateway relay', {
      hyperbeeKey
    });
    this.core = store.get({ key, valueEncoding: 'binary', sparse: true });
    await this.core.ready();
    this.db = new Hyperbee(this.core, { keyEncoding: 'binary', valueEncoding: 'utf-8' });
    await this.db.ready();

    this.store = store;
    this.hyperbeeKey = hyperbeeKey;
    this.discoveryKey = options.discoveryKey || b4a.toString(this.core.discoveryKey, 'hex');
    const initialLength = typeof this.core.length === 'number' ? this.core.length : 0;
    const initialContiguous = typeof this.core.contiguousLength === 'number'
      ? this.core.contiguousLength
      : initialLength;
    this.lastReplicationLog = 0;
    this._updateReplicaSnapshot({
      length: initialLength,
      contiguousLength: initialContiguous,
      version: this.db?.version || 0
    });

    this.core.on('download', (index, data) => {
      const contiguous = typeof this.core.contiguousLength === 'number'
        ? this.core.contiguousLength
        : null;
      if (typeof contiguous === 'number') {
        const length = typeof this.core.length === 'number' ? this.core.length : this.lastLength;
        const lag = this._updateReplicaSnapshot({
          length,
          contiguousLength: contiguous,
          version: this.db?.version || 0
        });
        this.logger?.debug?.('[PublicGatewayRelayClient] Download progress', {
          hyperbeeKey: this.hyperbeeKey,
          contiguousLength: contiguous,
          totalLength: this.lastLength
        });
        const now = Date.now();
        if (!this.lastReplicationLog || (now - this.lastReplicationLog) >= 5000) {
          this.logger?.info?.('[PublicGatewayRelayClient] Replication sync update', {
            hyperbeeKey: this.hyperbeeKey,
            contiguousLength: contiguous,
            totalLength: this.lastLength
          });
          this.lastReplicationLog = now;
        }
        if (lag > 0) {
          this.logger?.debug?.('[PublicGatewayRelayClient] Replica lag after download', {
            hyperbeeKey: this.hyperbeeKey,
            lag
          });
        }
      } else {
        this.lastDownloaded += 1;
      }
      if (Number.isInteger(index)) {
        this.logger?.debug?.('[PublicGatewayRelayClient] Downloaded block', {
          hyperbeeKey: this.hyperbeeKey,
          index,
          size: data?.length || 0
        });
      }
    });

    this.logger?.info?.('[PublicGatewayRelayClient] Configured', {
      hyperbeeKey: this.hyperbeeKey,
      discoveryKey: this.discoveryKey,
      contiguousLength: this.lastDownloaded,
      totalLength: this.lastLength
    });
  }

  _updateReplicaSnapshot({ length, contiguousLength, version } = {}) {
    const normalizedLength = Number.isFinite(length)
      ? length
      : (typeof this.core?.length === 'number' ? this.core.length : this.lastLength || 0);
    const normalizedContiguous = Number.isFinite(contiguousLength)
      ? contiguousLength
      : (typeof this.core?.contiguousLength === 'number' ? this.core.contiguousLength : this.lastDownloaded || 0);
    const snapshotVersion = Number.isFinite(version) ? version : (this.db?.version || 0);
    const lag = Math.max(0, normalizedLength - normalizedContiguous);
    this.lastLength = normalizedLength;
    this.lastDownloaded = normalizedContiguous;
    this.lastReplicaUpdateAt = Date.now();
    this.replicaSnapshot = {
      length: normalizedLength,
      contiguousLength: normalizedContiguous,
      lag,
      version: snapshotVersion,
      updatedAt: this.lastReplicaUpdateAt
    };
    this.logger?.debug?.('[PublicGatewayRelayClient] Replica snapshot updated', {
      hyperbeeKey: this.hyperbeeKey,
      length: normalizedLength,
      contiguousLength: normalizedContiguous,
      lag,
      version: snapshotVersion
    });
    return lag;
  }

  async _refreshReplicaSnapshot() {
    if (!this.core) {
      return 0;
    }
    let info = null;
    if (typeof this.core.info === 'function') {
      try {
        info = await this.core.info();
      } catch (error) {
        this.logger?.debug?.('[PublicGatewayRelayClient] Failed to fetch core info', {
          hyperbeeKey: this.hyperbeeKey,
          error: error?.message || error
        });
      }
    }
    const length = Number.isFinite(info?.length)
      ? info.length
      : (typeof this.core.length === 'number' ? this.core.length : this.lastLength);
    const contiguous = Number.isFinite(info?.contiguousLength)
      ? info.contiguousLength
      : (typeof this.core.contiguousLength === 'number' ? this.core.contiguousLength : this.lastDownloaded);
    const lag = this._updateReplicaSnapshot({
      length,
      contiguousLength: contiguous,
      version: this.db?.version || 0
    });
    if (lag > 0) {
      this.logger?.debug?.('[PublicGatewayRelayClient] Replica snapshot lag detected', {
        hyperbeeKey: this.hyperbeeKey,
        length,
        contiguous,
        lag
      });
    }
    return lag;
  }

  async _waitWithTimeout(promise, timeoutMs) {
    const timeout = Number.isFinite(timeoutMs) && timeoutMs > 0 ? timeoutMs : null;
    if (timeout === null) {
      return promise;
    }
    let timer = null;
    try {
      return await Promise.race([
        promise,
        new Promise((_, reject) => {
          timer = setTimeout(() => reject(new Error('replica-update-timeout')), timeout);
        })
      ]);
    } finally {
      if (timer) clearTimeout(timer);
    }
  }

  async _attemptReplicaUpdate(maxWaitMs) {
    if (!this.core) return;
    const tasks = [];

    if (typeof this.core.update === 'function') {
      tasks.push(() => this.core.update({ wait: true }));
    } else if (typeof this.core.ready === 'function') {
      tasks.push(() => this.core.ready());
    }

    if (this.db) {
      if (typeof this.db.update === 'function') {
        tasks.push(() => this.db.update({ wait: true }));
      } else if (typeof this.db.ready === 'function') {
        tasks.push(() => this.db.ready());
      }
    }

    let remaining = Number.isFinite(maxWaitMs) && maxWaitMs >= 0 ? maxWaitMs : null;

    for (const task of tasks) {
      if (remaining !== null && remaining <= 0) {
        throw new Error('replica-update-timeout');
      }
      const startedAt = Date.now();
      const promise = task();
      await this._waitWithTimeout(promise, remaining);
      if (remaining !== null) {
        remaining = Math.max(0, remaining - (Date.now() - startedAt));
      }
    }
  }

  async _downloadMissingBlocks(maxWaitMs) {
    if (!this.core) return;
    const lag = Math.max(0, this.lastLength - this.lastDownloaded);
    if (lag <= 0) return;

    const start = Number.isFinite(this.lastDownloaded) ? this.lastDownloaded : 0;
    const end = Number.isFinite(this.lastLength) ? this.lastLength : start;
    if (!Number.isFinite(start) || !Number.isFinite(end) || end <= start) {
      return;
    }

    let download = null;
    try {
      this.logger?.debug?.('[PublicGatewayRelayClient] Initiating replica download', {
        hyperbeeKey: this.hyperbeeKey,
        start,
        end
      });
      download = this.core.download({
        start,
        end,
        linear: true
      });
      await this._waitWithTimeout(download.done(), maxWaitMs);
      this.logger?.debug?.('[PublicGatewayRelayClient] Replica download completed', {
        hyperbeeKey: this.hyperbeeKey,
        start,
        end
      });
    } finally {
      try {
        download?.destroy?.();
      } catch (_) {}
    }
  }

  async ensureSynchronized({ maxWaitMs = 2000, pollIntervalMs = 50 } = {}) {
    if (!this.core || !this.db) {
      return false;
    }

    const interval = Number.isFinite(pollIntervalMs) && pollIntervalMs > 0
      ? Math.min(Math.round(pollIntervalMs), 1000)
      : 50;
    const deadline = Number.isFinite(maxWaitMs) && maxWaitMs > 0
      ? Date.now() + Math.round(maxWaitMs)
      : null;

    if (this._ensureSyncPromise) {
      return this._ensureSyncPromise;
    }

    this.logger?.debug?.('[PublicGatewayRelayClient] ensureSynchronized invoked', {
      hyperbeeKey: this.hyperbeeKey,
      maxWaitMs,
      pollIntervalMs,
      lastLength: this.lastLength,
      lastDownloaded: this.lastDownloaded
    });

    const runner = (async () => {
      while (!deadline || Date.now() < deadline) {
        const remaining = deadline ? Math.max(0, deadline - Date.now()) : null;

        try {
          await this._attemptReplicaUpdate(remaining);
        } catch (error) {
          if (error?.message !== 'replica-update-timeout') {
            this.logger?.debug?.('[PublicGatewayRelayClient] Replica update attempt failed', {
              hyperbeeKey: this.hyperbeeKey,
              error: error?.message || error
            });
          }
        }

        let lag = await this._refreshReplicaSnapshot();
        if (lag === 0) {
          return true;
        }
        this.logger?.debug?.('[PublicGatewayRelayClient] Replica still lagging after update', {
          hyperbeeKey: this.hyperbeeKey,
          lag,
          remaining
        });

        try {
          await this._downloadMissingBlocks(remaining);
        } catch (error) {
          if (error?.message !== 'replica-update-timeout') {
            this.logger?.debug?.('[PublicGatewayRelayClient] Replica download attempt failed', {
              hyperbeeKey: this.hyperbeeKey,
              error: error?.message || error
            });
          }
        }

        lag = await this._refreshReplicaSnapshot();
        if (lag === 0) {
          return true;
        }

        const waitMs = deadline
          ? Math.min(interval, Math.max(0, deadline - Date.now()))
          : interval;
        if (waitMs <= 0) {
          break;
        }
        await new Promise((resolve) => setTimeout(resolve, waitMs));
      }

      this.logger?.debug?.('[PublicGatewayRelayClient] Replica synchronization loop ended with lag', {
        hyperbeeKey: this.hyperbeeKey,
        lag: Math.max(0, this.lastLength - this.lastDownloaded),
        lastLength: this.lastLength,
        lastDownloaded: this.lastDownloaded
      });
      return false;
    })();

    this._ensureSyncPromise = runner
      .catch((error) => {
        this.logger?.debug?.('[PublicGatewayRelayClient] ensureSynchronized error', {
          hyperbeeKey: this.hyperbeeKey,
          error: error?.message || error
        });
        return false;
      })
      .finally(() => {
        this._ensureSyncPromise = null;
      });

    return this._ensureSyncPromise;
  }

  getHyperbee() {
    return this.db;
  }

  getCore() {
    return this.core;
  }

  getHyperbeeKey() {
    return this.hyperbeeKey;
  }

  hasReplica() {
    return !!(this.core && this.db);
  }

  attachProtocol(protocol) {
    if (!this.core || !protocol || !this.hyperbeeKey) {
      return;
    }

    if (this.protocolReplicationChannels.has(protocol)) {
      return;
    }

    this.#attachReplicationChannel(protocol).catch((error) => {
      this.logger?.warn?.('[PublicGatewayRelayClient] Failed to attach replication channel', {
        error: error?.message || error
      });
    });
  }

  async #attachReplicationChannel(protocol) {
    const isInitiator = protocol?.mux?.stream?.isInitiator === true;

    this.logger?.debug?.('[PublicGatewayRelayClient] Preparing to attach replication channel', {
      hyperbeeKey: this.hyperbeeKey,
      isInitiator
    });

    const { channel, stream, remoteHandshake } = await openHyperbeeReplicationChannel({
      protocol,
      hyperbeeKey: this.hyperbeeKey,
      discoveryKey: this.discoveryKey,
      isInitiator,
      role: 'replica',
      replicationMode: 'download',
      logger: this.logger
    });

    if (remoteHandshake?.version && remoteHandshake.version !== 1) {
      this.logger?.warn?.('[PublicGatewayRelayClient] Remote replication channel version mismatch', {
        expected: 1,
        received: remoteHandshake.version
      });
    }

    this.logger?.info?.('[PublicGatewayRelayClient] Hyperbee replication channel established', {
      hyperbeeKey: this.hyperbeeKey,
      isInitiator,
      remoteHandshake
    });

    let replication;
    try {
      replication = this.core.replicate(isInitiator, {
        live: true,
        download: true,
        upload: false
      });
    } catch (error) {
      try {
        channel.close();
      } catch (_) {}
      throw error;
    }

    replication.on('handshake', () => {
      this.logger?.debug?.('[PublicGatewayRelayClient] Hyperbee replication handshake (inbound)', {
        hyperbeeKey: this.hyperbeeKey,
        isInitiator,
        localLength: this.core.length,
        remoteLength: this.core.remoteLength
      });
    });

    replication.on('error', (error) => {
      this.logger?.warn?.('[PublicGatewayRelayClient] Hyperbee replication error', {
        hyperbeeKey: this.hyperbeeKey,
        error: error?.message || error
      });
    });
    replication.once('close', () => {
      this.logger?.debug?.('[PublicGatewayRelayClient] Hyperbee replication stream closed', {
        hyperbeeKey: this.hyperbeeKey,
        isInitiator
      });
    });

    stream.pipe(replication).pipe(stream);

    this.protocolReplicationChannels.set(protocol, channel);
    this.replications.set(channel, { replication, stream, channel, remoteHandshake });

    const cleanup = (reason) => {
      if (!this.replications.has(channel)) return;
      const entry = this.replications.get(channel);
      try {
        entry?.replication?.end?.();
        entry?.replication?.destroy?.();
      } catch (_) {}
      try {
        entry?.stream?.destroy?.();
      } catch (_) {}
      this.replications.delete(channel);
      this.protocolReplicationChannels.delete(protocol);
      this.logger?.debug?.('[PublicGatewayRelayClient] Replication channel closed', {
        hyperbeeKey: this.hyperbeeKey,
        reason
      });
    };

    channel.fullyClosed()
      .then(() => cleanup('channel-closed'))
      .catch((error) => cleanup(error?.message || 'channel-error'));
    protocol.once?.('close', () => cleanup('protocol-close'));
    protocol.once?.('destroy', () => cleanup('protocol-destroy'));

    this.logger?.debug?.('[PublicGatewayRelayClient] Replication channel attached', {
      hyperbeeKey: this.hyperbeeKey
    });
  }

  async close() {
    for (const entry of this.replications.values()) {
      try {
        entry?.replication?.end?.();
        entry?.replication?.destroy?.();
      } catch (_) {}
      try {
        entry?.stream?.destroy?.();
      } catch (_) {}
      try {
        entry?.channel?.close?.();
      } catch (_) {}
    }
    this.replications.clear();
    this.protocolReplicationChannels = new WeakMap();
    if (this.db) {
      await this.db.close();
      this.db = null;
    }
    if (this.core) {
      await this.core.close();
      this.core = null;
    }
    this.store = null;
    this.hyperbeeKey = null;
    this.discoveryKey = null;
    this.replicaSnapshot = {
      length: 0,
      contiguousLength: 0,
      lag: 0,
      version: 0,
      updatedAt: 0
    };
    this.lastReplicaUpdateAt = 0;
    this._ensureSyncPromise = null;
  }

  async getTelemetry() {
    if (!this.core) {
      return {
        hyperbeeVersion: 0,
        hyperbeeLag: 0,
        hyperbeeContiguousLength: 0,
        hyperbeeLength: 0,
        hyperbeeLastUpdatedAt: 0,
        hyperbeeKey: null,
        hyperbeeDiscoveryKey: null
      };
    }
    try {
      const info = await this.core.info().catch(() => null);
      const length = info?.length ?? (typeof this.core.length === 'number' ? this.core.length : this.lastLength);
      const contiguous = info?.contiguousLength ?? (typeof this.core.contiguousLength === 'number' ? this.core.contiguousLength : this.lastDownloaded);
      const lag = this._updateReplicaSnapshot({
        length,
        contiguousLength: contiguous,
        version: this.db?.version || 0
      });
      return {
        hyperbeeVersion: this.db?.version || 0,
        hyperbeeLag: lag,
        hyperbeeContiguousLength: contiguous,
        hyperbeeLength: length,
        hyperbeeLastUpdatedAt: this.lastReplicaUpdateAt,
        hyperbeeKey: this.hyperbeeKey,
        hyperbeeDiscoveryKey: this.discoveryKey
      };
    } catch (error) {
      this.logger?.debug?.('[PublicGatewayRelayClient] Failed to collect telemetry', {
        error: error?.message || error
      });
      const lag = Math.max(0, this.lastLength - this.lastDownloaded);
      return {
        hyperbeeVersion: this.db?.version || 0,
        hyperbeeLag: lag,
        hyperbeeContiguousLength: this.lastDownloaded,
        hyperbeeLength: this.lastLength,
        hyperbeeLastUpdatedAt: this.lastReplicaUpdateAt,
        hyperbeeKey: this.hyperbeeKey,
        hyperbeeDiscoveryKey: this.discoveryKey
      };
    }
  }

  getReplicaSnapshot() {
    return {
      hyperbeeKey: this.hyperbeeKey,
      discoveryKey: this.discoveryKey,
      ...this.replicaSnapshot
    };
  }
}

export default PublicGatewayRelayClient;
