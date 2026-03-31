import b4a from 'b4a';

const DEFAULT_SUBSCRIPTION_STATE = () => ({
  filters: [],
  lastReturnedAt: null
});

export default class PublicGatewayVirtualRelayManager {
  constructor({
    identifier,
    hyperbeeAdapter,
    logger = console
  } = {}) {
    if (!identifier || typeof identifier !== 'string') {
      throw new Error('identifier is required for PublicGatewayVirtualRelayManager');
    }

    this.identifier = identifier;
    this.logger = logger || console;
    this.connections = new Map(); // connectionKey -> { subscriptions: Map, createdAt, updatedAt }
    this.hyperbeeAdapter = hyperbeeAdapter || null;
    this.readOnly = true;

    this.#log('info', 'Virtual relay manager initialized', { identifier });
  }

  setHyperbeeAdapter(adapter) {
    this.hyperbeeAdapter = adapter || null;
    const hasReplica = !!(this.hyperbeeAdapter && typeof this.hyperbeeAdapter.hasReplica === 'function' && this.hyperbeeAdapter.hasReplica());
    this.#log('info', 'Hyperbee adapter set', { hasReplica });
  }

  getIdentifier() {
    return this.identifier;
  }

  getMetadata() {
    return {
      identifier: this.identifier,
      readOnly: this.readOnly,
      type: 'public-gateway-hyperbee'
    };
  }

  async getReplicaStats() {
    if (!this.hyperbeeAdapter || typeof this.hyperbeeAdapter.getReplicaStats !== 'function') {
      return {
        length: 0,
        downloaded: 0,
        lag: 0
      };
    }

    try {
      const stats = await this.hyperbeeAdapter.getReplicaStats();
      return {
        length: stats?.length ?? 0,
        downloaded: stats?.downloaded ?? 0,
        lag: stats?.lag ?? 0
      };
    } catch (error) {
      this.#log('debug', 'Failed to collect replica stats', { error: error?.message });
      return {
        length: 0,
        downloaded: 0,
        lag: 0
      };
    }
  }

  async handleMessage(message, sendResponse, connectionKey) {
    if (!Array.isArray(message) || message.length === 0) {
      this.#log('warn', 'Received invalid message frame', { connectionKey, message });
      return;
    }

    const [verb] = message;
    switch (verb) {
      case 'REQ':
        await this.#handleReq(message, sendResponse, connectionKey);
        break;
      case 'CLOSE':
        await this.#handleClose(message, sendResponse, connectionKey);
        break;
      case 'EVENT':
        this.#handleEvent(message, sendResponse, connectionKey);
        break;
      case 'COUNT':
        this.#handleCount(message, sendResponse, connectionKey);
        break;
      case 'PING':
        this.#handlePing(sendResponse);
        break;
      default:
        this.#log('debug', 'Unhandled Nostr verb for virtual relay', { verb, connectionKey });
        if (typeof sendResponse === 'function') {
          sendResponse(['NOTICE', `Unsupported verb ${verb} for read-only relay`]);
        }
        break;
    }
  }

  async handleSubscription(connectionKey) {
    const session = this.connections.get(connectionKey);
    if (!session) {
      this.#log('debug', 'No subscription state for connection', { connectionKey });
      return [[], null];
    }

    if (!this.hyperbeeAdapter || typeof this.hyperbeeAdapter.query !== 'function') {
      this.#log('warn', 'Hyperbee adapter unavailable during subscription handling', { connectionKey });
      return [this.#buildEoseFrames(session), null];
    }

    const frames = [];
    const updatePayload = {
      connection: connectionKey,
      subscriptions: {}
    };

    for (const [subscriptionId, state] of session.subscriptions.entries()) {
      const { filters, lastReturnedAt } = state;
      const result = await this.#queryForSubscription(subscriptionId, filters, lastReturnedAt);
      const { events, newestTimestamp } = result;

      for (const event of events) {
        frames.push(['EVENT', subscriptionId, event]);
      }
      frames.push(['EOSE', subscriptionId]);

      const nextTimestamp = Number.isFinite(newestTimestamp) ? newestTimestamp : lastReturnedAt;
      session.subscriptions.set(subscriptionId, {
        ...state,
        lastReturnedAt: nextTimestamp
      });

      updatePayload.subscriptions[subscriptionId] = {
        last_returned_event_timestamp: nextTimestamp ?? null,
        filters
      };
    }

    session.updatedAt = Date.now();

    const hasUpdates = Object.keys(updatePayload.subscriptions).length > 0;
    return [frames, hasUpdates ? updatePayload : null];
  }

  async updateSubscriptions(connectionKey, activeSubscriptionsUpdated) {
    if (!activeSubscriptionsUpdated) return;
    const session = this.connections.get(connectionKey);
    if (!session) return;

    const subs = activeSubscriptionsUpdated?.subscriptions;
    if (!subs || typeof subs !== 'object') return;

    for (const [subscriptionId, payload] of Object.entries(subs)) {
      const entry = session.subscriptions.get(subscriptionId) || DEFAULT_SUBSCRIPTION_STATE();
      entry.lastReturnedAt = payload?.last_returned_event_timestamp ?? entry.lastReturnedAt ?? null;
      if (Array.isArray(payload?.filters)) {
        entry.filters = payload.filters;
      }
      session.subscriptions.set(subscriptionId, entry);
    }

    session.updatedAt = Date.now();
    this.#log('debug', 'Applied subscription updates from pear-relay-server', {
      connectionKey,
      subscriptionCount: session.subscriptions.size
    });
  }

  async close() {
    this.#log('info', 'Closing virtual relay manager', {
      connectionCount: this.connections.size
    });
    this.connections.clear();
  }

  #ensureSession(connectionKey) {
    if (!this.connections.has(connectionKey)) {
      this.connections.set(connectionKey, {
        createdAt: Date.now(),
        updatedAt: Date.now(),
        subscriptions: new Map()
      });
    }
    return this.connections.get(connectionKey);
  }

  async #handleReq(message, sendResponse, connectionKey) {
    if (message.length < 3) {
      this.#log('warn', 'REQ frame missing filters', { connectionKey, frame: message });
      if (typeof sendResponse === 'function') {
        sendResponse(['NOTICE', 'REQ missing filters']);
      }
      return;
    }

    const [, subscriptionId, ...filters] = message;
    if (!subscriptionId || !filters.length) {
      this.#log('warn', 'REQ frame missing subscription id or filters', { connectionKey, frame: message });
      if (typeof sendResponse === 'function') {
        sendResponse(['NOTICE', 'REQ missing subscription id or filters']);
      }
      return;
    }

    const normalizedFilters = filters.filter(Boolean).map(this.#normalizeFilter.bind(this));
    const session = this.#ensureSession(connectionKey);
    const existing = session.subscriptions.get(subscriptionId) || DEFAULT_SUBSCRIPTION_STATE();
    session.subscriptions.set(subscriptionId, {
      filters: normalizedFilters,
      lastReturnedAt: existing.lastReturnedAt ?? null
    });
    session.updatedAt = Date.now();

    this.#log('info', 'Registered subscription for public gateway relay', {
      connectionKey,
      subscriptionId,
      filterCount: normalizedFilters.length
    });

    if (typeof sendResponse === 'function') {
      sendResponse(['NOTICE', `Subscription ${subscriptionId} registered for ${this.identifier}`]);
      sendResponse(['ACK', subscriptionId, 'registered']);
    }
  }

  async #handleClose(message, sendResponse, connectionKey) {
    if (message.length < 2) return;
    const [, subscriptionId] = message;
    const session = this.connections.get(connectionKey);
    if (!session) return;

    session.subscriptions.delete(subscriptionId);
    session.updatedAt = Date.now();

    this.#log('info', 'Closed subscription for connection', {
      connectionKey,
      subscriptionId,
      remaining: session.subscriptions.size
    });

    if (session.subscriptions.size === 0) {
      this.connections.delete(connectionKey);
    }

    if (typeof sendResponse === 'function') {
      sendResponse(['NOTICE', `Subscription ${subscriptionId} closed`]);
    }
  }

  #handleEvent(message, sendResponse, connectionKey) {
    const event = message.length === 2 ? message[1] : message[2];
    const eventId = event?.id || (event && event.id === 0 ? 0 : null);

    this.#log('warn', 'Received EVENT for read-only public gateway relay', {
      connectionKey,
      eventId
    });

    if (typeof sendResponse === 'function') {
      const responseId = typeof eventId === 'string' ? eventId : (eventId && b4a.isBuffer(eventId) ? b4a.toString(eventId, 'hex') : null);
      sendResponse(['OK', responseId, false, 'error: public gateway relay is read-only']);
    }
  }

  #handleCount(message, sendResponse, connectionKey) {
    if (typeof sendResponse !== 'function') return;
    const [, subscriptionId] = message;
    this.#log('debug', 'COUNT requested for read-only relay', { connectionKey, subscriptionId });
    sendResponse(['COUNT', subscriptionId || '', 0]);
  }

  #handlePing(sendResponse) {
    if (typeof sendResponse !== 'function') return;
    sendResponse(['PONG']);
  }

  async #queryForSubscription(subscriptionId, filters, lastReturnedAt) {
    const results = new Map();
    let newestTimestamp = lastReturnedAt ?? null;

    for (const filter of filters) {
      this.#log('debug', 'Querying Hyperbee for subscription filter', {
        subscriptionId,
        filter,
        lastReturnedAt
      });
      try {
        const queryResult = await this.hyperbeeAdapter.query([filter]);
        const events = Array.isArray(queryResult?.events) ? queryResult.events : [];
        this.#log('debug', 'Hyperbee query result', {
          subscriptionId,
          filter,
          eventCount: events.length
        });
        for (const event of events) {
          const createdAt = Number(event?.created_at ?? 0);
          if (Number.isFinite(lastReturnedAt) && createdAt <= lastReturnedAt) {
            continue;
          }
          if (!event?.id) continue;
          results.set(event.id, event);
          if (!Number.isFinite(newestTimestamp) || createdAt > newestTimestamp) {
            newestTimestamp = createdAt;
          }
        }
      } catch (error) {
        this.#log('warn', 'Hyperbee query failed for subscription', {
          subscriptionId,
          error: error?.message
        });
      }
    }

    const sortedEvents = Array.from(results.values()).sort((a, b) => (a?.created_at || 0) - (b?.created_at || 0));
    this.#log('debug', 'Subscription query completed', {
      subscriptionId,
      returnedEvents: sortedEvents.length,
      newestTimestamp
    });
    return {
      events: sortedEvents,
      newestTimestamp
    };
  }

  #buildEoseFrames(session) {
    const frames = [];
    for (const subscriptionId of session.subscriptions.keys()) {
      frames.push(['EOSE', subscriptionId]);
    }
    return frames;
  }

  #normalizeFilter(filter) {
    if (!filter || typeof filter !== 'object') return {};
    const normalized = { ...filter };

    if (Array.isArray(normalized.ids)) {
      normalized.ids = normalized.ids.filter(Boolean);
    }
    if (Array.isArray(normalized.kinds)) {
      normalized.kinds = normalized.kinds.map((kind) => Number(kind)).filter((kind) => Number.isFinite(kind));
    }
    if (normalized.limit != null) {
      const limit = Number(normalized.limit);
      if (Number.isFinite(limit) && limit > 0) {
        normalized.limit = Math.floor(limit);
      } else {
        delete normalized.limit;
      }
    }
    return normalized;
  }

  #log(level, message, context = {}) {
    const logger = this.logger || console;
    const entry = {
      scope: 'PublicGatewayVirtualRelayManager',
      identifier: this.identifier,
      ...context
    };

    const candidate = (logger && typeof logger[level] === 'function')
      ? logger[level].bind(logger)
      : (logger && typeof logger.log === 'function')
        ? logger.log.bind(logger)
        : null;

    if (candidate) {
      try {
        candidate(`[PublicGatewayVirtualRelayManager] ${message}`, entry);
      } catch (error) {
        if (logger && typeof logger.error === 'function') {
          logger.error('[PublicGatewayVirtualRelayManager] Logging failure', {
            message,
            error: error?.message
          });
        }
      }
    }
  }
}
