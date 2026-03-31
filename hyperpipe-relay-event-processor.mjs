// this is the script for /backend/hyperpipe-relay-event-processor.mjs

import Autobee from './hyperpipe-relay-helper.mjs';
import b4a from 'b4a';
import { nobleSecp256k1 } from './crypto-libraries.js';
import { NostrUtils } from './nostr-utils.js';

export { validateEvent, verifyEventSignature, getEventHash, serializeEvent };

function logWithTimestamp(message, data = null) {
  const timestamp = new Date().toISOString();
  console.log(`[${timestamp}] ${message}`);
  if (data) {
      console.log(typeof data === 'object' ? JSON.stringify(data, null, 2) : data);
  }
}

const TIMELINE_VOLATILE_FILTER_KEYS = new Set(['since', 'until', 'limit']);
const TIMELINE_SUBSCRIPTION_STALE_TTL_MS = 20 * 60 * 1000;
const MAX_TIMELINE_SUBSCRIPTIONS = 32;

function serializeEvent(event) {
  logWithTimestamp("serializeEvent: Serializing event", event);
  const serialized = JSON.stringify([0, event.pubkey, event.created_at, event.kind, event.tags, event.content]);
  logWithTimestamp("serializeEvent: Serialized event", serialized);
  return serialized;
}

async function getEventHash(event) {
  logWithTimestamp("getEventHash: Generating hash for event", event);
  const serialized = JSON.stringify([0, event.pubkey, event.created_at, event.kind, event.tags, event.content]);
  const hashBytes = await nobleSecp256k1.utils.sha256(b4a.from(serialized, 'utf8'));
  const hash = NostrUtils.bytesToHex(hashBytes);
  logWithTimestamp("getEventHash: Generated hash", hash);
  return hash;
}

function validateEvent(event) {
  // logWithTimestamp('validateEvent: Validating event:', JSON.stringify(event, null, 2));
  
  if (!event.id) {
    logWithTimestamp('validateEvent: Event is missing id');
    return false;
  }
  if (!event.pubkey) {
    logWithTimestamp('validateEvent: Event is missing pubkey');
    return false;
  }
  if (!event.pubkey.match(/^[a-f0-9]{64}$/)) {
    logWithTimestamp('validateEvent: Event pubkey is not a valid 32-byte hex string');
    return false;
  }
  if (!event.created_at) {
    logWithTimestamp('validateEvent: Event is missing created_at');
    return false;
  }
  if (event.kind === undefined) {
    logWithTimestamp('validateEvent: Event is missing kind');
    return false;
  }
  if (!Array.isArray(event.tags)) {
    logWithTimestamp('validateEvent: Event tags is not an array');
    return false;
  }
  if (typeof event.content !== 'string') {
    logWithTimestamp('validateEvent: Event content is not a string');
    return false;
  }
  if (!event.sig) {
    logWithTimestamp('validateEvent: Event is missing signature');
    return false;
  }

  if (typeof event.kind !== 'number') {
    logWithTimestamp('validateEvent: Event kind is not a number');
    return false;
  }
  if (typeof event.created_at !== 'number') {
    logWithTimestamp('validateEvent: Event created_at is not a number');
    return false;
  }

  for (let tag of event.tags) {
    if (!Array.isArray(tag)) {
      logWithTimestamp('validateEvent: Event tag is not an array');
      return false;
    }
    for (let item of tag) {
      if (typeof item === 'object') {
        logWithTimestamp('validateEvent: Event tag item is an object');
        return false;
      }
    }
  }

  logWithTimestamp('validateEvent: Event passed all validation checks');
  return true;
}

async function verifyEventSignature(event) {
  logWithTimestamp('verifyEventSignature: Verifying event signature');
  logWithTimestamp('verifyEventSignature: Event ID:', event.id);
  logWithTimestamp('verifyEventSignature: Event pubkey:', event.pubkey);
  logWithTimestamp('verifyEventSignature: Event signature:', event.sig);
  
  try {
    const serializedEvent = serializeEvent(event);
    const eventHashBytes = await nobleSecp256k1.utils.sha256(b4a.from(serializedEvent, 'utf8'));
    const eventHashHex = NostrUtils.bytesToHex(eventHashBytes);
    
    logWithTimestamp('verifyEventSignature: Serialized event:', serializedEvent);
    logWithTimestamp('verifyEventSignature: Event hash:', eventHashHex);
    
    // Verify the hash matches the event ID
    if (eventHashHex !== event.id) {
      logWithTimestamp('verifyEventSignature: Event hash does not match event ID');
      return false;
    }
    
    // Our schnorr.verify can handle hex strings directly
    const isValid = await nobleSecp256k1.schnorr.verify(
      event.sig,    // hex string
      event.id,     // hex string
      event.pubkey  // hex string (x-only pubkey)
    );
    
    logWithTimestamp('verifyEventSignature: Signature verification result:', isValid);
    return isValid;
  } catch (error) {
    logWithTimestamp('verifyEventSignature: Error verifying event signature:', error);
    return false;
  }
}

export default class NostrRelay extends Autobee {
    constructor(store, bootstrap, handlers = {}) {
      super(store, bootstrap, handlers);
      this.verifyEvent = handlers.verifyEvent || this.defaultVerifyEvent.bind(this);
      this.executeIdQueries = this.executeIdQueries.bind(this);
      this.findCommonIds = this.findCommonIds.bind(this);
      this.subscriptionWriteQueue = new Map();
      this.pendingSubscriptionWrites = [];
      this.pendingSubscriptionMax = 250;
      this.pendingSubscriptionFlushActive = false;
      this.pendingSubscriptionFlushScheduled = false;
      this.pendingEventWrites = [];
      this.pendingEventMax = 250;
      this.pendingEventFlushActive = false;
      this.pendingEventFlushScheduled = false;
      if (typeof this.on === 'function') {
        this.on('writable', () => {
          this._flushPendingSubscriptionWrites('writable').catch((error) => {
            logWithTimestamp('pendingSubscriptionWrites: flush failed after writable', error?.message || error);
          });
          this._flushPendingEventWrites('writable').catch((error) => {
            logWithTimestamp('pendingEventWrites: flush failed after writable', error?.message || error);
          });
        });
      }
      logWithTimestamp('NostrRelay: Initialized');
    }

  _queueSubscriptionWrite(queueKey, task) {
    const key = queueKey || 'unknown';
    const previous = this.subscriptionWriteQueue.get(key) || Promise.resolve();
    const next = previous.catch(() => null).then(task);
    // Store a non-rejecting queue tail so shutdown-time append failures do not
    // become unhandled promise rejections when the tail is not awaited directly.
    const queueTail = next
      .catch(() => null)
      .finally(() => {
        if (this.subscriptionWriteQueue.get(key) === queueTail) {
          this.subscriptionWriteQueue.delete(key);
        }
      });
    this.subscriptionWriteQueue.set(key, queueTail);
    return next;
  }

  _enqueuePendingSubscriptionWrite(entry) {
    if (!entry) return;
    if (this.pendingSubscriptionWrites.length >= this.pendingSubscriptionMax) {
      const dropped = this.pendingSubscriptionWrites.shift();
      logWithTimestamp('pendingSubscriptionWrites: dropped oldest entry', {
        connectionKey: dropped?.connectionKey ?? null,
        subscriptionId: dropped?.subscriptionId ?? null,
        queuedAt: dropped?.queuedAt ?? null,
        max: this.pendingSubscriptionMax
      });
    }
    this.pendingSubscriptionWrites.push(entry);
  }

  _schedulePendingSubscriptionFlush(reason = 'scheduled') {
    if (this.pendingSubscriptionFlushScheduled) return;
    this.pendingSubscriptionFlushScheduled = true;
    setTimeout(() => {
      this.pendingSubscriptionFlushScheduled = false;
      this._flushPendingSubscriptionWrites(`timer:${reason}`).catch((error) => {
        logWithTimestamp('pendingSubscriptionWrites: flush failed on timer', error?.message || error);
      });
    }, 1000);
  }

  async _flushPendingSubscriptionWrites(reason = 'flush') {
    if (!this.writable) {
      logWithTimestamp('pendingSubscriptionWrites: flush skipped (not writable)', {
        reason,
        pending: this.pendingSubscriptionWrites.length
      });
      return;
    }
    if (this.pendingSubscriptionFlushActive) return;
    if (this.pendingSubscriptionWrites.length === 0) return;

    this.pendingSubscriptionFlushActive = true;
    const startCount = this.pendingSubscriptionWrites.length;
    logWithTimestamp('pendingSubscriptionWrites: flushing', {
      reason,
      pending: startCount
    });

    try {
      while (this.pendingSubscriptionWrites.length > 0) {
        if (!this.writable) {
          logWithTimestamp('pendingSubscriptionWrites: flush paused (lost writable)', {
            remaining: this.pendingSubscriptionWrites.length
          });
          break;
        }
        const entry = this.pendingSubscriptionWrites.shift();
        if (!entry?.connectionKey || !entry?.reqMessage) {
          continue;
        }
        try {
          const activeSubscriptions = await this.getSubscriptions(entry.connectionKey);
          await this.publishSubscription(entry.connectionKey, entry.reqMessage, activeSubscriptions, entry.clientId);
          logWithTimestamp('pendingSubscriptionWrites: flushed entry', {
            connectionKey: entry.connectionKey,
            subscriptionId: entry.subscriptionId ?? null
          });
        } catch (error) {
          logWithTimestamp('pendingSubscriptionWrites: flush entry failed', {
            connectionKey: entry.connectionKey,
            subscriptionId: entry.subscriptionId ?? null,
            error: error?.message || error
          });
        }
      }
    } finally {
      this.pendingSubscriptionFlushActive = false;
      if (this.pendingSubscriptionWrites.length > 0) {
        this._schedulePendingSubscriptionFlush('drain');
      }
    }
  }

  _enqueuePendingEventWrite(entry) {
    if (!entry) return;
    if (this.pendingEventWrites.length >= this.pendingEventMax) {
      const dropped = this.pendingEventWrites.shift();
      logWithTimestamp('pendingEventWrites: dropped oldest entry', {
        eventId: dropped?.eventId ?? null,
        queuedAt: dropped?.queuedAt ?? null,
        max: this.pendingEventMax
      });
    }
    this.pendingEventWrites.push(entry);
  }

  _schedulePendingEventFlush(reason = 'scheduled') {
    if (this.pendingEventFlushScheduled) return;
    this.pendingEventFlushScheduled = true;
    setTimeout(() => {
      this.pendingEventFlushScheduled = false;
      this._flushPendingEventWrites(`timer:${reason}`).catch((error) => {
        logWithTimestamp('pendingEventWrites: flush failed on timer', error?.message || error);
      });
    }, 1000);
  }

  async _flushPendingEventWrites(reason = 'flush') {
    if (!this.writable) {
      logWithTimestamp('pendingEventWrites: flush skipped (not writable)', {
        reason,
        pending: this.pendingEventWrites.length
      });
      return;
    }
    if (this.pendingEventFlushActive) return;
    if (this.pendingEventWrites.length === 0) return;

    this.pendingEventFlushActive = true;
    const startCount = this.pendingEventWrites.length;
    logWithTimestamp('pendingEventWrites: flushing', {
      reason,
      pending: startCount
    });

    try {
      while (this.pendingEventWrites.length > 0) {
        if (!this.writable) {
          logWithTimestamp('pendingEventWrites: flush paused (lost writable)', {
            remaining: this.pendingEventWrites.length
          });
          break;
        }
        const entry = this.pendingEventWrites.shift();
        if (!entry?.event) {
          continue;
        }
        try {
          await this.publishEvent(entry.event);
          logWithTimestamp('pendingEventWrites: flushed entry', {
            eventId: entry.eventId ?? entry.event?.id ?? null
          });
        } catch (error) {
          logWithTimestamp('pendingEventWrites: flush entry failed', {
            eventId: entry.eventId ?? entry.event?.id ?? null,
            error: error?.message || error
          });
        }
      }
    } finally {
      this.pendingEventFlushActive = false;
      if (this.pendingEventWrites.length > 0) {
        this._schedulePendingEventFlush('drain');
      }
    }
  }

  _isEphemeralSubscriptionId(subscriptionId) {
    if (typeof subscriptionId !== 'string') return false;
    return (
      subscriptionId.startsWith('f-fetch-events') ||
      subscriptionId.startsWith('f-more') ||
      subscriptionId.startsWith('f-temporary')
    );
  }

  _isTimelineSubscriptionId(subscriptionId) {
    return typeof subscriptionId === 'string' && subscriptionId.startsWith('f-timeline');
  }

  _buildSubscriptionSignature(entry, { stripVolatileTimelineKeys = false } = {}) {
    if (!entry || typeof entry !== 'object') return null;
    const filters = Array.isArray(entry.filters) ? entry.filters : null;
    if (!filters || filters.length === 0) return null;
    try {
      const normalizedFilters = filters.map((filter) => {
        if (!filter || typeof filter !== 'object' || Array.isArray(filter)) return filter;
        const normalizedFilter = {};
        const keys = Object.keys(filter).sort();
        for (const key of keys) {
          if (stripVolatileTimelineKeys && TIMELINE_VOLATILE_FILTER_KEYS.has(key)) {
            continue;
          }
          const value = filter[key];
          if (Array.isArray(value)) {
            normalizedFilter[key] = [...value].sort((a, b) =>
              String(a).localeCompare(String(b))
            );
          } else {
            normalizedFilter[key] = value;
          }
        }
        return normalizedFilter;
      });
      return JSON.stringify(normalizedFilters);
    } catch {
      return null;
    }
  }

  _subscriptionTimestamp(entry) {
    const ts = entry?.last_returned_event_timestamp;
    return Number.isFinite(ts) ? ts : -Infinity;
  }

  _subscriptionUpdatedAtMs(entry) {
    const updatedAt = entry?.updated_at;
    if (Number.isFinite(updatedAt)) {
      return updatedAt;
    }
    const lastReturned = entry?.last_returned_event_timestamp;
    if (Number.isFinite(lastReturned)) {
      return lastReturned * 1000;
    }
    return null;
  }

  _subscriptionRecencyScore(entry) {
    const updatedAt = this._subscriptionUpdatedAtMs(entry);
    return Number.isFinite(updatedAt) ? updatedAt : -Infinity;
  }

  _timelineSubscriptionBaseId(subscriptionId) {
    if (typeof subscriptionId !== 'string') return null;
    const separatorIdx = subscriptionId.indexOf(':');
    return separatorIdx === -1 ? subscriptionId : subscriptionId.slice(0, separatorIdx);
  }

  _isStaleTimelineSubscription(entry, nowMs, staleTimelineTtlMs) {
    if (!Number.isFinite(staleTimelineTtlMs) || staleTimelineTtlMs <= 0) {
      return false;
    }
    const updatedAt = this._subscriptionUpdatedAtMs(entry);
    if (!Number.isFinite(updatedAt)) {
      return false;
    }
    return nowMs - updatedAt > staleTimelineTtlMs;
  }

  _touchSubscriptionEntry(entry, updatedAtMs = Date.now()) {
    const baseEntry = entry && typeof entry === 'object' ? { ...entry } : {};
    baseEntry.updated_at = Number.isFinite(updatedAtMs) ? updatedAtMs : Date.now();
    return baseEntry;
  }

  _pruneTimelineSubscriptions(
    subscriptions,
    {
      preferredSubscriptionId = null,
      maxTimelineSubscriptions = MAX_TIMELINE_SUBSCRIPTIONS,
      staleTimelineTtlMs = TIMELINE_SUBSCRIPTION_STALE_TTL_MS
    } = {}
  ) {
    if (!subscriptions || typeof subscriptions !== 'object') {
      return { subscriptions: {}, removedTimelineIds: [], keptTimelineIds: [] };
    }

    const nonTimelineSubscriptions = {};
    const timelineEntries = [];
    const bySignature = new Map();
    const nowMs = Date.now();

    for (const [subscriptionId, entry] of Object.entries(subscriptions)) {
      if (!this._isTimelineSubscriptionId(subscriptionId)) {
        nonTimelineSubscriptions[subscriptionId] = entry;
        continue;
      }
      timelineEntries.push({ subscriptionId, entry });
      if (
        subscriptionId !== preferredSubscriptionId &&
        this._isStaleTimelineSubscription(entry, nowMs, staleTimelineTtlMs)
      ) {
        continue;
      }
      const timelineBaseId = this._timelineSubscriptionBaseId(subscriptionId) || subscriptionId;
      const signature =
        this._buildSubscriptionSignature(entry, { stripVolatileTimelineKeys: true }) || '__nosig';
      const dedupeKey = `${timelineBaseId}|${signature}`;
      const existing = bySignature.get(dedupeKey);
      if (!existing) {
        bySignature.set(dedupeKey, { subscriptionId, entry });
        continue;
      }

      const existingPreferred = existing.subscriptionId === preferredSubscriptionId;
      const incomingPreferred = subscriptionId === preferredSubscriptionId;
      if (incomingPreferred && !existingPreferred) {
        bySignature.set(dedupeKey, { subscriptionId, entry });
        continue;
      }
      if (!incomingPreferred && existingPreferred) {
        continue;
      }

      const existingTs = this._subscriptionRecencyScore(existing.entry);
      const incomingTs = this._subscriptionRecencyScore(entry);
      if (incomingTs > existingTs) {
        bySignature.set(dedupeKey, { subscriptionId, entry });
      }
    }

    let selectedTimelineEntries = Array.from(bySignature.values());
    if (selectedTimelineEntries.length > maxTimelineSubscriptions) {
      selectedTimelineEntries = selectedTimelineEntries
        .sort((a, b) => {
          if (a.subscriptionId === preferredSubscriptionId) return -1;
          if (b.subscriptionId === preferredSubscriptionId) return 1;
          const bTs = this._subscriptionRecencyScore(b.entry);
          const aTs = this._subscriptionRecencyScore(a.entry);
          return bTs - aTs;
        })
        .slice(0, maxTimelineSubscriptions);
    }

    const keptTimelineIds = selectedTimelineEntries.map((entry) => entry.subscriptionId);
    const keptTimelineIdSet = new Set(keptTimelineIds);
    const removedTimelineIds = timelineEntries
      .map((entry) => entry.subscriptionId)
      .filter((subscriptionId) => !keptTimelineIdSet.has(subscriptionId));

    const prunedSubscriptions = { ...nonTimelineSubscriptions };
    for (const { subscriptionId, entry } of selectedTimelineEntries) {
      prunedSubscriptions[subscriptionId] = entry;
    }

    return { subscriptions: prunedSubscriptions, removedTimelineIds, keptTimelineIds };
  }

  _filterEphemeralSubscriptions(subscriptions) {
    if (!subscriptions || typeof subscriptions !== 'object') return {};
    const filtered = {};
    for (const [subscriptionId, entry] of Object.entries(subscriptions)) {
      if (this._isEphemeralSubscriptionId(subscriptionId)) {
        continue;
      }
      filtered[subscriptionId] = entry;
    }
    return filtered;
  }

  _mergeSubscriptionEntry(baseEntry, incomingEntry) {
    if (!baseEntry) return incomingEntry ? { ...incomingEntry } : {};
    if (!incomingEntry) return { ...baseEntry };

    const merged = { ...baseEntry, ...incomingEntry };
    if (incomingEntry.filters) {
      merged.filters = incomingEntry.filters;
    } else if (baseEntry.filters && !merged.filters) {
      merged.filters = baseEntry.filters;
    }

    const baseTimestamp = baseEntry.last_returned_event_timestamp;
    const incomingTimestamp = incomingEntry.last_returned_event_timestamp;
    if (Number.isFinite(baseTimestamp) || Number.isFinite(incomingTimestamp)) {
      const safeBase = Number.isFinite(baseTimestamp) ? baseTimestamp : -Infinity;
      const safeIncoming = Number.isFinite(incomingTimestamp) ? incomingTimestamp : -Infinity;
      merged.last_returned_event_timestamp = Math.max(safeBase, safeIncoming);
    }

    const baseUpdatedAt = this._subscriptionUpdatedAtMs(baseEntry);
    const incomingUpdatedAt = this._subscriptionUpdatedAtMs(incomingEntry);
    if (Number.isFinite(baseUpdatedAt) || Number.isFinite(incomingUpdatedAt)) {
      const safeBaseUpdated = Number.isFinite(baseUpdatedAt) ? baseUpdatedAt : -Infinity;
      const safeIncomingUpdated = Number.isFinite(incomingUpdatedAt) ? incomingUpdatedAt : -Infinity;
      merged.updated_at = Math.max(safeBaseUpdated, safeIncomingUpdated);
    }

    return merged;
  }

  _mergeSubscriptionSnapshots(baseSnapshot, incomingSnapshot) {
    const baseSubscriptions = baseSnapshot?.subscriptions && typeof baseSnapshot.subscriptions === 'object'
      ? baseSnapshot.subscriptions
      : {};
    const incomingSubscriptions = incomingSnapshot?.subscriptions && typeof incomingSnapshot.subscriptions === 'object'
      ? incomingSnapshot.subscriptions
      : {};
    const mergedSubscriptions = { ...baseSubscriptions };

    for (const [subscriptionId, entry] of Object.entries(incomingSubscriptions)) {
      mergedSubscriptions[subscriptionId] = this._mergeSubscriptionEntry(
        mergedSubscriptions[subscriptionId],
        entry
      );
    }

    const merged = {
      connection: incomingSnapshot?.connection || baseSnapshot?.connection || null,
      subscriptions: mergedSubscriptions
    };

    if (baseSnapshot?.clientId || incomingSnapshot?.clientId) {
      merged.clientId = incomingSnapshot?.clientId || baseSnapshot?.clientId || null;
    }

    return merged;
  }
  
  // Update defaultVerifyEvent to be async
  async defaultVerifyEvent(event) {
    logWithTimestamp('defaultVerifyEvent: Verifying event', event);
    const result = validateEvent(event) && await verifyEventSignature(event);
    logWithTimestamp('defaultVerifyEvent: Verification result', result);
    return result;
  }

  static async apply(batch, view, base) {
    logWithTimestamp('NostrRelay.apply: Applying batch');
    const b = view.batch({ update: false })
  
    for (const node of batch) {
        const op = node.value;
        if (op.type === 'event') {
            const event = JSON.parse(op.event);
            // Note: This is a static method, so we can't use async verification here
            // The verification should happen before the event reaches this point
            // We'll just do basic validation
            if (validateEvent(event)) {
                // Store the full event under its ID
                const eventKey = b4a.from(event.id, 'hex');
                logWithTimestamp(`NostrRelay.apply: Storing event with ID: ${event.id}`);
                await b.put(eventKey, op.event);

                // Store index references - store just the event ID
                const kindKey = NostrRelay.constructIndexKeyKind(event);
                logWithTimestamp(`NostrRelay.apply: Storing kind index for event ${event.id} under key: ${kindKey}`);
                await b.put(b4a.from(kindKey, 'utf8'), event.id);

                const pubkeyKey = NostrRelay.constructIndexKeyPubkey(event);
                logWithTimestamp(`NostrRelay.apply: Storing pubkey index for event ${event.id} under key: ${pubkeyKey}`);
                await b.put(b4a.from(pubkeyKey, 'utf8'), event.id);

                const createdAtKey = NostrRelay.constructIndexKeyCreatedAt(event);
                logWithTimestamp(`NostrRelay.apply: Storing created_at index for event ${event.id} under key: ${createdAtKey}`);
                await b.put(b4a.from(createdAtKey, 'utf8'), event.id);

                // Store tag references
                let fileKeyHash = null
                let driveKey = null

                for (const tag of event.tags) {
                    if (tag.length >= 2 && /^[a-zA-Z]$/.test(tag[0])) {
                        const tagKey = NostrRelay.constructIndexKeyTagKey(event, tag[0], tag[1]);
                        logWithTimestamp(`NostrRelay.apply: Storing tag index for event ${event.id} under key: ${tagKey}`);
                        await b.put(b4a.from(tagKey, 'utf8'), event.id);
                    }

                    if (tag[0] === 'filekey' && tag[1]) fileKeyHash = tag[1]
                    if (tag[0] === 'drivekey' && tag[1]) driveKey = tag[1]
                }

                if (fileKeyHash && driveKey) {
                    const fileKey = NostrRelay.constructIndexKeyFilekey(event, fileKeyHash, driveKey)
                    logWithTimestamp(`NostrRelay.apply: Storing filekey index for event ${event.id} under key: ${fileKey}`)
                    const fileKeyValue = {
                        filekey: fileKeyHash,
                        drivekey: driveKey,
                        pubkey: event.pubkey
                    }
                    await b.put(
                        b4a.from(fileKey, 'utf8'),
                        b4a.from(JSON.stringify(fileKeyValue), 'utf8')
                    )
                }
            } else {
                logWithTimestamp(`NostrRelay.apply: Invalid event, not storing. ID: ${event.id}`);
            }
        } else if (op.type === 'subscriptions') {
            const subscriptionData = JSON.parse(op.subscriptions);
            // logWithTimestamp('NostrRelay.apply: Processing subscription data:', subscriptionData);
            const key = b4a.from(subscriptionData.connection, 'hex');
            logWithTimestamp(`NostrRelay.apply: Storing subscription data for connection: ${subscriptionData.connection}`);
            await b.put(key, op.subscriptions);
        } else if (op.type === 'client-subscriptions') {
            const subscriptionData = JSON.parse(op.subscriptions);
            const clientId = subscriptionData.clientId || op.clientId;
            if (!clientId) {
                logWithTimestamp('NostrRelay.apply: Missing clientId for client-subscriptions');
                continue;
            }
            const key = b4a.from(`client:${clientId}`, 'utf8');
            logWithTimestamp(`NostrRelay.apply: Storing client subscription data for client: ${clientId}`);
            await b.put(key, op.subscriptions);
        }
    }
  
    logWithTimestamp('NostrRelay.apply: Flushing batch');
    await b.flush();
}

  /////////////////////////////////////////////////////////////////////////////////////////////////////////
  // PROCESSES TO <PUBLISH> EVENTS TO HYPERBEE: ///////////////////////////////////////////////////////////
  /////////////////////////////////////////////////////////////////////////////////////////////////////////

  // helper functions to be used by NostrRelay.apply() method to create searchable composite keys when publishing each hyperbee event entry


  static constructIndexKeyId(event) {
    return event.id;
  }

  static constructIndexKeyKind(event) {
    return `kind:${NostrRelay.padNumber(event.kind, 5)}:created_at:${event.created_at}:id:${event.id}`;
  }

  static constructIndexKeyPubkey(event) {
    return `pubkey:${event.pubkey}:created_at:${NostrRelay.padTimestamp(event.created_at)}:id:${event.id}`;
  }

  static constructIndexKeyFilekey(event, filekey, driveKey) {
    return `filekey:${filekey}:drivekey:${driveKey}:pubkey:${event.pubkey}`;
  }

  // ENHANCEMENT: logic is required to extract element 1 from each tag array and pass to 
  static constructIndexKeyTagKey(event, tagName, tagValue) {
    return `tagKey:${tagName}:tagValue:${tagValue}:created_at:${NostrRelay.padTimestamp(event.created_at)}:id:${event.id}`;
  }

  static constructIndexKeyCreatedAt(event) {
    return `created_at:${NostrRelay.padTimestamp(event.created_at)}:id:${event.id}`;
  }


  // function to verify event object structure and attributes are valid + append valid event objects to hyperbee log
  // note: apply() method will take objects appended to hyperbee log + handle the final processes to 'put' new entries into the db.
  async publishEvent(event) {
    // logWithTimestamp('publishEvent: Attempting to publish event:', JSON.stringify(event, null, 2));
    
    if (!this.writable) {
      if (!event.id) {
        event.id = await getEventHash(event);
        logWithTimestamp('publishEvent: Generated event ID:', event.id);
      }
      const isValid = await this.verifyEvent(event);
      logWithTimestamp('publishEvent: Event verification result:', isValid);
      if (!isValid) {
        logWithTimestamp('publishEvent: Event failed verification');
        return ["OK", event.id, false, "invalid: event failed verification"];
      }
      this._enqueuePendingEventWrite({
        event,
        eventId: event.id,
        queuedAt: Date.now()
      });
      logWithTimestamp('publishEvent: Not writable; queued event', {
        eventId: event.id,
        pending: this.pendingEventWrites.length
      });
      this._schedulePendingEventFlush('not-writable');
      return ["OK", event.id, false, "Relay initializing; event queued"];
    }
    
    if (!event.id) {
      event.id = await getEventHash(event);  // Now using await
      logWithTimestamp('publishEvent: Generated event ID:', event.id);
    }
    
    const isValid = await this.verifyEvent(event);  // Now using await
    logWithTimestamp('publishEvent: Event verification result:', isValid);
    
    if (isValid) {
      logWithTimestamp(`publishEvent: Publishing event with ID: ${event.id}`);
      try {
        const batch = [
          {
            type: 'event',
            event: JSON.stringify(event)
          },
          ...this.constructTagEntries(event)
        ];
        
        await this.append(batch);
        logWithTimestamp(`publishEvent: Event published successfully: ${event.id}`);
        return ["OK", event.id, true, ""];
      } catch (error) {
        logWithTimestamp(`publishEvent: Error publishing event: ${error.message}`);
        return ["ERROR", event.id, false, `Error publishing event: ${error.message}`];
      }
    } else {
      logWithTimestamp('publishEvent: Event failed verification');
      return ["OK", event.id, false, "invalid: event failed verification"];
    }
  }

    constructTagEntries(event) {
        const entries = [];
        for (const tag of event.tags) {
          if (tag.length >= 2 && /^[a-zA-Z]$/.test(tag[0])) {
            const tagKey = NostrRelay.constructIndexKeyTagKey(event, tag[0], tag[1]);
            entries.push({
              type: 'event',
              key: tagKey,
              event: JSON.stringify(event)
            });
          }
        }
        return entries;
      }

  /////////////////////////////////////////////////////////////////////////////////////////////////////////
  /////////////////////////////////////////////////////////////////////////////////////////////////////////


  /////////////////////////////////////////////////////////////////////////////////////////////////////////
  // PROCESS TO <DELETE> EVENT BY ID FROM HYPERBEE: ///////////////////////////////////////////////////////
  /////////////////////////////////////////////////////////////////////////////////////////////////////////

  async deleteEvent(id) {
    logWithTimestamp(`deleteEvent: Deleting event with ID: ${id}`);
    if (!this.writable) {
      logWithTimestamp('deleteEvent: Error - Not writable');
      throw new Error('Not writable');
    }

    await this.append({
      type: 'delete',
      id: typeof id === 'string' ? id : b4a.toString(id, 'hex')
    });
  }

  /////////////////////////////////////////////////////////////////////////////////////////////////////////
  /////////////////////////////////////////////////////////////////////////////////////////////////////////

  /////////////////////////////////////////////////////////////////////////////////////////////////////////
  // PROCESS TO <GET> EVENT BY ID FROM HYPERBEE: //////////////////////////////////////////////////////////
  /////////////////////////////////////////////////////////////////////////////////////////////////////////  

  async getEvent(id) {
    logWithTimestamp(`getEvent: Attempting to retrieve event with ID: ${id}`);
    const key = b4a.from(id, 'hex');  // Direct conversion of ID to buffer
    logWithTimestamp(`getEvent: Converted key: ${key.toString('hex')}`);
    
    try {
        const event = await this.view.get(key);
        if (event) {
            logWithTimestamp(`getEvent: Event found for ID ${id}`);
            try {
                return typeof event.value === 'string' ? 
                       JSON.parse(event.value) : 
                       event.value;
            } catch (error) {
                logWithTimestamp('getEvent: Error parsing event:', error.message);
                return null;
            }
        }
        logWithTimestamp(`getEvent: No event found for ID ${id}`);
        return null;
    } catch (error) {
        logWithTimestamp('getEvent: Error retrieving event:', error.message);
        return null;
    }
}


  ///////////////////////////////////////////////////////////////////////////////////////////////////////
  // PROCESSES TO <GET> EVENTS FROM HYPERBEE THAT MATCH SUBSCRIPTION FILTERS CRITERIA: //////////////////
  ///////////////////////////////////////////////////////////////////////////////////////////////////////


  // Helper functions for query key construction
  static padNumber(num, length) {
    return num.toString().padStart(length, '0');
  }
  
  static padTimestamp(timestamp) {
    return timestamp.toString().padStart(10, '0');
  }
  
  async executeIdQueries(filter, last_returned_event_timestamp) {
    logWithTimestamp(`executeIdQueries: Processing ${filter.ids.length} IDs`);
    const results = [];
    const since = last_returned_event_timestamp || filter.since

    for (const id of filter.ids) {
      const event = await this.getEvent(id);
      
      if (!event) {
        logWithTimestamp(`executeIdQueries: Event not found for ID ${id}`);
        continue;
      }
  
      // Skip events older than last_returned_event_timestamp if it exists
      if (last_returned_event_timestamp && event.created_at < last_returned_event_timestamp) {
        logWithTimestamp(`executeIdQueries: Event ${id} skipped due to timestamp`);
        continue;
      }
  
      // Check if event matches additional filters
      let matches = true;
  
      // Check time-based filters
      if (filter.since && event.created_at < since) {
        matches = false;
      }
      if (filter.until && event.created_at > filter.until) {
        matches = false;
      }
  
      // Check kinds filter
      if (filter.kinds && !filter.kinds.includes(event.kind)) {
        matches = false;
      }
  
      // Check authors filter
      if (filter.authors && !filter.authors.includes(event.pubkey)) {
        matches = false;
      }
  
      // Check tag filters
      for (const [key, values] of Object.entries(filter)) {
        if (key.startsWith('#') && key.length === 2) {
          const tagName = key.slice(1);
          const matchingTags = event.tags.filter(tag => tag[0] === tagName);
          if (!matchingTags.some(tag => values.includes(tag[1]))) {
            matches = false;
            break;
          }
        }
      }
  
      if (matches) {
        results.push(event);
      }
    }

    if (filter.limit && !last_returned_event_timestamp) {
        results.splice(filter.limit);
        logWithTimestamp(`queryEvents: Results truncated to limit:`, filter.limit);
      }
  
    logWithTimestamp(`executeIdQueries: Found ${results.length} matching events`);
    return results;
  }

  async queryEvents(filter, last_returned_event_timestamp) {
    // logWithTimestamp(`queryEvents: Starting query with filter:`, JSON.stringify(filter, null, 2));
    logWithTimestamp(`queryEvents: Last returned event timestamp:`, last_returned_event_timestamp);
    const queries = this.constructQueries(filter, last_returned_event_timestamp);
    // logWithTimestamp(`queryEvents: Constructed query groups:`, JSON.stringify(queries, null, 2));
    
    const results = await this.executeQueries(queries);
    logWithTimestamp(`queryEvents: Raw query results count:`, results.length);
    
    if (filter.limit && !last_returned_event_timestamp) {
      results.splice(filter.limit);
      logWithTimestamp(`queryEvents: Results truncated to limit:`, filter.limit);
    }
    
    return results;
  }
  
  constructQueries(filter, last_returned_event_timestamp) {
    // logWithTimestamp(
    //   `constructQueries: Constructing queries for filter:`,
    //   JSON.stringify(filter, null, 2)
    // );
    logWithTimestamp(
      `constructQueries: Using timestamp:`,
      last_returned_event_timestamp
        ? `last_returned_event_timestamp: ${last_returned_event_timestamp}`
        : `filter.since: ${filter.since || 0}`
    );

    const groups = [];

    // Determine time range parameters - prioritize last_returned_event_timestamp over filter.since
    const since = last_returned_event_timestamp
      ? last_returned_event_timestamp + 1 // Add 1 to exclude previously returned events
      : filter.since || 0;
    const until = filter.until || 9999999999;

    logWithTimestamp(
      `constructQueries: Using time range - since: ${since}, until: ${until}`
    );

    // Case 1: Only time-based query (no other filters)
    if (
      (!filter.kinds || filter.kinds.length === 0) &&
      (!filter.authors || filter.authors.length === 0) &&
      !this.hasTagFilters(filter)
    ) {
      const query = this.constructor.constructTimeRangeQuery(since, until);
      // logWithTimestamp(`constructQueries: Constructed time-based query:`, query);
      groups.push([query]);
      return groups;
    }

    // Case 2: Kinds-based queries (union within kinds)
    if (filter.kinds && filter.kinds.length > 0) {
      const kindGroup = [];
      for (const kind of filter.kinds) {
        const query = this.constructor.constructKindRangeQuery(kind, since, until);
        // logWithTimestamp(`constructQueries: Constructed kind query for ${kind}:`, query);
        kindGroup.push(query);
      }
      groups.push(kindGroup);
    }

    // Case 3: Authors-based queries (union within authors)
    if (filter.authors && filter.authors.length > 0) {
      const authorGroup = [];
      for (const author of filter.authors) {
        const query = this.constructor.constructAuthorRangeQuery(author, since, until);
        // logWithTimestamp(
        //   `constructQueries: Constructed author query for ${author}:`,
        //   query
        // );
        authorGroup.push(query);
      }
      groups.push(authorGroup);
    }

    // Case 4: Tag-based queries (union within each tag key)
    const tagGroups = this.constructTagQueries(filter, since, until);
    if (tagGroups.length > 0) {
      logWithTimestamp(
        `constructQueries: Adding ${tagGroups.length} tag-based query groups`
      );
      groups.push(...tagGroups);
    }

    logWithTimestamp(
      `constructQueries: Constructed ${groups.length} query groups`
    );
    return groups;
  }
  
  // Helper method to check if filter has tag-based filters
  hasTagFilters(filter) {
    return Object.keys(filter).some(key => key.startsWith('#') && key.length === 2);
  }


// Static methods for constructing specific range queries
  static constructTimeRangeQuery(since, until) {
    const gte = b4a.from(`created_at:${this.padTimestamp(since)}:id:`, 'utf8');
    // Use a high-sentinel to include all keys under the prefix range
    const lte = b4a.from(`created_at:${this.padTimestamp(until)}:id:#`, 'utf8');
    return { gte, lte };
  }
  
  static constructKindRangeQuery(kind, since, until) {
    const paddedKind = this.padNumber(kind, 5);
    const gte = b4a.from(`kind:${paddedKind}:created_at:${this.padTimestamp(since)}:id:`, 'utf8');
    const lte = b4a.from(`kind:${paddedKind}:created_at:${this.padTimestamp(until)}:id:#`, 'utf8');
    return { gte, lte };
  }

  static constructAuthorRangeQuery(author, since, until) {
    const gte = b4a.from(`pubkey:${author}:created_at:${this.padTimestamp(since)}:id:`, 'utf8');
    const lte = b4a.from(`pubkey:${author}:created_at:${this.padTimestamp(until)}:id:#`, 'utf8');
    return { gte, lte };
  }

  static constructFilekeyRangeQuery({ filekey, drivekey, pubkey } = {}) {
    // To select all keys with a given prefix in Hyperbee, use an upper bound
    // that is the prefix plus a 0xFF byte (max byte) — not '#', which sorts
    // before digits/letters and inadvertently excludes valid keys.
    const MAX_BYTE = b4a.from([0xff]);

    if (filekey && drivekey && pubkey) {
      return {
        key: b4a.from(
          `filekey:${filekey}:drivekey:${drivekey}:pubkey:${pubkey}`,
          'utf8'
        )
      };
    }

    if (filekey && drivekey) {
      const prefix = b4a.from(
        `filekey:${filekey}:drivekey:${drivekey}:pubkey:`,
        'utf8'
      );
      const gte = prefix;
      const lte = b4a.concat([prefix, MAX_BYTE]);
      return { gte, lte };
    }

    if (filekey) {
      const prefix = b4a.from(`filekey:${filekey}:`, 'utf8');
      const gte = prefix;
      const lte = b4a.concat([prefix, MAX_BYTE]);
      return { gte, lte };
    }

    const prefix = b4a.from(`filekey:`, 'utf8');
    const gte = prefix;
    const lte = b4a.concat([prefix, MAX_BYTE]);
    return { gte, lte };
  }

  async executeFilekeyQuery(query) {
    if (query.key) {
      const node = await this.view.get(query.key);
      if (node && node.value) {
        try {
          return [JSON.parse(node.value.toString())];
        } catch (err) {
          logWithTimestamp('executeFilekeyQuery: Error parsing entry', err);
          return [];
        }
      }
      return [];
    }

    const results = [];
    for await (const entry of this.view.createReadStream(query)) {
      if (!entry || !entry.value) continue;
      try {
        results.push(JSON.parse(entry.value.toString()));
      } catch (err) {
        logWithTimestamp('executeFilekeyQuery: Error parsing entry', err);
      }
    }
    return results;
  }

  async queryFilekeyIndex(options = {}) {
    const query = this.constructor.constructFilekeyRangeQuery(options);
    const entries = await this.executeFilekeyQuery(query);
    const filekeyMap = new Map();

    for (const { filekey, drivekey, pubkey } of entries) {
      if (!filekeyMap.has(filekey)) filekeyMap.set(filekey, new Map());
      const drives = filekeyMap.get(filekey);
      drives.set(drivekey, pubkey);
    }

    // Debug: dump a small sample
    try {
      const sample = [];
      for (const [fh, dm] of filekeyMap.entries()) {
        sample.push({ fileHash: fh, drives: Array.from(dm.keys()) });
        if (sample.length >= 5) break;
      }
      logWithTimestamp(`queryFilekeyIndex: entries=${entries.length}, uniqueFilekeys=${filekeyMap.size}, sample=${JSON.stringify(sample)}`);
    } catch (_) {}

    return filekeyMap;
  }
  
  constructTagQueries(filter, since, until) {
    const tagGroups = [];

    for (const [key, values] of Object.entries(filter)) {
      if (key.startsWith('#') && key.length === 2) {
        const group = [];
        const tagName = key.slice(1);
        for (const tagValue of values) {
          const query = this.constructor.constructTagRangeQuery(
            tagName,
            tagValue,
            since,
            until
          );
          // logWithTimestamp(
          //   `constructTagQueries: Constructed query for tag ${tagName}=${tagValue}:`,
          //   query
          // );
          group.push(query);
        }
        tagGroups.push(group);
      }
    }

    logWithTimestamp(
      `constructTagQueries: Constructed ${tagGroups.reduce((a, g) => a + g.length, 0)} tag queries in ${tagGroups.length} groups`
    );
    return tagGroups;
  }

  static constructTagRangeQuery(tagName, tagValue, since, until) {
    const gte = b4a.from(
      `tagKey:${tagName}:tagValue:${tagValue}:created_at:${this.padTimestamp(since)}:id:`, 
      'utf8'
    );
    const lte = b4a.from(
      `tagKey:${tagName}:tagValue:${tagValue}:created_at:${this.padTimestamp(until)}:id:#`, 
      'utf8'
    );
    return { gte, lte };
  }


async executeQueries(queryGroups) {
    logWithTimestamp(`executeQueries: Starting execution of ${queryGroups.length} query groups`);

    if (!queryGroups || queryGroups.length === 0) {
        logWithTimestamp('executeQueries: No queries to execute');
        return [];
    }

    const groupResultSets = [];

    try {
        for (let i = 0; i < queryGroups.length; i++) {
            const group = queryGroups[i];
            logWithTimestamp(`executeQueries: Processing group ${i + 1}/${queryGroups.length}`);

            const unionIds = new Set();
            for (let j = 0; j < group.length; j++) {
                const query = group[j];
                logWithTimestamp(`executeQueries:  Query ${j + 1}/${group.length} in group ${i + 1}`);
                for await (const entry of this.view.createReadStream(query)) {
                    if (!entry || !entry.value) continue;
                    const eventId = entry.value; // direct event ID
                    unionIds.add(eventId);
                }
            }
            logWithTimestamp(`executeQueries: Group ${i + 1} produced ${unionIds.size} unique IDs`);
            groupResultSets.push(unionIds);
        }

        const commonIds = this.findCommonIds(groupResultSets);
        logWithTimestamp(`executeQueries: Found ${commonIds.size} common IDs across all groups`);

        const results = [];
        for (const id of commonIds) {
            try {
                const event = await this.getEvent(id);
                if (event) {
                    results.push(event);
                }
            } catch (error) {
                logWithTimestamp(`executeQueries: Error fetching event for ID ${id}:`, error.message);
            }
        }

        logWithTimestamp(`executeQueries: Successfully retrieved ${results.length} full events`);
        return results;

    } catch (error) {
        logWithTimestamp('executeQueries: Error during query execution:', error.message);
        throw error;
    }
}

findCommonIds(resultSets) {
    logWithTimestamp(`findCommonIds: Starting to process ${resultSets.length} result sets`);

    if (!resultSets || resultSets.length === 0) {
        logWithTimestamp('findCommonIds: No result sets to process');
        return new Set();
    }

    const commonIds = new Set(resultSets[0]);
    if (commonIds.size === 0) {
        logWithTimestamp('findCommonIds: No IDs in first result set');
        return commonIds;
    }

    for (let i = 1; i < resultSets.length; i++) {
        if (commonIds.size === 0) {
            logWithTimestamp('findCommonIds: No common IDs remain, exiting early');
            return commonIds;
        }

        const currentSet = resultSets[i];
        logWithTimestamp(`findCommonIds: Processing result set ${i + 1}, size: ${currentSet.size}`);

        const initialSize = commonIds.size;
        for (const id of Array.from(commonIds)) {
            if (!currentSet.has(id)) {
                commonIds.delete(id);
            }
        }
        logWithTimestamp(`findCommonIds: After intersection with set ${i + 1}: reduced from ${initialSize} to ${commonIds.size} common IDs`);
    }

    logWithTimestamp(`findCommonIds: Final common ID count: ${commonIds.size}`);
    return commonIds;
}

async handleSubscription(connectionKey) {
    logWithTimestamp(`handleSubscription: Handling subscription for connection: ${connectionKey}`);
    const activeSubscriptions = await this.getSubscriptions(connectionKey);
    if (!activeSubscriptions) {
        logWithTimestamp(`handleSubscription: No active subscriptions for connection: ${connectionKey}`);
        return [[], null];
    }

    const subscriptionCount = activeSubscriptions?.subscriptions
        ? Object.keys(activeSubscriptions.subscriptions).length
        : 0;
    logWithTimestamp('handleSubscription: Subscription snapshot', {
        connectionKey,
        subscriptionCount,
        viewVersion: this.view?.version ?? null,
        relayVersion: this.version ?? null,
        coreLength: this.core?.length ?? null
    });

    // logWithTimestamp(`handleSubscription: Active subscriptions:`, JSON.stringify(activeSubscriptions, null, 2));
    const eventsForClient = [];
    let activeSubscriptionsUpdated = JSON.parse(JSON.stringify(activeSubscriptions));
    let removedEphemeralCount = 0;

    for (const [subscriptionId, subscription] of Object.entries(activeSubscriptions.subscriptions)) {
        const last_returned_event_timestamp = subscription.last_returned_event_timestamp;
        logWithTimestamp(`handleSubscription: Processing subscription ${subscriptionId} with last timestamp: ${last_returned_event_timestamp}`);
        if (activeSubscriptionsUpdated.subscriptions?.[subscriptionId]) {
            activeSubscriptionsUpdated.subscriptions[subscriptionId] = this._touchSubscriptionEntry(
                activeSubscriptionsUpdated.subscriptions[subscriptionId]
            );
        }
        
        for (const filter of subscription.filters) {
            logWithTimestamp(`handleSubscription: Processing filter with last_returned_event_timestamp:`, last_returned_event_timestamp);
            
            let events;
            if (filter.ids && filter.ids.length > 0) {
                events = await this.executeIdQueries(filter, last_returned_event_timestamp);
            } else {
                events = await this.queryEvents(filter, last_returned_event_timestamp);
            }

            logWithTimestamp(`handleSubscription: Filter results for ${subscriptionId}`, {
                eventCount: events.length,
                newest: events[0]?.created_at ?? null,
                oldest: events[events.length - 1]?.created_at ?? null
            });

            // Sort events by created_at in descending order
            if (events.length > 0) {
                events.sort((a, b) => b.created_at - a.created_at);
                const new_last_returned_event_timestamp = events[0].created_at;
                
                logWithTimestamp(`handleSubscription: Updating last_returned_event_timestamp for subscription ${subscriptionId}:`, {
                    previous: last_returned_event_timestamp,
                    new: new_last_returned_event_timestamp
                });
                
                activeSubscriptionsUpdated.subscriptions[subscriptionId].last_returned_event_timestamp = 
                    new_last_returned_event_timestamp;
                
                for (const event of events) {
                    eventsForClient.push(['EVENT', subscriptionId, event]);
                }
            }
        }
        eventsForClient.push(['EOSE', subscriptionId]);
        // One-shot fetch subscriptions must not accumulate in persisted snapshots.
        // They are expected to complete after a single replay cycle.
        if (this._isEphemeralSubscriptionId(subscriptionId)) {
            delete activeSubscriptionsUpdated.subscriptions[subscriptionId];
            removedEphemeralCount += 1;
        }
    }

    if (removedEphemeralCount > 0) {
        logWithTimestamp('handleSubscription: pruned ephemeral subscriptions after replay', {
            connectionKey,
            removedEphemeralCount,
            remainingSubscriptions: Object.keys(activeSubscriptionsUpdated.subscriptions || {}).length
        });
    }
    
    logWithTimestamp(`handleSubscription: Total events and EOSE messages for client:`, eventsForClient.length);
    return [eventsForClient, activeSubscriptionsUpdated];
}

  ///////////////////////////////////////////////////////////////////////////////////////////////////////
  ///////////////////////////////////////////////////////////////////////////////////////////////////////

  ///////////////////////////////////////////////////////////////////////////////////////////////////////////////  
  // PROCESSES TO <GET> <PUBLISH> AND <UPDATE> SUBSCRIPTIONS TO HYPERBEE: ///////////////////////////////////////
  ///////////////////////////////////////////////////////////////////////////////////////////////////////////////

  async getSubscriptions(connectionKey) {
    logWithTimestamp(`getSubscriptions: Attempting to retrieve subscriptions for connectionKey: ${connectionKey}`);
    const key = b4a.from(connectionKey, 'hex');
    logWithTimestamp(`getSubscriptions: Converted key: ${key.toString('hex')}`);
    logWithTimestamp('getSubscriptions: View state', {
      viewVersion: this.view?.version ?? null,
      relayVersion: this.version ?? null,
      coreLength: this.core?.length ?? null
    });
    const subscriptionData = await this.view.get(key);
    if (subscriptionData) {
      logWithTimestamp(`getSubscriptions: Subscriptions found for connection ${connectionKey}: ${JSON.stringify(subscriptionData)}`);
      try {
        return typeof subscriptionData.value === 'string' ? JSON.parse(subscriptionData.value) : subscriptionData.value;
      } catch (error) {
        logWithTimestamp('getSubscriptions: Error parsing subscriptions:', error.message);
        return null;
      }
    } else {
      logWithTimestamp(`getSubscriptions: No subscriptions found for connection: ${connectionKey}`);
      return null;
    }
  }


async publishSubscription(connectionKey, reqMessage, activeSubscriptions = null, clientId = null) {
    // logWithTimestamp('publishSubscription: Attempting to publish subscription:', JSON.stringify(reqMessage, null, 2));

    return this._queueSubscriptionWrite(connectionKey, async () => {
      if (!this.writable) {
        const subscriptionId = Array.isArray(reqMessage) ? reqMessage[1] : null;
        this._enqueuePendingSubscriptionWrite({
          connectionKey,
          reqMessage,
          clientId,
          subscriptionId,
          queuedAt: Date.now()
        });
        logWithTimestamp('publishSubscription: Not writable; queued subscription write', {
          connectionKey,
          subscriptionId,
          pending: this.pendingSubscriptionWrites.length
        });
        this._schedulePendingSubscriptionFlush('not-writable');
        return ['NOTICE', 'Relay initializing; subscription queued'];
      }

      const [, subscriptionId, ...filters] = reqMessage;

      if (!connectionKey || !subscriptionId || filters.length === 0) {
        logWithTimestamp('publishSubscription: Error - Invalid subscription parameters');
        return ['NOTICE', 'Error: Invalid subscription parameters'];
      }

      const isValid = this.validateFilters(filters);
      logWithTimestamp('publishSubscription: Filters validation result:', isValid);

      if (!isValid) {
        logWithTimestamp('publishSubscription: Invalid filters');
        return ['NOTICE', 'Error: Invalid filters'];
      }

      const key = b4a.from(connectionKey, 'hex');
      const storedSnapshot = await this.getSubscriptions(connectionKey);
      const mergedSnapshot = this._mergeSubscriptionSnapshots(storedSnapshot, activeSubscriptions);
      const existingSubscriptions = mergedSnapshot?.subscriptions || {};
      const existingCount = Object.keys(existingSubscriptions).length;
      const subscriptions = { ...existingSubscriptions };
      const nowMs = Date.now();

      // Create or update subscription with the new structure
      subscriptions[subscriptionId] = this._touchSubscriptionEntry({
        ...(subscriptions[subscriptionId] || {}),
        last_returned_event_timestamp: undefined,
        filters: filters
      }, nowMs);

      const {
        subscriptions: prunedSubscriptions,
        removedTimelineIds,
        keptTimelineIds
      } = this._pruneTimelineSubscriptions(subscriptions, {
        preferredSubscriptionId: subscriptionId
      });
      if (removedTimelineIds.length > 0) {
        logWithTimestamp('publishSubscription: pruned timeline subscriptions', {
          connectionKey,
          preferredSubscriptionId: subscriptionId,
          removedCount: removedTimelineIds.length,
          keptCount: keptTimelineIds.length
        });
      }

      const subscriptionObject = {
        ...mergedSnapshot,
        connection: connectionKey,
        subscriptions: prunedSubscriptions
      };

      logWithTimestamp('publishSubscription: Subscription write requested', {
        connectionKey,
        keyHex: key.toString('hex'),
        filtersCount: filters.length,
        existingCount,
        viewVersion: this.view?.version ?? null
      });

      await this.append({
        type: 'subscriptions',
        subscriptions: JSON.stringify(subscriptionObject)
      });

      const stored = await this.view.get(key);
      if (stored) {
        let storedCount = null;
        try {
          const parsed = typeof stored.value === 'string' ? JSON.parse(stored.value) : stored.value;
          storedCount = parsed?.subscriptions ? Object.keys(parsed.subscriptions).length : 0;
        } catch (error) {
          logWithTimestamp('publishSubscription: Error parsing stored subscription snapshot', error.message);
        }
        logWithTimestamp('publishSubscription: Stored subscription snapshot', {
          connectionKey,
          storedCount,
          storedBytes: typeof stored.value === 'string' ? stored.value.length : stored.value?.length ?? null,
          viewVersion: this.view?.version ?? null
        });
      } else {
        logWithTimestamp('publishSubscription: Storage verification failed (no record)', {
          connectionKey,
          viewVersion: this.view?.version ?? null
        });
      }

      logWithTimestamp(`publishSubscription: Published subscription for connection: ${connectionKey}, subscriptionId: ${subscriptionId}`);
      if (clientId) {
        const persistentSubscriptions = this._filterEphemeralSubscriptions(prunedSubscriptions);
        const clientSnapshot = {
          clientId,
          connection: connectionKey,
          subscriptions: persistentSubscriptions
        };
        try {
          await this.updateClientSubscriptions(clientId, clientSnapshot);
          logWithTimestamp('publishSubscription: Client subscription snapshot stored', {
            clientId,
            connectionKey,
            subscriptionCount: Object.keys(persistentSubscriptions || {}).length,
            viewVersion: this.view?.version ?? null
          });
        } catch (error) {
          logWithTimestamp('publishSubscription: Failed to store client subscription snapshot', {
            clientId,
            connectionKey,
            error: error?.message || error
          });
        }
      }
      if (this._isEphemeralSubscriptionId(subscriptionId)) {
        // One-shot fetch subscriptions are expected to be high volume.
        // Suppress success NOTICE chatter to keep clients responsive.
        return null;
      }

      return ['NOTICE', `Subscription ${subscriptionId} created/updated successfully`];
    });
  }

 async updateSubscriptions(connectionKey, activeSubscriptionsUpdated) {
    // logWithTimestamp('updateSubscriptions: Updating subscriptions:', JSON.stringify(activeSubscriptionsUpdated, null, 2));
    
    return this._queueSubscriptionWrite(connectionKey, async () => {
      if (!this.writable) {
        logWithTimestamp('updateSubscriptions: Error - Not writable');
        throw new Error('Not writable');
      }

      const storedSnapshot = await this.getSubscriptions(connectionKey);
      const mergedSnapshot = this._mergeSubscriptionSnapshots(storedSnapshot, activeSubscriptionsUpdated);
      const {
        subscriptions: prunedSubscriptions,
        removedTimelineIds
      } = this._pruneTimelineSubscriptions(mergedSnapshot?.subscriptions || {});
      mergedSnapshot.connection = connectionKey;
      mergedSnapshot.subscriptions = prunedSubscriptions;
      if (removedTimelineIds.length > 0) {
        logWithTimestamp('updateSubscriptions: pruned timeline subscriptions', {
          connectionKey,
          removedCount: removedTimelineIds.length
        });
      }

      await this.append({
        type: 'subscriptions',
        subscriptions: JSON.stringify(mergedSnapshot)
      });

      const key = b4a.from(connectionKey, 'hex');
      const stored = await this.view.get(key);
      if (stored) {
        let storedCount = null;
        try {
          const parsed = typeof stored.value === 'string' ? JSON.parse(stored.value) : stored.value;
          storedCount = parsed?.subscriptions ? Object.keys(parsed.subscriptions).length : 0;
        } catch (error) {
          logWithTimestamp('updateSubscriptions: Error parsing stored subscription snapshot', error.message);
        }
        logWithTimestamp('updateSubscriptions: Stored subscription snapshot', {
          connectionKey,
          storedCount,
          storedBytes: typeof stored.value === 'string' ? stored.value.length : stored.value?.length ?? null,
          viewVersion: this.view?.version ?? null
        });
      } else {
        logWithTimestamp('updateSubscriptions: Storage verification failed (no record)', {
          connectionKey,
          viewVersion: this.view?.version ?? null
        });
      }

      logWithTimestamp(`updateSubscriptions: Updated subscriptions for connection: ${connectionKey}`);
      return ['NOTICE', 'Subscriptions updated successfully'];
    });
  }

  async getClientSubscriptions(clientId) {
    logWithTimestamp(`getClientSubscriptions: Attempting to retrieve subscriptions for clientId: ${clientId}`);
    const key = b4a.from(`client:${clientId}`, 'utf8');
    const subscriptionData = await this.view.get(key);
    if (subscriptionData) {
      logWithTimestamp(`getClientSubscriptions: Subscriptions found for clientId ${clientId}`);
      try {
        return typeof subscriptionData.value === 'string' ? JSON.parse(subscriptionData.value) : subscriptionData.value;
      } catch (error) {
        logWithTimestamp('getClientSubscriptions: Error parsing subscriptions:', error.message);
        return null;
      }
    }
    logWithTimestamp(`getClientSubscriptions: No subscriptions found for clientId: ${clientId}`);
    return null;
  }

  async updateClientSubscriptions(clientId, subscriptionObject) {
    return this._queueSubscriptionWrite(`client:${clientId}`, async () => {
      if (!this.writable) {
        logWithTimestamp('updateClientSubscriptions: Error - Not writable');
        throw new Error('Not writable');
      }

      const existingSnapshot = await this.getClientSubscriptions(clientId);
      const mergedSnapshot = this._mergeSubscriptionSnapshots(existingSnapshot, subscriptionObject);
      const filteredSubscriptions = this._filterEphemeralSubscriptions(mergedSnapshot?.subscriptions || {});
      const {
        subscriptions: prunedSubscriptions,
        removedTimelineIds
      } = this._pruneTimelineSubscriptions(filteredSubscriptions);
      if (removedTimelineIds.length > 0) {
        logWithTimestamp('updateClientSubscriptions: pruned timeline subscriptions', {
          clientId,
          removedCount: removedTimelineIds.length
        });
      }

      const safeSnapshot = {
        clientId,
        connection: mergedSnapshot?.connection ?? null,
        subscriptions: prunedSubscriptions
      };

      await this.append({
        type: 'client-subscriptions',
        clientId,
        subscriptions: JSON.stringify(safeSnapshot)
      });

      const key = b4a.from(`client:${clientId}`, 'utf8');
      const stored = await this.view.get(key);
      if (stored) {
        let storedCount = null;
        try {
          const parsed = typeof stored.value === 'string' ? JSON.parse(stored.value) : stored.value;
          storedCount = parsed?.subscriptions ? Object.keys(parsed.subscriptions).length : 0;
        } catch (error) {
          logWithTimestamp('updateClientSubscriptions: Error parsing stored snapshot', error.message);
        }
        logWithTimestamp('updateClientSubscriptions: Stored client snapshot', {
          clientId,
          storedCount,
          viewVersion: this.view?.version ?? null
        });
      } else {
        logWithTimestamp('updateClientSubscriptions: Storage verification failed (no record)', {
          clientId,
          viewVersion: this.view?.version ?? null
        });
      }
    });
  }

  // helper function for publishSubscription() to verify that the structure and attributes of REQ 'filters' object 
  // conforms to NIP-01 specifications before appending subscription entry to hyperbee log.
  validateFilters(filters) {
    logWithTimestamp('validateFilters: Validating filters:', JSON.stringify(filters, null, 2));
    
    for (const filter of filters) {
      if (typeof filter !== 'object' || Object.keys(filter).length === 0) {
        logWithTimestamp('validateFilters: Invalid filter object');
        return false;
      }
      
      const validKeys = ['ids', 'authors', 'kinds', 'since', 'until', 'limit'];
      const hasValidKey = validKeys.some(key => filter.hasOwnProperty(key));
      
      if (!hasValidKey) {
        const tagKeys = Object.keys(filter).filter(key => /^#[a-zA-Z]$/.test(key));
        if (tagKeys.length === 0) {
          logWithTimestamp('validateFilters: Filter does not contain any valid keys');
          return false;
        }
      }
    }
    
    logWithTimestamp('validateFilters: All filters are valid');
    return true;
  }

  ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
  ///////////////////////////////////////////////////////////////////////////////////////////////////////////////

  ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
  // CORE PROCESS TO MANAGE INBOUND EVENT + REQ + CLOSE MESSAGES FROM NOSTR CLIENTS AND PUBLISH TO HYPERBEE: //// 
  ///////////////////////////////////////////////////////////////////////////////////////////////////////////////

  // Update handleMessage to work with the new subscription structure
async handleMessage(message, sendResponse, connectionKey, clientId = null) {
    // logWithTimestamp(`handleMessage: Received message:`, JSON.stringify(message, null, 2));
    try {
      const [type, ...params] = message;
  
      switch (type) {
        case 'EVENT':
          logWithTimestamp(`handleMessage: Processing EVENT message for client connection: ${connectionKey}`);
          const event = params[0];
          try {
            const publishResult = await this.publishEvent(event);
            logWithTimestamp(`handleMessage: EVENT publish result:`, JSON.stringify(publishResult, null, 2));
            sendResponse(publishResult);
          } catch (error) {
            logWithTimestamp(`handleMessage: Error publishing event: ${error.message}`);
            sendResponse(["ERROR", event.id, false, `Error publishing event: ${error.message}`]);
          }
          break;
  
        case 'REQ':
          logWithTimestamp(`handleMessage: Processing REQ message for client connection: ${connectionKey}`);
          const activeSubscriptions = await this.getSubscriptions(connectionKey);
          const publishSubResult = await this.publishSubscription(connectionKey, message, activeSubscriptions, clientId);
          logWithTimestamp(`handleMessage: REQ publish result:`, JSON.stringify(publishSubResult, null, 2));
          if (publishSubResult) {
            sendResponse(publishSubResult);
          }
          break;
  
        case 'CLOSE':
          logWithTimestamp(`handleMessage: Processing CLOSE message for client connection: ${connectionKey}`);
          const closeSubscriptionId = params[0];
          await this.unsubscribe(connectionKey, closeSubscriptionId, clientId);
          sendResponse(['NOTICE', 'Subscription closed']);
          logWithTimestamp(`handleMessage: Closed subscription ${closeSubscriptionId}`);
          break;
  
        default:
          logWithTimestamp(`handleMessage: Unknown message type: ${type}`);
          throw new Error('Unknown message type');
      }
    } catch (error) {
      logWithTimestamp('handleMessage: Error handling message:', error);
      sendResponse(['NOTICE', `Error: ${error.message}`]);
    }
  }

  // Add the missing unsubscribe method
  async unsubscribe(connectionKey, subscriptionId, clientId = null) {
    logWithTimestamp(`unsubscribe: Removing subscription ${subscriptionId} for connection ${connectionKey}`);
    await this._queueSubscriptionWrite(connectionKey, async () => {
      const activeSubscriptions = await this.getSubscriptions(connectionKey);

      if (!activeSubscriptions || !activeSubscriptions.subscriptions[subscriptionId]) {
        logWithTimestamp(`unsubscribe: Subscription ${subscriptionId} not found`);
        return;
      }

      delete activeSubscriptions.subscriptions[subscriptionId];
      const {
        subscriptions: prunedSubscriptions,
        removedTimelineIds
      } = this._pruneTimelineSubscriptions(activeSubscriptions.subscriptions || {});
      activeSubscriptions.subscriptions = prunedSubscriptions;

      // Update the subscriptions in the database
      await this.append({
        type: 'subscriptions',
        subscriptions: JSON.stringify(activeSubscriptions)
      });
      if (removedTimelineIds.length > 0) {
        logWithTimestamp('unsubscribe: pruned timeline subscriptions in connection snapshot', {
          connectionKey,
          removedCount: removedTimelineIds.length
        });
      }

      if (clientId) {
        try {
          const clientSubscriptions = await this.getClientSubscriptions(clientId);
          if (clientSubscriptions?.subscriptions?.[subscriptionId]) {
            delete clientSubscriptions.subscriptions[subscriptionId];
            const filteredClientSubscriptions = this._filterEphemeralSubscriptions(
              clientSubscriptions.subscriptions
            );
            const {
              subscriptions: prunedClientSubscriptions,
              removedTimelineIds
            } = this._pruneTimelineSubscriptions(filteredClientSubscriptions);
            const safeClientSnapshot = {
              ...clientSubscriptions,
              clientId,
              connection: connectionKey,
              subscriptions: prunedClientSubscriptions
            };
            await this.append({
              type: 'client-subscriptions',
              clientId,
              subscriptions: JSON.stringify(safeClientSnapshot)
            });
            if (removedTimelineIds.length > 0) {
              logWithTimestamp('unsubscribe: pruned timeline subscriptions in client snapshot', {
                clientId,
                removedCount: removedTimelineIds.length
              });
            }
          }
        } catch (error) {
          logWithTimestamp('unsubscribe: Failed to update client snapshot', {
            clientId,
            subscriptionId,
            error: error?.message || error
          });
        }
      }

      logWithTimestamp(`unsubscribe: Successfully removed subscription ${subscriptionId}`);
    });
  }
}
