// ./relay-worker/hyperpipe-relay-profile-manager.mjs
// Worker-compatible version of the relay profile manager

import { promises as fs } from 'node:fs';
import { join, dirname } from 'node:path';
import process from 'node:process';

// Constants
const RELAY_PROFILES_FILE = 'relay-profiles.json';

// Simple mutex to serialize file access
let profileLock = Promise.resolve();
async function withProfileLock(fn) {
    let release;
    const wait = profileLock;
    profileLock = new Promise(res => {
        release = res;
    });
    await wait;
    try {
        return await fn();
    } finally {
        release();
    }
}

const DEFAULT_STORAGE_BASE = process.env.STORAGE_DIR || join(process.cwd(), 'data');

// Get storage directory from runtime config or use default
function getStorageDir(userKey = null) {
    const baseDir = global.userConfig?.storage || DEFAULT_STORAGE_BASE;
    
    // If we have a userKey from config, use user-specific directory
    if (userKey || global.userConfig?.userKey) {
        const key = userKey || global.userConfig.userKey;
        const normalizedBase = baseDir.replace(/\\+/g, '/');
        const suffix = `/users/${key}`;
        if (normalizedBase.endsWith(suffix)) {
            return baseDir;
        }
        return join(baseDir, 'users', key);
    }
    
    // Fallback to base directory (but log a warning)
    console.warn('[ProfileManager] No user key available, using base storage directory');
    return baseDir;
}

// Get full path to relay profiles file
function getRelayProfilesPath(userKey = null) {
    return join(getStorageDir(userKey), RELAY_PROFILES_FILE);
}

// Ensure a relay profile has the expected schema
function ensureProfileSchema(profile) {
    if (!profile) return null;
    if (profile.admin_pubkey === undefined) {
        profile.admin_pubkey = null;
    }
    if (!Array.isArray(profile.members)) {
        profile.members = profile.admin_pubkey ? [profile.admin_pubkey] : [];
    } else if (profile.admin_pubkey && !profile.members.includes(profile.admin_pubkey)) {
        profile.members.unshift(profile.admin_pubkey);
    }
    if (!Array.isArray(profile.member_adds)) {
        profile.member_adds = [];
    }
    if (!Array.isArray(profile.member_removes)) {
        profile.member_removes = [];
    }
    // Add auth-related fields
    if (!profile.auth_tokens) {
        profile.auth_tokens = {}; // Map of pubkey -> token
    }
    
    if (!profile.auth_config) {
        profile.auth_config = {
            requiresAuth: false,
            tokenProtected: false,
            authorizedUsers: [], // Array of { pubkey, token }
            auth_adds: [],
            auth_removes: []
        };
    } else {
        if (!Array.isArray(profile.auth_config.auth_adds)) {
            profile.auth_config.auth_adds = [];
        }
        if (!Array.isArray(profile.auth_config.auth_removes)) {
            profile.auth_config.auth_removes = [];
        }
    }

    // Migrate legacy root-level auth_adds/auth_removes
    if (Array.isArray(profile.auth_adds)) {
        profile.auth_config.auth_adds.push(...profile.auth_adds);
        delete profile.auth_adds;
    }
    if (Array.isArray(profile.auth_removes)) {
        profile.auth_config.auth_removes.push(...profile.auth_removes);
        delete profile.auth_removes;
    }

    // NEW: ensure visibility and join flags exist
    if (profile.isPublic === undefined) {
        profile.isPublic = false;
    }
    if (profile.isOpen === undefined) {
        profile.isOpen = false;
    }

    return profile;
}

// NEW FUNCTION: Calculate the final list of authorized users
export function calculateAuthorizedUsers(auth_adds = [], auth_removes = []) {
    const addMap = new Map(); // pubkey -> { token, ts }
    for (const auth of auth_adds) {
        addMap.set(auth.pubkey, auth);
    }

    const removeMap = new Map(); // pubkey -> ts
    for (const rem of auth_removes) {
        removeMap.set(rem.pubkey, rem.ts);
    }

    const finalAuthorizedUsers = [];
    for (const [pubkey, auth] of addMap.entries()) {
        const removeTs = removeMap.get(pubkey);
        // An authorization is valid if it hasn't been removed, or if it was re-added after removal
        if (!removeTs || auth.ts > removeTs) {
            finalAuthorizedUsers.push({ pubkey, token: auth.token });
        }
    }
    return finalAuthorizedUsers;
}

// Add a function to update auth token for a user
export async function updateRelayAuthToken(identifier, pubkey, token) {
    try {
        const profile = await withProfileLock(async () => {
            let p = await getRelayProfileByKeyUnlocked(identifier);
            if (!p) {
                p = await getRelayProfileByPublicIdentifierUnlocked(identifier);
            }
            if (!p) return null;

            // Ensure schema
            p = ensureProfileSchema(p);

            // NEW: Update auth_adds array
            const existingAuthAddIndex = p.auth_config.auth_adds.findIndex(a => a.pubkey === pubkey);
            const newAuthEntry = { pubkey, token, ts: Date.now() };

            if (existingAuthAddIndex !== -1) {
                const existingAuth = p.auth_config.auth_adds[existingAuthAddIndex];
                existingAuth.token = token;
                existingAuth.ts = newAuthEntry.ts;
            } else {
                p.auth_config.auth_adds.push(newAuthEntry);
            }

            // NEW: Remove from auth_removes if it exists there (re-adding a removed user)
            p.auth_config.auth_removes = p.auth_config.auth_removes.filter(r => r.pubkey !== pubkey);

            // Update auth config
            p.auth_config.requiresAuth = true;
            p.auth_config.tokenProtected = true;

            // Recalculate authorizedUsers based on the updated auth_adds and auth_removes
            p.auth_config.authorizedUsers = calculateAuthorizedUsers(p.auth_config.auth_adds, p.auth_config.auth_removes);

            p.updated_at = new Date().toISOString();
            const saved = await _saveRelayProfile(p);
            return saved ? p : null;
        });

        if (!profile) return null;

        if (profile) {
            try {
                const { getRelayAuthStore } = await import('./relay-auth-store.mjs');
                const store = getRelayAuthStore();
                store.addAuth(profile.relay_key, pubkey, token);
                if (profile.public_identifier) {
                    store.addAuth(profile.public_identifier, pubkey, token);
                }
            } catch (err) {
                console.error('[ProfileManager] Failed to update auth store:', err);
            }
        }

        return profile;
    } catch (error) {
        console.error(`[ProfileManager] Error updating auth token for ${identifier}:`, error);
        return null;
    }
}

// NEW FUNCTION: Remove authorization for a user
export async function removeRelayAuth(identifier, pubkey) {
    let profile = await getRelayProfileByKey(identifier);
    if (!profile) {
        profile = await getRelayProfileByPublicIdentifier(identifier);
    }
    if (!profile) return null;

    profile = ensureProfileSchema(profile);

    // Add to auth_removes
    const existingAuthRemoveIndex = profile.auth_config.auth_removes.findIndex(r => r.pubkey === pubkey);
    const removeTimestamp = Date.now();
    if (existingAuthRemoveIndex !== -1) {
        profile.auth_config.auth_removes[existingAuthRemoveIndex].ts = removeTimestamp;
    } else {
        profile.auth_config.auth_removes.push({ pubkey, ts: removeTimestamp });
    }

    // Remove from auth_adds (if it exists there)
    profile.auth_config.auth_adds = profile.auth_config.auth_adds.filter(a => a.pubkey !== pubkey);

    profile.updated_at = new Date().toISOString();

    // Recalculate authorizedUsers
    profile.auth_config.authorizedUsers = calculateAuthorizedUsers(profile.auth_config.auth_adds, profile.auth_config.auth_removes);

    const saved = await saveRelayProfile(profile);
    if (saved) {
        try {
            const { getRelayAuthStore } = await import('./relay-auth-store.mjs');
            const store = getRelayAuthStore();
            store.removeAuth(profile.relay_key, pubkey);
            if (profile.public_identifier) {
                store.removeAuth(profile.public_identifier, pubkey);
            }
        } catch (err) {
            console.error('[ProfileManager] Failed to update auth store:', err);
        }
    }
    return saved ? profile : null;
}

/**
 * Initialize the relay profiles storage file if it doesn't exist
 * @returns {Promise<void>}
 */
export async function initRelayProfilesStorage(userKey = null) {
    try {
        const profilesPath = getRelayProfilesPath(userKey);
        
        // Ensure directory exists
        const dir = dirname(profilesPath);
        await fs.mkdir(dir, { recursive: true });
        
        // Check if the file exists
        try {
            await fs.access(profilesPath);
            // File exists, no need to create
        } catch {
            // File doesn't exist, create it with an empty array
            const tmp = profilesPath + '.tmp';
            await fs.writeFile(tmp, JSON.stringify({ relays: [] }, null, 2));
            await fs.rename(tmp, profilesPath);
            console.log(`[ProfileManager] Created relay profiles storage file at ${profilesPath}`);
        }
    } catch (error) {
        console.error(`[ProfileManager] Error initializing relay profiles storage: ${error.message}`);
        throw error;
    }
}

/**
 * Load all relay profiles from the storage file
 * @returns {Promise<Array>} - Array of relay profiles
 */
// Internal helper that loads all profiles without acquiring the mutex. This
// allows functions already holding the lock to read the profiles without
// deadlocking.
async function _getAllRelayProfiles(userKey = null) {
    try {
        await initRelayProfilesStorage(userKey);

        const profilesPath = getRelayProfilesPath(userKey);

        const data = await fs.readFile(profilesPath, 'utf8');
        let profiles;
        try {
            profiles = JSON.parse(data);
        } catch (parseErr) {
            console.error(`[ProfileManager] Error parsing relay profiles: ${parseErr.message}`);
            const tmp = profilesPath + '.tmp';
            await fs.writeFile(tmp, JSON.stringify({ relays: [] }, null, 2));
            await fs.rename(tmp, profilesPath);
            return [];
        }
        const relays = Array.isArray(profiles.relays) ? profiles.relays : [];
        return relays.map(p => ensureProfileSchema(p));
    } catch (error) {
        console.error(`[ProfileManager] Error loading relay profiles: ${error.message}`);
        return [];
    }
}

export async function getAllRelayProfiles(userKey = null) {
    return withProfileLock(() => _getAllRelayProfiles(userKey));
}

// Internal unlocked helpers used when a caller already holds the profile lock
async function getRelayProfileByKeyUnlocked(relayKey) {
    const profiles = await _getAllRelayProfiles();
    const profile = profiles.find(p => p.relay_key === relayKey) || null;
    return ensureProfileSchema(profile);
}

async function getRelayProfileByPublicIdentifierUnlocked(identifier) {
    const profiles = await _getAllRelayProfiles();
    const profile = profiles.find(p => p.public_identifier === identifier) || null;
    return ensureProfileSchema(profile);
}

/**
 * Get a relay profile by its key
 * @param {string} relayKey - The relay key to look for
 * @returns {Promise<Object|null>} - The relay profile or null if not found
 */
export async function getRelayProfileByKey(relayKey) {
    try {
        const profiles = await getAllRelayProfiles();
        const profile = profiles.find(profile => profile.relay_key === relayKey) || null;
        return ensureProfileSchema(profile);
    } catch (error) {
        console.error(`[ProfileManager] Error getting relay profile for key ${relayKey}: ${error.message}`);
        return null;
    }
}

/**
 * Get a relay profile by its public identifier
 * @param {string} publicIdentifier - Public identifier string
 * @returns {Promise<Object|null>} - The relay profile or null if not found
 */
export async function getRelayProfileByPublicIdentifier(publicIdentifier) {
    try {
        const profiles = await getAllRelayProfiles();
        const profile = profiles.find(p => p.public_identifier === publicIdentifier) || null;
        return ensureProfileSchema(profile);
    } catch (error) {
        console.error(`[ProfileManager] Error getting relay profile for identifier ${publicIdentifier}: ${error.message}`);
        return null;
    }
}

/**
 * Add or update a relay profile in the storage file
 * @param {Object} relayProfile - The relay profile to add or update
 * @returns {Promise<boolean>} - True if successful, false otherwise
 */
export async function saveRelayProfile(relayProfile) {
    return withProfileLock(() => _saveRelayProfile(relayProfile));
}

// Internal version of saveRelayProfile that assumes the caller holds the lock
async function _saveRelayProfile(relayProfile) {
    try {
        if (!relayProfile || !relayProfile.relay_key) {
            console.error('[ProfileManager] Invalid relay profile data:', relayProfile);
            throw new Error('Invalid relay profile data');
        }

        // Ensure schema fields exist
        relayProfile = ensureProfileSchema(relayProfile);

        // NEW: Ensure `authorizedUsers` is derived from `auth_adds` and `auth_removes` before saving
        if (relayProfile.auth_config) {
            relayProfile.auth_config.authorizedUsers = calculateAuthorizedUsers(
                relayProfile.auth_config.auth_adds,
                relayProfile.auth_config.auth_removes
            );
        }
        
        console.log(`[ProfileManager] Saving relay profile for ${relayProfile.relay_key}:`, {
            name: relayProfile.name,
            auto_connect: relayProfile.auto_connect,
            updated_at: relayProfile.updated_at
        });
        
        // Ensure auto_connect is set (default to true if not specified)
        if (relayProfile.auto_connect === undefined) {
            relayProfile.auto_connect = true;
            console.log(`[ProfileManager] Auto-connect not specified, defaulting to true for ${relayProfile.relay_key}`);
        }
        
        // Load existing profiles
        let profiles = await _getAllRelayProfiles();
        console.log(`[ProfileManager] Loaded ${profiles.length} existing profiles`);
        
        // Check if profile already exists
        const existingIndex = profiles.findIndex(p => p.relay_key === relayProfile.relay_key);
        
        if (existingIndex >= 0) {
            // Update existing profile, preserving auto_connect setting if not explicitly changed
            if (relayProfile.auto_connect === undefined) {
                relayProfile.auto_connect = profiles[existingIndex].auto_connect !== false;
                console.log(`[ProfileManager] Preserving existing auto_connect value: ${relayProfile.auto_connect}`);
            }
            
            console.log(`[ProfileManager] Updating existing profile at index ${existingIndex} for ${relayProfile.relay_key}`);
            let mergedProfile = { ...profiles[existingIndex], ...relayProfile };
            if (profiles[existingIndex].auth_config && relayProfile.auth_config) {
                mergedProfile.auth_config = {
                    ...profiles[existingIndex].auth_config,
                    ...relayProfile.auth_config
                };
            }
            if (profiles[existingIndex].auth_tokens && relayProfile.auth_tokens) {
                mergedProfile.auth_tokens = {
                    ...profiles[existingIndex].auth_tokens,
                    ...relayProfile.auth_tokens
                };
            }
            profiles[existingIndex] = mergedProfile;
        } else {
            // Add new profile
            console.log(`[ProfileManager] Adding new profile for ${relayProfile.relay_key}`);
            profiles.push(relayProfile);
        }
        
        // Write updated profiles back to file
        const profilesPath = getRelayProfilesPath();
        console.log(`[ProfileManager] Writing ${profiles.length} profiles to ${profilesPath}`);
        const sanitized = profiles.map(p => ensureProfileSchema(p));
        const tmpPath = profilesPath + '.tmp';
        await fs.writeFile(tmpPath, JSON.stringify({ relays: sanitized }, null, 2));
        await fs.rename(tmpPath, profilesPath);
        console.log(`[ProfileManager] Successfully saved relay profile for ${relayProfile.relay_key}`);
        
        // Update in-memory relay members map in adapter
        try {
            const { setRelayMembers, setRelayMapping } = await import('./hyperpipe-relay-manager-adapter.mjs');
            if (relayProfile.members) {
                setRelayMembers(relayProfile.relay_key, relayProfile.members);
                if (relayProfile.public_identifier) {
                    setRelayMembers(relayProfile.public_identifier, relayProfile.members);
                }
            }
            if (relayProfile.public_identifier) {
                setRelayMapping(relayProfile.relay_key, relayProfile.public_identifier);
            }
        } catch (err) {
            console.error('[ProfileManager] Failed to update relay adapter maps:', err);
        }

        return true;
    } catch (error) {
        console.error(`[ProfileManager] Error saving relay profile:`, error);
        console.error(error.stack);
        return false;
    }
}

/**
 * Remove a relay profile from the storage file
 * @param {string} relayKey - The relay key to remove
 * @returns {Promise<boolean>} - True if successful, false otherwise
 */
export async function removeRelayProfile(relayKey) {
    return withProfileLock(async () => {
    try {
        // Load existing profiles
        let profiles = await _getAllRelayProfiles();
        
        // Filter out the profile to remove
        const newProfiles = profiles.filter(profile => profile.relay_key !== relayKey);
        
        // Write updated profiles back to file
        const profilesPath = getRelayProfilesPath();
        const sanitized = newProfiles.map(p => ensureProfileSchema(p));
        const tmpPath = profilesPath + '.tmp';
        await fs.writeFile(tmpPath, JSON.stringify({ relays: sanitized }, null, 2));
        await fs.rename(tmpPath, profilesPath);

        try {
            const { removeRelayMapping } = await import('./hyperpipe-relay-manager-adapter.mjs');
            removeRelayMapping(relayKey);
        } catch (err) {
            console.error('[ProfileManager] Failed to update relay mapping:', err);
        }

        return true;
    } catch (error) {
        console.error(`[ProfileManager] Error removing relay profile: ${error.message}`);
        return false;
    }
    });
}

/**
 * Import legacy relay profile files into the consolidated storage
 * @returns {Promise<number>} - Number of profiles imported
 */
export async function importLegacyRelayProfiles() {
    try {
        const storageDir = getStorageDir();
        
        // Get all files in the storage directory
        const files = await fs.readdir(storageDir);
        
        // Filter for relay profile files
        const profileFiles = files.filter(file => file.startsWith('relay-profile-') && file.endsWith('.json'));
        
        let importedCount = 0;
        
        // Process each legacy file
        for (const file of profileFiles) {
            try {
                // Read and parse the legacy file
                const data = await fs.readFile(join(storageDir, file), 'utf8');
                const profile = JSON.parse(data);
                
                // Save to consolidated storage
                if (profile && profile.relay_key) {
                    await saveRelayProfile(profile);
                    importedCount++;
                    
                    // Optionally backup and remove the old file
                    const backupDir = join(storageDir, 'legacy-profiles-backup');
                    await fs.mkdir(backupDir, { recursive: true });
                    
                    const backupFile = join(backupDir, file);
                    await fs.copyFile(join(storageDir, file), backupFile);
                    await fs.unlink(join(storageDir, file));
                }
            } catch (fileError) {
                console.error(`[ProfileManager] Error processing legacy profile file ${file}: ${fileError.message}`);
            }
        }
        
        console.log(`[ProfileManager] Imported ${importedCount} legacy relay profiles into consolidated storage`);
        return importedCount;
    } catch (error) {
        console.error(`[ProfileManager] Error importing legacy relay profiles: ${error.message}`);
        return 0;
    }
}

/**
 * Update the auto-connect setting for a relay profile
 * @param {string} relayKey - The relay key
 * @param {boolean} autoConnect - Whether to auto-connect on startup
 * @returns {Promise<boolean>} - True if successful, false otherwise
 */
export async function updateAutoConnectSetting(relayKey, autoConnect) {
    try {
        console.log(`[ProfileManager] updateAutoConnectSetting called for ${relayKey} with value ${autoConnect}`);
        
        // Get the existing profile
        const profile = await getRelayProfileByKey(relayKey);
        if (!profile) {
            console.error(`[ProfileManager] Profile not found for relay key: ${relayKey}`);
            return false;
        }
        
        console.log(`[ProfileManager] Found existing profile for ${relayKey}:`, {
            name: profile.name,
            currentAutoConnect: profile.auto_connect,
            isActive: profile.is_active
        });
        
        // Update the auto_connect setting
        profile.auto_connect = !!autoConnect; // Convert to boolean
        profile.updated_at = new Date().toISOString();
        
        // Save the updated profile
        const success = await saveRelayProfile(profile);
        console.log(`[ProfileManager] Profile save result for ${relayKey}: ${success}`);
        
        return success;
    } catch (error) {
        console.error(`[ProfileManager] Error updating auto-connect setting for ${relayKey}:`, error);
        console.error(error.stack);
        return false;
    }
}

/**
 * Get the auto-connect settings for all relay profiles
 * @returns {Promise<Array>} - Array of profiles with auto-connect info
 */
export async function getAutoConnectSettings() {
    try {
        const profiles = await getAllRelayProfiles();
        console.log(`[ProfileManager] Retrieved ${profiles.length} profiles for auto-connect settings`);
        
        const settings = profiles.map(profile => {
            const setting = {
                relay_key: profile.relay_key,
                name: profile.name || 'Unnamed Relay',
                auto_connect: profile.auto_connect !== false, // Default to true if not set
                is_active: profile.is_active || false,
                storage_dir: profile.relay_storage
            };
            
            console.log(`[ProfileManager] Auto-connect setting for ${profile.relay_key}:`, setting);
            return setting;
        });
        
        return settings;
    } catch (error) {
        console.error(`[ProfileManager] Error getting auto-connect settings:`, error);
        console.error(error.stack);
        return [];
    }
}

/**
 * Update the member list for a relay profile
 * @param {string} relayKey - Relay key
 * @param {Array<string>} members - Array of member pubkeys
 * @returns {Promise<boolean>} - True if saved
 */
export async function updateRelayMembers(identifier, members = []) {
    try {
        const profile = await withProfileLock(async () => {
            let p = await getRelayProfileByKeyUnlocked(identifier);
            if (!p) {
                p = await getRelayProfileByPublicIdentifierUnlocked(identifier);
            }
            if (!p) return null;
            p.members = members;
            p.updated_at = new Date().toISOString();
            const saved = await _saveRelayProfile(p);
            return saved ? p : null;
        });

        return profile;
    } catch (error) {
        console.error(`[ProfileManager] Error updating members for ${identifier}:`, error);
        return null;
    }
}

export function calculateMembers(adds = [], removes = []) {
    const addMap = new Map(adds.map(a => [a.pubkey, a.ts]));
    const removeMap = new Map(removes.map(r => [r.pubkey, r.ts]));
    const final = [];
    for (const [pubkey, ts] of addMap) {
        const rts = removeMap.get(pubkey);
        if (!rts || ts > rts) {
            final.push(pubkey);
        }
    }
    return final;
}

export async function updateRelayMemberSets(identifier, adds = [], removes = []) {
    try {
        const profile = await withProfileLock(async () => {
            let p = await getRelayProfileByKeyUnlocked(identifier);
            if (!p) {
                p = await getRelayProfileByPublicIdentifierUnlocked(identifier);
            }
            if (!p) return null;

            // Merge adds
            for (const add of adds) {
                const idx = p.member_adds.findIndex(a => a.pubkey === add.pubkey);
                if (idx >= 0) {
                    if (p.member_adds[idx].ts < add.ts) p.member_adds[idx] = add;
                } else {
                    p.member_adds.push(add);
                }
            }

            // Merge removes
            for (const rem of removes) {
                const idx = p.member_removes.findIndex(r => r.pubkey === rem.pubkey);
                if (idx >= 0) {
                    if (p.member_removes[idx].ts < rem.ts) p.member_removes[idx] = rem;
                } else {
                    p.member_removes.push(rem);
                }
            }

            p.members = calculateMembers(p.member_adds, p.member_removes);
            p.updated_at = new Date().toISOString();
            const saved = await _saveRelayProfile(p);
            return saved ? p : null;
        });

        return profile;
    } catch (error) {
        console.error(`[ProfileManager] Error updating member sets for ${identifier}:`, error);
        return null;
    }
}
