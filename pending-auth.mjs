export const pendingAuthUpdates = new Map();

export function queuePendingAuthUpdate(identifier, pubkey, token) {
  if (!pendingAuthUpdates.has(identifier)) {
    pendingAuthUpdates.set(identifier, []);
  }
  pendingAuthUpdates.get(identifier).push({ pubkey, token });
}

export async function applyPendingAuthUpdates(updateFn, ...identifiers) {
  for (const id of identifiers) {
    const updates = pendingAuthUpdates.get(id);
    if (updates) {
      for (const { pubkey, token } of updates) {
        await updateFn(id, pubkey, token);
      }
      pendingAuthUpdates.delete(id);
    }
  }
}
