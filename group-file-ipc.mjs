import { extname, join } from 'node:path'

function isHex64 (value) {
  return typeof value === 'string' && /^[a-fA-F0-9]{64}$/.test(value)
}

export function normalizeDownloadFileName ({ fileName, fileHash }) {
  const raw = typeof fileName === 'string' ? fileName.trim() : ''
  const safe = raw.replace(/[<>:"/\\|?*\u0000-\u001f]/g, '_').replace(/\s+/g, ' ').trim()
  if (safe) return safe
  const hash = typeof fileHash === 'string' ? fileHash.trim().toLowerCase() : ''
  return hash ? `file-${hash.slice(0, 12)}` : `file-${Date.now()}`
}

export async function ensureUniqueDownloadPath (baseDir, fileName, { fileAccess } = {}) {
  const access = fileAccess || (async () => false)
  const extension = extname(fileName)
  const base = extension ? fileName.slice(0, -extension.length) : fileName
  let attempt = 0
  while (attempt < 5000) {
    const suffix = attempt === 0 ? '' : ` (${attempt})`
    const candidate = join(baseDir, `${base}${suffix}${extension}`)
    const exists = await access(candidate)
    if (!exists) return candidate
    attempt += 1
  }
  return join(baseDir, `${base}-${Date.now()}${extension}`)
}

export async function resolveGroupFileTarget (
  payload = {},
  {
    getRelayKeyFromPublicIdentifier,
    getRelayProfileByKey,
    commandName
  } = {}
) {
  const requestedRelayKey = typeof payload.relayKey === 'string' ? payload.relayKey.trim() : ''
  const requestedPublicIdentifier = typeof payload.publicIdentifier === 'string' ? payload.publicIdentifier.trim() : ''
  const requestedIdentifier = typeof payload.identifier === 'string' ? payload.identifier.trim() : ''
  const requestedGroupId = typeof payload.groupId === 'string' ? payload.groupId.trim() : ''

  let relayKey = requestedRelayKey || null
  let identifier = requestedIdentifier || requestedPublicIdentifier || requestedGroupId || null

  if (!relayKey && identifier && isHex64(identifier)) {
    relayKey = identifier.toLowerCase()
  }
  if (!relayKey && identifier && !isHex64(identifier) && typeof getRelayKeyFromPublicIdentifier === 'function') {
    try {
      relayKey = await getRelayKeyFromPublicIdentifier(identifier)
    } catch (_) {}
  }
  if (!identifier && relayKey) {
    try {
      const profile = typeof getRelayProfileByKey === 'function'
        ? await getRelayProfileByKey(relayKey)
        : null
      identifier = profile?.public_identifier || relayKey
    } catch (_) {
      identifier = relayKey
    }
  }
  if (!identifier) {
    throw new Error(`${commandName || 'group-file'} could not resolve identifier`)
  }
  return {
    relayKey,
    identifier
  }
}

export async function downloadGroupFileOperation (
  payload = {},
  {
    getRelayKeyFromPublicIdentifier,
    getRelayProfileByKey,
    recoverRelayDriveFile,
    getFile,
    writeFileToDownloads
  } = {}
) {
  const requestedFileHash = typeof payload.fileHash === 'string' ? payload.fileHash.trim().toLowerCase() : ''
  const requestedFileName = typeof payload.fileName === 'string' ? payload.fileName.trim() : ''
  const requestedSavePath = typeof payload.savePath === 'string' ? payload.savePath.trim() : ''
  if (!requestedFileHash) throw new Error('download-group-file requires fileHash')

  const { relayKey, identifier } = await resolveGroupFileTarget(payload, {
    getRelayKeyFromPublicIdentifier,
    getRelayProfileByKey,
    commandName: 'download-group-file'
  })

  const recovered = await recoverRelayDriveFile({
    relayKey,
    identifier,
    fileHash: requestedFileHash,
    reason: 'on-demand-download'
  })
  if (recovered?.status !== 'ok' && recovered?.reason !== 'already-local') {
    throw new Error(`file recovery failed: ${recovered?.reason || 'unknown'}`)
  }

  const resolvedIdentifier =
    (typeof recovered?.identifier === 'string' && recovered.identifier) || identifier
  const resolvedRelayKey =
    (typeof recovered?.relayKey === 'string' && recovered.relayKey) || relayKey || null

  let buffer = await getFile(resolvedIdentifier, requestedFileHash)
  if (!buffer && resolvedRelayKey && resolvedRelayKey !== resolvedIdentifier) {
    buffer = await getFile(resolvedRelayKey, requestedFileHash)
  }
  if (!buffer) throw new Error('Local file not found after recovery')

  const fallbackFileName = requestedFileHash ? `file-${requestedFileHash.slice(0, 12)}` : ''
  const normalizedFileName = normalizeDownloadFileName({
    fileName: requestedFileName || fallbackFileName,
    fileHash: requestedFileHash
  })
  const savePath = await writeFileToDownloads({
    fileName: normalizedFileName,
    data: buffer,
    savePath: requestedSavePath || undefined
  })

  return {
    relayKey: resolvedRelayKey,
    identifier: resolvedIdentifier,
    fileHash: requestedFileHash,
    fileName: normalizedFileName,
    savedPath: savePath,
    bytes: buffer?.length || 0,
    source: recovered?.reason === 'already-local' ? 'local' : 'recovered'
  }
}

export async function deleteLocalGroupFileOperation (
  payload = {},
  {
    getRelayKeyFromPublicIdentifier,
    getRelayProfileByKey,
    deleteRelayFile
  } = {}
) {
  const requestedFileHash = typeof payload.fileHash === 'string' ? payload.fileHash.trim().toLowerCase() : ''
  if (!requestedFileHash) throw new Error('delete-local-group-file requires fileHash')

  const { relayKey, identifier } = await resolveGroupFileTarget(payload, {
    getRelayKeyFromPublicIdentifier,
    getRelayProfileByKey,
    commandName: 'delete-local-group-file'
  })

  let deletion = await deleteRelayFile(identifier, requestedFileHash)
  if (!deletion?.deleted && relayKey && relayKey !== identifier) {
    deletion = await deleteRelayFile(relayKey, requestedFileHash)
  }

  return {
    relayKey,
    identifier,
    fileHash: requestedFileHash,
    deleted: !!deletion?.deleted,
    reason: deletion?.reason || null
  }
}
