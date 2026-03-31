import nodeCrypto from 'node:crypto'
import { promises as fs } from 'node:fs'
import { join } from 'node:path'

function createId(prefix = 'recording') {
  if (typeof nodeCrypto.randomUUID === 'function') {
    return `${prefix}-${nodeCrypto.randomUUID()}`
  }
  return `${prefix}-${nodeCrypto.randomBytes(12).toString('hex')}`
}

function sanitizeId(value, label) {
  if (typeof value !== 'string' || !value.trim()) {
    throw new Error(`${label} is required`)
  }
  return value.trim()
}

export default class RecordingService {
  constructor({
    storageRoot,
    logger = console,
    transcodeEnabled = false
  } = {}) {
    if (!storageRoot || typeof storageRoot !== 'string') {
      throw new Error('RecordingService requires storageRoot')
    }
    this.storageRoot = storageRoot
    this.logger = logger
    this.transcodeEnabled = transcodeEnabled
    this.recordings = new Map()
    this.artifactDir = join(storageRoot, 'media', 'recordings')
  }

  async ensureStorage() {
    await fs.mkdir(this.artifactDir, { recursive: true })
  }

  async startRecording({
    sessionId,
    requestedBy = null,
    format = 'webm',
    options = null
  } = {}) {
    const normalizedSessionId = sanitizeId(sessionId, 'sessionId')
    await this.ensureStorage()

    const now = Date.now()
    const recordingId = createId('recording')
    const artifactPath = join(this.artifactDir, `${recordingId}.json`)

    const entry = {
      recordingId,
      sessionId: normalizedSessionId,
      requestedBy: typeof requestedBy === 'string' ? requestedBy : null,
      format: typeof format === 'string' && format ? format : 'webm',
      options: options && typeof options === 'object' ? { ...options } : null,
      status: 'recording',
      createdAt: now,
      startedAt: now,
      stoppedAt: null,
      artifactPath,
      bytesWritten: 0
    }

    this.recordings.set(recordingId, entry)
    await fs.writeFile(
      artifactPath,
      JSON.stringify({ ...entry, event: 'recording-started' }, null, 2),
      'utf8'
    )
    return { ...entry }
  }

  async stopRecording({ recordingId } = {}) {
    const normalizedRecordingId = sanitizeId(recordingId, 'recordingId')
    const entry = this.recordings.get(normalizedRecordingId)
    if (!entry) throw new Error(`Recording not found: ${normalizedRecordingId}`)
    if (entry.status !== 'recording') {
      return { ...entry }
    }

    const now = Date.now()
    entry.status = 'completed'
    entry.stoppedAt = now
    entry.bytesWritten = Buffer.byteLength(
      JSON.stringify({
        recordingId: entry.recordingId,
        sessionId: entry.sessionId,
        startedAt: entry.startedAt,
        stoppedAt: now
      }),
      'utf8'
    )
    this.recordings.set(normalizedRecordingId, entry)
    await fs.writeFile(
      entry.artifactPath,
      JSON.stringify({ ...entry, event: 'recording-stopped' }, null, 2),
      'utf8'
    )
    return { ...entry }
  }

  async listRecordings({ sessionId = null } = {}) {
    const values = Array.from(this.recordings.values()).map((entry) => ({ ...entry }))
    if (!sessionId) return values
    return values.filter((entry) => entry.sessionId === sessionId)
  }

  async exportRecording({ recordingId, targetPath } = {}) {
    const normalizedRecordingId = sanitizeId(recordingId, 'recordingId')
    const normalizedTarget = sanitizeId(targetPath, 'targetPath')
    const entry = this.recordings.get(normalizedRecordingId)
    if (!entry) throw new Error(`Recording not found: ${normalizedRecordingId}`)
    await this.ensureStorage()
    await fs.mkdir(join(normalizedTarget, '..'), { recursive: true })
    await fs.copyFile(entry.artifactPath, normalizedTarget)
    return { recordingId: normalizedRecordingId, targetPath: normalizedTarget }
  }

  async transcodeRecording({
    recordingId,
    targetFormat = 'mp4',
    targetPath
  } = {}) {
    const normalizedRecordingId = sanitizeId(recordingId, 'recordingId')
    const normalizedFormat = sanitizeId(targetFormat, 'targetFormat')
    const entry = this.recordings.get(normalizedRecordingId)
    if (!entry) throw new Error(`Recording not found: ${normalizedRecordingId}`)
    if (!this.transcodeEnabled) {
      throw new Error('Host transcode service is unavailable on this build')
    }

    const outputPath = targetPath
      ? sanitizeId(targetPath, 'targetPath')
      : join(this.artifactDir, `${normalizedRecordingId}.${normalizedFormat}`)

    await fs.copyFile(entry.artifactPath, outputPath)
    return {
      recordingId: normalizedRecordingId,
      targetFormat: normalizedFormat,
      outputPath
    }
  }

  getServiceStatus() {
    const recordings = Array.from(this.recordings.values())
    return {
      activeRecordings: recordings.filter((entry) => entry.status === 'recording').length,
      totalRecordings: recordings.length,
      transcodeEnabled: this.transcodeEnabled
    }
  }
}
