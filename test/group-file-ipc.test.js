import test from 'brittle'

import {
  deleteLocalGroupFileOperation,
  downloadGroupFileOperation,
  ensureUniqueDownloadPath,
  normalizeDownloadFileName,
  resolveGroupFileTarget
} from '../group-file-ipc.mjs'

function hex64 (char) {
  return String(char).repeat(64)
}

test('normalizeDownloadFileName sanitizes unsafe characters and falls back to hash', async (t) => {
  const explicit = normalizeDownloadFileName({
    fileName: ' report<>:"/\\|?*.txt ',
    fileHash: hex64('a')
  })
  t.is(explicit, 'report_________.txt')

  const fallback = normalizeDownloadFileName({
    fileName: '',
    fileHash: 'ABCDEF1234567890'
  })
  t.is(fallback, 'file-abcdef123456')
})

test('ensureUniqueDownloadPath appends numeric suffix when collisions exist', async (t) => {
  const checks = new Map([
    ['/tmp/Downloads/file.txt', true],
    ['/tmp/Downloads/file (1).txt', true]
  ])

  const path = await ensureUniqueDownloadPath('/tmp/Downloads', 'file.txt', {
    fileAccess: async (candidate) => checks.get(candidate) === true
  })

  t.is(path, '/tmp/Downloads/file (2).txt')
})

test('resolveGroupFileTarget derives relay key from public identifier lookup', async (t) => {
  const relayKey = hex64('b')
  const target = await resolveGroupFileTarget(
    { publicIdentifier: 'npubdemo:group-a' },
    {
      getRelayKeyFromPublicIdentifier: async () => relayKey,
      getRelayProfileByKey: async () => ({ public_identifier: 'npubdemo:group-a' }),
      commandName: 'download-group-file'
    }
  )
  t.is(target.relayKey, relayKey)
  t.is(target.identifier, 'npubdemo:group-a')
})

test('resolveGroupFileTarget rejects unresolved identifiers', async (t) => {
  await t.exception(async () => {
    await resolveGroupFileTarget(
      {},
      {
        getRelayKeyFromPublicIdentifier: async () => null,
        getRelayProfileByKey: async () => null,
        commandName: 'download-group-file'
      }
    )
  }, /could not resolve identifier/)
})

test('downloadGroupFileOperation returns saved path and bytes for recovered file', async (t) => {
  const relayKey = hex64('c')
  const fileHash = hex64('f')
  const calls = {
    recover: 0,
    write: 0
  }

  const result = await downloadGroupFileOperation(
    {
      groupId: 'npubdemo:group-a',
      fileHash,
      fileName: 'example.bin'
    },
    {
      getRelayKeyFromPublicIdentifier: async () => relayKey,
      getRelayProfileByKey: async () => ({ public_identifier: 'npubdemo:group-a' }),
      recoverRelayDriveFile: async (input) => {
        calls.recover += 1
        t.is(input.reason, 'on-demand-download')
        return {
          status: 'ok',
          reason: 'fetched',
          identifier: 'npubdemo:group-a',
          relayKey
        }
      },
      getFile: async (identifier, hash) => {
        t.is(identifier, 'npubdemo:group-a')
        t.is(hash, fileHash)
        return Buffer.from('hello world')
      },
      writeFileToDownloads: async ({ fileName, data }) => {
        calls.write += 1
        t.is(fileName, 'example.bin')
        t.is(data.length, 11)
        return '/tmp/Downloads/example.bin'
      }
    }
  )

  t.is(calls.recover, 1)
  t.is(calls.write, 1)
  t.is(result.savedPath, '/tmp/Downloads/example.bin')
  t.is(result.bytes, 11)
  t.is(result.source, 'recovered')
})

test('downloadGroupFileOperation retries local read via relay key fallback', async (t) => {
  const relayKey = hex64('d')
  const fileHash = hex64('e')
  const reads = []

  const result = await downloadGroupFileOperation(
    {
      groupId: 'npubdemo:group-b',
      fileHash
    },
    {
      getRelayKeyFromPublicIdentifier: async () => relayKey,
      getRelayProfileByKey: async () => ({ public_identifier: 'npubdemo:group-b' }),
      recoverRelayDriveFile: async () => ({
        status: 'ok',
        reason: 'already-local',
        identifier: 'npubdemo:group-b',
        relayKey
      }),
      getFile: async (identifier) => {
        reads.push(identifier)
        if (identifier === 'npubdemo:group-b') return null
        return Buffer.from('abc')
      },
      writeFileToDownloads: async () => '/tmp/Downloads/file.bin'
    }
  )

  t.alike(reads, ['npubdemo:group-b', relayKey])
  t.is(result.bytes, 3)
  t.is(result.source, 'local')
})

test('downloadGroupFileOperation forwards an explicit save path to the writer', async (t) => {
  const relayKey = hex64('d')
  const fileHash = hex64('7')
  let writePayload = null

  const result = await downloadGroupFileOperation(
    {
      groupId: 'npubdemo:group-explicit',
      fileHash,
      fileName: 'index.html',
      savePath: '/tmp/custom/index.html'
    },
    {
      getRelayKeyFromPublicIdentifier: async () => relayKey,
      getRelayProfileByKey: async () => ({ public_identifier: 'npubdemo:group-explicit' }),
      recoverRelayDriveFile: async () => ({
        status: 'ok',
        reason: 'already-local',
        identifier: 'npubdemo:group-explicit',
        relayKey
      }),
      getFile: async () => Buffer.from('<html></html>'),
      writeFileToDownloads: async (payload) => {
        writePayload = payload
        return payload.savePath
      }
    }
  )

  t.is(writePayload.fileName, 'index.html')
  t.is(writePayload.savePath, '/tmp/custom/index.html')
  t.is(result.savedPath, '/tmp/custom/index.html')
})

test('downloadGroupFileOperation validates file hash and recovery errors', async (t) => {
  await t.exception(async () => {
    await downloadGroupFileOperation({}, {
      recoverRelayDriveFile: async () => ({ status: 'ok' }),
      getFile: async () => Buffer.from('x'),
      writeFileToDownloads: async () => '/tmp/Downloads/x'
    })
  }, /requires fileHash/)

  await t.exception(async () => {
    await downloadGroupFileOperation(
      { groupId: 'npubdemo:group-c', fileHash: hex64('1') },
      {
        getRelayKeyFromPublicIdentifier: async () => hex64('9'),
        getRelayProfileByKey: async () => ({ public_identifier: 'npubdemo:group-c' }),
        recoverRelayDriveFile: async () => ({ status: 'error', reason: 'fetch-failed' }),
        getFile: async () => null,
        writeFileToDownloads: async () => '/tmp/Downloads/x'
      }
    )
  }, /file recovery failed: fetch-failed/)

  await t.exception(async () => {
    await downloadGroupFileOperation(
      {
        groupId: 'npubdemo:group-c',
        fileHash: hex64('6'),
        fileName: 'bad<>:"/\\|?*name.txt'
      },
      {
        getRelayKeyFromPublicIdentifier: async () => hex64('8'),
        getRelayProfileByKey: async () => ({ public_identifier: 'npubdemo:group-c' }),
        recoverRelayDriveFile: async () => ({ status: 'ok', reason: 'already-local' }),
        getFile: async () => null,
        writeFileToDownloads: async () => '/tmp/Downloads/x'
      }
    )
  }, /Local file not found after recovery/)
})

test('deleteLocalGroupFileOperation retries delete by relay key and reports response', async (t) => {
  const relayKey = hex64('a')
  const fileHash = hex64('2')
  const deleteCalls = []

  const result = await deleteLocalGroupFileOperation(
    {
      groupId: 'npubdemo:group-d',
      fileHash
    },
    {
      getRelayKeyFromPublicIdentifier: async () => relayKey,
      getRelayProfileByKey: async () => ({ public_identifier: 'npubdemo:group-d' }),
      deleteRelayFile: async (identifier) => {
        deleteCalls.push(identifier)
        if (identifier === 'npubdemo:group-d') {
          return { deleted: false, reason: 'not-found' }
        }
        return { deleted: true }
      }
    }
  )

  t.alike(deleteCalls, ['npubdemo:group-d', relayKey])
  t.is(result.deleted, true)
  t.is(result.reason, null)
  t.is(result.fileHash, fileHash)
})

test('deleteLocalGroupFileOperation is idempotent for missing file and validates hash', async (t) => {
  await t.exception(async () => {
    await deleteLocalGroupFileOperation({}, { deleteRelayFile: async () => ({ deleted: false }) })
  }, /requires fileHash/)

  const fileHash = hex64('3')
  const result = await deleteLocalGroupFileOperation(
    {
      relayKey: hex64('4'),
      fileHash
    },
    {
      getRelayProfileByKey: async () => ({ public_identifier: hex64('4') }),
      deleteRelayFile: async () => ({ deleted: false, reason: 'not-found' })
    }
  )

  t.is(result.deleted, false)
  t.is(result.reason, 'not-found')
})

test('deleteLocalGroupFileOperation resolves identifier from relay key profile', async (t) => {
  const relayKey = hex64('7')
  const fileHash = hex64('8')
  const calls = []

  const result = await deleteLocalGroupFileOperation(
    {
      relayKey,
      fileHash
    },
    {
      getRelayProfileByKey: async () => ({ public_identifier: 'npubdemo:group-e' }),
      deleteRelayFile: async (identifier) => {
        calls.push(identifier)
        return { deleted: true }
      }
    }
  )

  t.alike(calls, ['npubdemo:group-e'])
  t.is(result.identifier, 'npubdemo:group-e')
  t.is(result.deleted, true)
  t.is(result.reason, null)
})

test('downloadGroupFileOperation surfaces download write failures', async (t) => {
  await t.exception(async () => {
    await downloadGroupFileOperation(
      {
        groupId: 'npubdemo:group-f',
        fileHash: hex64('9'),
        fileName: 'report.bin'
      },
      {
        getRelayKeyFromPublicIdentifier: async () => hex64('a'),
        getRelayProfileByKey: async () => ({ public_identifier: 'npubdemo:group-f' }),
        recoverRelayDriveFile: async () => ({ status: 'ok', reason: 'already-local' }),
        getFile: async () => Buffer.from('content'),
        writeFileToDownloads: async () => {
          throw new Error('write failed')
        }
      }
    )
  }, /write failed/)
})

test('deleteLocalGroupFileOperation propagates delete errors', async (t) => {
  await t.exception(async () => {
    await deleteLocalGroupFileOperation(
      {
        groupId: 'npubdemo:group-g',
        fileHash: hex64('b')
      },
      {
        getRelayKeyFromPublicIdentifier: async () => hex64('c'),
        getRelayProfileByKey: async () => ({ public_identifier: 'npubdemo:group-g' }),
        deleteRelayFile: async () => {
          throw new Error('delete failed')
        }
      }
    )
  }, /delete failed/)
})
