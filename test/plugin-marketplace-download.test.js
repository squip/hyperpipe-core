import test from 'brittle'
import { promises as fs } from 'node:fs'
import path from 'node:path'
import os from 'node:os'
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'

import PluginMarketplaceService from '../plugins/PluginMarketplaceService.mjs'

const execFileAsync = promisify(execFile)

const QUIET_LOGGER = {
  info() {},
  warn() {},
  error() {},
  debug() {}
}

async function createSimpleArchive(rootDir) {
  const packageRoot = path.join(rootDir, 'plugin-package')
  await fs.mkdir(packageRoot, { recursive: true })
  await fs.writeFile(path.join(packageRoot, 'manifest.json'), JSON.stringify({ name: 'fixture' }), 'utf8')
  await fs.writeFile(path.join(packageRoot, 'README.txt'), 'fixture', 'utf8')

  const archivePath = path.join(rootDir, 'fixture.htplugin.tgz')
  await execFileAsync('tar', ['-czf', archivePath, '-C', packageRoot, '.'])
  return archivePath
}

test('PluginMarketplaceService downloads local listing archive into cache', async (t) => {
  const tmpRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'plugin-marketplace-download-'))
  const sourceArchivePath = await createSimpleArchive(tmpRoot)
  const service = new PluginMarketplaceService({
    storageRoot: tmpRoot,
    logger: QUIET_LOGGER,
    fetchImpl: null
  })

  try {
    const listing = {
      manifest: {
        id: 'com.hyperpipe.marketplace-download',
        version: '1.2.3'
      },
      metadata: {
        archiveUrl: sourceArchivePath
      }
    }

    const download = await service.downloadArchive({
      listing,
      timeoutMs: 5000
    })

    t.ok(download.archivePath.endsWith('.htplugin.tgz'))
    t.ok(download.archivePath.includes('plugin-marketplace-cache'))
    t.is(download.warnings.length, 0)

    const sourceBytes = await fs.readFile(sourceArchivePath)
    const cachedBytes = await fs.readFile(download.archivePath)
    t.is(download.sizeBytes, sourceBytes.length)
    t.alike(cachedBytes, sourceBytes)
  } finally {
    await fs.rm(tmpRoot, { recursive: true, force: true }).catch(() => {})
  }
})
