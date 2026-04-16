import test from 'brittle'
import fs from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'

import {
  PUBLIC_GATEWAY_SETTINGS_FILENAME,
  clearCachedPublicGatewaySettings,
  loadPublicGatewaySettings,
  setPublicGatewaySettingsNodeStorage
} from '../../hyperpipe-bridge/config/PublicGatewaySettings.mjs'

test('public gateway settings migrate only neutral preferences into user-scoped storage', async t => {
  const tmp = await fs.mkdtemp(path.join(os.tmpdir(), 'public-gateway-settings-'))
  const legacyPath = path.join(tmp, 'legacy', PUBLIC_GATEWAY_SETTINGS_FILENAME)
  const userPath = path.join(tmp, 'users', 'alice', PUBLIC_GATEWAY_SETTINGS_FILENAME)

  await fs.mkdir(path.dirname(legacyPath), { recursive: true })
  await fs.writeFile(legacyPath, JSON.stringify({
    selectionMode: 'discovered',
    selectedGatewayId: 'gateway-24',
    preferredBaseUrl: 'https://hypertuna.com',
    baseUrl: 'https://hypertuna.com',
    blindPeerKeys: ['x597qroj14ith1y8'],
    sharedSecret: 'should-not-migrate',
    resolvedGatewayId: 'resolved-24',
    resolvedSharedSecretHash: 'hash',
    resolvedGatewayRelay: {
      hyperbeeKey: 'abc'
    }
  }, null, 2), 'utf8')

  try {
    setPublicGatewaySettingsNodeStorage({
      filePath: userPath,
      legacyFilePath: legacyPath
    })
    clearCachedPublicGatewaySettings()

    const settings = await loadPublicGatewaySettings()
    t.is(settings.selectionMode, 'discovered')
    t.is(settings.selectedGatewayId, 'gateway-24')
    t.is(settings.preferredBaseUrl, 'https://hypertuna.com')
    t.is(settings.baseUrl, 'https://hypertuna.com')
    t.alike(settings.blindPeerKeys, [])
    t.alike(settings.blindPeerManualKeys, [])
    t.is(settings.sharedSecret, '')
    t.is(settings.resolvedGatewayId, null)
    t.is(settings.resolvedSharedSecretHash, null)
    t.is(settings.resolvedGatewayRelay, null)

    const migratedRaw = JSON.parse(await fs.readFile(userPath, 'utf8'))
    t.alike(migratedRaw, {
      selectionMode: 'discovered',
      selectedGatewayId: 'gateway-24',
      preferredBaseUrl: 'https://hypertuna.com',
      baseUrl: 'https://hypertuna.com'
    })
  } finally {
    setPublicGatewaySettingsNodeStorage({
      filePath: null,
      legacyFilePath: null
    })
    clearCachedPublicGatewaySettings()
    await fs.rm(tmp, { recursive: true, force: true })
  }
})
