import test from 'brittle'

import { GatewayService } from '../gateway/GatewayService.mjs'

test('GatewayService exposes verified operator identity on authorized gateways only', async t => {
  const service = new GatewayService({})
  service.discoveredGateways = [
    {
      gatewayId: 'a'.repeat(64),
      publicUrl: 'https://gateway.example',
      displayName: 'Example Gateway'
    },
    {
      gatewayId: 'b'.repeat(64),
      publicUrl: 'https://denied.example',
      displayName: 'Denied Gateway'
    }
  ]
  service.gatewayAccessCatalog.set('a'.repeat(64), {
    gatewayId: 'a'.repeat(64),
    gatewayOrigin: 'https://gateway.example',
    hostingState: 'approved',
    operatorIdentity: {
      pubkey: '1'.repeat(64),
      attestation: {
        version: 1,
        payload: {
          purpose: 'gateway-operator-attestation',
          operatorPubkey: '1'.repeat(64),
          gatewayId: 'a'.repeat(64),
          publicUrl: 'https://gateway.example',
          issuedAt: Date.now(),
          expiresAt: Date.now() + 60_000
        },
        signature: '2'.repeat(128)
      }
    }
  })
  service.gatewayAccessCatalog.set('b'.repeat(64), {
    gatewayId: 'b'.repeat(64),
    gatewayOrigin: 'https://denied.example',
    hostingState: 'denied'
  })

  const state = service.getPublicGatewayState()
  t.is(state.authorizedGateways.length, 1)
  t.is(state.authorizedGateways[0].gatewayId, 'a'.repeat(64))
  t.is(state.authorizedGateways[0].operatorIdentity.pubkey, '1'.repeat(64))
  t.is(state.discoveredGateways.length, 2)
})
