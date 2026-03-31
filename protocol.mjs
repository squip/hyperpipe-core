export const CORE_PROTOCOL_VERSION = 1
export const JOIN_TRACE_REQUEST_ID_HEADER = 'x-hyperpipe-core-request-id'

export function makeCoreRequestId(prefix = 'core-req') {
  return `${prefix}-${Date.now().toString(16)}-${Math.random().toString(16).slice(2)}`
}
