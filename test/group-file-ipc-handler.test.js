import test from 'brittle'
import { readFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const workerIndexPath = join(__dirname, '..', 'index.js')

function extractCaseBlock(source, caseName, nextCaseName) {
  const start = source.indexOf(`case '${caseName}':`)
  if (start < 0) return null
  const end = source.indexOf(`case '${nextCaseName}':`, start)
  return source.slice(start, end > start ? end : source.length)
}

test('download-group-file IPC handler emits response and worker-response paths', async (t) => {
  const source = await readFile(workerIndexPath, 'utf8')
  const block = extractCaseBlock(source, 'download-group-file', 'delete-local-group-file')
  t.ok(block, 'download-group-file case exists')
  t.ok(block.includes('downloadGroupFileOperation'), 'download operation invoked')
  t.ok(block.includes("sendMessage({ type: 'download-group-file-complete', data: response })"), 'success event emitted')
  t.ok(block.includes("sendMessage({ type: 'download-group-file-error', error: errorMessage })"), 'error event emitted')
  t.ok(block.includes('sendWorkerResponse(requestId, { success: true, data: response })'), 'success worker-response emitted')
  t.ok(block.includes('sendWorkerResponse(requestId, { success: false, error: errorMessage })'), 'error worker-response emitted')
})

test('delete-local-group-file IPC handler emits response and worker-response paths', async (t) => {
  const source = await readFile(workerIndexPath, 'utf8')
  const block = extractCaseBlock(source, 'delete-local-group-file', 'upload-file')
  t.ok(block, 'delete-local-group-file case exists')
  t.ok(block.includes('deleteLocalGroupFileOperation'), 'delete operation invoked')
  t.ok(block.includes("sendMessage({ type: 'delete-local-group-file-complete', data: response })"), 'success event emitted')
  t.ok(block.includes("sendMessage({ type: 'delete-local-group-file-error', error: errorMessage })"), 'error event emitted')
  t.ok(block.includes('sendWorkerResponse(requestId, { success: true, data: response })'), 'success worker-response emitted')
  t.ok(block.includes('sendWorkerResponse(requestId, { success: false, error: errorMessage })'), 'error worker-response emitted')
})
