import test from 'brittle'
import { readFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const workerIndexPath = join(__dirname, '..', 'index.js')

test('provision-writer-for-invitee keeps requestId worker-response compatibility', async (t) => {
  const source = await readFile(workerIndexPath, 'utf8')
  const start = source.indexOf("case 'provision-writer-for-invitee'")
  t.ok(start >= 0, 'provision writer handler exists')

  const end = source.indexOf("\n    case 'update-members':", start)
  const block = source.slice(start, end > start ? end : source.length)

  t.ok(
    block.includes("sendWorkerResponse(requestId, { success: true, data: responsePayload })"),
    'success worker-response emitted'
  )
  t.ok(
    block.includes("sendWorkerResponse(message?.requestId, { success: false, error: errorMessage })"),
    'error worker-response emitted'
  )
})

