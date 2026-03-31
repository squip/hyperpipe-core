#!/usr/bin/env node
import { installCoreLogger } from '../logger.mjs'

installCoreLogger()
await import('../index.js')
