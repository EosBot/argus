import type { FullConfig } from '@playwright/test'

export default async function globalSetup(_config: FullConfig): Promise<void> {
  const endpoint = `${process.env.ARGUS_E2E_API_URL ?? 'http://127.0.0.1:8000'}/ready`
  const deadline = Date.now() + 45_000
  let lastError = 'not attempted'
  while (Date.now() < deadline) {
    try {
      const response = await fetch(endpoint, { signal: AbortSignal.timeout(3_000) })
      if (response.ok) {
        const body = await response.json() as { status?: string }
        if (body.status === 'ready') return
      }
      lastError = `HTTP ${response.status}`
    } catch (cause) {
      lastError = cause instanceof Error ? cause.message : String(cause)
    }
    await new Promise((resolve) => setTimeout(resolve, 1_000))
  }
  throw new Error(`ARGUS backend did not become ready at ${endpoint}: ${lastError}`)
}
