import fs from 'node:fs'
import path from 'node:path'
import { expect, test } from '@playwright/test'

function localCredentials(): { username: string; password: string } {
  const envPath = path.resolve(process.cwd(), '..', '.env')
  const values = new Map<string, string>()
  for (const rawLine of fs.readFileSync(envPath, 'utf8').split(/\r?\n/)) {
    const line = rawLine.trim()
    if (!line || line.startsWith('#')) continue
    const separator = line.indexOf('=')
    if (separator < 1) continue
    const key = line.slice(0, separator).trim()
    let value = line.slice(separator + 1).trim()
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1)
    }
    values.set(key, value)
  }
  const password = process.env.ARGUS_ADMIN_PASSWORD ?? values.get('ARGUS_ADMIN_PASSWORD')
  if (!password) throw new Error('ARGUS_ADMIN_PASSWORD is required for local E2E')
  return { username: process.env.ARGUS_ADMIN_USER ?? values.get('ARGUS_ADMIN_USER') ?? 'admin', password }
}

test('authenticated investigator workspace is usable and case-aware', async ({ page }, testInfo) => {
  const errors: string[] = []
  page.on('pageerror', (error) => errors.push(`pageerror: ${error.message}`))
  page.on('console', (message) => {
    if (message.type() === 'error') errors.push(`console: ${message.text()}`)
  })

  const credentials = localCredentials()
  await page.goto('/')
  await page.locator('#auth-username').fill(credentials.username)
  await page.locator('#auth-password').fill(credentials.password)
  await page.getByRole('button', { name: 'Acessar' }).click()

  await expect(page.getByText('Backend online')).toBeVisible()
  await expect(page.getByLabel('Investigação do terminal')).toBeVisible()
  await expect(page.getByLabel('Investigação do terminal').locator('option')).not.toHaveCount(1)
  await expect(page.getByText('argus-terminal')).toBeVisible()
  await page.screenshot({ path: testInfo.outputPath('workspace.png'), fullPage: true })

  await page.getByTitle('Settings (Ctrl+,)').click()
  await expect(page.getByRole('dialog', { name: 'Settings' })).toBeVisible()
  await page.screenshot({ path: testInfo.outputPath('settings.png'), fullPage: true })

  const viewport = page.viewportSize()
  if (viewport) {
    const scrollWidth = await page.evaluate(() => document.documentElement.scrollWidth)
    expect(scrollWidth).toBeLessThanOrEqual(viewport.width + 1)
  }
  expect(errors).toEqual([])
})
