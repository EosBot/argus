import fs from 'node:fs'
import path from 'node:path'
import { expect, test } from '@playwright/test'

function localCredentials(): { username: string; password: string } {
  const values = new Map<string, string>()
  for (const rawLine of fs.readFileSync(path.resolve(process.cwd(), '..', '.env'), 'utf8').split(/\r?\n/)) {
    const line = rawLine.trim()
    if (!line || line.startsWith('#')) continue
    const separator = line.indexOf('=')
    if (separator < 1) continue
    let value = line.slice(separator + 1).trim()
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) value = value.slice(1, -1)
    values.set(line.slice(0, separator).trim(), value)
  }
  const password = process.env.ARGUS_ADMIN_PASSWORD ?? values.get('ARGUS_ADMIN_PASSWORD')
  if (!password) throw new Error('ARGUS_ADMIN_PASSWORD is required for local E2E')
  return { username: process.env.ARGUS_ADMIN_USER ?? values.get('ARGUS_ADMIN_USER') ?? 'admin', password }
}

test('admin settings persist and user lifecycle exposes the one-time credential', async ({ page }) => {
  test.skip(test.info().project.name !== 'desktop-chromium', 'Mutation journey runs once against shared backend state')
  const credentials = localCredentials()
  const suffix = Date.now().toString(36)
  const username = `e2e_${suffix}`
  const providerName = `Provider ${suffix}`
  const connectionName = `Connection ${suffix}`

  await page.goto('/')
  await page.locator('#auth-username').fill(credentials.username)
  await page.locator('#auth-password').fill(credentials.password)
  await page.getByRole('button', { name: 'Acessar' }).click()
  await expect(page.getByText('Backend online')).toBeVisible()
  await page.getByTitle('Settings (Ctrl+,)').click()

  await page.getByRole('button', { name: 'Avançado' }).click()
  await expect(page.getByRole('button', { name: 'Avançado' })).toHaveAttribute('aria-pressed', 'true')
  await page.reload()
  await page.getByTitle('Settings (Ctrl+,)').click()
  await expect(page.getByRole('button', { name: 'Avançado' })).toHaveAttribute('aria-pressed', 'true')

  await page.getByRole('button', { name: 'Users' }).click()
  await page.getByRole('button', { name: 'Add User' }).click()
  await page.getByLabel('Username').fill(username)
  await page.getByLabel('Email').fill(`${username}@example.org`)
  await page.getByRole('button', { name: 'Add User' }).last().click()

  await expect(page.getByText('Credencial temporária — exibida uma única vez')).toBeVisible()
  await expect(page.getByText(username, { exact: true })).toBeVisible()
  page.once('dialog', (dialog) => dialog.accept())
  await page.getByRole('button', { name: `Excluir usuário ${username}` }).click()
  await expect(page.getByText(username, { exact: true })).not.toBeVisible()

  await page.getByRole('button', { name: 'Providers' }).click()
  await page.getByRole('button', { name: 'Add Provider' }).click()
  await page.getByLabel('Name').fill(providerName)
  await page.getByLabel('Type').selectOption('custom')
  await page.getByLabel('Endpoint').fill('https://example.invalid/v1')
  await page.getByRole('button', { name: 'Add Provider' }).last().click()
  await expect(page.getByText(providerName, { exact: true })).toBeVisible()
  await page.getByText(providerName, { exact: true }).click()
  await page.getByRole('button', { name: 'Delete' }).click()
  await expect(page.getByText(providerName, { exact: true })).not.toBeVisible()

  await page.getByRole('button', { name: 'Connections' }).click()
  await page.getByRole('button', { name: 'Add Connection' }).click()
  await page.getByLabel('Name').fill(connectionName)
  await page.getByLabel('Tool Type').selectOption('custom')
  await page.getByLabel('Endpoint').fill('https://example.invalid/api')
  await page.getByRole('button', { name: 'Add Connection' }).last().click()
  await expect(page.getByText(connectionName, { exact: true })).toBeVisible()
  await page.getByText(connectionName, { exact: true }).click()
  await page.getByRole('button', { name: 'Delete' }).click()
  await expect(page.getByText(connectionName, { exact: true })).not.toBeVisible()

  await page.getByRole('button', { name: 'Models' }).click()
  const generalSelection = page.getByLabel('Selected model for General')
  const originalGeneralModel = (await generalSelection.textContent())?.trim() ?? 'Not selected'
  const assignmentButtons = page.getByRole('button', { name: /^Assign / })
  if (await assignmentButtons.count()) {
    const modelToExercise = originalGeneralModel === 'Not selected'
      ? (await assignmentButtons.first().getAttribute('aria-label'))!.replace(/^Assign /, '')
      : originalGeneralModel
    await page.getByRole('button', { name: `Assign ${modelToExercise}`, exact: true }).click()
    if (originalGeneralModel === 'Not selected') {
      await page.getByRole('button', { name: /General$/ }).last().click()
      await expect(generalSelection).toHaveText(modelToExercise)
    } else {
      await page.getByRole('button', { name: /Remove General/ }).click()
      await expect(generalSelection).toHaveText('Not selected')
    }
    await page.reload()
    await page.getByTitle('Settings (Ctrl+,)').click()
    await page.getByRole('button', { name: 'Models' }).click()
    await expect(page.getByLabel('Selected model for General')).toHaveText(
      originalGeneralModel === 'Not selected' ? modelToExercise : 'Not selected',
    )
    await page.getByRole('button', { name: `Assign ${modelToExercise}`, exact: true }).click()
    await page.getByRole('button', {
      name: originalGeneralModel === 'Not selected' ? /Remove General/ : /General$/,
    }).last().click()
    await expect(page.getByLabel('Selected model for General')).toHaveText(originalGeneralModel)
  }

  await page.getByRole('button', { name: 'OPSEC' }).click()
  const rateLimit = page.getByLabel('Max requests per minute')
  const originalRate = await rateLimit.inputValue()
  const changedRate = originalRate === '31' ? '32' : '31'
  await rateLimit.fill(changedRate)
  await page.getByRole('button', { name: 'Salvar OPSEC' }).click()
  await page.reload()
  await page.getByTitle('Settings (Ctrl+,)').click()
  await page.getByRole('button', { name: 'OPSEC' }).click()
  await expect(page.getByLabel('Max requests per minute')).toHaveValue(changedRate)
  await page.getByLabel('Max requests per minute').fill(originalRate)
  const restoredOpsec = page.waitForResponse((response) => response.url().endsWith('/api/operations/settings') && response.request().method() === 'PUT' && response.ok())
  await page.getByRole('button', { name: 'Salvar OPSEC' }).click()
  await restoredOpsec

  await page.getByRole('button', { name: 'Tools' }).click()
  await page.getByPlaceholder('Buscar por nome, função ou pacote…').fill('Wayback')
  const toolSwitch = page.getByRole('switch', { name: /Wayback Machine/ })
  const originallyEnabled = await toolSwitch.getAttribute('aria-checked') === 'true'
  await toolSwitch.click()
  await expect(toolSwitch).toHaveAttribute('aria-checked', String(!originallyEnabled))
  await page.reload()
  await page.getByTitle('Settings (Ctrl+,)').click()
  await page.getByRole('button', { name: 'Tools' }).click()
  await page.getByPlaceholder('Buscar por nome, função ou pacote…').fill('Wayback')
  const persistedSwitch = page.getByRole('switch', { name: /Wayback Machine/ })
  await expect(persistedSwitch).toHaveAttribute('aria-checked', String(!originallyEnabled))
  await persistedSwitch.click()
  await expect(persistedSwitch).toHaveAttribute('aria-checked', String(originallyEnabled))

  await page.getByRole('button', { name: 'Básico' }).click()
  await expect(page.getByRole('button', { name: 'Básico' })).toHaveAttribute('aria-pressed', 'true')
})
