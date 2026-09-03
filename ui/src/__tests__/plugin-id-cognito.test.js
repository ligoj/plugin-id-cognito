import { describe, it, expect } from 'vitest'
import { setActivePinia, createPinia } from 'pinia'
// `@ligoj/host` is aliased in vite.config.js → app-ui/src/host.js so the
// plugin's tests use the real registry / stores / helpers the host
// publishes at runtime.
import { pluginRegistry, useI18nStore } from '@ligoj/host'
// Plugin source (pre-build). The built bundle under
// ../src/main/resources/.../webjars/id-cognito/vue/index.js is what the
// host loads at runtime — here we test the authoring surface directly.
import pluginIdCognitoDef from '../index.js'
// Cross-plugin reference: the shared parameter fields live in the PARENT
// plugin and are resolved through the runtime registry. The two repos sit
// side by side in the workspace.
import pluginIdDef from '../../../../plugin-id/ui/src/index.js'

describe('plugin-id-cognito contract', () => {
  it('exports required fields (id, label, install, feature, service, meta)', () => {
    expect(pluginIdCognitoDef.id).toBe('id-cognito')
    expect(typeof pluginIdCognitoDef.label).toBe('string')
    expect(typeof pluginIdCognitoDef.install).toBe('function')
    expect(typeof pluginIdCognitoDef.feature).toBe('function')
    expect(pluginIdCognitoDef.service).toBeTypeOf('object')
    expect(pluginIdCognitoDef.meta).toMatchObject({ icon: expect.any(String), color: expect.any(String) })
  })

  it('declares `requires: ["id"]` — parent plugin must load first', () => {
    expect(pluginIdCognitoDef.requires).toEqual(['id'])
  })

  it('declares no routes — tool-level augmentation only', () => {
    expect(pluginIdCognitoDef.routes).toBeUndefined()
  })

  it('feature() throws for unknown actions — delegateFeature() swallows these', () => {
    expect(() => pluginIdCognitoDef.feature('unknown')).toThrow(/no feature "unknown"/)
    // In particular no subscription-row features (legacy cognito.js had none)
    expect(() => pluginIdCognitoDef.feature('renderFeatures', {})).toThrow(/no feature "renderFeatures"/)
  })

  it('install() merges the Cognito parameter labels', () => {
    setActivePinia(createPinia())
    pluginIdCognitoDef.install()
    const { t } = useI18nStore()
    expect(t('service:id:cognito:pool-id')).toBe('Cognito Pool Id')
    expect(t('service:id:cognito:access-key-id')).toBe('Access Key Id')
  })

  it('parameterField() resolves the PARENT shared group fields in subscribe mode', () => {
    setActivePinia(createPinia())
    // Register plugin-id the way the loader does (guaranteed before us by
    // `requires: ['id']`) — the fields come from its `service.parameterFields`.
    pluginRegistry.register('id', pluginIdDef)
    const parentComp = pluginIdCognitoDef.feature('parameterField', {
      parameter: { id: 'service:id:parent-group' },
      mode: 'create',
      isNode: false,
    })
    const groupComp = pluginIdCognitoDef.feature('parameterField', {
      parameter: { id: 'service:id:group' },
      mode: 'link',
      isNode: false,
    })
    expect(parentComp).toBe(pluginIdDef.service.parameterFields['service:id:parent-group'])
    expect(groupComp).toBe(pluginIdDef.service.parameterFields['service:id:group'])
  })

  it('parameterField() returns null in node edit/create mode and for uncustomised parameters', () => {
    setActivePinia(createPinia())
    pluginRegistry.register('id', pluginIdDef)
    expect(pluginIdCognitoDef.feature('parameterField', {
      parameter: { id: 'service:id:group' }, mode: 'create', isNode: true,
    })).toBeNull()
    // Cognito's own connection parameters keep the default typed inputs
    expect(pluginIdCognitoDef.feature('parameterField', {
      parameter: { id: 'service:id:cognito:pool-id' }, mode: 'create', isNode: false,
    })).toBeNull()
    // No OU customisation (LDAP-specific) — parity with the legacy cognito.js
    expect(pluginIdCognitoDef.feature('parameterField', {
      parameter: { id: 'service:id:ou' }, mode: 'create', isNode: false,
    })).toBeNull()
  })

  it('parameterLayout() clusters the five AWS connection parameters', () => {
    const layout = pluginIdCognitoDef.feature('parameterLayout')
    expect(layout).toHaveLength(1)
    expect(layout[0].label).toBe('id.cognito.wizard.connection')
    expect(layout[0].parameters).toEqual([
      'service:id:cognito:access-key-id',
      'service:id:cognito:secret-access-key',
      'service:id:cognito:region',
      'service:id:cognito:pool-id',
      'service:id:cognito:user-attribute-id',
    ])
  })
})
