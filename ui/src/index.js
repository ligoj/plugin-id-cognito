/*
 * Plugin "id-cognito" — AWS Cognito implementation of plugin-id.
 *
 * Tool-level plugin: lives at `service:id:cognito` in the node tree. It
 * does not own routes or a top-level component — it augments the parent
 * `plugin-id` via:
 *
 *   - i18n: Cognito-specific parameter labels (access key, pool id, ...)
 *     so the subscribe wizard's auto-rendered parameter form shows
 *     friendly names.
 *   - feature('parameterField'): the subscription's parent-group /
 *     group inputs reuse the PARENT's shared rich fields (autocomplete +
 *     composite group editor), resolved through the runtime registry —
 *     mirrors the legacy `cognito.js` Select2 registrations.
 *   - feature('parameterLayout'): clusters the AWS connection parameters
 *     into one labelled wizard group.
 *
 * Authored as source — compiled to `/main/id-cognito/vue/index.js` by
 * Vite. Shared host surface (stores, components) is imported from
 * `@ligoj/host` and kept external at build so plugin and host share the
 * same instances.
 */
import { useI18nStore } from '@ligoj/host'
import enMessages from './i18n/en.js'
import frMessages from './i18n/fr.js'
import service from './service.js'

const features = {
  parameterField: service.parameterField,
  parameterLayout: service.parameterLayout,
}

export default {
  id: 'id-cognito',
  label: 'Identity AWS Cognito',
  // Declared dependency: the parent service-level plugin contributes the
  // inherited parameter labels (`service:id:group`, …), the shared
  // parameter-field components resolved from the registry, and the
  // `/id/*` routes. The loader awaits these before calling our
  // install(), so the parent's bundle is already registered when any
  // delegation or label lookup runs.
  requires: ['id'],
  // No routes — the legacy `cognito.html` carried no screen of its own;
  // parameter forms come from the parent's wizard.
  install() {
    const i18n = useI18nStore()
    i18n.merge(enMessages, 'en')
    i18n.merge(frMessages, 'fr')
  },
  feature(action, ...args) {
    const fn = features[action]
    if (!fn) throw new Error(`Plugin "id-cognito" has no feature "${action}"`)
    return fn(...args)
  },
  service,
  meta: { icon: 'mdi-aws', color: 'orange-darken-3' },
}

export { service }
