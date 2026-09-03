import { pluginRegistry } from '@ligoj/host'

/**
 * Shared subscription parameter fields owned by the PARENT plugin-id
 * (parent-group autocomplete, composite group editor — they only hit
 * `rest/service/id/...` endpoints). A sibling bundle cannot be imported,
 * so they are resolved at call time through the runtime registry — the
 * parent is guaranteed loaded by `requires: ['id']`. Mirrors the legacy
 * `cognito.js`, which registered the same two Select2 fields.
 */
function sharedIdFields() {
  return pluginRegistry.get('id')?.service?.parameterFields || {}
}

const service = {
  /**
   * Wizard hook: subscription mode only — in `edit-node` / `create-node`
   * the wizard edits the AWS connection parameters, plain typed inputs
   * where the default renderer is right.
   */
  parameterField({ parameter, isNode } = {}) {
    if (isNode) return null
    return sharedIdFields()[parameter?.id] || null
  },

  /**
   * Node/subscription form layout: the five AWS connection parameters in
   * a single labelled group, ordered credentials first. Anything else
   * (the parent's subscription parameters) keeps the default ordering.
   */
  parameterLayout() {
    return [
      {
        label: 'id.cognito.wizard.connection',
        parameters: [
          'service:id:cognito:access-key-id',
          'service:id:cognito:secret-access-key',
          'service:id:cognito:region',
          'service:id:cognito:pool-id',
          'service:id:cognito:user-attribute-id',
        ],
      },
    ]
  },
}

export default service
