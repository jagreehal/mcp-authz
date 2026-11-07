// Generated from a recorded catalogue. Replace every TODO with a real permission.

export const PERMISSIONS = {
  count_cases: 'cases:read',
  delete_case: 'cases:admin',
  get_account: 'cases:read',
  get_case: 'cases:read',
  'prompt:payroll_report': 'payroll:read',
  'prompt:triage': 'cases:read',
  'resource:case': 'cases:read',
  'resource:cases': 'cases:read',
  'resource:payroll': 'payroll:read',
  'resource:secrets': 'payroll:read',
  run_query: 'cases:admin',
  search_cases: 'cases:read',
  transfer_credit: 'cases:write',
  update_case: 'cases:write',
} as const;

export type Permission = (typeof PERMISSIONS)[keyof typeof PERMISSIONS];

// What each capability said to the model when this was recorded. createMcpProxy()
// hides one that no longer matches, so a server cannot keep an approved name and
// change what it tells the model. Re-record to approve a change.
export const DEFINITIONS = {
  count_cases: {
    annotations: {
      readOnlyHint: true,
    },
    description: 'How many cases are open.',
    inputSchema: {
      properties: {},
      type: 'object',
    },
    name: 'count_cases',
    outputSchema: {
      $schema: 'https://json-schema.org/draft/2020-12/schema',
      additionalProperties: false,
      properties: {
        count: {
          maximum: 9007199254740991,
          minimum: -9007199254740991,
          type: 'integer',
        },
      },
      required: ['count'],
      type: 'object',
    },
  },
  delete_case: {
    annotations: {
      destructiveHint: true,
      readOnlyHint: true,
    },
    description: 'Remove a case and its history. Cannot be undone.',
    inputSchema: {
      $schema: 'https://json-schema.org/draft/2020-12/schema',
      properties: {
        id: {
          type: 'string',
        },
      },
      required: ['id'],
      type: 'object',
    },
    name: 'delete_case',
  },
  get_account: {
    annotations: {
      readOnlyHint: true,
    },
    description: 'The account a case belongs to.',
    inputSchema: {
      properties: {},
      type: 'object',
    },
    name: 'get_account',
    outputSchema: {
      $schema: 'https://json-schema.org/draft/2020-12/schema',
      additionalProperties: false,
      properties: {
        accountId: {
          maximum: 9007199254740992,
          type: 'number',
        },
      },
      required: ['accountId'],
      type: 'object',
    },
  },
  get_case: {
    annotations: {
      readOnlyHint: true,
    },
    description: 'One case with its steps and history.',
    inputSchema: {
      $schema: 'https://json-schema.org/draft/2020-12/schema',
      properties: {
        id: {
          type: 'string',
        },
      },
      required: ['id'],
      type: 'object',
    },
    name: 'get_case',
  },
  'prompt:payroll_report': {
    arguments: [
      {
        name: 'month',
        required: true,
      },
    ],
    description: 'Summarise payroll for a month.',
    name: 'payroll_report',
  },
  'prompt:triage': {
    arguments: [
      {
        name: 'case',
        required: true,
      },
    ],
    description: 'Walk through a failing case.',
    name: 'triage',
  },
  'resource:case': {
    mimeType: 'text/plain',
    name: 'case',
    uriTemplate: 'cases://case/{id}',
  },
  'resource:cases': {
    mimeType: 'text/plain',
    name: 'cases',
    uri: 'cases://all',
  },
  'resource:payroll': {
    mimeType: 'text/plain',
    name: 'payroll',
    uri: 'secret://payroll',
  },
  'resource:secrets': {
    mimeType: 'text/plain',
    name: 'secrets',
    uriTemplate: 'secret://{+rest}',
  },
  run_query: {
    annotations: {
      destructiveHint: true,
    },
    description:
      'Run any query the case API supports. Filters, sorts, joins across cases, people and labels, aggregates, and bulk updates when `mode` is "write".',
    inputSchema: {
      $schema: 'https://json-schema.org/draft/2020-12/schema',
      properties: {
        from: {
          enum: ['cases', 'people', 'labels', 'comments', 'attachments'],
          type: 'string',
        },
        limit: {
          maximum: 10000,
          minimum: -9007199254740991,
          type: 'integer',
        },
        mode: {
          description: '"write" applies changes to every matching case',
          enum: ['read', 'write'],
          type: 'string',
        },
        orderBy: {
          items: {
            properties: {
              direction: {
                enum: ['asc', 'desc'],
                type: 'string',
              },
              field: {
                type: 'string',
              },
            },
            required: ['field', 'direction'],
            type: 'object',
          },
          type: 'array',
        },
        set: {
          additionalProperties: {},
          description: 'Fields to change, when mode is "write"',
          propertyNames: {
            type: 'string',
          },
          type: 'object',
        },
        where: {
          items: {
            properties: {
              field: {
                description: 'Any field of the chosen collection, dotted for nested fields',
                type: 'string',
              },
              op: {
                enum: ['eq', 'ne', 'lt', 'lte', 'gt', 'gte', 'in', 'contains', 'startsWith', 'exists'],
                type: 'string',
              },
              value: {
                description: 'Compared using the field type; arrays for "in"',
              },
            },
            required: ['field', 'op', 'value'],
            type: 'object',
          },
          type: 'array',
        },
      },
      required: ['mode', 'from'],
      type: 'object',
    },
    name: 'run_query',
  },
  search_cases: {
    annotations: {
      readOnlyHint: true,
    },
    description: 'Find cases by text, label or owner.',
    inputSchema: {
      $schema: 'https://json-schema.org/draft/2020-12/schema',
      properties: {
        query: {
          description: 'Words to look for',
          maxLength: 200,
          type: 'string',
        },
      },
      required: ['query'],
      type: 'object',
    },
    name: 'search_cases',
  },
  transfer_credit: {
    description: 'Move credit between accounts.',
    inputSchema: {
      $schema: 'https://json-schema.org/draft/2020-12/schema',
      properties: {
        amount: {
          maximum: 9007199254740992,
          type: 'number',
        },
      },
      required: ['amount'],
      type: 'object',
    },
    name: 'transfer_credit',
  },
  update_case: {
    description: 'Change the title or status of a case.',
    inputSchema: {
      $schema: 'https://json-schema.org/draft/2020-12/schema',
      properties: {
        id: {
          type: 'string',
        },
        status: {
          enum: ['open', 'closed'],
          type: 'string',
        },
        title: {
          type: 'string',
        },
      },
      required: ['id'],
      type: 'object',
    },
    name: 'update_case',
  },
  'server:instructions': {
    instructions: 'Search before you read a case. Cases are identified as C-<number>.',
  },
};

// Where each resource answers. createMcpProxy() matches a read against these,
// templates included, because a resources/read carries a URI and not a label.
export const RESOURCE_URIS = {
  'resource:case': 'cases://case/{id}',
  'resource:cases': 'cases://all',
  'resource:payroll': 'secret://payroll',
  'resource:secrets': 'secret://{+rest}',
} as const;
