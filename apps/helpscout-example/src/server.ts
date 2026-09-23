import { authz, type AuditEvent } from 'mcp-authz';
import { z } from 'zod';
import { docsClient, mailboxClient } from './helpscout';
import { policy } from './policy';

const { tool, server } = authz(policy);

const json = (value: unknown) => ({
  content: [{ type: 'text' as const, text: JSON.stringify(value, null, 2) }],
});
const readOnly = { readOnlyHint: true, idempotentHint: true };

type Docs = ReturnType<typeof docsClient>;
type Mailbox = ReturnType<typeof mailboxClient>;

function docsTools(docs: Docs) {
  return [
    tool(
      'search_articles',
      {
        permission: 'helpscout:read',
        description: 'Search the Help Scout Docs knowledge base. Returns article ids, names and URLs.',
        inputSchema: z.object({
          query: z.string().describe('Free-text search, e.g. "reset password"'),
          collectionId: z.string().optional().describe('Restrict to one collection'),
        }),
        annotations: readOnly,
      },
      async ({ query, collectionId }) => json(await docs('search/articles', { query, collectionId })),
    ),

    tool(
      'get_article',
      {
        permission: 'helpscout:read',
        description: 'Fetch one Docs article in full, by id or article number.',
        inputSchema: z.object({ id: z.string().describe('Article id or number') }),
        annotations: readOnly,
        audit: ({ id }) => `article:${id}`,
      },
      async ({ id }) => json(await docs(`articles/${encodeURIComponent(id)}`)),
    ),

    tool(
      'list_collections',
      {
        permission: 'helpscout:read',
        description: 'List Docs collections, so a search can be scoped to one.',
        annotations: readOnly,
      },
      async () => json(await docs('collections')),
    ),
  ];
}

function mailboxTools(mailbox: Mailbox) {
  return [
    tool(
      'search_conversations',
      {
        permission: 'helpscout:read',
        description:
          'Search inbox conversations. `query` uses Help Scout search syntax, e.g. (status:active AND tag:billing) or email:"a@b.com".',
        inputSchema: z.object({
          query: z.string().describe('Help Scout search query'),
          inbox: z.string().optional().describe('Inbox id to search within'),
          status: z.enum(['active', 'pending', 'closed', 'spam', 'all']).optional(),
          page: z.number().int().positive().optional(),
        }),
        annotations: readOnly,
      },
      async ({ query, inbox, status, page }) =>
        json(await mailbox('conversations', { query, mailbox: inbox, status, page: page?.toString() })),
    ),

    tool(
      'get_conversation',
      {
        permission: 'helpscout:read',
        description: 'Fetch one conversation with its threads (customer messages, replies and notes).',
        inputSchema: z.object({ id: z.string().describe('Conversation id') }),
        annotations: readOnly,
        audit: ({ id }) => `conversation:${id}`,
      },
      async ({ id }) => json(await mailbox(`conversations/${encodeURIComponent(id)}`, { embed: 'threads' })),
    ),

    tool(
      'get_customer',
      {
        permission: 'helpscout:read',
        description: 'Look up a customer profile by email address.',
        inputSchema: z.object({ email: z.string().email() }),
        annotations: readOnly,
        audit: ({ email }) => `customer:${email}`,
      },
      async ({ email }) => json(await mailbox('customers', { query: `(email:"${email}")` })),
    ),

    tool(
      'list_inboxes',
      {
        permission: 'helpscout:read',
        description: 'List inboxes (mailboxes) with their ids, for scoping a conversation search.',
        annotations: readOnly,
      },
      async () => json(await mailbox('mailboxes')),
    ),
  ];
}

/** Mailbox tools exist only when their credential does: a tool that cannot work is not listed. */
export function buildServer(docs: Docs, mailbox?: Mailbox) {
  return server([...docsTools(docs), ...(mailbox ? mailboxTools(mailbox) : [])], {
    name: 'mcp-authz-helpscout-example',
    version: '0.1.0',
    onAudit: (event: AuditEvent) => console.log(JSON.stringify(event)),
  });
}
