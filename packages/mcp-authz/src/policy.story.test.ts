import { story } from 'executable-stories-vitest';
import { describe, expect, it } from 'vitest';
import { definePolicy, reconcile } from './policy';
import type { Identity } from './identity';

const caller = (email: string, extra: Partial<Identity> = {}): Identity => ({
  issuer: 'https://issuer.example',
  sub: `sub-${email}`,
  email,
  emailVerified: true,
  claims: {},
  ...extra,
});

/**
 * The policy is the part an administrator actually edits, so its failure modes
 * are the ones that bite in production.
 */

describe('Deciding what a caller may do', () => {
  it('keys a stable subject by issuer as well as sub', () => {
    const policy = definePolicy({
      roles: { member: ['cases:read'] },
      rules: [
        {
          match: { issuer: 'https://trusted.example', sub: 'shared-subject' },
          role: 'member',
        },
      ],
    });

    expect(
      policy(
        caller('person@example.com', {
          issuer: 'https://trusted.example',
          sub: 'shared-subject',
        }),
      ).can('cases:read'),
    ).toBe(true);
    expect(
      policy(
        caller('person@example.com', {
          issuer: 'https://other.example',
          sub: 'shared-subject',
        }),
      ).can('cases:read'),
    ).toBe(false);
  });

  it('grants nothing to someone no rule matches', async ({ task }) => {
    story.init(task, { tags: ['policy', 'security'], covers: ['src/policy.ts'] });

    story.given('a policy that opens the company domain and names one editor');
    const policy = definePolicy({
      roles: { reader: ['cases:read'], editor: ['cases:read', 'cases:write'] },
      rules: [
        { match: { domain: 'acme.com' }, role: 'reader' },
        { match: { email: 'alice@acme.com' }, role: 'editor' },
      ],
    });

    story.then('a colleague gets the domain role');
    expect(policy(caller('dana@acme.com')).can('cases:read')).toBe(true);
    expect(policy(caller('dana@acme.com')).can('cases:write')).toBe(false);

    story.and('the named editor gets both roles, and the permissions union');
    const alice = policy(caller('alice@acme.com'));
    expect(alice.roles.sort()).toEqual(['editor', 'reader']);
    expect(alice.can('cases:write')).toBe(true);

    story.and('an outsider gets nothing at all');
    story.note(
      'There is no default setting to get wrong. Matching no rule means no permissions, ' +
        'and a policy that fails open is invisible: it works for everybody, including ' +
        'the people it was written to exclude.',
    );
    expect(policy(caller('outsider@other.com')).permissions).toEqual([]);
  });

  it('lets deny win over a grant that nobody tidied up', async ({ task }) => {
    story.init(task, { tags: ['policy', 'security'], covers: ['src/policy.ts'] });

    story.given('a contractor who left, denied by subject but still on the editor rule');
    const policy = definePolicy({
      roles: { editor: ['cases:write'] },
      rules: [
        { match: { email: 'contractor@acme.com' }, role: 'editor' },
        { match: { sub: 'sub-contractor@acme.com' }, deny: true },
      ],
    });

    story.when('they connect');
    story.then('deny wins, and it is keyed to the subject rather than the email');
    story.note(
      'The half-finished revocation is the realistic one. Denying by `sub` also survives ' +
        'the email being reassigned to a new joiner.',
    );
    expect(policy(caller('contractor@acme.com')).permissions).toEqual([]);
  });

  it('matches an IdP group claim so the list is maintained in one place', async ({ task }) => {
    story.init(task, { tags: ['policy'], covers: ['src/policy.ts'] });

    story.given('a policy keyed to a group the identity provider already maintains');
    const policy = definePolicy({
      roles: { lead: ['cases:write'] },
      rules: [{ match: { claim: { 'org.groups': 'qa-leads' } }, role: 'lead' }],
    });

    story.then('an array claim matches when it contains the value');
    const inGroup = caller('lead@acme.com', { claims: { org: { groups: ['qa-leads', 'oncall'] } } });
    expect(policy(inGroup).can('cases:write')).toBe(true);

    story.and('somebody in a different group is refused without being named anywhere');
    const other = caller('dev@acme.com', { claims: { org: { groups: ['engineering'] } } });
    expect(policy(other).permissions).toEqual([]);
  });

  it('matches a namespaced claim whose own name contains dots', async ({ task }) => {
    story.init(task, { tags: ['policy'], covers: ['src/policy.ts'] });

    story.given('the namespaced claim an IdP actually emits');
    story.note(
      'Auth0 writes group memberships to a URL-shaped claim. Treating the name as a ' +
        'dotted path splits it at `https://acme` and matches nothing, so the rule looks ' +
        'correct and silently grants no one.',
    );
    const policy = definePolicy({
      roles: { lead: ['cases:write'] },
      rules: [{ match: { claim: { 'https://acme.com/groups': 'qa-leads' } }, role: 'lead' }],
    });

    story.then('the literal claim name wins over splitting it on dots');
    const lead = caller('lead@acme.com', { claims: { 'https://acme.com/groups': ['qa-leads'] } });
    expect(policy(lead).can('cases:write')).toBe(true);
  });

  it('refuses to start on a policy that cannot mean what it says', async ({ task }) => {
    story.init(task, { tags: ['policy', 'operations'], covers: ['src/policy.ts'] });

    story.given('a rule naming a role that was renamed or never existed');
    story.then('it throws at construction, naming the rule and the role');
    expect(() =>
      definePolicy({
        roles: { reader: ['cases:read'] },
        // @ts-expect-error the role name is checked at compile time too
        rules: [{ match: { domain: 'acme.com' }, role: 'raeder' }],
      }),
    ).toThrow("names role 'raeder'");

    story.and('a repeated permission is tidied rather than fatal');
    story.note(
      'Everything downstream is a set, so a repeat changes nothing. Failing the boot over ' +
        "it punishes a policy assembled from JSON, where a duplicate is somebody else's bug.",
    );
    const repeated = definePolicy({
      roles: { reader: ['cases:read', 'cases:read'] },
      rules: [{ match: { domain: 'acme.com' }, role: 'reader' }],
    });
    expect(repeated.roles.get('reader')).toEqual(['cases:read']);
    expect(
      repeated({
        issuer: 'https://issuer.example',
        sub: 'u1',
        email: 'dana@acme.com',
        emailVerified: true,
        claims: {},
      }).permissions,
    ).toEqual(['cases:read']);

    story.and('a rule that grants nothing is a mistake rather than a subtle deny');
    expect(() => definePolicy({ roles: {}, rules: [{ match: { domain: 'acme.com' } }] })).toThrow(
      'grants nothing',
    );

    story.and('runtime-loaded match values are validated before the first request');
    expect(() =>
      definePolicy({
        roles: { reader: ['cases:read'] },
        rules: [{ match: { domain: 42 }, role: 'reader' }],
      } as never),
    ).toThrow('domain');
  });

  it('uses an explicit permission catalogue for wildcard-only policies', () => {
    const policy = definePolicy({
      permissions: ['cases:read', 'cases:write'],
      roles: { admin: ['*'] },
      rules: [{ role: 'admin' }],
    });

    expect(policy(caller('admin@acme.com')).can('cases:write')).toBe(true);
  });
});

describe('Reconciling the policy against the tools at startup', () => {
  it('reports drift in both directions', async ({ task }) => {
    story.init(task, { tags: ['policy', 'operations'], covers: ['src/policy.ts'] });

    story.given('a role granting a permission no tool requires');
    story.and('a tool requiring a permission no role grants');
    const roles = new Map([['lead', ['cases:read', 'cases:write', 'cases:archive']]]);
    const required = new Map([
      ['get_case', 'cases:read'],
      ['update_case', 'cases:write'],
      ['delete_case', 'cases:delete'],
    ]);

    story.when('the server boots');
    const { error, warning } = reconcile(roles, required);

    story.then('the unreachable tool is fatal');
    story.note(
      'A tool no role can reach is dead code that looks live. A gateway cannot run this ' +
        'check — it does not learn the tool list until traffic arrives.',
    );
    expect(error).toContain('delete_case');
    expect(error).toContain('granted by: no role');

    story.and('the unused permission is only a warning');
    story.note(
      'Granting a role ahead of the tool that will use it is how a staged rollout works. ' +
        'Failing the boot on it teaches people to add dummy tools to deploy.',
    );
    expect(warning).toContain('cases:archive');
    expect(warning).toContain('required by: no registered capability');

    story.and('a policy that matches its tools starts silently');
    expect(reconcile(new Map([['reader', ['cases:read']]]), new Map([['get_case', 'cases:read']]))).toEqual(
      {},
    );
  });
});
