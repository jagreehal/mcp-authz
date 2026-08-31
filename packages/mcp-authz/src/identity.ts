/**
 * What the token verifier proved about the caller.
 *
 * Its own file because everything downstream depends on it and nothing it
 * depends on is vendor-specific.
 */
export type Identity = {
  /** Exact token issuer. Stable identity is the pair `(issuer, sub)`. */
  issuer: string;
  /**
   * The token's `sub`. Stable across an email change and across a rename, which
   * is why policy should prefer it for anything durable.
   */
  sub: string;
  /** Email asserted by the issuer, when present. Never a client-supplied header. */
  email?: string;
  /** Whether the verifier proved the email claim. */
  emailVerified: boolean;
  /** Google Workspace domain (the `hd` claim), when the AS passes it through. */
  domain?: string;
  /**
   * The remaining verified claims, so policy can match on groups an IdP already
   * maintains rather than a list somebody has to keep in step by hand.
   */
  claims: Record<string, unknown>;
};

/** Why a verified caller was refused. */
export type DenialReason = 'not_permitted' | 'no_credential';

export class AccessDeniedError extends Error {
  readonly email: string;
  readonly reason: DenialReason;

  constructor(email: string, reason: DenialReason, message: string) {
    super(message);
    this.name = 'AccessDeniedError';
    this.email = email;
    this.reason = reason;
  }

  static notPermitted(email: string, policyHint = 'the access policy'): AccessDeniedError {
    return new AccessDeniedError(
      email,
      'not_permitted',
      `${email} matches no rule in ${policyHint}, so they hold no permissions. Ask an administrator to grant them a role.`,
    );
  }

  static noCredential(email: string, credentialHint = 'a backend credential'): AccessDeniedError {
    return new AccessDeniedError(
      email,
      'no_credential',
      `${email} is permitted but has no ${credentialHint}, and no shared account is configured.`,
    );
  }
}
