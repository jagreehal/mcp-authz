/** Docs API: Basic auth, key as username, `X` as password. */
export function docsClient(apiKey: string, fetchFn: typeof fetch = fetch) {
  const auth = `Basic ${Buffer.from(`${apiKey}:X`).toString('base64')}`;
  return async (path: string, query: Record<string, string | undefined> = {}) =>
    getJson(fetchFn, new URL(path, 'https://docsapi.helpscout.net/v1/'), query, auth);
}

/** Mailbox API 2.0: client credentials, token good for 2 days, refreshed on expiry. */
export function mailboxClient(appId: string, appSecret: string, fetchFn: typeof fetch = fetch) {
  let token: { value: string; expiresAt: number } | undefined;

  async function bearer(): Promise<string> {
    if (token && Date.now() < token.expiresAt) return token.value;
    const response = await fetchFn('https://api.helpscout.net/v2/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'client_credentials',
        client_id: appId,
        client_secret: appSecret,
      }),
    });
    if (!response.ok) throw new Error(`Help Scout token request failed: HTTP ${response.status}`);
    const body = (await response.json()) as { access_token: string; expires_in: number };
    // Renew a minute early so a call never straddles the expiry.
    token = { value: body.access_token, expiresAt: Date.now() + (body.expires_in - 60) * 1000 };
    return token.value;
  }

  return async (path: string, query: Record<string, string | undefined> = {}) =>
    getJson(fetchFn, new URL(path, 'https://api.helpscout.net/v2/'), query, `Bearer ${await bearer()}`);
}

async function getJson(
  fetchFn: typeof fetch,
  url: URL,
  query: Record<string, string | undefined>,
  authorization: string,
): Promise<unknown> {
  for (const [key, value] of Object.entries(query)) if (value !== undefined) url.searchParams.set(key, value);
  const response = await fetchFn(url, {
    headers: { Authorization: authorization, Accept: 'application/json' },
  });
  if (!response.ok) throw new Error(`Help Scout ${url.pathname}: HTTP ${response.status}`);
  return response.json();
}
