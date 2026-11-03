function unauthorized() {
  return new Response("Wymagane jest hasło.", {
    status: 401,
    headers: {
      "WWW-Authenticate": 'Basic realm="Strona rocznicowa", charset="UTF-8"',
      "Cache-Control": "no-store",
    },
  });
}

export async function onRequest(context) {
  const authorization = context.request.headers.get("Authorization");
  const match = authorization?.match(/^Basic\s+(.+)$/i);

  if (!match) {
    return unauthorized();
  }

  try {
    const bytes = Uint8Array.from(atob(match[1]), (char) => char.charCodeAt(0));
    const credentials = new TextDecoder().decode(bytes);
    const separator = credentials.indexOf(":");

    const username = credentials.slice(0, separator);
    const password = credentials.slice(separator + 1);

    if (
      separator === -1 ||
      username !== "rocznica" ||
      !context.env.SITE_PASSWORD ||
      password !== context.env.SITE_PASSWORD
    ) {
      return unauthorized();
    }
  } catch {
    return unauthorized();
  }

  const response = await context.next();
  const headers = new Headers(response.headers);
  headers.set("Cache-Control", "private, no-store");

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}