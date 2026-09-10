const DISCORD_REDIRECT_URI =
  "https://blemm-studios.blemmished.workers.dev/auth/callback";

const SESSION_COOKIE = "__Host-blemm_session";
const STATE_COOKIE = "__Host-discord_state";

const SESSION_MAX_AGE = 60 * 60 * 24 * 7;
const STATE_MAX_AGE = 60 * 10;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const pathname = url.pathname;

    // ================================
    // DISCORD LOGIN
    // ================================

    if (pathname === "/auth/discord") {
      return startDiscordLogin(env);
    }

    // ================================
    // DISCORD CALLBACK
    // ================================

    if (pathname === "/auth/callback") {
      return handleDiscordCallback(request, env);
    }

    // ================================
    // LOGOUT
    // ================================

    if (pathname === "/auth/logout") {
      return logout();
    }

    // ================================
    // CURRENT DISCORD USER
    // ================================

    if (pathname === "/api/session") {
      return getSession(request, env);
    }

    // ================================
    // TEMPORARY DISCORD DEBUG
    // ================================

    if (pathname === "/api/debug-discord") {
      return new Response(
        JSON.stringify({
          clientId: env.DISCORD_CLIENT_ID || null,
          hasClientSecret: !!env.DISCORD_CLIENT_SECRET,
          clientSecretLength: env.DISCORD_CLIENT_SECRET
            ? env.DISCORD_CLIENT_SECRET.length
            : 0,
          hasSessionSecret: !!env.SESSION_SECRET
        }),
        {
          headers: {
            "Content-Type": "application/json",
            "Cache-Control": "no-store"
          }
        }
      );
    }

    // ================================
    // PROTECT WEBSITE PAGES
    // ================================

    if (isProtectedPage(pathname)) {
      const session = await getValidSession(request, env);

      if (!session) {
        return Response.redirect(
          new URL("/login.html", request.url).toString(),
          302
        );
      }
    }

    return env.ASSETS.fetch(request);
  }
};


// ================================
// PROTECTED PAGES
// ================================

function isProtectedPage(pathname) {
  return (
    pathname === "/" ||
    pathname === "/index.html" ||
    pathname === "/commissions.html"
  );
}


// ================================
// START DISCORD LOGIN
// ================================

async function startDiscordLogin(env) {
  const state = randomString(32);

  const discordURL = new URL(
    "https://discord.com/oauth2/authorize"
  );

  discordURL.searchParams.set(
    "client_id",
    env.DISCORD_CLIENT_ID
  );

  discordURL.searchParams.set(
    "response_type",
    "code"
  );

  discordURL.searchParams.set(
    "scope",
    "identify"
  );

  discordURL.searchParams.set(
    "state",
    state
  );

  discordURL.searchParams.set(
    "redirect_uri",
    DISCORD_REDIRECT_URI
  );

  const response = new Response(null, {
    status: 302,
    headers: {
      "Location": discordURL.toString()
    }
  });

  response.headers.append(
    "Set-Cookie",
    `${STATE_COOKIE}=${state}; Max-Age=${STATE_MAX_AGE}; Path=/; HttpOnly; Secure; SameSite=Lax`
  );

  return response;
}


// ================================
// DISCORD CALLBACK
// ================================

async function handleDiscordCallback(request, env) {
  const url = new URL(request.url);

  const code = url.searchParams.get("code");
  const returnedState = url.searchParams.get("state");

  if (!code || !returnedState) {
    return errorPage(
      "Discord did not provide a valid authorization code."
    );
  }

  const cookies = parseCookies(
    request.headers.get("Cookie")
  );

  const savedState = cookies[STATE_COOKIE];

  if (!savedState || savedState !== returnedState) {
    return errorPage(
      "Your Discord login session expired. Please try again."
    );
  }

  // ================================
  // EXCHANGE CODE FOR ACCESS TOKEN
  // ================================

  const tokenBody = new URLSearchParams();

  tokenBody.set(
    "client_id",
    env.DISCORD_CLIENT_ID
  );

  tokenBody.set(
    "client_secret",
    env.DISCORD_CLIENT_SECRET
  );

  tokenBody.set(
    "grant_type",
    "authorization_code"
  );

  tokenBody.set(
    "code",
    code
  );

  tokenBody.set(
    "redirect_uri",
    DISCORD_REDIRECT_URI
  );

  const tokenResponse = await fetch(
    "https://discord.com/api/oauth2/token",
    {
      method: "POST",

      headers: {
        "Content-Type":
          "application/x-www-form-urlencoded"
      },

      body: tokenBody.toString()
    }
  );

  if (!tokenResponse.ok) {
    const errorText = await tokenResponse.text();

    return errorPage(
      `Discord token exchange failed.<br><br>
       <small>${escapeHTML(errorText)}</small>`
    );
  }

  const tokenData = await tokenResponse.json();

  if (!tokenData.access_token) {
    return errorPage(
      "Discord did not return an access token."
    );
  }

  // ================================
  // GET DISCORD ACCOUNT
  // ================================

  const userResponse = await fetch(
    "https://discord.com/api/v10/users/@me",
    {
      headers: {
        Authorization:
          `Bearer ${tokenData.access_token}`
      }
    }
  );

  if (!userResponse.ok) {
    return errorPage(
      "We could not retrieve your Discord account."
    );
  }

  const user = await userResponse.json();

  // username = actual Discord username
  // global_name = display name

  const session = {
    id: user.id,
    username: user.username,
    expires:
      Date.now() +
      SESSION_MAX_AGE * 1000
  };

  const payload = base64urlEncode(
    JSON.stringify(session)
  );

  const signature = await sign(
    payload,
    env.SESSION_SECRET
  );

  const sessionCookie =
    `${SESSION_COOKIE}=${payload}.${signature}; ` +
    `Max-Age=${SESSION_MAX_AGE}; ` +
    `Path=/; ` +
    `HttpOnly; ` +
    `Secure; ` +
    `SameSite=Lax`;

  const response = new Response(null, {
    status: 302,
    headers: {
      "Location": "/"
    }
  });

  response.headers.append(
    "Set-Cookie",
    sessionCookie
  );

  response.headers.append(
    "Set-Cookie",
    `${STATE_COOKIE}=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Lax`
  );

  return response;
}


// ================================
// SESSION API
// ================================

async function getSession(request, env) {
  const session =
    await getValidSession(request, env);

  if (!session) {
    return new Response(
      JSON.stringify({
        loggedIn: false
      }),
      {
        status: 401,
        headers: {
          "Content-Type":
            "application/json",
          "Cache-Control":
            "no-store"
        }
      }
    );
  }

  return new Response(
    JSON.stringify({
      loggedIn: true,
      id: session.id,
      username: session.username
    }),
    {
      status: 200,
      headers: {
        "Content-Type":
          "application/json",
        "Cache-Control":
          "no-store"
      }
    }
  );
}


// ================================
// CHECK SESSION
// ================================

async function getValidSession(request, env) {
  const cookies = parseCookies(
    request.headers.get("Cookie")
  );

  const cookie =
    cookies[SESSION_COOKIE];

  if (!cookie) {
    return null;
  }

  const parts = cookie.split(".");

  if (parts.length !== 2) {
    return null;
  }

  const payload = parts[0];
  const signature = parts[1];

  const valid =
    await verify(
      payload,
      signature,
      env.SESSION_SECRET
    );

  if (!valid) {
    return null;
  }

  try {
    const session =
      JSON.parse(
        base64urlDecode(payload)
      );

    if (
      !session.id ||
      !session.username ||
      !session.expires
    ) {
      return null;
    }

    if (Date.now() > session.expires) {
      return null;
    }

    return session;

  } catch {
    return null;
  }
}


// ================================
// LOGOUT
// ================================

function logout() {
  const response = new Response(null, {
    status: 302,
    headers: {
      "Location": "/login.html"
    }
  });

  response.headers.append(
    "Set-Cookie",
    `${SESSION_COOKIE}=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Lax`
  );

  return response;
}


// ================================
// CRYPTO
// ================================

async function sign(value, secret) {
  const key =
    await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(secret),
      {
        name: "HMAC",
        hash: "SHA-256"
      },
      false,
      ["sign"]
    );

  const signature =
    await crypto.subtle.sign(
      "HMAC",
      key,
      new TextEncoder().encode(value)
    );

  return base64urlFromBytes(
    new Uint8Array(signature)
  );
}


async function verify(
  value,
  signature,
  secret
) {
  try {
    const key =
      await crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(secret),
        {
          name: "HMAC",
          hash: "SHA-256"
        },
        false,
        ["verify"]
      );

    return await crypto.subtle.verify(
      "HMAC",
      key,
      base64urlToBytes(signature),
      new TextEncoder().encode(value)
    );

  } catch {
    return false;
  }
}


// ================================
// BASE64URL
// ================================

function base64urlEncode(value) {
  return base64urlFromBytes(
    new TextEncoder().encode(value)
  );
}


function base64urlFromBytes(bytes) {
  let binary = "";

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}


function base64urlDecode(value) {
  return new TextDecoder().decode(
    base64urlToBytes(value)
  );
}


function base64urlToBytes(value) {
  let base64 = value
    .replace(/-/g, "+")
    .replace(/_/g, "/");

  while (base64.length % 4) {
    base64 += "=";
  }

  const binary = atob(base64);

  return Uint8Array.from(
    binary,
    char => char.charCodeAt(0)
  );
}


// ================================
// COOKIES
// ================================

function parseCookies(header) {
  const cookies = {};

  if (!header) {
    return cookies;
  }

  for (const part of header.split(";")) {
    const index = part.indexOf("=");

    if (index === -1) {
      continue;
    }

    const name =
      part.slice(0, index).trim();

    const value =
      part.slice(index + 1).trim();

    cookies[name] = value;
  }

  return cookies;
}


// ================================
// HTML ESCAPING
// ================================

function escapeHTML(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}


// ================================
// ERROR PAGE
// ================================

function errorPage(message) {
  return new Response(
    `<!DOCTYPE html>
<html>
<head>
<title>Blemmished Studios - Login Error</title>

<style>
body {
  background: #0d0912;
  color: white;
  font-family: Arial, sans-serif;
  display: flex;
  align-items: center;
  justify-content: center;
  min-height: 100vh;
  margin: 0;
  padding: 20px;
}

.box {
  background: #19111f;
  border: 1px solid #32203d;
  border-radius: 16px;
  padding: 35px;
  max-width: 500px;
  text-align: center;
}

h1 {
  color: #b77aff;
}

p {
  color: #c8b9d2;
  line-height: 1.6;
}

a {
  color: #b77aff;
}
</style>
</head>

<body>
<div class="box">

<h1>Login Error</h1>

<p>${message}</p>

<p>
<a href="/login.html">
Return to login
</a>
</p>

</div>
</body>
</html>`,
    {
      status: 400,
      headers: {
        "Content-Type":
          "text/html; charset=UTF-8"
      }
    }
  );
}
