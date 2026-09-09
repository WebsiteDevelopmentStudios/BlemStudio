const DISCORD_REDIRECT_URI =
  "https://blemm-studios.blemmished.workers.dev/auth/callback";

const SESSION_COOKIE = "__Host-blemm_session";
const STATE_COOKIE = "__Host-discord_state";

const SESSION_MAX_AGE = 60 * 60 * 24 * 7; // 7 days
const STATE_MAX_AGE = 60 * 10; // 10 minutes


export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const pathname = url.pathname;

    // Discord login
    if (pathname === "/auth/discord") {
      return startDiscordLogin(env);
    }

    // Discord OAuth callback
    if (pathname === "/auth/callback") {
      return handleDiscordCallback(request, env);
    }

    // Logout
    if (pathname === "/auth/logout") {
      return logout();
    }

    // Current logged-in user
    if (pathname === "/api/session") {
      return getSession(request, env);
    }

    // Protect the actual website pages
    if (isProtectedPage(pathname)) {
      const session = await getValidSession(request, env);

      if (!session) {
        return Response.redirect(
          new URL("/login.html", request.url).toString(),
          302
        );
      }
    }

    // Let Cloudflare serve your normal files
    return env.ASSETS.fetch(request);
  }
};


// --------------------------------------------------
// PAGE PROTECTION
// --------------------------------------------------

function isProtectedPage(pathname) {
  return (
    pathname === "/" ||
    pathname === "/index.html" ||
    pathname === "/commissions.html" ||
    pathname.endsWith(".html")
  );
}


// --------------------------------------------------
// DISCORD LOGIN
// --------------------------------------------------

async function startDiscordLogin(env) {
  const state = randomString(32);

  const authorizeURL = new URL(
    "https://discord.com/oauth2/authorize"
  );

  authorizeURL.searchParams.set(
    "client_id",
    env.DISCORD_CLIENT_ID
  );

  authorizeURL.searchParams.set(
    "response_type",
    "code"
  );

  authorizeURL.searchParams.set(
    "redirect_uri",
    DISCORD_REDIRECT_URI
  );

  authorizeURL.searchParams.set(
    "scope",
    "identify"
  );

  authorizeURL.searchParams.set(
    "state",
    state
  );

  return new Response(null, {
    status: 302,
    headers: {
      Location: authorizeURL.toString(),

      "Set-Cookie":
        `${STATE_COOKIE}=${state}; ` +
        `Max-Age=${STATE_MAX_AGE}; ` +
        `Path=/; ` +
        `HttpOnly; ` +
        `Secure; ` +
        `SameSite=Lax`
    }
  });
}


// --------------------------------------------------
// DISCORD CALLBACK
// --------------------------------------------------

async function handleDiscordCallback(request, env) {
  const url = new URL(request.url);

  const code = url.searchParams.get("code");
  const returnedState = url.searchParams.get("state");

  if (!code || !returnedState) {
    return errorPage("Missing Discord authorization information.");
  }

  const cookies = parseCookies(request.headers.get("Cookie"));
  const savedState = cookies[STATE_COOKIE];

  if (!savedState || savedState !== returnedState) {
    return errorPage("Invalid or expired login request.");
  }

  // Exchange authorization code for access token
  const tokenResponse = await fetch(
    "https://discord.com/api/v10/oauth2/token",
    {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body: new URLSearchParams({
        client_id: env.DISCORD_CLIENT_ID,
        client_secret: env.DISCORD_CLIENT_SECRET,
        grant_type: "authorization_code",
        code: code,
        redirect_uri: DISCORD_REDIRECT_URI
      })
    }
  );

  if (!tokenResponse.ok) {
    return errorPage("Discord token exchange failed.");
  }

  const tokenData = await tokenResponse.json();

  const accessToken = tokenData.access_token;

  if (!accessToken) {
    return errorPage("Discord did not provide an access token.");
  }

  // Get the actual Discord account
  const userResponse = await fetch(
    "https://discord.com/api/v10/users/@me",
    {
      headers: {
        Authorization: `Bearer ${accessToken}`
      }
    }
  );

  if (!userResponse.ok) {
    return errorPage("Could not retrieve your Discord account.");
  }

  const user = await userResponse.json();

  /*
    IMPORTANT:

    user.username = actual Discord username
    user.global_name = display name

    We intentionally use username, NOT global_name.
  */

  const sessionData = {
    id: user.id,
    username: user.username,
    expires: Date.now() + SESSION_MAX_AGE * 1000
  };

  const sessionPayload = base64urlEncode(
    JSON.stringify(sessionData)
  );

  const signature = await sign(
    sessionPayload,
    env.SESSION_SECRET
  );

  const sessionCookie =
    `${SESSION_COOKIE}=${sessionPayload}.${signature}; ` +
    `Max-Age=${SESSION_MAX_AGE}; ` +
    `Path=/; ` +
    `HttpOnly; ` +
    `Secure; ` +
    `SameSite=Lax`;

  const clearStateCookie =
    `${STATE_COOKIE}=; ` +
    `Max-Age=0; ` +
    `Path=/; ` +
    `HttpOnly; ` +
    `Secure; ` +
    `SameSite=Lax`;

  return new Response(null, {
    status: 302,
    headers: {
      Location: "/",
      "Set-Cookie": [
        sessionCookie,
        clearStateCookie
      ]
    }
  });
}


// --------------------------------------------------
// SESSION API
// --------------------------------------------------

async function getSession(request, env) {
  const session = await getValidSession(request, env);

  if (!session) {
    return new Response(
      JSON.stringify({
        loggedIn: false
      }),
      {
        status: 401,
        headers: {
          "Content-Type": "application/json"
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
        "Content-Type": "application/json",
        "Cache-Control": "no-store"
      }
    }
  );
}


// --------------------------------------------------
// VALIDATE SESSION
// --------------------------------------------------

async function getValidSession(request, env) {
  const cookies = parseCookies(
    request.headers.get("Cookie")
  );

  const cookie = cookies[SESSION_COOKIE];

  if (!cookie) {
    return null;
  }

  const parts = cookie.split(".");

  if (parts.length !== 2) {
    return null;
  }

  const payload = parts[0];
  const signature = parts[1];

  const validSignature = await verify(
    payload,
    signature,
    env.SESSION_SECRET
  );

  if (!validSignature) {
    return null;
  }

  try {
    const session = JSON.parse(
      base64urlDecode(payload)
    );

    if (!session.expires || Date.now() > session.expires) {
      return null;
    }

    if (!session.id || !session.username) {
      return null;
    }

    return session;
  } catch {
    return null;
  }
}


// --------------------------------------------------
// LOGOUT
// --------------------------------------------------

function logout() {
  return new Response(null, {
    status: 302,
    headers: {
      Location: "/login.html",

      "Set-Cookie":
        `${SESSION_COOKIE}=; ` +
        `Max-Age=0; ` +
        `Path=/; ` +
        `HttpOnly; ` +
        `Secure; ` +
        `SameSite=Lax`
    }
  });
}


// --------------------------------------------------
// CRYPTO
// --------------------------------------------------

function randomString(length) {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);

  return Array.from(bytes)
    .map(byte => byte.toString(16).padStart(2, "0"))
    .join("");
}


async function sign(value, secret) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    {
      name: "HMAC",
      hash: "SHA-256"
    },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(value)
  );

  return base64urlFromBytes(
    new Uint8Array(signature)
  );
}


async function verify(value, signature, secret) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    {
      name: "HMAC",
      hash: "SHA-256"
    },
    false,
    ["verify"]
  );

  try {
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


// --------------------------------------------------
// BASE64URL
// --------------------------------------------------

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
  const bytes = base64urlToBytes(value);

  return new TextDecoder().decode(bytes);
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


// --------------------------------------------------
// COOKIES
// --------------------------------------------------

function parseCookies(cookieHeader) {
  const cookies = {};

  if (!cookieHeader) {
    return cookies;
  }

  for (const part of cookieHeader.split(";")) {
    const index = part.indexOf("=");

    if (index === -1) {
      continue;
    }

    const name = part
      .slice(0, index)
      .trim();

    const value = part
      .slice(index + 1)
      .trim();

    cookies[name] = value;
  }

  return cookies;
}


// --------------------------------------------------
// ERROR PAGE
// --------------------------------------------------

function errorPage(message) {
  return new Response(
    `
    <!DOCTYPE html>
    <html>
    <head>
      <title>Blemmished Studios - Login Error</title>
      <style>
        body {
          background: #0d0912;
          color: white;
          font-family: Arial, sans-serif;
          display: flex;
          justify-content: center;
          align-items: center;
          min-height: 100vh;
          text-align: center;
        }

        .box {
          background: #19111f;
          border: 1px solid #32203d;
          border-radius: 16px;
          padding: 35px;
          max-width: 450px;
        }

        h1 {
          color: #b77aff;
        }

        p {
          color: #c8b9d2;
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
          <a href="/login.html">Return to login</a>
        </p>
      </div>
    </body>
    </html>
    `,
    {
      status: 400,
      headers: {
        "Content-Type": "text/html; charset=UTF-8"
      }
    }
  );
}
