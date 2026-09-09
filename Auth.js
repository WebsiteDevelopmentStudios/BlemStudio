function loginWithDiscord() {

    /*
        Your Cloudflare Worker will handle the
        actual Discord OAuth2 login.

        Change this URL once we create the Worker.

        Example:

        https://auth.blemmished.com/auth/discord

        or

        https://your-worker-name.workers.dev/auth/discord
    */

    const discordLoginURL =
        "https://YOUR-CLOUDFLARE-WORKER-URL/auth/discord";

    window.location.href = discordLoginURL;
}
