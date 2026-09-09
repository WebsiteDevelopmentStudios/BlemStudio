function loginWithDiscord() {
    window.location.href = "/auth/discord";
}

async function checkLogin() {
    try {
        const response = await fetch("/api/session", {
            credentials: "include"
        });

        if (response.ok) {
            window.location.href = "/";
        }
    } catch (error) {
        console.error("Login check failed:", error);
    }
}

if (window.location.pathname === "/login.html") {
    checkLogin();
}
