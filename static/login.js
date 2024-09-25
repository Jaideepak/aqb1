console.log("js is loaded")

function handleLogoutAll() {
    clearCookies();  
    document.getElementById('logoutAllForm').submit();
}

function clearCookies() {
    document.cookie.split(";").forEach(function(cookie) {
        let name = cookie.trim().split("=")[0];
        document.cookie = name + "=;expires=Thu, 01 Jan 1970 00:00:00 GMT;path=/";
    });
    console.log("All cookies have been cleared.");
}
