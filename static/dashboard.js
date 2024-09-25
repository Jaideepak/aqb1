console.log("js is loaded");

let timeout;

function resetTimer(expiration) {
    clearTimeout(timeout);
    const currentTime = new Date().getTime();
    const timeUntilExpiration = (expiration - currentTime) / 200;

    console.log("Current time:", currentTime);
    console.log("Expiration time:", expiration);
    console.log("Time until expiration:", timeUntilExpiration);

    if (timeUntilExpiration <= 0) {
        console.log("Token expired. Logging out...");
        saveFormData();  // Save form data before logging out
        logout();
    } else {
        timeout = setTimeout(() => {
            saveFormData();  // Save form data before session expires
            logout();
        }, timeUntilExpiration);  // Convert to milliseconds
        console.log("Timeout set for", timeUntilExpiration, "seconds.");
    }
}

function logout() {
    document.getElementById('logoutForm').submit();
}

function handleLogoutAll() {
    saveFormData();  // Save form data before logging out from all devices
    document.getElementById('logoutAllForm').submit();
}

function retrieveFormData() {
    const unsavedData = JSON.parse(document.getElementById('unsavedData').textContent || "{}");

    if (unsavedData) {
        console.log("Retrieved unsaved form data:", unsavedData);
        document.getElementById('name').value = unsavedData.name || '';
        document.getElementById('email').value = unsavedData.email || '';
        document.getElementById('phone').value = unsavedData.phone || '';
        document.getElementById('textField').value = unsavedData.textField || '';
    } else {
        console.log("No unsaved form data found.");
        alert("No unsaved changes found.");
    }
}

function saveFormData() {
    const formData = {
        name: document.getElementById('name').value,
        email: document.getElementById('email').value,
        phone: document.getElementById('phone').value,
        textField: document.getElementById('textField').value
    };

    // Send the form data to the server via AJAX
    const xhr = new XMLHttpRequest();
    xhr.open("POST", "/save_form_data", true);  // New endpoint to handle form data saving
    xhr.setRequestHeader("Content-Type", "application/json;charset=UTF-8");
    xhr.onreadystatechange = function () {
        if (xhr.readyState === 4 && xhr.status === 200) {
            console.log("Form data saved successfully");
        }
    };
    xhr.send(JSON.stringify(formData));
}

window.onload = function() {
    resetTimer(EXPIRATION);

    // Event listeners for auto-saving form data on input change
    document.getElementById('name').addEventListener('input', saveFormData);
    document.getElementById('email').addEventListener('input', saveFormData);
    document.getElementById('phone').addEventListener('input', saveFormData);
    document.getElementById('textField').addEventListener('input', saveFormData);
};

document.onmousemove = function() { resetTimer(EXPIRATION); };
document.onkeydown = function() { resetTimer(EXPIRATION); };
document.ontouchstart = function() { resetTimer(EXPIRATION); };
document.ontouchmove = function() { resetTimer(EXPIRATION); };
