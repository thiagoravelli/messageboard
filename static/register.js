document.addEventListener('DOMContentLoaded', () => {
    const regUsernameInput = document.getElementById('reg-username');
    const regPasswordInput = document.getElementById('reg-password');
    const registerButton = document.getElementById('register-button');

    function registerUser() {
        const username = regUsernameInput.value.trim();
        const password = regPasswordInput.value;
        if (!username || !password) {
            alert('Username and password are required.');
            return;
        }
        fetch('/api/register', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ username, password })
        })
        .then(response => {
            if (response.ok) {
                alert('Registration successful. You can now log in.');
                window.location.href = 'index.html';
            } else {
                response.text().then(text => alert(text));
            }
        });
    }

    registerButton.addEventListener('click', registerUser);
});
