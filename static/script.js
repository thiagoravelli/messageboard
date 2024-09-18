document.addEventListener('DOMContentLoaded', () => {
    const loginUsernameInput = document.getElementById('login-username');
    const loginPasswordInput = document.getElementById('login-password');
    const loginButton = document.getElementById('login-button');
    const logoutButton = document.getElementById('logout-button');

    const contentInput = document.getElementById('content');
    const postButton = document.getElementById('post-button');
    const messageList = document.getElementById('message-list');
    const currentUserSpan = document.getElementById('current-user');

    const loginForm = document.getElementById('login-form');
    const userInfo = document.getElementById('user-info');
    const messageForm = document.getElementById('message-form');

    let currentUser = null;

    function checkAuth() {
        fetch('/api/check_session')
            .then(response => {
                if (response.ok) {
                    return response.json();
                } else {
                    throw new Error('Not authenticated');
                }
            })
            .then(data => {
                currentUser = data.username;
                currentUserSpan.textContent = currentUser;
                loginForm.style.display = 'none';
                userInfo.style.display = 'flex';
                messageForm.style.display = 'block';
                fetchMessages();
            })
            .catch(() => {
                currentUser = null;
                loginForm.style.display = 'flex';
                userInfo.style.display = 'none';
                messageForm.style.display = 'none';
                fetchMessages();
            });
    }

    function loginUser() {
        const username = loginUsernameInput.value.trim();
        const password = loginPasswordInput.value;
        if (!username || !password) {
            alert('Username and password are required.');
            return;
        }
        fetch('/api/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ username, password })
        })
        .then(response => {
            if (response.ok) {
                currentUser = username;
                currentUserSpan.textContent = currentUser;
                loginForm.style.display = 'none';
                userInfo.style.display = 'flex';
                messageForm.style.display = 'block';
                loginUsernameInput.value = '';
                loginPasswordInput.value = '';
                fetchMessages();
            } else {
                response.text().then(text => alert(text));
            }
        });
    }

    function logoutUser() {
        fetch('/api/logout', { method: 'POST' })
            .then(() => {
                currentUser = null;
                loginForm.style.display = 'flex';
                userInfo.style.display = 'none';
                messageForm.style.display = 'none';
                fetchMessages();
            });
    }

    function fetchMessages() {
        fetch('/api/messages')
            .then(response => response.json())
            .then(messages => {
                messageList.innerHTML = '';
                messages.reverse().forEach(message => {
                    const messageDiv = document.createElement('div');
                    messageDiv.className = 'message';
                    messageDiv.dataset.id = message.id;

                    const infoDiv = document.createElement('div');
                    infoDiv.className = 'info';
                    infoDiv.innerHTML = `<strong>${message.user}</strong> at ${message.timestamp}`;

                    const contentDiv = document.createElement('div');
                    contentDiv.className = 'content';
                    contentDiv.textContent = message.content;

                    messageDiv.appendChild(infoDiv);
                    messageDiv.appendChild(contentDiv);

                    if (currentUser === message.user) {
                        const updateButton = document.createElement('button');
                        updateButton.textContent = 'Update';
                        updateButton.addEventListener('click', () => updateMessage(message));
                        const deleteButton = document.createElement('button');
                        deleteButton.textContent = 'Delete';
                        deleteButton.addEventListener('click', () => deleteMessage(message));
                        messageDiv.appendChild(updateButton);
                        messageDiv.appendChild(deleteButton);
                    }
                    messageList.appendChild(messageDiv);
                });
            });
    }

    function postMessage() {
        const content = contentInput.value.trim();
        if (!content) {
            alert('Message content is required.');
            return;
        }
        fetch('/api/messages', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ content })
        })
        .then(response => {
            if (response.ok) {
                contentInput.value = '';
                fetchMessages();
            } else if (response.status === 401) {
                alert('You must be logged in to post messages.');
                logoutUser();
            } else {
                response.text().then(text => alert(text));
            }
        });
    }

    function updateMessage(message) {
        const newContent = prompt('Update your message:', message.content);
        if (newContent !== null && newContent.trim() !== '') {
            fetch(`/api/messages/${message.id}`, {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ content: newContent })
            })
            .then(response => {
                if (response.ok) {
                    fetchMessages();
                } else {
                    response.text().then(text => alert(text));
                }
            });
        }
    }

    function deleteMessage(message) {
        if (confirm('Are you sure you want to delete this message?')) {
            fetch(`/api/messages/${message.id}`, {
                method: 'DELETE'
            })
            .then(response => {
                if (response.ok) {
                    fetchMessages();
                } else {
                    response.text().then(text => alert(text));
                }
            });
        }
    }

    loginButton.addEventListener('click', loginUser);
    logoutButton.addEventListener('click', logoutUser);
    postButton.addEventListener('click', postMessage);

    checkAuth();
});
