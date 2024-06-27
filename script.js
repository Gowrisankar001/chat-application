document.getElementById('loginForm').addEventListener('submit', function(event) {
    event.preventDefault();
    var username = document.getElementById('loginUsername').value;
    var password = document.getElementById('loginPassword').value;

    fetch('/login', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            username: username,
            password: password
        }),
    })
    .then(response => response.json())
    .then(data => {
        if (data.message === 'Login successful') {
            window.location.href = '/home'; // Redirect to home page
        } else {
            document.getElementById('loginMessage').textContent = data.message;
        }
    })
    .catch((error) => {
        console.error('Error:', error);
        document.getElementById('loginMessage').textContent = 'An error occurred. Please try again.';
    });
});

// Function to handle signup form submission
document.getElementById('signupForm').addEventListener('submit', function(event) {
    event.preventDefault();
    var username = document.getElementById('signupUsername').value;
    var email = document.getElementById('signupEmail').value;
    var password = document.getElementById('signupPassword').value;

    fetch('/signup', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            username: username,
            password: password,
            email: email
        }),
    })
    .then(response => response.json())
    .then(data => {
        document.getElementById('signupMessage').textContent = data.message;
        if (data.message === 'User registered successfully') {
            setTimeout(() => {
                window.location.href = '/'; // Redirect to login page after signup
            }, 2000);
        }
    })
    .catch((error) => {
        console.error('Error:', error);
        document.getElementById('signupMessage').textContent = 'An error occurred. Please try again.';
    });
});

