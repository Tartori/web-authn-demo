/**
 * Switch to login page
 */
$('#toLogin').click(function (e) {
    e.preventDefault();
    $('#registerContainer').hide();
    $('#loginContainer').show();
})

/**
 * Switch to registration page
 */
$('#toRegistration').click(function (e) {
    e.preventDefault();
    $('#loginContainer').hide();
    $('#registerContainer').show();
})

let loadMainContainer = (username) => {
    return fetch('http://localhost:8080/users/' + username)
        .then((response) => response.json())
        .then((response) => {
            if (response.status === 'ok') {
                $('#theSecret').html(response.theSecret)
                $('#name').html(response.name)
                $('#registerContainer').hide();
                $('#loginContainer').hide();
                $('#mainContainer').show();
            } else {
                alert(`Error! ${response.message}`)
            }
        })
}

let checkIfLoggedIn = () => {
    return fetch('/isLoggedIn', { credentials: 'include' })
        .then((response) => response.json())
        .then((response) => {
            if (response.status === 'ok') {
                return true
            } else {
                return false
            }
        })
}

$('#logoutButton').click(() => {
    fetch('/logout', { credentials: 'include' });

    $('#registerContainer').hide();
    $('#mainContainer').hide();
    $('#loginContainer').show();
})