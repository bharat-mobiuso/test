/**
 ## WARNING ##
 If you want to make any changes in this file
 please make sure to generate sha256 hash and include in html file where this file is used.
 ## ------- ##
 */

function getURLParameter(p) {
    const sPageURL = window.location.search.substring(1);
    const sURLVariables = sPageURL.split('&');
    for (let i = 0; i < sURLVariables.length; i++) {
        let sParameterName = sURLVariables[i].split('=');
        if (sParameterName[0] === p) {
            return sParameterName[1].replace(/%20/g, ' ');
        }
    }
    return "";
}

function getCsrfToken() {
    fetch("https://sv.bluestarindia.com/csrf-token",
        {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json; charset=UTF-8',
                'Accept': 'application/json',
                'Cache-Control': 'no-cache, no-store, must-revalidate',
                'Pragma': 'no-cache',
                'Expires': '0',
            }
        }).then(response => {
        return response.json()
    }).then(output => {
        document.getElementById('_csrf').setAttribute('value', output.csrfToken);
    });
}

window.onload = function () {
    checkErrors();
    getCsrfToken();
}

function checkErrors() {
    const errorMessage = getURLParameter('error')
    if (errorMessage) {
        document.getElementById('error_message').innerHTML = errorMessage
    }
}

