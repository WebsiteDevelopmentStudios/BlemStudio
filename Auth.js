function createAccount() {

    const username = document.getElementById("username").value;
    const password = document.getElementById("password").value;


    if(username === "" || password === "") {
        message("Please fill in everything");
        return;
    }


    let users = JSON.parse(localStorage.getItem("users")) || {};


    if(users[username]) {
        message("Username already exists");
        return;
    }


    users[username] = {
        password: password
    };


    localStorage.setItem("users", JSON.stringify(users));


    localStorage.setItem("loggedIn", username);


    window.location.href = "index.html";
}



function login() {

    const username = document.getElementById("username").value;
    const password = document.getElementById("password").value;


    let users = JSON.parse(localStorage.getItem("users")) || {};


    if(users[username] && users[username].password === password) {

        localStorage.setItem("loggedIn", username);

        window.location.href = "index.html";

    } else {

        message("Wrong username or password");

    }

}



function message(text) {

    document.getElementById("message").innerText = text;

}
