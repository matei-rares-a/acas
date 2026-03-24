document.addEventListener('click', function(event) {
    if (event.target && event.target.id === 'zkLoginBtn') {
        
        const myString = event.target.getAttribute('data-value'); // Gets "ipstring"
        
        console.log("1. Browser sending to extension:", myString);

        // Send message and WAIT for a response
        chrome.runtime.sendMessage(
            { action: "authenticate", payload: myString }, 
            function(response) {
                // 5. This runs when the background script replies!
                console.log("5. Browser received response from extension:", response);
                
                if (response && response.status === "authenticated") {
                    // Print it to the screen
                    document.getElementById('statusText').innerText = response.status;
                }
            }
        );
    }
});