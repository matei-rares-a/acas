document.addEventListener('DOMContentLoaded', function() {
    const button = document.getElementById('helloButton');
    const displayArea = document.getElementById('displayArea'); // Get the new paragraph text area
    
    // 1. Immediately check storage for the string when popup opens
    chrome.storage.local.get(['savedWebsiteString'], function(result) {
        // If a string exists in storage, update the HTML text
        if (result.savedWebsiteString) {
            displayArea.textContent = "Received: " + result.savedWebsiteString;
        }
    });

    // 2. Keep your old button logic just for fun
    button.addEventListener('click', function() {
        alert('You clicked the button! Have a great day.');
    });
});