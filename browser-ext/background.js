chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    
    if (message.action === "authenticate") {
        console.log("2. Background received:", message.payload);

        // Save the string to local storage
        chrome.storage.local.set({ savedIPString: message.payload }, function() {
            console.log("3. String saved to local storage!");

            // --- SIMULATED FETCH REQUEST ---
            /* fetch('http://localhost:5000/api/auth')
                .then(res => res.text())
                .then(data => { ... })
            */
            
            // Initializing value with "ok" as requested
            const serverResponse = "ok"; 
            console.log("4. Server responded with:", serverResponse);

            // Check the response and reply to the content script
            if (serverResponse === "ok") {
                sendResponse({ status: "authenticated" });
            } else {
                sendResponse({ status: "failed" });
            }
        });

        // CRITICAL: This tells Chrome to keep the message channel open 
        // because we are sending sendResponse asynchronously inside the storage callback.
        return true; 
    }
});