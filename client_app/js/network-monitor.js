/**
 * Network Monitor - Intercepts and logs all fetch requests/responses in real-time
 */

const NetworkMonitor = {
    requestCounter: 0,
    maxLogs: 100,

    /**
     * Add a log entry to the network monitor
     * @param {string} type - 'request', 'response', 'error', 'info'
     * @param {string} message - The message to log
     * @param {object} data - Optional data object to display
     */
    addLog(type, message, data = null) {
        const logDiv = document.getElementById('network-log');
        if (!logDiv) return;

        const timestamp = new Date().toLocaleTimeString();
        const logItem = document.createElement('div');
        logItem.className = `log-item log-${type}`;

        let content = `<span class="log-time">[${timestamp}]</span> `;
        
        // Add icon based on type
        const icons = {
            'request': 'OUT->',
            'response': '<-IN',
            'error': 'ERR',
            'info': 'INFO'
        };
        
        content += `<span class="log-label">${icons[type] || type}</span> ${message}`;
        
        if (data) {
            try {
                const dataStr = typeof data === 'string' ? data : JSON.stringify(data, null, 2);
                content += `<div class="log-data"><pre>${escapeHtml(dataStr)}</pre></div>`;
            } catch (e) {
                content += `<div class="log-data"><pre>${escapeHtml(String(data))}</pre></div>`;
            }
        }

        logItem.innerHTML = content;
        logDiv.appendChild(logItem);

        // Keep only the last N logs
        const items = logDiv.querySelectorAll('.log-item');
        if (items.length > this.maxLogs) {
            items[0].remove();
        }

        // Auto-scroll to bottom
        logDiv.scrollTop = logDiv.scrollHeight;
    },

    /**
     * Escape HTML special characters for safe display
     */
    escapeHtml(text) {
        const map = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#039;'
        };
        return text.replace(/[&<>"']/g, m => map[m]);
    }
};

// Utility function for HTML escaping
function escapeHtml(text) {
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    };
    return String(text).replace(/[&<>"']/g, m => map[m]);
}

/**
 * Clear the network monitor log
 */
function clearNetworkMonitor() {
    const logDiv = document.getElementById('network-log');
    if (logDiv) {
        logDiv.innerHTML = '<div class="log-item log-info">  Monitor cleared. Ready for new requests.</div>';
    }
}

/**
 * Intercept the native fetch function
 */
const originalFetch = window.fetch;
window.fetch = function(...args) {
    const [resource, config] = args;
    const requestId = ++NetworkMonitor.requestCounter;

    // Parse request details
    const method = (config && config.method) || 'GET';
    const url = resource instanceof Request ? resource.url : String(resource);
    const displayUrl = url.split('/').pop() || url;

    // Log request
    NetworkMonitor.addLog('request', `${method} ${displayUrl}`, {
        url: url,
        method: method,
        headers: config?.headers || {},
        body: config?.body ? tryParseJson(config.body) : null
    });

    // Call original fetch
    return originalFetch.apply(this, args)
        .then(response => {
            // Clone response to read body without consuming it
            const clonedResponse = response.clone();
            
            const contentType = response.headers.get('content-type') || '';
            let bodyPromise;
            
            if (contentType.includes('application/json')) {
                bodyPromise = clonedResponse.json();
            } else if (contentType.includes('text')) {
                bodyPromise = clonedResponse.text();
            } else {
                bodyPromise = clonedResponse.text();
            }

            return bodyPromise.then(body => {
                // Log response
                NetworkMonitor.addLog('response', `${method} ${displayUrl} → ${response.status}`, {
                    status: response.status,
                    headers: Object.fromEntries(response.headers.entries()),
                    body: body ? tryParseJson(body) : body
                });

                // Return original response for caller to use
                return response;
            }).catch(err => {
                NetworkMonitor.addLog('response', `${method} ${displayUrl} → ${response.status}`, {
                    status: response.status,
                    note: 'Could not parse response body'
                });
                return response;
            });
        })
        .catch(error => {
            // Log error
            NetworkMonitor.addLog('error', `${method} ${displayUrl}`, {
                error: error.message,
                stack: error.stack
            });
            throw error;
        });
};

/**
 * Try to parse JSON string, return object or original string
 */
function tryParseJson(str) {
    try {
        return JSON.parse(str);
    } catch (e) {
        return str;
    }
}

console.log('✓ Network Monitor initialized');
