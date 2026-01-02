/**
 * Wolf Prowler API Utility
 * Centralizes API calls with Authentication and Error Handling
 */

const API_KEY = 'dev-key-12345'; // Development API Key

/**
 * Performs an authenticated fetch request.
 * Redirects to login on 401 Unauthorized.
 * 
 * @param {string} url - The API endpoint URL
 * @param {object} options - Fetch options
 * @returns {Promise<Response>} - The fetch response
 */
async function fetchWithAuth(url, options = {}) {
    const headers = {
        'X-API-Key': API_KEY,
        'Content-Type': 'application/json',
        ...options.headers
    };

    try {
        const response = await fetch(url, { ...options, headers });

        if (response.status === 401) {
            console.warn(`Unauthorized access to ${url}. Redirecting to login...`);
            // Optional: Add a toast notification here if desired
            window.location.href = '/'; 
            throw new Error('Unauthorized'); // Stop execution flow
        }

        if (response.status === 403) {
            console.warn(`Forbidden access to ${url}.`);
            // You might want to handle permission errors differently
        }

        return response;
    } catch (error) {
        console.error(`API Request failed for ${url}:`, error);
        throw error;
    }
}

/**
 * Helper to parse JSON safely
 */
async function getJson(url) {
    const response = await fetchWithAuth(url);
    if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
    }
    return await response.json();
}
