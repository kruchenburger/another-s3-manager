let currentBucket = '';
let currentPath = '';
let currentRole = '';
let config = null;
let authToken = null;
let currentUser = null;
let appInfo = null;
let errorClearTimer = null;
let currentErrorTimeout = null;

const SELECT_ROLE_MESSAGE = 'Please choose a role to view available buckets.';
const SELECT_BUCKET_MESSAGE = 'Select a bucket to start browsing objects.';
const NO_ROLES_MESSAGE = 'No roles assigned. Please contact your administrator.';
const NO_BUCKETS_MESSAGE = 'No buckets available for the selected role.';

// Virtualization and pagination state
let allFiles = []; // All files from server
let filteredFiles = []; // Files after search filter
let displayedFiles = []; // Files currently displayed
let searchQuery = '';
let itemsPerPage = 200; // Number of items to render at once (loaded from server config)
let currentPage = 0;
let isScrolling = false;
let scrollTimeout = null;


// Get auth token from localStorage
function getAuthToken() {
    if (!authToken) {
        authToken = localStorage.getItem('access_token');
    }
    return authToken;
}

function applyAppBranding(info) {
    if (!info) {
        return;
    }

    const appName = info.app_name || 'Another S3 Manager';
    const appNameElement = document.getElementById('app-name');
    if (appNameElement) {
        appNameElement.textContent = appName;
    }

    const versionElement = document.getElementById('app-version');
    if (versionElement) {
        versionElement.textContent = info.app_version ? `(v${info.app_version})` : '';
    }

    const pageTitle = document.getElementById('page-title');
    if (pageTitle) {
        pageTitle.textContent = appName;
    }

    // Show demo banner if demo mode is enabled
    // Don't hide banner if info is not available yet - it might be shown by inline script
    const demoBanner = document.getElementById('demo-banner');
    if (demoBanner && info && info.is_demo) {
        demoBanner.style.display = 'block';
        const demoBucketLimit = document.getElementById('demo-bucket-limit');
        if (demoBucketLimit && info.demo_bucket_limit) {
            demoBucketLimit.textContent = info.demo_bucket_limit;
        }
    }
    // Don't hide banner if info is not available - let inline script handle it
}

async function loadAppInfo() {
    if (appInfo) {
        applyAppBranding(appInfo); // Re-apply branding in case banner was hidden
        return appInfo;
    }

    try {
        const response = await fetch('/api/app-info');
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }
        const data = await response.json();
        appInfo = data;
        applyAppBranding(data);
        return data;
    } catch (error) {
        console.error('Failed to load app info:', error);
        return null;
    }
}

// Check authentication and redirect if needed
async function checkAuth() {
    const token = getAuthToken();
    if (!token) {
        window.location.replace('/login');
        return false;
    }

    try {
        const response = await fetch('/api/me', {
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });

        if (response.ok) {
            const userData = await response.json();
            currentUser = userData;
            // Store CSRF token if provided
            if (userData.csrf_token) {
                localStorage.setItem('csrf_token', userData.csrf_token);
            }
            // Apply theme
            applyTheme(userData.theme || 'auto');
            // Update app name if provided
            if (userData.app_name) {
                const info = {
                    app_name: userData.app_name,
                    app_version: appInfo ? appInfo.app_version : undefined,
                };
                applyAppBranding(info);
            }
            // Update UI immediately
            updateUserInfo();
            return true;
        } else {
            // Clear invalid token and redirect
            localStorage.removeItem('access_token');
            localStorage.removeItem('user');
            localStorage.removeItem('csrf_token');
            window.location.replace('/login');
            return false;
        }
    } catch (error) {
        // Clear invalid token and redirect
        localStorage.removeItem('access_token');
        localStorage.removeItem('user');
        localStorage.removeItem('csrf_token');
        window.location.replace('/login');
        return false;
    }
}

function updateUserInfo() {
    const userInfo = document.getElementById('user-info');
    const adminLink = document.getElementById('admin-link');
    const configBtn = document.getElementById('config-btn');

    if (!userInfo) {
        console.warn('user-info element not found');
        return;
    }

    if (currentUser) {
        // Sanitize username to prevent XSS
        const username = document.createTextNode(currentUser.username).textContent;
        userInfo.innerHTML = '';
        const icon = document.createTextNode('👤 ');
        const strong = document.createElement('strong');
        strong.textContent = username;
        userInfo.appendChild(icon);
        userInfo.appendChild(strong);
        if (currentUser.is_admin) {
            const adminBadge = document.createElement('span');
            adminBadge.style.cssText = 'background: #28a745; color: white; padding: 2px 6px; border-radius: 3px; font-size: 11px; margin-left: 5px;';
            adminBadge.textContent = 'ADMIN';
            userInfo.appendChild(adminBadge);
        }
        userInfo.style.display = 'inline';

        if (currentUser.is_admin) {
            if (adminLink) {
                adminLink.style.display = 'inline-block';
            }
            if (configBtn) {
                configBtn.style.display = 'inline-block';
            }
        } else {
            if (adminLink) {
                adminLink.style.display = 'none';
            }
            if (configBtn) {
                configBtn.style.display = 'none';
            }
        }
    } else {
        // Fallback: try to get user from localStorage
        const storedUser = localStorage.getItem('user');
        if (storedUser) {
            try {
                currentUser = JSON.parse(storedUser);
                updateUserInfo();
            } catch (e) {
                console.error('Failed to parse stored user:', e);
            }
        }
    }
}

function logout() {
    localStorage.removeItem('access_token');
    localStorage.removeItem('user');
    localStorage.removeItem('csrf_token');
    window.location.replace('/login');
}

// Theme management
function getSystemTheme() {
    return window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

function applyTheme(themePreference) {
    let actualTheme = themePreference || 'auto';
    if (actualTheme === 'auto') {
        actualTheme = getSystemTheme();
    }

    document.documentElement.setAttribute('data-theme', actualTheme);

    // Update toggle button icon
    const toggleBtn = document.getElementById('theme-toggle');
    if (toggleBtn) {
        toggleBtn.textContent = actualTheme === 'dark' ? '☀️' : '🌙';
        toggleBtn.title = `Switch to ${actualTheme === 'dark' ? 'light' : 'dark'} theme`;
    }
}

async function toggleTheme() {
    // Prevent multiple clicks
    const toggleBtn = document.getElementById('theme-toggle');
    if (toggleBtn && toggleBtn.disabled) {
        return;
    }

    // Get current user if not loaded
    if (!currentUser) {
        try {
            const token = getAuthToken();
            if (!token) return;

            const response = await fetch('/api/me', {
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });

            if (response.ok) {
                currentUser = await response.json();
            } else {
                console.error('Failed to get user info');
                return;
            }
        } catch (error) {
            console.error('Error getting user info:', error);
            return;
        }
    }

    const currentTheme = currentUser.theme || 'auto';
    let newTheme;

    // If current theme is 'auto', switch to opposite of system theme
    // After that, only toggle between 'light' and 'dark'
    if (currentTheme === 'auto') {
        // First manual change: switch to opposite of current system theme
        const systemTheme = getSystemTheme();
        newTheme = systemTheme === 'dark' ? 'light' : 'dark';
    } else {
        // Toggle between light and dark only
        newTheme = currentTheme === 'light' ? 'dark' : 'light';
    }

    // Disable button during request
    if (toggleBtn) {
        toggleBtn.disabled = true;
    }

    try {
        const response = await authFetch('/api/user/theme', {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ theme: newTheme })
        });

        if (response.ok) {
            const data = await response.json();
            currentUser.theme = newTheme;
            // Update localStorage
            const storedUser = localStorage.getItem('user');
            if (storedUser) {
                try {
                    const user = JSON.parse(storedUser);
                    user.theme = newTheme;
                    localStorage.setItem('user', JSON.stringify(user));
                } catch (e) {
                    console.error('Failed to update user in localStorage:', e);
                }
            }
            applyTheme(newTheme);
        } else {
            console.error('Failed to update theme');
        }
    } catch (error) {
        console.error('Error updating theme:', error);
    } finally {
        // Re-enable button
        if (toggleBtn) {
            toggleBtn.disabled = false;
        }
    }
}

// Listen for system theme changes
if (window.matchMedia) {
    window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', (e) => {
        if (currentUser && currentUser.theme === 'auto') {
            applyTheme('auto');
        }
    });
}

function getCsrfToken() {
    return localStorage.getItem('csrf_token');
}

// Helper function to add auth header to fetch requests
function authFetch(url, options = {}) {
    const token = getAuthToken();
    if (!token) {
        window.location.href = '/login';
        return Promise.reject(new Error('Not authenticated'));
    }

    options.headers = options.headers || {};
    options.headers['Authorization'] = `Bearer ${token}`;

    // Add CSRF token for state-changing requests (POST, PUT, DELETE)
    const method = (options.method || 'GET').toUpperCase();
    if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(method)) {
        const csrfToken = getCsrfToken();
        if (csrfToken) {
            options.headers['X-CSRF-Token'] = csrfToken;
        }
    }

    return fetch(url, options);
}

async function loadConfig(forceReload = true) {
    try {
        console.log('Loading config, forceReload:', forceReload);
        const url = forceReload ? '/api/config?force_reload=true' : '/api/config';
        console.log('Fetching from URL:', url);
        const response = await authFetch(url);
        console.log('Response status:', response.status, response.ok);
        if (!response.ok) {
            const errorText = await response.text();
            console.error('Response error:', errorText);
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
        config = await response.json();
        console.log('Loaded config:', JSON.stringify(config, null, 2));
        if (!config) {
            console.error('Config is null or undefined');
            return null;
        }

        // Update itemsPerPage from config
        if (config.items_per_page !== undefined) {
            itemsPerPage = parseInt(config.items_per_page) || 200;
            console.log('Set itemsPerPage to:', itemsPerPage);
        }

        // Update DISABLE_DELETION flag
        window.DISABLE_DELETION = config.disable_deletion === true;

        // Update ENABLE_LAZY_LOADING flag
        if (config.enable_lazy_loading !== undefined) {
            window.ENABLE_LAZY_LOADING = config.enable_lazy_loading === true;
        } else {
            window.ENABLE_LAZY_LOADING = true; // Default to true if not specified
        }

        const roles = Array.isArray(config.roles) ? config.roles : [];
        const savedRole = localStorage.getItem('selected_role');

        // Use current_role from API response (computed from default_role, not stored in config)
        const configCurrentRole = config.current_role || '';
        const hasCurrentRole = currentRole && roles.some(r => r.name === currentRole);

        if (hasCurrentRole) {
            console.log('Keeping current role:', currentRole);
        } else if (configCurrentRole && roles.some(r => r.name === configCurrentRole)) {
            // Use role from API (computed from default_role)
            currentRole = configCurrentRole;
            localStorage.setItem('selected_role', currentRole);
            console.log('Using role from API (computed from default_role):', currentRole);
        } else if (savedRole && roles.some(r => r.name === savedRole)) {
            currentRole = savedRole;
            console.log('Restored saved role from localStorage:', currentRole);
        } else {
            currentRole = '';
            localStorage.removeItem('selected_role');
            console.log('No saved role found. Waiting for user selection.');
        }

        updateRoleSelector();
        return config;
    } catch (error) {
        console.error('Failed to load configuration:', error);
        showError('Failed to load configuration: ' + error.message);
        return null;
    }
}

// reloadConfig function removed - config is now automatically reloaded when needed

function updateRoleSelector() {
    const select = document.getElementById('role-select');
    if (!select) {
        console.warn('role-select element not found');
        return;
    }

    const bucketSelect = document.getElementById('bucket-select');

    const roles = config && Array.isArray(config.roles) ? config.roles : [];
    select.innerHTML = '';
    select.onchange = null;

    if (roles.length === 0) {
        const option = document.createElement('option');
        option.value = '';
        option.textContent = 'No roles assigned';
        option.selected = true;
        select.appendChild(option);
        select.disabled = true;
        if (bucketSelect) {
            bucketSelect.innerHTML = '<option value="">No roles assigned</option>';
            bucketSelect.value = '';
            bucketSelect.disabled = true;
        }
        clearFileList(NO_ROLES_MESSAGE);
        disableButtons();
        return;
    }

    select.disabled = false;
    if (bucketSelect) {
        bucketSelect.disabled = !currentRole;
    }

    const placeholderOption = document.createElement('option');
    placeholderOption.value = '';
    placeholderOption.textContent = 'Select a role...';
    placeholderOption.selected = !currentRole;
    select.appendChild(placeholderOption);

    roles.forEach(role => {
        const option = document.createElement('option');
        option.value = role.name;
        option.textContent = role.name + (role.description ? ` - ${role.description}` : '');
        if (role.name === currentRole) {
            option.selected = true;
        }
        select.appendChild(option);
    });

    console.log('Role selector updated, current role:', currentRole);

    select.onchange = async () => {
        currentRole = select.value;
        if (currentRole) {
            localStorage.setItem('selected_role', currentRole);
        } else {
            localStorage.removeItem('selected_role');
        }

        currentBucket = '';
        currentPath = '';

        if (bucketSelect) {
            bucketSelect.innerHTML = '<option value="">Select a bucket...</option>';
            bucketSelect.value = '';
            bucketSelect.disabled = !currentRole;
        }

        disableButtons();
        clearFileList(currentRole ? SELECT_BUCKET_MESSAGE : SELECT_ROLE_MESSAGE);

        if (currentRole) {
            await loadBuckets();
        }
    };
}

async function loadBuckets() {
    try {
        if (!currentRole) {
            const select = document.getElementById('bucket-select');
            if (select) {
                select.innerHTML = '<option value="">Select a bucket...</option>';
                select.value = '';
                select.disabled = true;
            }
            disableButtons();
            clearFileList(SELECT_ROLE_MESSAGE);
            return;
        }

        const roleIsAvailable = config && Array.isArray(config.roles) && config.roles.some(r => r.name === currentRole);
        if (!roleIsAvailable) {
            console.warn('Selected role not available in config:', currentRole);
            const select = document.getElementById('bucket-select');
            if (select) {
                select.innerHTML = '<option value="">Select a bucket...</option>';
                select.value = '';
                select.disabled = true;
            }
            disableButtons();
            clearFileList(SELECT_ROLE_MESSAGE);
            return;
        }

        const url = `/api/buckets?role=${encodeURIComponent(currentRole)}`;
        const response = await authFetch(url);

        if (!response.ok) {
            const errorData = await response.json().catch(() => ({ detail: 'Failed to load buckets' }));
            const errorMessage = errorData.detail || errorData.message || `HTTP ${response.status}: Failed to load buckets`;
            throw new Error(errorMessage);
        }

        const data = await response.json();

        // Check if response is an array (success) or error object
        if (!Array.isArray(data)) {
            // If it's an error object, extract the message
            const errorMessage = data.detail || data.message || 'Invalid response format';
            throw new Error(errorMessage);
        }

        const buckets = data;
        const select = document.getElementById('bucket-select');
        select.innerHTML = '<option value="">Select a bucket...</option>';
        select.disabled = false;
        clearError({ force: true });

        if (buckets.length > 0) {
            buckets.forEach(bucket => {
                const option = document.createElement('option');
                option.value = bucket;
                option.textContent = bucket;
                select.appendChild(option);
            });
        }
        if (buckets.length === 0) {
            clearFileList(NO_BUCKETS_MESSAGE);
            showError('No buckets returned for the selected role.', { duration: 180000 });
        }

        select.onchange = () => {
            currentBucket = select.value;
            currentPath = '';
            updateBreadcrumbs(); // Update breadcrumbs when bucket changes
            if (currentBucket) {
                enableButtons();
                loadFiles();
            } else {
                disableButtons();
                clearFileList(); // Clear file list when bucket is deselected
            }
        };

        // Auto-select bucket if only one is available
        if (buckets.length === 1) {
            select.value = buckets[0];
            currentBucket = buckets[0];
            currentPath = '';
            updateBreadcrumbs();
            enableButtons();
            loadFiles();
        } else {
            // Initially disable buttons if no bucket selected
            disableButtons();
        }
    } catch (error) {
        // Extract clean error message (remove "Failed to load buckets: " prefix if present)
        let errorMessage = error.message;
        if (errorMessage.startsWith('Failed to load buckets: ')) {
            errorMessage = errorMessage.substring('Failed to load buckets: '.length);
        }
        const isAccessError = /credentials|permission|accessdenied|sso|session/i.test(errorMessage);
        showError(errorMessage, { duration: isAccessError ? 180000 : null });
        // Clear bucket selector on error
        const select = document.getElementById('bucket-select');
        if (select) {
            select.innerHTML = '<option value="">Select a bucket...</option>';
            select.value = '';
            select.disabled = true;
        }
        disableButtons();
        clearFileList(SELECT_BUCKET_MESSAGE);
    }
}

function clearFileList(message = SELECT_BUCKET_MESSAGE) {
    // Clear file list display
    const list = document.getElementById('file-list');
    if (list) {
        list.innerHTML = `<div class="info-message">${message}</div>`;
    }

    // Reset state
    allFiles = [];
    filteredFiles = [];
    displayedFiles = [];
    currentPage = 0;
    searchQuery = '';

    // Clear search input
    const searchInput = document.getElementById('search-input');
    if (searchInput) {
        searchInput.value = '';
    }

    // Update file count
    updateFileCount(0, 0);

    // Update breadcrumbs to show only root
    updateBreadcrumbs();

    // Hide delete selected button
    const stickyDeleteContainer = document.getElementById('sticky-delete-container');
    if (stickyDeleteContainer) {
        stickyDeleteContainer.style.display = 'none';
    }
}

async function loadFiles() {
    if (!currentBucket) {
        clearFileList();
        return;
    }
    const list = document.getElementById('file-list');
    list.innerHTML = '<div class="loading"><span class="spinner"></span>Loading files...</div>';

    // Reset state
    allFiles = [];
    filteredFiles = [];
    displayedFiles = [];
    currentPage = 0;
    searchQuery = '';

    // Clear search input
    const searchInput = document.getElementById('search-input');
    if (searchInput) {
        searchInput.value = '';
    }

    try {
        const path = currentPath || '';
        const roleParam = currentRole ? `&role=${encodeURIComponent(currentRole)}` : '';
        const response = await authFetch(`/api/buckets/${currentBucket}/files?path=${encodeURIComponent(path)}${roleParam}`);
        const data = await response.json();
        updateBreadcrumbs();

        allFiles = data.files || [];

        if (allFiles.length === 0) {
            list.innerHTML = '<div class="loading">Empty folder</div>';
            updateFileCount(0, 0);
            return;
        }

        // Apply search filter if any
        applySearchFilter();

        // Render initial page
        renderFiles();

        // Setup scroll listener for lazy loading (only if enabled)
        if (window.ENABLE_LAZY_LOADING) {
            setupScrollListener();
        }

        // Check if we need to load more immediately (if initial render doesn't fill the container)
        // Only if lazy loading is enabled
        if (window.ENABLE_LAZY_LOADING) {
            setTimeout(() => {
                const container = document.getElementById('file-list-container');
                if (container) {
                    const scrollHeight = container.scrollHeight;
                    const clientHeight = container.clientHeight;
                    // If content doesn't fill the container, load more
                    if (scrollHeight <= clientHeight && currentPage + 1 < Math.ceil(filteredFiles.length / itemsPerPage)) {
                        loadMoreFiles();
                    }
                }
            }, 100);
        }

        updateDeleteButton();
    } catch (error) {
        showError('Failed to load files: ' + error.message);
    }
}

function applySearchFilter() {
    if (!searchQuery.trim()) {
        filteredFiles = [...allFiles];
    } else {
        const query = searchQuery.toLowerCase();
        filteredFiles = allFiles.filter(file =>
            file.name.toLowerCase().includes(query)
        );
    }
    currentPage = 0; // Reset to first page when filtering
    updateFileCount(allFiles.length, filteredFiles.length);
}

function renderFiles() {
    const list = document.getElementById('file-list');
    const startIndex = currentPage * itemsPerPage;
    const endIndex = Math.min(startIndex + itemsPerPage, filteredFiles.length);
    const filesToRender = filteredFiles.slice(startIndex, endIndex);

    // Clear list if starting from beginning
    if (currentPage === 0) {
        list.innerHTML = '';
    }

    filesToRender.forEach((file, localIndex) => {
        const globalIndex = startIndex + localIndex;
        const item = createFileItem(file, globalIndex);
        list.appendChild(item);
    });

    // Add placeholder for remaining items if not all rendered
    // Remove existing placeholder first to avoid duplicates
    const existingPlaceholder = document.getElementById('loading-placeholder');
    if (existingPlaceholder) {
        existingPlaceholder.remove();
    }

    if (endIndex < filteredFiles.length) {
        const placeholder = document.createElement('div');
        placeholder.className = 'file-item loading-placeholder';
        placeholder.style.height = '50px';
        placeholder.style.display = 'flex';
        placeholder.style.alignItems = 'center';
        placeholder.style.justifyContent = 'center';
        placeholder.style.color = 'var(--text-secondary)';
        placeholder.id = 'loading-placeholder';

        // If lazy loading is disabled, make it clickable
        if (!window.ENABLE_LAZY_LOADING) {
            placeholder.style.cursor = 'pointer';
            placeholder.style.userSelect = 'none';
            placeholder.style.backgroundColor = 'var(--bg-secondary)';
            placeholder.style.border = '1px solid var(--border-color)';
            placeholder.style.borderRadius = '4px';
            placeholder.style.margin = '8px';
            placeholder.style.transition = 'background-color 0.2s';
            placeholder.textContent = `Click to load more... (${endIndex}/${filteredFiles.length})`;
            placeholder.onclick = function() {
                loadMoreFiles();
            };
            placeholder.onmouseenter = function() {
                this.style.backgroundColor = 'var(--bg-hover)';
            };
            placeholder.onmouseleave = function() {
                this.style.backgroundColor = 'var(--bg-secondary)';
            };
        } else {
            placeholder.textContent = `Loading more... (${endIndex}/${filteredFiles.length})`;
        }

        list.appendChild(placeholder);
    }

    displayedFiles = filteredFiles.slice(0, endIndex);
}

function createFileItem(file, index) {
    const item = document.createElement('div');
    item.className = 'file-item';
    const icon = file.is_directory ? '📁' : '📄';
    const size = file.is_directory ? '' : formatSize(file.size);
    const fileId = `file-${index}`;

    // Create elements safely to prevent XSS
    const checkbox = document.createElement('input');
    checkbox.type = 'checkbox';
    checkbox.className = 'file-checkbox';
    checkbox.id = fileId;
    checkbox.setAttribute('data-name', file.name);
    checkbox.setAttribute('data-is-dir', file.is_directory);
    checkbox.onchange = updateDeleteButton;
    checkbox.onclick = (e) => e.stopPropagation();

    const iconSpan = document.createElement('span');
    iconSpan.className = 'file-icon';
    iconSpan.textContent = icon;

    const nameSpan = document.createElement('span');
    nameSpan.className = 'file-name';
    nameSpan.textContent = file.name;

    const sizeSpan = document.createElement('span');
    sizeSpan.className = 'file-size';
    sizeSpan.textContent = size;

    const actionsDiv = document.createElement('div');
    actionsDiv.className = 'file-actions';
    actionsDiv.onclick = (e) => e.stopPropagation();

    // Add download button for files (not directories)
    if (!file.is_directory) {
        const downloadBtn = document.createElement('button');
        downloadBtn.className = 'btn-primary';
        downloadBtn.style.marginRight = '5px';
        downloadBtn.textContent = '⬇️ Download';
        downloadBtn.onclick = (e) => {
            e.stopPropagation();
            downloadFile(file.name);
        };
        actionsDiv.appendChild(downloadBtn);
    }

    // Add delete button (only if deletion is not disabled)
    if (!window.DISABLE_DELETION) {
        const deleteBtn = document.createElement('button');
        deleteBtn.className = 'btn-danger';
        deleteBtn.textContent = '🗑️ Delete';
        deleteBtn.onclick = (e) => {
            e.stopPropagation();
            deleteItem(file.name, file.is_directory);
        };
        actionsDiv.appendChild(deleteBtn);
    }
    item.appendChild(checkbox);
    item.appendChild(iconSpan);
    item.appendChild(nameSpan);
    item.appendChild(sizeSpan);
    item.appendChild(actionsDiv);

    // Add click handler to the entire row
    if (file.is_directory) {
        // For directories, navigate on click
        item.onclick = (e) => {
            // Don't navigate if clicking on checkbox or button
            if (e.target.tagName === 'INPUT' || e.target.tagName === 'BUTTON' || e.target.closest('.file-actions')) {
                return;
            }
            navigateTo(file.name);
        };
    } else {
        // For files, toggle checkbox on click
        item.onclick = (e) => {
            // Don't toggle if clicking on checkbox or button
            if (e.target.tagName === 'INPUT' || e.target.tagName === 'BUTTON' || e.target.closest('.file-actions')) {
                return;
            }
            toggleCheckbox(fileId);
        };
    }

    return item;
}

function setupScrollListener() {
    const container = document.getElementById('file-list-container');
    if (!container) return;

    // Remove existing listener if any (use named function for proper removal)
    const scrollHandler = (e) => handleScroll(e);
    container.removeEventListener('scroll', scrollHandler);

    // Add scroll listener for lazy loading
    container.addEventListener('scroll', scrollHandler, { passive: true });

    // Store handler for later removal
    container._scrollHandler = scrollHandler;
}

function handleScroll(e) {
    // If lazy loading is disabled, don't auto-load on scroll
    if (!window.ENABLE_LAZY_LOADING) {
        return;
    }

    // Use throttling to avoid too many calls
    if (isScrolling) return;

    const container = e.target;
    const scrollTop = container.scrollTop;
    const scrollHeight = container.scrollHeight;
    const clientHeight = container.clientHeight;

    // Check if we're near the bottom (within 100px or 80% threshold)
    const threshold = 0.8;
    const distanceFromBottom = scrollHeight - (scrollTop + clientHeight);
    const thresholdPixels = 100;

    if (distanceFromBottom <= thresholdPixels || (scrollTop + clientHeight >= scrollHeight * threshold)) {
        // Check if there are more files to load
        const totalPages = Math.ceil(filteredFiles.length / itemsPerPage);
        if (currentPage + 1 < totalPages) {
            loadMoreFiles();
        }
    }
}

function loadMoreFiles() {
    // Prevent multiple simultaneous calls
    if (isScrolling) {
        return;
    }

    const totalPages = Math.ceil(filteredFiles.length / itemsPerPage);
    if (currentPage + 1 >= totalPages) {
        // All files already loaded, remove placeholder if exists
        const placeholder = document.getElementById('loading-placeholder');
        if (placeholder) {
            placeholder.remove();
        }
        isScrolling = false;
        return;
    }

    isScrolling = true;
    currentPage++;
    renderFiles();

    // Reset scrolling flag after a short delay
    clearTimeout(scrollTimeout);
    scrollTimeout = setTimeout(() => {
        isScrolling = false;
        // Check if we need to load more (user might have scrolled while loading)
        const container = document.getElementById('file-list-container');
        if (container) {
            const scrollTop = container.scrollTop;
            const scrollHeight = container.scrollHeight;
            const clientHeight = container.clientHeight;
            const distanceFromBottom = scrollHeight - (scrollTop + clientHeight);
            if (distanceFromBottom <= 100) {
                loadMoreFiles();
            }
        }
    }, 100);
}

function updateFileCount(total, filtered) {
    const countElement = document.getElementById('file-count');
    if (countElement) {
        if (searchQuery.trim()) {
            countElement.textContent = `Showing ${filtered} of ${total} object${total !== 1 ? 's' : ''}`;
        } else {
            countElement.textContent = `${total} object${total !== 1 ? 's' : ''}`;
        }
    }
}

function navigateTo(name) {
    currentPath = currentPath ? `${currentPath}/${name}` : name;
    loadFiles();
}

function navigateToPath(path) {
    currentPath = path;
    loadFiles();
}

function goUp() {
    if (!currentPath) return;
    const parts = currentPath.split('/');
    parts.pop();
    currentPath = parts.join('/');
    loadFiles();
}

function updateBreadcrumbs() {
    const breadcrumbsContainer = document.getElementById('breadcrumbs');
    if (!breadcrumbsContainer) return;

    breadcrumbsContainer.innerHTML = '';

    // Always add Root
    const rootItem = document.createElement('span');
    rootItem.className = 'breadcrumb-item';
    if (!currentPath) {
        rootItem.classList.add('current');
    }
    rootItem.textContent = '🏠 Root';
    rootItem.onclick = () => navigateToPath('');
    breadcrumbsContainer.appendChild(rootItem);

    if (!currentPath) {
        return; // We're at root, nothing more to show
    }

    // Add separator
    const separator = document.createElement('span');
    separator.className = 'breadcrumb-separator';
    separator.textContent = '/';
    breadcrumbsContainer.appendChild(separator);

    // Split path and create breadcrumb items
    const parts = currentPath.split('/').filter(p => p); // Filter empty parts

    parts.forEach((part, index) => {
        // Add separator before each part (except first)
        if (index > 0) {
            const sep = document.createElement('span');
            sep.className = 'breadcrumb-separator';
            sep.textContent = '/';
            breadcrumbsContainer.appendChild(sep);
        }

        // Create breadcrumb item
        const item = document.createElement('span');
        item.className = 'breadcrumb-item';

        // If this is the last part, it's the current location
        if (index === parts.length - 1) {
            item.classList.add('current');
        }

        item.textContent = part;

        // Build path up to this point
        const pathToHere = parts.slice(0, index + 1).join('/');
        item.onclick = () => navigateToPath(pathToHere);

        breadcrumbsContainer.appendChild(item);
    });
}

function refreshList() {
    loadFiles();
}

async function downloadFile(fileName) {
    if (!currentBucket) {
        showError('Please select a bucket first');
        return;
    }

    try {
        const path = currentPath ? `${currentPath}/${fileName}` : fileName;
        const roleParam = currentRole ? `&role=${encodeURIComponent(currentRole)}` : '';
        const url = `/api/buckets/${currentBucket}/download?path=${encodeURIComponent(path)}${roleParam}`;

        // Get auth token for the download request
        const token = getAuthToken();
        if (!token) {
            showError('Not authenticated');
            return;
        }

        // Fetch file and trigger download
        const response = await fetch(url, {
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.detail || 'Failed to download file');
        }

        // Get blob and create download link
        const blob = await response.blob();
        const downloadUrl = window.URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = downloadUrl;
        link.download = fileName;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        window.URL.revokeObjectURL(downloadUrl);
    } catch (error) {
        showError('Failed to download file: ' + error.message);
    }
}

let itemToDelete = null;
let itemToDeleteIsDirectory = false;

function deleteItem(name, isDirectory) {
    itemToDelete = name;
    itemToDeleteIsDirectory = isDirectory;
    document.getElementById('delete-item-type').textContent = isDirectory ? 'folder' : 'file';
    document.getElementById('delete-item-name').textContent = name;
    const modal = document.getElementById('confirm-delete-modal');
    modal.style.display = 'block';
}

function closeConfirmDeleteModal() {
    const modal = document.getElementById('confirm-delete-modal');
    modal.style.display = 'none';
    itemToDelete = null;
}

async function confirmDeleteItem() {
    if (!itemToDelete) return;

    const name = itemToDelete;
    const isDirectory = itemToDeleteIsDirectory;
    closeConfirmDeleteModal();

    showProgress(0, `Deleting ${isDirectory ? 'folder' : 'file'} "${name}"...`);

    try {
        const path = currentPath ? `${currentPath}/${name}` : name;
        updateProgress(50, `Deleting ${isDirectory ? 'folder' : 'file'} "${name}"...`);
        const roleParam = currentRole ? `&role=${encodeURIComponent(currentRole)}` : '';

        const response = await authFetch(`/api/buckets/${currentBucket}/files?path=${encodeURIComponent(path)}${roleParam}`, {
            method: 'DELETE'
        });

        if (response.ok) {
            updateProgress(100, `Successfully deleted "${name}"!`);

            // Hide delete button if no files are selected anymore
            updateDeleteButton();

            setTimeout(() => {
                hideProgress();
                loadFiles();
            }, 500);
        } else {
            const error = await response.json();
            hideProgress();
            showError('Failed to delete: ' + error.detail);
        }
    } catch (error) {
        hideProgress();
        showError('Failed to delete: ' + error.message);
    }
}

async function uploadFile(event) {
    if (!currentBucket) {
        showError('Please select a bucket first');
        return;
    }
    const files = Array.from(event.target.files);
    if (files.length === 0) return;
    await uploadFiles(files, '');
}

async function uploadFolder(event) {
    if (!currentBucket) {
        showError('Please select a bucket first');
        return;
    }
    const files = Array.from(event.target.files);
    if (files.length === 0) return;
    // Get folder name from the first file's path
    const folderName = files[0].webkitRelativePath.split('/')[0];
    await uploadFiles(files, folderName, folderName);
}

async function uploadFiles(files, folderPrefix, folderName) {
    if (!currentBucket) {
        showError('Please select a bucket first');
        return;
    }

    showProgress(0, `Uploading ${files.length} file(s)...`);

    // Start timing
    const startTime = Date.now();

    let uploaded = 0;
    let failed = 0;
    const errors = [];

    // Process files sequentially (parallelism doesn't provide significant speedup)
    for (let i = 0; i < files.length; i++) {
        const file = files[i];

        // Calculate key for this file
        let key = currentPath ? `${currentPath}/` : '';

        // Check if file has _relativePath (from drag-and-drop with folder structure)
        if (file._relativePath) {
            // Use the stored relative path directly
            // The path already includes folder structure (e.g., "folderName/subfolder/file.txt")
            key += file._relativePath;
        } else if (folderPrefix && folderName) {
            // Include folder name in the path (from folder upload button)
            const relativePath = file.webkitRelativePath || file.name;
            // Remove folder prefix but keep folder name
            const pathWithoutFolder = relativePath.replace(folderPrefix + '/', '');
            key += folderName + '/' + pathWithoutFolder;
        } else {
            key += file.name;
        }

        const progressPercent = ((i + 1) / files.length) * 100;
        updateProgress(progressPercent, `Uploading ${i + 1}/${files.length}: ${file.name}...`);

        try {
            const formData = new FormData();
            formData.append('file', file);
            formData.append('key', key);
            if (currentRole) {
                formData.append('role', currentRole);
            }

            // Add timeout to prevent hanging on slow connections
            const uploadPromise = authFetch(`/api/buckets/${currentBucket}/upload`, {
                method: 'POST',
                body: formData
            });

            const timeoutPromise = new Promise((_, reject) =>
                setTimeout(() => reject(new Error('Upload timeout')), 60000) // 60 second timeout
            );

            const response = await Promise.race([uploadPromise, timeoutPromise]);

            if (!response.ok) {
                let errorMessage = `Failed to upload ${file.name}`;
                try {
                    const error = await response.json();
                    errorMessage += ': ' + (error.detail || error.message || JSON.stringify(error));
                } catch (e) {
                    errorMessage += `: HTTP ${response.status} ${response.statusText}`;
                }
                throw new Error(errorMessage);
            }
            uploaded++;

            // Add progressive delay between uploads to prevent overwhelming MinIO or S3
            // Increase delay as we upload more files to prevent connection exhaustion
            if (i < files.length - 1) {
                // Progressive delay: 50ms base + 1ms per 10 files uploaded
                const delay = 50 + Math.floor(i / 10);
                await new Promise(resolve => setTimeout(resolve, delay));
            }
        } catch (error) {
            failed++;
            errors.push(`${file.name}: ${error.message || error.toString()}`);

            // Add delay even on error to prevent rapid retries
            if (i < files.length - 1) {
                await new Promise(resolve => setTimeout(resolve, 100)); // Longer delay on error
            }
        }
    }

    // Clear file inputs
    document.getElementById('file-input').value = '';
    document.getElementById('folder-input').value = '';

    // Calculate elapsed time
    const elapsedTime = ((Date.now() - startTime) / 1000).toFixed(2);
    const timeText = elapsedTime < 1 ? `${(elapsedTime * 1000).toFixed(0)}ms` : `${elapsedTime}s`;

    // Show errors if any
    if (errors.length > 0) {
        const errorMessage = `Failed to upload ${failed} file(s):\n${errors.slice(0, 10).join('\n')}${errors.length > 10 ? `\n... and ${errors.length - 10} more` : ''}`;
        showError(errorMessage);
    }

    updateProgress(100, `Successfully uploaded ${uploaded} file(s)${failed > 0 ? ` (${failed} failed)` : ''} in ${timeText}!`);
    setTimeout(() => {
        hideProgress();
        loadFiles();
    }, 2000); // Show completion message for 2 seconds
}

function handleDragOver(event) {
    if (!currentBucket) {
        return; // Don't allow drag if no bucket selected
    }
    event.preventDefault();
    event.stopPropagation();
    event.currentTarget.classList.add('dragover');
}

function handleDragLeave(event) {
    event.preventDefault();
    event.stopPropagation();
    event.currentTarget.classList.remove('dragover');
}

async function handleDrop(event) {
    if (!currentBucket) {
        event.preventDefault();
        event.stopPropagation();
        showError('Please select a bucket first');
        return;
    }

    event.preventDefault();
    event.stopPropagation();
    event.currentTarget.classList.remove('dragover');

    const items = Array.from(event.dataTransfer.items);
    const files = [];
    const fileEntries = [];

    // Try to get file entries to preserve folder structure
    for (const item of items) {
        if (item.kind === 'file') {
            const entry = item.webkitGetAsEntry ? item.webkitGetAsEntry() : null;
            if (entry) {
                fileEntries.push(entry);
            } else {
                // Fallback to regular file
                const file = item.getAsFile();
                if (file) {
                    files.push(file);
                }
            }
        }
    }

    // Process file entries with folder structure
    if (fileEntries.length > 0) {
        const allFiles = [];
        const folderMap = new Map();

        async function processEntry(entry, path = '') {
            if (entry.isFile) {
                return new Promise((resolve) => {
                    entry.file((file) => {
                        const fullPath = path ? `${path}/${file.name}` : file.name;
                        // Store file with its relative path
                        file._relativePath = fullPath;
                        allFiles.push(file);
                        resolve();
                    });
                });
            } else if (entry.isDirectory) {
                const dirReader = entry.createReader();
                const dirName = entry.name;
                const newPath = path ? `${path}/${dirName}` : dirName;

                return new Promise((resolve) => {
                    function readEntries() {
                        dirReader.readEntries(async (entries) => {
                            if (entries.length === 0) {
                                resolve();
                            } else {
                                for (const subEntry of entries) {
                                    await processEntry(subEntry, newPath);
                                }
                                // Continue reading if there are more entries
                                readEntries();
                            }
                        });
                    }
                    readEntries();
                });
            }
        }

        // Process all entries
        for (const entry of fileEntries) {
            await processEntry(entry);
        }

        if (allFiles.length > 0) {
            // Check if we have a folder structure
            // If the first entry was a directory, use its name as folder name
            let folderName = '';
            if (fileEntries.length > 0 && fileEntries[0].isDirectory) {
                folderName = fileEntries[0].name;
            } else {
                // Try to extract from file paths
                const firstPath = allFiles[0]._relativePath;
                if (firstPath && firstPath.includes('/')) {
                    folderName = firstPath.split('/')[0];
                }
            }

            if (folderName) {
                // Upload with folder structure
                // Files already have _relativePath with full structure (e.g., "folderName/subfolder/file.txt")
                // We'll use this directly in uploadFiles
                await uploadFiles(allFiles, folderName, folderName);
            } else {
                // No folder structure, upload as individual files
                await uploadFiles(allFiles, '');
            }
        }
    } else if (files.length > 0) {
        // Fallback: upload as individual files
        await uploadFiles(files, '');
    }
}

function formatSize(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
}

function showError(message, { duration = null } = {}) {
    const errorDiv = document.getElementById('error-message');
    if (errorClearTimer) {
        clearTimeout(errorClearTimer);
        errorClearTimer = null;
    }
    currentErrorTimeout = duration;
    errorDiv.innerHTML = `<div class="error">${message}</div>`;
    const timeout = typeof duration === 'number' && duration > 0 ? duration : 7000;
    if (timeout > 0) {
        errorClearTimer = setTimeout(() => {
            if (errorDiv.innerHTML.includes(message)) {
                errorDiv.innerHTML = '';
            }
            errorClearTimer = null;
            currentErrorTimeout = null;
        }, timeout);
    }
}

function clearError({ force = false } = {}) {
    if (!force && currentErrorTimeout === null) {
        return;
    }
    const errorDiv = document.getElementById('error-message');
    errorDiv.innerHTML = '';
    if (errorClearTimer) {
        clearTimeout(errorClearTimer);
        errorClearTimer = null;
    }
    currentErrorTimeout = null;
}

function toggleCheckbox(checkboxId) {
    const checkbox = document.getElementById(checkboxId);
    if (checkbox) {
        checkbox.checked = !checkbox.checked;
        // Update visual state
        const item = checkbox.closest('.file-item');
        if (item) {
            if (checkbox.checked) {
                item.classList.add('selected');
            } else {
                item.classList.remove('selected');
            }
        }
        updateDeleteButton();
    }
}

function toggleSelectAll() {
    const checkboxes = document.querySelectorAll('.file-checkbox');
    const checked = document.querySelectorAll('.file-checkbox:checked');
    const selectAllBtn = document.getElementById('select-all-btn');

    // If all visible are checked, uncheck all; otherwise check all visible
    const shouldSelectAll = checked.length < checkboxes.length;

    checkboxes.forEach(checkbox => {
        checkbox.checked = shouldSelectAll;
        const item = checkbox.closest('.file-item');
        if (item) {
            if (shouldSelectAll) {
                item.classList.add('selected');
            } else {
                item.classList.remove('selected');
            }
        }
    });

    // Update button text based on visible checkboxes
    if (shouldSelectAll) {
        selectAllBtn.textContent = '☐ Deselect All';
    } else {
        selectAllBtn.textContent = '☑️ Select All';
    }

    updateDeleteButton();
}

function updateDeleteButton() {
    const checkboxes = document.querySelectorAll('.file-checkbox');
    const checked = document.querySelectorAll('.file-checkbox:checked');
    const count = checked.length;
    const stickyContainer = document.getElementById('sticky-delete-container');
    const countSpans = document.querySelectorAll('.selected-count');
    const deleteBtn = document.getElementById('delete-selected-sticky');
    const selectAllBtn = document.getElementById('select-all-btn');

    // Update visual state for all items
    checkboxes.forEach(checkbox => {
        const item = checkbox.closest('.file-item');
        if (item) {
            if (checkbox.checked) {
                item.classList.add('selected');
            } else {
                item.classList.remove('selected');
            }
        }
    });

    // Update Select All button text
    if (selectAllBtn) {
        if (count === checkboxes.length && checkboxes.length > 0) {
            selectAllBtn.textContent = '☐ Deselect All';
        } else {
            selectAllBtn.textContent = '☑️ Select All';
        }
    }

    // Update sticky container visibility
    if (count > 0) {
        if (stickyContainer) {
            stickyContainer.style.display = 'block';
        }
        // Update all count spans
        countSpans.forEach(span => {
            span.textContent = count;
        });

        if (deleteBtn) {
            deleteBtn.style.display = window.DISABLE_DELETION ? 'none' : 'inline-block';
        }

        // Disable individual delete buttons when multiple items are selected
        const individualDeleteButtons = document.querySelectorAll('.file-actions button.btn-danger');
        if (!window.DISABLE_DELETION) {
            individualDeleteButtons.forEach(btn => {
                btn.disabled = true;
                const tooltipText = `You have ${count} item(s) selected. Deselect all items to delete files individually, or use the "Delete Selected" button above to delete all selected items.`;
                btn.setAttribute('data-tooltip', tooltipText);
            });
        }
    } else {
        if (stickyContainer) {
            stickyContainer.style.display = 'none';
        }
        // Enable individual delete buttons when nothing is selected (only if deletion is enabled)
        if (!window.DISABLE_DELETION) {
            const individualDeleteButtons = document.querySelectorAll('.file-actions button.btn-danger');
            individualDeleteButtons.forEach(btn => {
                btn.disabled = false;
                btn.removeAttribute('data-tooltip');
                // Remove tooltip if exists
                const oldTooltip = btn.querySelector('.custom-tooltip');
                if (oldTooltip) {
                    oldTooltip.remove();
                }
            });
        }
    }
}

let itemsToDelete = null;

function deleteSelected() {
    const checkboxes = document.querySelectorAll('.file-checkbox:checked');
    if (checkboxes.length === 0) {
        return;
    }

    const items = Array.from(checkboxes).map(cb => ({
        name: cb.getAttribute('data-name'),
        isDirectory: cb.getAttribute('data-is-dir') === 'true'
    }));

    itemsToDelete = items;
    document.getElementById('delete-selected-count').textContent = items.length;
    const modal = document.getElementById('confirm-delete-selected-modal');
    modal.style.display = 'block';
}

function closeConfirmDeleteSelectedModal() {
    const modal = document.getElementById('confirm-delete-selected-modal');
    modal.style.display = 'none';
    itemsToDelete = null;
}

async function confirmDeleteSelected() {
    if (!itemsToDelete || itemsToDelete.length === 0) return;

    const btn = document.getElementById('confirm-delete-selected-btn');
    const originalText = btn.innerHTML;

    // Show spinner and disable button
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner" style="display: inline-block; width: 14px; height: 14px; border: 2px solid #ffffff; border-top-color: transparent; border-radius: 50%; animation: spin 0.8s linear infinite; margin-right: 5px; vertical-align: middle;"></span> Deleting...';

    const items = itemsToDelete;
    closeConfirmDeleteSelectedModal();

    // Hide delete button immediately and show progress bar
    const stickyContainer = document.getElementById('sticky-delete-container');
    stickyContainer.style.display = 'none';

    showProgress(0, `Deleting ${items.length} item(s)...`);

    // Start timing
    const startTime = Date.now();

    let deleted = 0;
    let failed = 0;
    const errors = [];

    // Process items sequentially (parallelism doesn't provide significant speedup)
    for (let i = 0; i < items.length; i++) {
        const item = items[i];
        const progressPercent = ((i + 1) / items.length) * 100;
        updateProgress(progressPercent, `Deleting ${i + 1}/${items.length}: ${item.name}...`);

        try {
            const path = currentPath ? `${currentPath}/${item.name}` : item.name;
            const roleParam = currentRole ? `&role=${encodeURIComponent(currentRole)}` : '';
            const response = await authFetch(`/api/buckets/${currentBucket}/files?path=${encodeURIComponent(path)}${roleParam}`, {
                method: 'DELETE'
            });

            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.detail || 'Unknown error');
            }
            deleted++;
        } catch (error) {
            failed++;
            errors.push(`${item.name}: ${error.message || error.toString()}`);
        }
    }

    // Calculate elapsed time
    const elapsedTime = ((Date.now() - startTime) / 1000).toFixed(2);
    const timeText = elapsedTime < 1 ? `${(elapsedTime * 1000).toFixed(0)}ms` : `${elapsedTime}s`;

    // Show errors if any
    if (errors.length > 0) {
        const errorMessage = `Failed to delete ${failed} item(s):\n${errors.slice(0, 10).join('\n')}${errors.length > 10 ? `\n... and ${errors.length - 10} more` : ''}`;
        showError(errorMessage);
    }

    updateProgress(100, `Successfully deleted ${deleted} item(s)${failed > 0 ? ` (${failed} failed)` : ''} in ${timeText}!`);

    setTimeout(() => {
        hideProgress();
        loadFiles();
        // Restore button state (modal is already closed, but button might be cached)
        const btnEl = document.getElementById('confirm-delete-selected-btn');
        if (btnEl) {
            btnEl.disabled = false;
            btnEl.innerHTML = originalText;
        }
    }, 2000); // Show completion message for 2 seconds
}

function showProgress(percent, text) {
    const container = document.getElementById('progress-container');
    const fill = document.getElementById('progress-fill');
    const textEl = document.getElementById('progress-text');

    container.style.display = 'block';
    // Ensure minimum width for visibility even at 0%
    fill.style.width = Math.max(percent, 2) + '%';
    textEl.innerHTML = `<span class="spinner"></span>${text}`;

    // Force a reflow to ensure the container is visible
    container.offsetHeight;
}

// Helper function to truncate long file names in progress messages
function truncateFileName(fileName, maxLength = 40) {
    if (fileName.length <= maxLength) {
        return fileName;
    }
    const lastDotIndex = fileName.lastIndexOf('.');
    // Check if file has extension (has dot and it's not at the start)
    if (lastDotIndex > 0 && lastDotIndex < fileName.length - 1) {
        const extension = fileName.substring(lastDotIndex);
        const nameWithoutExt = fileName.substring(0, lastDotIndex);
        const maxNameLength = maxLength - extension.length - 3; // 3 for "..."
        if (nameWithoutExt.length <= maxNameLength) {
            return fileName;
        }
        return nameWithoutExt.substring(0, maxNameLength) + '...' + extension;
    } else {
        // No extension, just truncate from the end
        return fileName.substring(0, maxLength - 3) + '...';
    }
}

function updateProgress(percent, text) {
    const fill = document.getElementById('progress-fill');
    const textEl = document.getElementById('progress-text');
    if (!textEl || !fill) return;

    // Ensure minimum width for visibility even at 0%
    fill.style.width = Math.max(percent, 2) + '%';

    // Truncate long file names in progress messages to prevent layout jumping
    let displayText = text;
    // Match patterns like "Uploading 1/10: very-long-file-name.txt..." or "Deleting 1/10: very-long-file-name.txt..."
    const fileMatch = text.match(/(Uploading|Deleting)\s+\d+\/\d+:\s+(.+?)(\.\.\.|$)/);
    if (fileMatch && fileMatch[2]) {
        const fileName = fileMatch[2];
        const truncatedName = truncateFileName(fileName, 40);
        if (truncatedName !== fileName) {
            displayText = text.replace(fileName, truncatedName);
        }
    }

    // Show spinner only if not completed (100%)
    if (percent >= 100) {
        textEl.innerHTML = displayText; // No spinner on completion
    } else {
        textEl.innerHTML = `<span class="spinner"></span>${displayText}`;
    }
}

function hideProgress() {
    const container = document.getElementById('progress-container');
    container.style.display = 'none';
    const fill = document.getElementById('progress-fill');
    fill.style.width = '0%';
}

function enableButtons() {
    document.getElementById('refresh-btn').disabled = false;
    document.getElementById('go-up-btn').disabled = false;
    document.getElementById('upload-file-btn').disabled = false;
    document.getElementById('upload-folder-btn').disabled = false;
    document.getElementById('select-all-btn').disabled = false;
    const searchInput = document.getElementById('search-input');
    if (searchInput) {
        searchInput.disabled = false;
    }
    const uploadArea = document.getElementById('upload-area');
    if (uploadArea) {
        uploadArea.classList.remove('disabled');
    }
}

function disableButtons() {
    document.getElementById('refresh-btn').disabled = true;
    document.getElementById('go-up-btn').disabled = true;
    document.getElementById('upload-file-btn').disabled = true;
    document.getElementById('upload-folder-btn').disabled = true;
    document.getElementById('select-all-btn').disabled = true;
    const searchInput = document.getElementById('search-input');
    if (searchInput) {
        searchInput.disabled = true;
    }
    const uploadArea = document.getElementById('upload-area');
    if (uploadArea) {
        uploadArea.classList.add('disabled');
    }
}

function openConfigModal() {
    const modal = document.getElementById('config-modal');
    const editor = document.getElementById('config-editor');
    editor.value = JSON.stringify(config, null, 2);
    modal.style.display = 'block';
}

function showUploadFolderModal() {
    const modal = document.getElementById('upload-folder-modal');
    if (modal) {
        modal.style.display = 'block';
    }
}

function closeUploadFolderModal() {
    const modal = document.getElementById('upload-folder-modal');
    if (modal) {
        modal.style.display = 'none';
    }
}

function closeConfigModal() {
    const modal = document.getElementById('config-modal');
    modal.style.display = 'none';
}

async function saveConfig() {
    const editor = document.getElementById('config-editor');
    try {
        const newConfig = JSON.parse(editor.value);
        await saveConfigToServer(newConfig);
        // Reload config from server to get updated values (including items_per_page, disable_deletion)
        await loadConfig(true);
        // Keep current role from localStorage (don't change it when config is reloaded)
        // If no role saved, use first available role
        const savedRole = localStorage.getItem('selected_role');
        if (savedRole && config.roles && config.roles.some(r => r.name === savedRole)) {
            currentRole = savedRole;
        } else {
            currentRole = config.roles && config.roles.length > 0 ? config.roles[0].name : '';
        }
        updateRoleSelector();
        closeConfigModal();
        // Show success message (using error div but with success styling)
        const errorDiv = document.getElementById('error-message');
        errorDiv.innerHTML = '<div style="background: #d4edda; color: #155724; padding: 10px; border-radius: 4px; margin-bottom: 15px;">✓ Configuration saved successfully!</div>';
        setTimeout(() => {
            errorDiv.innerHTML = '';
        }, 3000);
        // Reload buckets
        currentBucket = '';
        currentPath = '';
        const bucketSelect = document.getElementById('bucket-select');
        bucketSelect.innerHTML = '<option value="">Select a bucket...</option>';
        bucketSelect.value = '';
        disableButtons();
        await loadBuckets();
    } catch (error) {
        showError('Invalid JSON: ' + error.message);
    }
}

async function saveConfigToServer(newConfig) {
    const response = await authFetch('/api/config', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(newConfig)
    });

    if (!response.ok) {
        const error = await response.json();
        throw new Error(error.detail || 'Failed to save configuration');
    }
}

// Close modal when clicking outside
window.onclick = function(event) {
    const configModal = document.getElementById('config-modal');
    if (event.target === configModal) {
        closeConfigModal();
    }
    const deleteModal = document.getElementById('confirm-delete-modal');
    if (event.target === deleteModal) {
        closeConfirmDeleteModal();
    }
    const deleteSelectedModal = document.getElementById('confirm-delete-selected-modal');
    if (event.target === deleteSelectedModal) {
        closeConfirmDeleteSelectedModal();
    }
    const uploadFolderModal = document.getElementById('upload-folder-modal');
    if (event.target === uploadFolderModal) {
        closeUploadFolderModal();
    }
}

// Initialize on page load
// Wait for DOM to be ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initializeApp);
} else {
    // DOM is already ready
    initializeApp();
}

// Custom tooltip functionality
function initTooltips() {
    // Handle tooltips for elements with data-tooltip attribute
    document.addEventListener('mouseenter', function(e) {
        const element = e.target.closest('[data-tooltip]');
        if (element && element.disabled) {
            showTooltip(element, element.getAttribute('data-tooltip'));
        }
    }, true);

    document.addEventListener('mouseleave', function(e) {
        const element = e.target.closest('[data-tooltip]');
        if (element) {
            hideTooltip(element);
        }
    }, true);
}

function showTooltip(element, text) {
    // Remove existing tooltip if any
    hideTooltip(element);

    if (!text) return;

    const tooltip = document.createElement('div');
    tooltip.className = 'custom-tooltip';
    tooltip.textContent = text;
    document.body.appendChild(tooltip);

    // Position tooltip
    const rect = element.getBoundingClientRect();
    const tooltipRect = tooltip.getBoundingClientRect();
    const scrollTop = window.pageYOffset || document.documentElement.scrollTop;
    const scrollLeft = window.pageXOffset || document.documentElement.scrollLeft;

    // Try to position above first, then below if not enough space
    let top = rect.top + scrollTop - tooltipRect.height - 8;
    let left = rect.left + scrollLeft + (rect.width / 2) - (tooltipRect.width / 2);

    // Check if tooltip goes off screen
    if (top < scrollTop) {
        // Position below
        top = rect.bottom + scrollTop + 8;
        tooltip.classList.add('bottom');
    } else {
        tooltip.classList.add('top');
    }

    // Adjust horizontal position if goes off screen
    if (left < scrollLeft) {
        left = scrollLeft + 10;
    } else if (left + tooltipRect.width > scrollLeft + window.innerWidth) {
        left = scrollLeft + window.innerWidth - tooltipRect.width - 10;
    }

    tooltip.style.top = top + 'px';
    tooltip.style.left = left + 'px';

    // Store reference
    element._tooltip = tooltip;

    // Show with animation
    setTimeout(() => {
        tooltip.classList.add('show');
    }, 10);
}

function hideTooltip(element) {
    if (element._tooltip) {
        element._tooltip.remove();
        element._tooltip = null;
    }
}

async function initializeApp() {
    console.log('Initializing app...');
    await loadAppInfo();
    const authenticated = await checkAuth();
    if (authenticated) {
        console.log('User authenticated, loading config...');
        const configData = await loadConfig(true);
        const roles = configData && Array.isArray(configData.roles) ? configData.roles : [];

        if (!roles.length) {
            const bucketSelect = document.getElementById('bucket-select');
            if (bucketSelect) {
                bucketSelect.innerHTML = '<option value="">No roles assigned</option>';
                bucketSelect.value = '';
                bucketSelect.disabled = true;
            }
            disableButtons();
            clearFileList(NO_ROLES_MESSAGE);
            console.log('No roles available; skipping bucket loading.');
            return;
        }

        if (currentRole) {
            console.log('Config loaded, loading buckets for role:', currentRole);
            await loadBuckets();
        } else {
            const bucketSelect = document.getElementById('bucket-select');
            if (bucketSelect) {
                bucketSelect.innerHTML = '<option value="">Select a bucket...</option>';
                bucketSelect.value = '';
                bucketSelect.disabled = true;
            }
            disableButtons();
            clearFileList(SELECT_ROLE_MESSAGE);
            console.log('Waiting for user to select a role before loading buckets.');
            clearError({ force: true });
        }
        console.log('App initialized');
        // Initialize tooltips
        initTooltips();
        // Initialize search input
        const searchInput = document.getElementById('search-input');
        if (searchInput) {
            let searchTimeout = null;
            searchInput.addEventListener('input', (e) => {
                clearTimeout(searchTimeout);
                searchTimeout = setTimeout(() => {
                    searchQuery = e.target.value;
                    applySearchFilter();
                    renderFiles();
                }, 300); // Debounce search by 300ms
            });
        }
    }
}

