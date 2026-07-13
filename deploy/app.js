// app.js
const CLIENT_ID = '981549083683-mip1727gmq4jsqkgv7vvqhos8mulr2vf.apps.googleusercontent.com';
const FILE_ID = '1Y8dvHlVZQCE7pSZu--7qFqZRxL7vNBT4';
const SCOPES = 'https://www.googleapis.com/auth/drive';

const CACHE_KEY = 'id_dragon_favories';
const PEPPER = document.getElementById('vault-pepper').dataset.p;

let tokenClient, accessToken = null, currentDb = null, fileMetadata = null;
let autoUnlockAttempted = false;

const DOM = {
    stepAuth: document.getElementById('step-auth'),
    stepUnlock: document.getElementById('step-unlock'),
    stepDashboard: document.getElementById('step-dashboard'),
    btnLogin: document.getElementById('btn-login'),
    btnUnlock: document.getElementById('btn-unlock'),
    btnLockCache: document.getElementById('btn-lock-cache'),
    masterPassword: document.getElementById('master-password'),
    rememberMe: document.getElementById('remember-me'),
    cacheHint: document.getElementById('cache-hint'),
    passwordsList: document.getElementById('passwords-list'),
    skeletonLoader: document.getElementById('skeleton-loader'),
    lockIcon: document.getElementById('lock-icon'),
    lockShackle: document.getElementById('lock-shackle'),
    inputContainer: document.getElementById('input-container'),
    toast: document.getElementById('toast-container'),
    statusText: document.getElementById('status-text'),
    statusDot: document.getElementById('status-dot'),
    searchContainer: document.getElementById('search-container'),
    detailModal: document.getElementById('detail-modal'),
    detailBackdrop: document.getElementById('detail-backdrop'),
    detailPanel: document.getElementById('detail-panel'),
    detailClose: document.getElementById('detail-close'),
    detailIcon: document.getElementById('detail-icon'),
    detailTitle: document.getElementById('detail-title'),
    detailFields: document.getElementById('detail-fields')
};

/* =========================================================
   CHIFFREMENT LOCAL DU MOT DE PASSE MAÎTRE (Web Crypto API)
   La clé de dérivation combine :
   - Le "pepper" secret injecté dans le HTML (non trivialement lisible/partagé)
   - Un identifiant lié à ce navigateur/appareil (device fingerprint léger)
   Le résultat est stocké chiffré (AES-GCM) sous localStorage["id_dragon_favories"].
   Même si quelqu'un exfiltre le localStorage, il lui faudra aussi connaître/
   récupérer le pepper embarqué dans CE site précis pour déchiffrer.
========================================================= */

function getDeviceSeed() {
    // Empreinte légère et stable de l'appareil/navigateur (pas d'API externe)
    const seedParts = [
        navigator.userAgent,
        navigator.language,
        screen.colorDepth,
        screen.width + 'x' + screen.height,
        Intl.DateTimeFormat().resolvedOptions().timeZone
    ];
    return seedParts.join('|');
}

async function deriveCryptoKey() {
    const enc = new TextEncoder();
    const material = await crypto.subtle.importKey(
        'raw',
        enc.encode(PEPPER + '::' + getDeviceSeed()),
        'PBKDF2',
        false,
        ['deriveKey']
    );
    return crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            salt: enc.encode('securevault-static-salt-v1'),
            iterations: 150000,
            hash: 'SHA-256'
        },
        material,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
    );
}

async function encryptAndStorePassword(plainPassword) {
    try {
        const key = await deriveCryptoKey();
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const enc = new TextEncoder();
        const ciphertext = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv },
            key,
            enc.encode(plainPassword)
        );
        const payload = {
            iv: Array.from(iv),
            data: Array.from(new Uint8Array(ciphertext)),
            v: 1
        };
        localStorage.setItem(CACHE_KEY, JSON.stringify(payload));
    } catch (e) {
        console.error('Échec du chiffrement du cache local', e);
    }
}

async function loadCachedPassword() {
    const raw = localStorage.getItem(CACHE_KEY);
    if (!raw) return null;
    try {
        const payload = JSON.parse(raw);
        const key = await deriveCryptoKey();
        const iv = new Uint8Array(payload.iv);
        const data = new Uint8Array(payload.data);
        const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, data);
        return new TextDecoder().decode(decrypted);
    } catch (e) {
        // Cache corrompu, illisible, ou appareil différent -> on l'ignore
        console.warn('Impossible de déchiffrer le cache local (attendu si nouvel appareil).');
        return null;
    }
}

function clearCachedPassword() {
    localStorage.removeItem(CACHE_KEY);
    DOM.btnLockCache.classList.add('hidden');
}

DOM.btnLockCache.onclick = () => {
    clearCachedPassword();
    DOM.masterPassword.value = '';
    showToastMessage('Cache local effacé.');
};

/* ========================================================= */

window.onload = function () {
    gapi.load('client', () => { gapi.client.init({ discoveryDocs: ['https://www.googleapis.com/discovery/v1/apis/drive/v3/rest'] }); });
    tokenClient = google.accounts.oauth2.initTokenClient({
        client_id: CLIENT_ID,
        scope: SCOPES,
        callback: (tokenResponse) => {
            if (tokenResponse && tokenResponse.access_token) {
                accessToken = tokenResponse.access_token;
                updateStatus("Recherche du fichier...", "bg-yellow-500", "text-yellow-400");
                transitionView(DOM.stepAuth, DOM.stepUnlock);
                downloadKdbxFile();
            }
        },
    });

    if (localStorage.getItem(CACHE_KEY)) {
        DOM.btnLockCache.classList.remove('hidden');
    }
};

DOM.btnLogin.onclick = () => tokenClient.requestAccessToken({ prompt: 'consent' });

// --- ANIMATION CADENAS ---
DOM.masterPassword.addEventListener('input', (e) => {
    if (e.target.value.length > 0) {
        DOM.lockShackle.setAttribute('d', 'M8 11V7a4 4 0 118 0v4m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2z');
        DOM.lockIcon.classList.replace('text-gray-500', 'text-[#10B981]');
    } else {
        DOM.lockShackle.setAttribute('d', 'M8 11V7a4 4 0 118 0m-4 8v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2z');
        DOM.lockIcon.classList.replace('text-[#10B981]', 'text-gray-500');
    }
});

async function downloadKdbxFile() {
    try {
        const response = await fetch(`https://www.googleapis.com/drive/v3/files/${FILE_ID}?alt=media`, {
            headers: { 'Authorization': `Bearer ${accessToken}` }
        });
        if (!response.ok) throw new Error();
        fileMetadata = await response.arrayBuffer();
        updateStatus("Prêt pour déchiffrement", "bg-cyan-500", "text-cyan-400");

        // Tentative de déverrouillage automatique via le cache chiffré
        if (!autoUnlockAttempted) {
            autoUnlockAttempted = true;
            const cached = await loadCachedPassword();
            if (cached) {
                DOM.cacheHint.classList.remove('hidden');
                DOM.masterPassword.value = cached;
                setTimeout(() => attemptUnlock(cached, false), 400);
            }
        }
    } catch (e) {
        showError("Impossible d'accéder au conteneur.");
    }
}

DOM.btnUnlock.onclick = () => attemptUnlock(DOM.masterPassword.value, true);

DOM.masterPassword.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') attemptUnlock(DOM.masterPassword.value, true);
});

async function attemptUnlock(password, isManual) {
    if (!password) return;
    document.getElementById('error-msg').classList.add('hidden');

    const originalText = DOM.btnUnlock.innerText;
    DOM.btnUnlock.innerHTML = `<svg class="animate-spin h-5 w-5 mx-auto text-white" fill="none" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg>`;

    try {
        if (!fileMetadata) throw new Error("Fichier non chargé.");

        const credentials = new kdbxweb.Credentials(kdbxweb.ProtectedValue.fromString(password), null);
        currentDb = await kdbxweb.Kdbx.load(fileMetadata, credentials);

        // Succès : on stocke le mot de passe chiffré si demandé
        if (DOM.rememberMe.checked) {
            await encryptAndStorePassword(password);
            DOM.btnLockCache.classList.remove('hidden');
        } else {
            clearCachedPassword();
        }

        updateStatus("Déverrouillé", "bg-emerald-500 dot-pulse", "text-emerald-400");
        transitionView(DOM.stepUnlock, DOM.stepDashboard);

        generateSkeletons();
        setTimeout(() => {
            DOM.skeletonLoader.classList.add('hidden');
            DOM.passwordsList.classList.remove('hidden');
            DOM.searchContainer.classList.remove('hidden');
            displayEntries();
        }, 900);

    } catch (e) {
        console.error(e);
        DOM.cacheHint.classList.add('hidden');
        if (!isManual) {
            // Échec silencieux de l'auto-unlock : on efface le cache invalide et on laisse l'utilisateur saisir
            clearCachedPassword();
            DOM.masterPassword.value = '';
        } else {
            showError("Mot de passe incorrect ou fichier corrompu.");
            DOM.inputContainer.classList.add('animate-shake');
            setTimeout(() => DOM.inputContainer.classList.remove('animate-shake'), 400);
        }
    } finally {
        DOM.btnUnlock.innerText = originalText;
    }
}

// --- KEEPASS PARSING ET DOM ---
function escapeHtml(str) {
    return String(str)
        .replace(/&/g, '&')
        .replace(/</g, '<')
        .replace(/>/g, '>')
        .replace(/"/g, '"')
        .replace(/'/g, ''');
}

function getFieldText(entry, name) {
    const field = entry.fields.get(name);
    if (!field) return '';
    if (typeof field === 'string') return field;
    if (field.getText) return field.getText();
    return String(field);
}

function displayEntries() {
    DOM.passwordsList.innerHTML = '';
    const entries = currentDb.getDefaultGroup().entries;

    entries.forEach((entry, index) => {
        const title = getFieldText(entry, 'Title') || 'Sans titre';
        const username = getFieldText(entry, 'UserName') || '—';
        const passwordValue = getFieldText(entry, 'Password');
        const rawUrl = getFieldText(entry, 'URL');
        const notes = getFieldText(entry, 'Notes');

        // --- LOGIQUE DES FAVICONS ---
        let domain = "";
        if (rawUrl && rawUrl.includes('.')) {
            try { domain = new URL(rawUrl.startsWith('http') ? rawUrl : 'https://' + rawUrl).hostname; }
            catch (e) { domain = rawUrl; }
        } else {
            domain = title.toLowerCase().replace(/\s+/g, '') + '.com';
        }

        const fallbackIcon = `<div class="w-10 h-10 rounded-lg bg-gray-800 flex items-center justify-center border border-gray-700 text-gray-400 font-mono text-sm shadow-inner flex-shrink-0">${escapeHtml(title.charAt(0).toUpperCase())}</div>`;
        let iconHtml = fallbackIcon;
        if (domain && domain !== ".com") {
            iconHtml = `<img src="https://s2.googleusercontent.com/s2/favicons?domain=${encodeURIComponent(domain)}&sz=64" onerror="this.outerHTML='${fallbackIcon.replace(/'/g, "\\'")}'" class="w-10 h-10 rounded-lg object-contain bg-white/5 p-1.5 border border-white/5 flex-shrink-0 shadow-sm">`;
        }

        const id = `pwd-${index}`;
        const safePwd = escapeHtml(passwordValue).replace(/'/g, "\\'");

        const card = document.createElement('div');
        card.className = "spotlight-card rounded-2xl p-5 flex flex-col gap-5 group";
        card.dataset.entryIndex = index;

        card.addEventListener('mousemove', (e) => {
            const rect = card.getBoundingClientRect();
            card.style.setProperty('--mouse-x', `${e.clientX - rect.left}px`);
            card.style.setProperty('--mouse-y', `${e.clientY - rect.top}px`);
        });

        card.innerHTML = `
            <div class="flex items-center gap-3">
                ${iconHtml}
                <div class="flex-1 min-w-0">
                    <h3 class="font-semibold text-white truncate">${escapeHtml(title)}</h3>
                    <p class="text-xs text-gray-500 font-mono truncate">${escapeHtml(username)}</p>
                </div>
            </div>
            <div class="flex items-center gap-2 bg-[#0B0F19] rounded-xl border border-white/5 p-2">
                <input type="password" value="${safePwd}" class="flex-1 bg-transparent text-sm font-mono text-gray-300 px-2 outline-none pointer-events-none" readonly id="${id}">
                <div class="flex gap-1 flex-shrink-0">
                    <button data-action="reveal" data-id="${id}" data-pwd="${safePwd}" class="text-gray-500 hover:text-cyan-400 p-2 rounded transition-colors" title="Afficher/Masquer">
                        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"/></svg>
                    </button>
                    <button data-action="copy" data-pwd="${safePwd}" class="text-gray-500 hover:text-[#10B981] p-2 rounded transition-colors" title="Copier le MDP">
                        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"/></svg>
                    </button>
                </div>
            </div>
        `;

        // Boutons internes : on empêche la propagation vers l'ouverture de la modale
        card.querySelectorAll('button[data-action]').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.stopPropagation();
                const action = btn.dataset.action;
                if (action === 'reveal') revealMatrix(btn.dataset.id, decodeHtml(btn.dataset.pwd), btn);
                if (action === 'copy') copyAnim(decodeHtml(btn.dataset.pwd), btn);
            });
        });

        // Ouverture de la modale de détails au clic sur la carte
        card.addEventListener('click', () => openDetailModal({
            title, username, password: passwordValue, url: rawUrl, notes,
            iconHtml, entry
        }));

        DOM.passwordsList.appendChild(card);
    });
}

function decodeHtml(str) {
    const txt = document.createElement('textarea');
    txt.innerHTML = str;
    return txt.value;
}

// --- MODALE DE DÉTAILS ---
function openDetailModal(data) {
    DOM.detailIcon.innerHTML = data.iconHtml;
    DOM.detailTitle.textContent = data.title;

    const rows = [];

    rows.push(fieldRow('Identifiant', data.username, true));
    rows.push(passwordRow(data.password));
    if (data.url) rows.push(fieldRow('URL', data.url, true, true));
    if (data.notes) rows.push(fieldRow('Notes / Description', data.notes, false));

    // Champs personnalisés éventuels (hors champs standards KeePass)
    const standardFields = new Set(['Title', 'UserName', 'Password', 'URL', 'Notes']);
    if (data.entry && data.entry.fields) {
        data.entry.fields.forEach((value, key) => {
            if (!standardFields.has(key)) {
                const text = (value && value.getText) ? value.getText() : String(value);
                if (text) rows.push(fieldRow(key, text, false));
            }
        });
    }

    DOM.detailFields.innerHTML = rows.join('');

    // Attacher les actions copier sur les champs de la modale
    DOM.detailFields.querySelectorAll('[data-copy]').forEach(el => {
        el.addEventListener('click', () => copyAnim(el.dataset.copy, el));
    });
    const revealBtn = DOM.detailFields.querySelector('[data-reveal-pwd]');
    if (revealBtn) {
        revealBtn.addEventListener('click', () => {
            const input = document.getElementById('modal-pwd-field');
            revealMatrix('modal-pwd-field', data.password, revealBtn);
        });
    }

    DOM.detailModal.classList.remove('hidden');
    void DOM.detailPanel.offsetWidth;
    DOM.detailPanel.classList.remove('view-enter-start');
    DOM.detailPanel.classList.add('view-enter-end');
}

function fieldRow(label, value, copyable, isLink) {
    const safeValue = escapeHtml(value);
    const display = isLink
        ? `<a href="${safeValue.startsWith('http') ? safeValue : 'https://' + safeValue}" target="_blank" rel="noopener noreferrer" class="text-cyan-400 hover:underline break-all">${safeValue}</a>`
        : `<span class="text-gray-300 break-all whitespace-pre-wrap">${safeValue}</span>`;

    const copyBtn = copyable
        ? `<button data-copy="${escapeHtml(value).replace(/"/g, '"')}" class="text-gray-500 hover:text-[#10B981] p-1.5 rounded transition-colors flex-shrink-0" title="Copier">
                <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"/></svg>
           </button>`
        : '';

    return `
        <div class="space-y-1">
            <span class="text-xs uppercase tracking-widest text-gray-500">${escapeHtml(label)}</span>
            <div class="flex items-start justify-between gap-2 bg-[#0B0F19] border border-white/5 rounded-lg px-3 py-2">
                ${display}
                ${copyBtn}
            </div>
        </div>
    `;
}

function passwordRow(password) {
    const safePwd = escapeHtml(password).replace(/"/g, '"');
    return `
        <div class="space-y-1">
            <span class="text-xs uppercase tracking-widest text-gray-500">Mot de passe</span>
            <div class="flex items-center justify-between gap-2 bg-[#0B0F19] border border-white/5 rounded-lg px-3 py-2">
                <input type="password" id="modal-pwd-field" value="${safePwd}" readonly class="flex-1 bg-transparent text-gray-300 outline-none pointer-events-none font-mono">
                <div class="flex gap-1 flex-shrink-0">
                    <button data-reveal-pwd class="text-gray-500 hover:text-cyan-400 p-1.5 rounded transition-colors" title="Afficher/Masquer">
                        <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"/></svg>
                    </button>
                    <button data-copy="${safePwd}" class="text-gray-500 hover:text-[#10B981] p-1.5 rounded transition-colors" title="Copier">
                        <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"/></svg>
                    </button>
                </div>
            </div>
        </div>
    `;
}

function closeDetailModal() {
    DOM.detailPanel.classList.remove('view-enter-end');
    DOM.detailPanel.classList.add('view-enter-start');
    setTimeout(() => DOM.detailModal.classList.add('hidden'), 200);
}

DOM.detailClose.onclick = closeDetailModal;
DOM.detailBackdrop.onclick = closeDetailModal;
document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && !DOM.detailModal.classList.contains('hidden')) closeDetailModal();
});

// --- EFFET MATRIX ---
window.revealMatrix = (inputId, realText, btn) => {
    const input = document.getElementById(inputId);
    const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#$%&*";

    if (input.type === "password") {
        input.type = "text";
        btn.classList.add("text-cyan-400");

        let iterations = 0;
        input.value = realText.split('').map(() => chars[Math.floor(Math.random() * chars.length)]).join('');

        const interval = setInterval(() => {
            input.value = realText.split("").map((letter, index) => {
