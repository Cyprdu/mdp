const CLIENT_ID = '981549083683-mip1727gmq4jsqkgv7vvqhos8mulr2vf.apps.googleusercontent.com';
const FILE_ID = '1Y8dvHlVZQCE7pSZu--7qFqZRxL7vNBT4';
const SCOPES = 'https://www.googleapis.com/auth/drive';
const CACHE_KEY = 'id_dragon_favories';

let tokenClient, accessToken = null, currentDb = null, fileMetadata = null;
let entriesData = [];

const DOM = {
    stepAuth: document.getElementById('step-auth'),
    stepUnlock: document.getElementById('step-unlock'),
    stepDashboard: document.getElementById('step-dashboard'),
    btnLogin: document.getElementById('btn-login'),
    btnUnlock: document.getElementById('btn-unlock'),
    btnForget: document.getElementById('btn-forget'),
    masterPassword: document.getElementById('master-password'),
    passwordsList: document.getElementById('passwords-list'),
    skeletonLoader: document.getElementById('skeleton-loader'),
    lockIcon: document.getElementById('lock-icon'),
    lockShackle: document.getElementById('lock-shackle'),
    inputContainer: document.getElementById('input-container'),
    toast: document.getElementById('toast-container'),
    statusText: document.getElementById('status-text'),
    statusDot: document.getElementById('status-dot'),
    searchContainer: document.getElementById('search-container'),
    entryModal: document.getElementById('entry-modal'),
    entryModalHeader: document.getElementById('entry-modal-header'),
    entryModalFields: document.getElementById('entry-modal-fields'),
    entryModalClose: document.getElementById('entry-modal-close'),
};

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
        tryAutoUnlock();
    } catch (e) {
        showError("Impossible d'accéder au conteneur.");
    }
}

// =====================================================================
// CACHE LOCAL CHIFFRE DU MOT DE PASSE MAITRE
//
// Le mot de passe n'est jamais stocké en clair. Il est chiffré en
// AES-256-GCM avec une clé dérivée (PBKDF2) d'une longue phrase secrète
// répartie aléatoirement dans plusieurs attributs data-* du HTML.
//
// Important à savoir : comme ce code s'exécute entièrement côté client,
// cette phrase reste techniquement lisible par quelqu'un qui inspecte
// le code source de la page (vue source / devtools). Ce mécanisme
// protège donc contre une lecture "brute" du localStorage (un tiers qui
// aspire juste la valeur stockée sans le code de la page), mais ce
// n'est pas une protection absolue contre quelqu'un qui a accès complet
// au site. Ne considère pas ceci comme un coffre-fort inviolable.
// =====================================================================

function getEmbeddedKeyMaterial() {
    const parts = [
        document.querySelector('h1')?.dataset.sid,
        document.getElementById('status-badge')?.dataset.rid,
        document.getElementById('toast-container')?.dataset.cid,
        document.getElementById('step-dashboard')?.dataset.tid,
        document.getElementById('btn-unlock')?.dataset.nid,
    ];
    if (parts.some(p => !p)) {
        throw new Error('Clé locale introuvable dans le HTML.');
    }
    return parts.join('::');
}

function bufToB64(buf) {
    const bytes = new Uint8Array(buf);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary);
}

function b64ToBuf(b64) {
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes.buffer;
}

async function deriveKey(passphrase, saltBytes) {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(passphrase), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt: saltBytes, iterations: 250000, hash: 'SHA-256' },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
    );
}

async function cacheMasterPassword(password) {
    try {
        const passphrase = getEmbeddedKeyMaterial();
        const salt = crypto.getRandomValues(new Uint8Array(16));
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const key = await deriveKey(passphrase, salt);
        const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(password));
        const payload = { s: bufToB64(salt), i: bufToB64(iv), c: bufToB64(ciphertext) };
        localStorage.setItem(CACHE_KEY, JSON.stringify(payload));
    } catch (e) {
        console.warn('Mise en cache locale impossible :', e);
    }
}

async function getCachedMasterPassword() {
    const raw = localStorage.getItem(CACHE_KEY);
    if (!raw) return null;
    try {
        const payload = JSON.parse(raw);
        const passphrase = getEmbeddedKeyMaterial();
        const salt = new Uint8Array(b64ToBuf(payload.s));
        const iv = new Uint8Array(b64ToBuf(payload.i));
        const key = await deriveKey(passphrase, salt);
        const plainBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, b64ToBuf(payload.c));
        return new TextDecoder().decode(plainBuf);
    } catch (e) {
        localStorage.removeItem(CACHE_KEY);
        return null;
    }
}

function clearCachedMasterPassword() {
    localStorage.removeItem(CACHE_KEY);
    DOM.btnForget.classList.add('hidden');
}

function refreshForgetButtonVisibility() {
    DOM.btnForget.classList.toggle('hidden', !localStorage.getItem(CACHE_KEY));
}

DOM.btnForget.onclick = () => clearCachedMasterPassword();

async function tryAutoUnlock() {
    const cachedPwd = await getCachedMasterPassword();
    if (cachedPwd) {
        updateStatus("Déchiffrement automatique...", "bg-yellow-500", "text-yellow-400");
        const ok = await attemptUnlock(cachedPwd, { silent: true });
        if (ok) return;
        updateStatus("Prêt pour déchiffrement", "bg-cyan-500", "text-cyan-400");
    }
    refreshForgetButtonVisibility();
}

// --- DECHIFFREMENT DE LA BASE ---
async function attemptUnlock(password, { silent = false } = {}) {
    document.getElementById('error-msg').classList.add('hidden');

    let originalText;
    if (!silent) {
        originalText = DOM.btnUnlock.innerText;
        DOM.btnUnlock.innerHTML = `<svg class="animate-spin h-5 w-5 mx-auto text-white" fill="none" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg>`;
    }

    try {
        if (!silent) await new Promise(r => setTimeout(r, 400));
        const credentials = new kdbxweb.Credentials(kdbxweb.ProtectedValue.fromString(password));
        currentDb = await kdbxweb.Kdbx.load(fileMetadata, credentials);

        updateStatus("AES-256 Actif", "bg-[#10B981] dot-pulse", "text-[#10B981]");
        DOM.masterPassword.value = '';

        await cacheMasterPassword(password);
        refreshForgetButtonVisibility();

        transitionView(DOM.stepUnlock, DOM.stepDashboard);
        generateSkeletons();

        setTimeout(() => {
            DOM.skeletonLoader.classList.add('hidden');
            DOM.passwordsList.classList.remove('hidden');
            DOM.searchContainer.classList.remove('hidden');
            displayEntries();
        }, 1200);

        return true;
    } catch (e) {
        if (silent) {
            // Mot de passe en cache invalide (fichier changé, cache corrompu...) : on l'oublie et on redemande.
            clearCachedMasterPassword();
            return false;
        }
        DOM.btnUnlock.innerText = originalText;
        showError("Clé cryptographique rejetée.");
        DOM.inputContainer.classList.add('animate-shake');
        DOM.masterPassword.classList.add('border-red-500', 'focus:ring-red-500');
        setTimeout(() => {
            DOM.inputContainer.classList.remove('animate-shake');
            DOM.masterPassword.classList.remove('border-red-500', 'focus:ring-red-500');
        }, 400);
        return false;
    }
}

DOM.btnUnlock.onclick = () => attemptUnlock(DOM.masterPassword.value, { silent: false });

// --- UTILITAIRES DE SECURITE HTML ---
function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;');
}

function escapeAttr(str) {
    return escapeHtml(str).replace(/"/g, '&quot;');
}

function extractFieldText(value) {
    if (!value) return '';
    if (typeof value.getText === 'function') return value.getText();
    return String(value);
}

// --- KEEPASS PARSING (recursif : toutes les entrées, y compris sous-dossiers) ---
function getAllEntries(db) {
    const entries = [];
    function walk(group) {
        if (!group) return;
        if (group.entries) entries.push(...group.entries);
        if (group.groups) group.groups.forEach(walk);
    }
    walk(db.getDefaultGroup());
    return entries;
}

const KNOWN_FIELDS = new Set(['Title', 'UserName', 'Password', 'URL', 'Notes']);

function parseEntries(db) {
    const rawEntries = getAllEntries(db);
    return rawEntries.map((entry, index) => {
        const fields = entry.fields;
        const title = extractFieldText(fields.get('Title')) || 'Sans titre';
        const username = extractFieldText(fields.get('UserName'));
        const password = extractFieldText(fields.get('Password'));
        const url = extractFieldText(fields.get('URL'));
        const notes = extractFieldText(fields.get('Notes'));

        const others = [];
        fields.forEach((value, key) => {
            if (!KNOWN_FIELDS.has(key)) {
                const text = extractFieldText(value);
                if (text) others.push({ key, value: text });
            }
        });

        let domain = '';
        if (url && url.includes('.')) {
            try { domain = new URL(url).hostname; } catch (e) { domain = url; }
        } else if (title) {
            domain = title.toLowerCase().replace(/\s+/g, '') + '.com';
        }

        return { index, title, username, password, url, notes, others, domain };
    });
}

function displayEntries() {
    entriesData = parseEntries(currentDb);
    DOM.passwordsList.innerHTML = '';

    entriesData.forEach((e) => {
        const initial = (e.title || '?').charAt(0).toUpperCase();
        let iconHtml = `<div class="w-10 h-10 rounded-lg bg-gray-800 flex items-center justify-center border border-gray-700 text-gray-400 font-mono text-sm shadow-inner flex-shrink-0">${escapeHtml(initial)}</div>`;
        if (e.domain) {
            iconHtml = `<img src="https://s2.googleusercontent.com/s2/favicons?domain=${encodeURIComponent(e.domain)}&sz=64" onerror="this.outerHTML='${iconHtml.replace(/'/g, "\\'")}'" class="w-10 h-10 rounded-lg object-contain bg-white/5 p-1.5 border border-white/5 flex-shrink-0 shadow-sm">`;
        }

        const displayUsername = e.username || '—';
        const id = `pwd-${e.index}`;

        const card = document.createElement('div');
        card.className = "spotlight-card rounded-2xl p-5 flex flex-col gap-5 group";

        card.addEventListener('mousemove', (ev) => {
            const rect = card.getBoundingClientRect();
            card.style.setProperty('--mouse-x', `${ev.clientX - rect.left}px`);
            card.style.setProperty('--mouse-y', `${ev.clientY - rect.top}px`);
        });

        card.innerHTML = `
            <div class="flex items-start gap-4 border-b border-white/5 pb-4">
                ${iconHtml}
                <div class="overflow-hidden flex-1">
                    <h3 class="text-sm font-semibold text-gray-100 truncate">${escapeHtml(e.title)}</h3>
                    <div class="flex items-center gap-2 mt-1">
                        <p class="text-xs text-gray-500 font-mono truncate max-w-[150px]">${escapeHtml(displayUsername)}</p>
                        ${e.username ? `
                        <button type="button" data-copy="username" class="text-gray-600 hover:text-[#10B981] transition-colors p-1 rounded hover:bg-white/5" title="Copier l'identifiant">
                            <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"/></svg>
                        </button>` : ''}
                    </div>
                </div>
            </div>

            <div class="flex items-center justify-between bg-black/40 rounded-lg p-1.5 border border-white/5 mt-auto">
                <input type="password" value="${escapeAttr(e.password)}" class="bg-transparent border-none outline-none text-sm text-gray-300 font-mono pl-3 w-full pointer-events-none" readonly id="${id}">
                <div class="flex gap-1 flex-shrink-0">
                    <button type="button" data-action="reveal" class="text-gray-500 hover:text-cyan-400 p-2 rounded transition-colors" title="Afficher/Masquer">
                        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"/></svg>
                    </button>
                    <button type="button" data-action="copy-password" class="text-gray-500 hover:text-[#10B981] p-2 rounded transition-colors" title="Copier le mot de passe">
                        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"/></svg>
                    </button>
                </div>
            </div>
        `;

        const usernameCopyBtn = card.querySelector('[data-copy="username"]');
        if (usernameCopyBtn) usernameCopyBtn.addEventListener('click', (ev) => { ev.stopPropagation(); copyAnim(e.username, usernameCopyBtn); });

        const revealBtn = card.querySelector('[data-action="reveal"]');
        revealBtn.addEventListener('click', (ev) => { ev.stopPropagation(); revealMatrix(id, e.password, revealBtn); });

        const passwordCopyBtn = card.querySelector('[data-action="copy-password"]');
        passwordCopyBtn.addEventListener('click', (ev) => { ev.stopPropagation(); copyAnim(e.password, passwordCopyBtn); });

        card.addEventListener('click', () => openEntryModal(e.index));

        DOM.passwordsList.appendChild(card);
    });
}

// --- EFFET MATRIX ---
function revealMatrix(inputId, realText, btn) {
    const input = document.getElementById(inputId);
    const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#$%&*";

    if (input.type === "password") {
        input.type = "text";
        btn.classList.add("text-cyan-400");

        let iterations = 0;
        const interval = setInterval(() => {
            input.value = realText.split("").map((letter, index) => {
                if (index < iterations) return realText[index];
                return chars[Math.floor(Math.random() * chars.length)];
            }).join("");

            if (iterations >= realText.length) clearInterval(interval);
            iterations += 1 / 2;
        }, 30);
    } else {
        input.type = "password";
        input.value = realText;
        btn.classList.remove("text-cyan-400");
    }
}

// --- ANIMATION COPIE & TOAST ---
function copyAnim(text, btnElement) {
    if (!text) return;
    navigator.clipboard.writeText(text).then(() => {
        const svgIcon = btnElement.querySelector('svg');
        const originalHTML = svgIcon.innerHTML;

        svgIcon.innerHTML = `<path stroke-linecap="round" stroke-linejoin="round" stroke-width="3" class="text-[#10B981]" d="M5 13l4 4L19 7"/>`;
        DOM.toast.classList.remove('opacity-0', '-translate-y-10');

        setTimeout(() => { DOM.toast.classList.add('opacity-0', '-translate-y-10'); }, 2500);
        setTimeout(() => { navigator.clipboard.writeText(""); }, 15000);
        setTimeout(() => { svgIcon.innerHTML = originalHTML; }, 2000);
    });
}

// --- MODALE DE DETAIL D'ENTREE ---
function openEntryModal(idx) {
    const e = entriesData.find(x => x.index === idx);
    if (!e) return;

    DOM.entryModalHeader.innerHTML = '';
    DOM.entryModalFields.innerHTML = '';

    const initial = (e.title || '?').charAt(0).toUpperCase();
    const fallbackIcon = () => {
        const div = document.createElement('div');
        div.className = 'w-12 h-12 rounded-lg bg-gray-800 flex items-center justify-center border border-gray-700 text-gray-300 font-mono text-base flex-shrink-0';
        div.textContent = initial;
        return div;
    };

    if (e.domain) {
        const img = document.createElement('img');
        img.src = `https://s2.googleusercontent.com/s2/favicons?domain=${encodeURIComponent(e.domain)}&sz=64`;
        img.className = 'w-12 h-12 rounded-lg object-contain bg-white/5 p-1.5 border border-white/5 flex-shrink-0';
        img.onerror = () => img.replaceWith(fallbackIcon());
        DOM.entryModalHeader.appendChild(img);
    } else {
        DOM.entryModalHeader.appendChild(fallbackIcon());
    }

    const titleEl = document.createElement('h3');
    titleEl.className = 'text-lg font-semibold text-white truncate';
    titleEl.textContent = e.title;
    DOM.entryModalHeader.appendChild(titleEl);

    const rows = [];
    if (e.username) rows.push({ label: 'Identifiant', value: e.username, copy: true });
    if (e.password) rows.push({ label: 'Mot de passe', value: e.password, copy: true, secret: true });
    if (e.url) rows.push({ label: 'URL', value: e.url, link: true, copy: true });
    if (e.notes) rows.push({ label: 'Notes / Commentaire', value: e.notes, copy: true });
    e.others.forEach(o => rows.push({ label: o.key, value: o.value, copy: true }));

    if (rows.length === 0) {
        const empty = document.createElement('p');
        empty.className = 'text-sm text-gray-500 font-mono';
        empty.textContent = 'Aucune information supplémentaire pour cette entrée.';
        DOM.entryModalFields.appendChild(empty);
    }

    rows.forEach(r => {
        const row = document.createElement('div');
        row.className = 'detail-row flex items-start justify-between gap-3';

        const left = document.createElement('div');
        left.className = 'flex-1 min-w-0';

        const label = document.createElement('div');
        label.className = 'detail-label';
        label.textContent = r.label;
        left.appendChild(label);

        const valueEl = document.createElement('div');
        valueEl.className = 'detail-value';

        let revealed = !r.secret;
        const renderValue = () => {
            valueEl.innerHTML = '';
            if (r.secret && !revealed) {
                valueEl.textContent = '•'.repeat(Math.min(Math.max(r.value.length, 8), 24));
            } else if (r.link) {
                const a = document.createElement('a');
                a.href = r.value;
                a.target = '_blank';
                a.rel = 'noopener noreferrer';
                a.className = 'text-cyan-400 hover:underline break-all';
                a.textContent = r.value;
                valueEl.appendChild(a);
            } else {
                valueEl.textContent = r.value;
            }
        };
        renderValue();
        left.appendChild(valueEl);
        row.appendChild(left);

        const btnGroup = document.createElement('div');
        btnGroup.className = 'flex gap-1 flex-shrink-0 pt-1';

        if (r.secret) {
            const revealBtn = document.createElement('button');
            revealBtn.type = 'button';
            revealBtn.className = 'text-gray-500 hover:text-cyan-400 p-1.5 rounded transition-colors';
            revealBtn.title = 'Afficher/Masquer';
            revealBtn.innerHTML = `<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"/></svg>`;
            revealBtn.addEventListener('click', () => {
                revealed = !revealed;
                revealBtn.classList.toggle('text-cyan-400', revealed);
                renderValue();
            });
            btnGroup.appendChild(revealBtn);
        }

        if (r.copy) {
            const copyBtn = document.createElement('button');
            copyBtn.type = 'button';
            copyBtn.className = 'text-gray-500 hover:text-[#10B981] p-1.5 rounded transition-colors';
            copyBtn.title = 'Copier';
            copyBtn.innerHTML = `<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"/></svg>`;
            copyBtn.addEventListener('click', () => copyAnim(r.value, copyBtn));
            btnGroup.appendChild(copyBtn);
        }

        row.appendChild(btnGroup);
        DOM.entryModalFields.appendChild(row);
    });

    DOM.entryModal.classList.remove('hidden');
}

function closeEntryModal() {
    DOM.entryModal.classList.add('hidden');
}

DOM.entryModalClose.addEventListener('click', closeEntryModal);
DOM.entryModal.addEventListener('click', (e) => {
    if (e.target === DOM.entryModal) closeEntryModal();
});
document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && !DOM.entryModal.classList.contains('hidden')) closeEntryModal();
});

// --- BARRE DE RECHERCHE ---
document.getElementById('search-input').addEventListener('input', (e) => {
    const term = e.target.value.toLowerCase();
    const cards = document.querySelectorAll('.spotlight-card');

    cards.forEach(card => {
        const textContent = card.innerText.toLowerCase();
        card.style.display = textContent.includes(term) ? 'flex' : 'none';
    });
});

// --- UTILITAIRES ---
function transitionView(outView, inView) {
    outView.classList.add('view-exit');
    setTimeout(() => {
        outView.classList.add('hidden');
        outView.classList.remove('view-exit');
        inView.classList.remove('hidden');
        inView.classList.add('view-enter-start');

        void inView.offsetWidth;

        inView.classList.remove('view-enter-start');
        inView.classList.add('view-enter-end');
    }, 400);
}

function generateSkeletons() {
    DOM.skeletonLoader.classList.remove('hidden');
    DOM.passwordsList.classList.add('hidden');
    DOM.skeletonLoader.innerHTML = '';
    for (let i = 0; i < 6; i++) {
        DOM.skeletonLoader.innerHTML += `
            <div class="rounded-2xl p-5 border border-white/5 bg-gray-900/40">
                <div class="animate-pulse flex space-x-4">
                    <div class="rounded bg-gray-800 h-10 w-10"></div>
                    <div class="flex-1 space-y-2 py-1">
                        <div class="h-4 bg-gray-800 rounded w-3/4"></div>
                        <div class="h-3 bg-gray-800 rounded w-1/2"></div>
                    </div>
                </div>
                <div class="animate-pulse mt-5 h-10 bg-gray-800 rounded-lg"></div>
            </div>`;
    }
}

function updateStatus(text, dotClass, textClass) {
    DOM.statusText.textContent = text;
    DOM.statusText.className = `text-xs font-mono tracking-widest uppercase transition-colors ${textClass}`;
    DOM.statusDot.className = `w-2 h-2 rounded-full transition-all ${dotClass}`;
}

function showError(msg) {
    document.getElementById('error-text').textContent = msg;
    document.getElementById('error-msg').classList.remove('hidden');
}
