const CLIENT_ID = '981549083683-mip1727gmq4jsqkgv7vvqhos8mulr2vf.apps.googleusercontent.com'; 
const FILE_ID = '1Y8dvHlVZQCE7pSZu--7qFqZRxL7vNBT4';
const SCOPES = 'https://www.googleapis.com/auth/drive';

let tokenClient, accessToken = null, currentDb = null, fileMetadata = null; 

const DOM = {
    stepAuth: document.getElementById('step-auth'),
    stepUnlock: document.getElementById('step-unlock'),
    stepDashboard: document.getElementById('step-dashboard'),
    btnLogin: document.getElementById('btn-login'),
    btnUnlock: document.getElementById('btn-unlock'),
    masterPassword: document.getElementById('master-password'),
    passwordsList: document.getElementById('passwords-list'),
    skeletonLoader: document.getElementById('skeleton-loader'),
    lockIcon: document.getElementById('lock-icon'),
    lockShackle: document.getElementById('lock-shackle'),
    inputContainer: document.getElementById('input-container'),
    toast: document.getElementById('toast-container'),
    statusText: document.getElementById('status-text'),
    statusDot: document.getElementById('status-dot')
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
    if(e.target.value.length > 0) {
        DOM.lockShackle.setAttribute('d', 'M8 11V7a4 4 0 118 0v4m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2z');
        DOM.lockIcon.classList.replace('text-gray-500', 'text-[#10B981]');
    } else {
        // Cadenas ouvert
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
    } catch (e) {
        showError("Impossible d'accéder au conteneur.");
    }
}

DOM.btnUnlock.onclick = async () => {
    const password = DOM.masterPassword.value;
    document.getElementById('error-msg').classList.add('hidden');
    
    // Spinner
    const originalText = DOM.btnUnlock.innerText;
    DOM.btnUnlock.innerHTML = `<svg class="animate-spin h-5 w-5 mx-auto text-white" fill="none" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg>`;

    try {
        await new Promise(r => setTimeout(r, 400)); // Simuler le temps de calcul
        const credentials = new kdbxweb.Credentials(kdbxweb.ProtectedValue.fromString(password));
        currentDb = await kdbxweb.Kdbx.load(fileMetadata, credentials);
        
        updateStatus("AES-256 Actif", "bg-[#10B981] dot-pulse", "text-[#10B981]");
        DOM.masterPassword.value = ''; 
        
        transitionView(DOM.stepUnlock, DOM.stepDashboard);
        generateSkeletons();
        
        setTimeout(() => {
            DOM.skeletonLoader.classList.add('hidden');
            DOM.passwordsList.classList.remove('hidden');
            displayEntries();
        }, 1200); // Durée élégante du skeleton

    } catch (e) {
        DOM.btnUnlock.innerText = originalText;
        showError("Clé cryptographique rejetée.");
        // Animation shake et flash rouge
        DOM.inputContainer.classList.add('animate-shake');
        DOM.masterPassword.classList.add('border-red-500', 'focus:ring-red-500');
        setTimeout(() => {
            DOM.inputContainer.classList.remove('animate-shake');
            DOM.masterPassword.classList.remove('border-red-500', 'focus:ring-red-500');
        }, 400);
    }
};

// --- KEEPASS PARSING ET DOM ---
function displayEntries() {
    DOM.passwordsList.innerHTML = '';
    const entries = currentDb.getDefaultGroup().entries; 
    
    entries.forEach((entry, index) => {
        const title = entry.fields.get('Title') || 'Sans titre';
        const username = entry.fields.get('UserName') || '—';
        const passwordValue = entry.fields.get('Password') ? entry.fields.get('Password').getText() : '';
        const rawUrl = entry.fields.get('URL') ? entry.fields.get('URL') : '';
        
        // Tentative de récupération du Favicon via Clearbit
        let iconHtml = `<div class="w-10 h-10 rounded bg-gray-800 flex items-center justify-center border border-gray-700 text-gray-400 font-mono text-xs">${title.charAt(0).toUpperCase()}</div>`;
        try {
            if(rawUrl) {
                const domain = new URL(rawUrl).hostname;
                iconHtml = `<img src="https://logo.clearbit.com/${domain}?size=80" onerror="this.outerHTML='${iconHtml}'" class="w-10 h-10 rounded object-contain bg-white/5 p-1 border border-white/5">`;
            }
        } catch(e) {}

        const id = `pwd-${index}`;
        const safePwd = passwordValue.replace(/"/g, '&quot;').replace(/'/g, "\\'");

        const card = document.createElement('div');
        card.className = "spotlight-card rounded-2xl p-5 flex flex-col gap-5 group";
        
        // Attacher le mousemove pour l'effet Spotlight
        card.addEventListener('mousemove', (e) => {
            const rect = card.getBoundingClientRect();
            card.style.setProperty('--mouse-x', `${e.clientX - rect.left}px`);
            card.style.setProperty('--mouse-y', `${e.clientY - rect.top}px`);
        });

        card.innerHTML = `
            <div class="flex items-center gap-4">
                ${iconHtml}
                <div class="overflow-hidden">
                    <h3 class="text-sm font-semibold text-gray-100 truncate">${title}</h3>
                    <p class="text-xs text-gray-500 font-mono mt-0.5 truncate">${username}</p>
                </div>
            </div>
            
            <div class="flex items-center justify-between bg-black/40 rounded-lg p-1.5 border border-white/5">
                <input type="password" value="${safePwd}" class="bg-transparent border-none outline-none text-sm text-gray-300 font-mono pl-3 w-full pointer-events-none" readonly id="${id}">
                
                <div class="flex gap-1">
                    <button onclick="revealMatrix('${id}', '${safePwd}', this)" class="text-gray-500 hover:text-cyan-400 p-2 rounded transition-colors">
                        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"/></svg>
                    </button>
                    <button onclick="copyAnim('${safePwd}', this)" class="text-gray-500 hover:text-[#10B981] p-2 rounded transition-colors">
                        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"/></svg>
                    </button>
                </div>
            </div>
        `;
        DOM.passwordsList.appendChild(card);
    });
}

// --- EFFET MATRIX ---
window.revealMatrix = (inputId, realText, btn) => {
    const input = document.getElementById(inputId);
    const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#$%&*";
    
    if (input.type === "password") {
        input.type = "text";
        btn.classList.add("text-cyan-400");
        
        let iterations = 0;
        const interval = setInterval(() => {
            input.value = input.value.split("").map((letter, index) => {
                if(index < iterations) return realText[index];
                return chars[Math.floor(Math.random() * chars.length)];
            }).join("");
            
            if(iterations >= realText.length) clearInterval(interval);
            iterations += 1/2; // Vitesse de décryptage
        }, 30);
    } else {
        input.type = "password";
        input.value = realText;
        btn.classList.remove("text-cyan-400");
    }
};

// --- ANIMATION COPIE & TOAST ---
window.copyAnim = (text, btnElement) => {
    navigator.clipboard.writeText(text).then(() => {
        const svgIcon = btnElement.querySelector('svg');
        const originalHTML = svgIcon.innerHTML;
        
        // Morphing vers la coche
        svgIcon.innerHTML = `<path stroke-linecap="round" stroke-linejoin="round" stroke-width="3" class="text-[#10B981]" d="M5 13l4 4L19 7"/>`;
        DOM.toast.classList.remove('opacity-0', '-translate-y-10');
        
        setTimeout(() => { DOM.toast.classList.add('opacity-0', '-translate-y-10'); }, 2500);
        setTimeout(() => { navigator.clipboard.writeText(""); }, 15000);
        setTimeout(() => { svgIcon.innerHTML = originalHTML; }, 2000);
    });
};

// --- UTILITAIRES ---
function transitionView(outView, inView) {
    outView.classList.add('view-exit');
    setTimeout(() => {
        outView.classList.add('hidden');
        inView.classList.remove('hidden');
        inView.classList.add('view-enter-start');
        
        // Force reflow
        void inView.offsetWidth; 
        
        inView.classList.remove('view-enter-start');
        inView.classList.add('view-enter-end');
    }, 400); // 400ms pour laisser le fade-out se faire
}

function generateSkeletons() {
    DOM.skeletonLoader.innerHTML = '';
    for(let i=0; i<6; i++) {
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
