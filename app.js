// === CONFIGURATION ===
// Remplacez par votre ID Client obtenu dans Google Cloud Console
const CLIENT_ID = '981549083683-mip1727gmq4jsqkgv7vvqhos8mulr2vf.apps.googleusercontent.com'; 
// Votre fichier
const FILE_ID = '1Y8dvHlVZQCE7pSZu--7qFqZRxL7vNBT4';
// Le fameux scope ! C'est ici qu'on demande la permission dans le code.
const SCOPES = 'https://www.googleapis.com/auth/drive';
let tokenClient;
let accessToken = null;
let currentDb = null; // Stockera la base KeePass déchiffrée
let fileMetadata = null; // Pour gérer la sauvegarde

const DOM = {
    stepAuth: document.getElementById('step-auth'),
    stepUnlock: document.getElementById('step-unlock'),
    stepDashboard: document.getElementById('step-dashboard'),
    btnLogin: document.getElementById('btn-login'),
    btnUnlock: document.getElementById('btn-unlock'),
    masterPassword: document.getElementById('master-password'),
    passwordsList: document.getElementById('passwords-list'),
    statusBadge: document.getElementById('status-badge'),
    errorMsg: document.getElementById('error-msg')
};

// 1. Initialisation des API Google
window.onload = function () {
    // Initialise le client Drive API
    gapi.load('client', () => {
        gapi.client.init({
            discoveryDocs: ['https://www.googleapis.com/discovery/v1/apis/drive/v3/rest'],
        });
    });

    // Initialise le système de connexion Google Identity
    tokenClient = google.accounts.oauth2.initTokenClient({
        client_id: CLIENT_ID,
        scope: SCOPES,
        callback: (tokenResponse) => {
            if (tokenResponse && tokenResponse.access_token) {
                accessToken = tokenResponse.access_token;
                updateStatus("Connecté à Drive", "bg-yellow-900/50", "text-yellow-400", "border-yellow-800");
                DOM.stepAuth.classList.add('hidden');
                DOM.stepUnlock.classList.remove('hidden');
                downloadKdbxFile();
            }
        },
    });
};

DOM.btnLogin.onclick = () => {
    tokenClient.requestAccessToken({ prompt: 'consent' });
};

// 2. Téléchargement du fichier depuis Drive
async function downloadKdbxFile() {
    try {
        const response = await fetch(`https://www.googleapis.com/drive/v3/files/${FILE_ID}?alt=media`, {
            headers: { 'Authorization': `Bearer ${accessToken}` }
        });
        
        if (!response.ok) throw new Error("Fichier introuvable ou accès refusé.");
        
        fileMetadata = await response.arrayBuffer();
        updateStatus("Fichier téléchargé, en attente du MDP", "bg-yellow-900/50", "text-yellow-400", "border-yellow-800");
    } catch (e) {
        showError("Erreur lors du téléchargement : Vérifiez l'ID du fichier ou vos droits d'accès.");
    }
}

// 3. Déchiffrement
DOM.btnUnlock.onclick = async () => {
    const password = DOM.masterPassword.value;
    DOM.errorMsg.classList.add('hidden');

    try {
        const credentials = new kdbxweb.Credentials(kdbxweb.ProtectedValue.fromString(password));
        currentDb = await kdbxweb.Kdbx.load(fileMetadata, credentials);
        
        updateStatus("Coffre déverrouillé", "bg-emerald-900/50", "text-emerald-400", "border-emerald-800");
        DOM.stepUnlock.classList.add('hidden');
        DOM.stepDashboard.classList.remove('hidden');
        
        // Efface le mot de passe de la mémoire de l'input
        DOM.masterPassword.value = ''; 
        
        displayEntries();
    } catch (e) {
        showError("Mot de passe incorrect ou fichier corrompu.");
    }
};

// 4. Affichage des mots de passe
function displayEntries() {
    DOM.passwordsList.innerHTML = '';
    
    // Parcourt le groupe racine et ses sous-groupes
    const entries = currentDb.getDefaultGroup().entries; 
    
    entries.forEach(entry => {
        const title = entry.fields.get('Title') || 'Sans titre';
        const username = entry.fields.get('UserName') || 'Aucun';
        const passwordValue = entry.fields.get('Password') ? entry.fields.get('Password').getText() : '';

        const div = document.createElement('div');
        div.className = "bg-gray-900 border border-gray-700 p-4 rounded-lg flex justify-between items-center hover:border-gray-600 transition";
        
        div.innerHTML = `
            <div>
                <h3 class="font-medium text-gray-100">${title}</h3>
                <p class="text-sm text-gray-500">${username}</p>
            </div>
            <button onclick="copyToClipboard('${passwordValue.replace(/'/g, "\\'")}')" class="bg-gray-800 hover:bg-gray-700 text-gray-300 px-3 py-1.5 rounded border border-gray-600 text-sm transition">
                Copier MDP
            </button>
        `;
        DOM.passwordsList.appendChild(div);
    });
}

// 5. Fonction utilitaire de copie sécurisée
window.copyToClipboard = (text) => {
    navigator.clipboard.writeText(text).then(() => {
        alert("Mot de passe copié ! Il restera dans le presse-papier.");
        // Pour la sécurité, vous pourriez ajouter un setTimeout pour vider le presse-papier après 15s.
    });
};

function updateStatus(text, bgClass, textClass, borderClass) {
    DOM.statusBadge.textContent = text;
    DOM.statusBadge.className = `px-3 py-1 rounded-full text-xs font-medium ${bgClass} ${textClass} border ${borderClass}`;
}

function showError(msg) {
    DOM.errorMsg.textContent = msg;
    DOM.errorMsg.classList.remove('hidden');
}
