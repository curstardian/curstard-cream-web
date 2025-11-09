// --- 서버 접속 인원 랜덤 예시 ---
function updatePlayerCount() {
    const countEl = document.getElementById('player-count');
    const randomCount = Math.floor(Math.random() * 0); // 항상 0명
    if (countEl) countEl.textContent = randomCount;
}

updatePlayerCount();
setInterval(updatePlayerCount, 100000000); // 100,000,000ms 마다 갱신

// --- 할일 목록 기능 추가 ---
(function () {
    const img = document.querySelector('.side-image');
    const panel = document.getElementById('todo-panel');
    const closeBtn = document.getElementById('todo-close');
    const addBtn = document.getElementById('todo-add');
    const input = document.getElementById('todo-input');
    const listEl = document.getElementById('todo-list');

    const STORAGE_KEY = 'todo-items-v1';

    function loadTodos() {
        try {
            const raw = localStorage.getItem(STORAGE_KEY);
            return raw ? JSON.parse(raw) : [];
        } catch {
            return [];
        }
    }
    function saveTodos(items) {
        localStorage.setItem(STORAGE_KEY, JSON.stringify(items));
    }

    function render() {
        const items = loadTodos();
        listEl.innerHTML = '';
        items.forEach((text, idx) => {
            const li = document.createElement('li');
            li.textContent = text;
            const btn = document.createElement('button');
            btn.className = 'remove';
            btn.textContent = '삭제';
            btn.addEventListener('click', (e) => {
                e.stopPropagation(); // 패널 외부 클릭으로 닫히는 것을 방지
                const items = loadTodos();
                items.splice(idx, 1);
                saveTodos(items);
                render();
            });
            li.appendChild(btn);
            listEl.appendChild(li);
        });
    }

    function togglePanel(show) {
        const isOpen = panel.classList.contains('open');
        const willOpen = typeof show === 'boolean' ? show : !isOpen;
        if (willOpen) {
            panel.classList.add('open');
            panel.setAttribute('aria-hidden', 'false');
            input.focus();
        } else {
            panel.classList.remove('open');
            panel.setAttribute('aria-hidden', 'true');
        }
    }

    if (img && panel) {
        img.addEventListener('click', (e) => {
            e.stopPropagation();
            togglePanel();
        });
        closeBtn.addEventListener('click', () => togglePanel(false));
        // 닫기: 패널 외부 클릭 시
        document.addEventListener('click', (ev) => {
            if (!panel.contains(ev.target) && ev.target !== img) togglePanel(false);
        });
        // 추가
        addBtn.addEventListener('click', () => {
            const v = input.value.trim();
            if (!v) return;
            const items = loadTodos();
            items.push(v);
            saveTodos(items);
            input.value = '';
            render();
        });
        input.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') addBtn.click();
        });

        render();
    }
})();

// --- 간이 인증 / 프로필 기능 (localStorage 사용 데모) ---
(function () {
    const KEY_USERS = 'sc_users_v1'; // 저장된 모든 사용자 {username:{password,nick,avatar}}
    const KEY_CUR = 'sc_current_user_v1'; // 현재 로그인한 username

    const modalLogin = document.getElementById('modal-login');
    const modalSignup = document.getElementById('modal-signup');
    const modalProfile = document.getElementById('modal-profile');

    const userBtn = document.getElementById('user-btn');
    const userAvatar = document.getElementById('user-avatar');
    const userNickEl = document.getElementById('user-nick');

    function getUsers() {
        try {
            return JSON.parse(localStorage.getItem(KEY_USERS) || '{}');
        } catch {
            return {};
        }
    }
    function saveUsers(u) { localStorage.setItem(KEY_USERS, JSON.stringify(u)); }
    function setCurrent(username) { localStorage.setItem(KEY_CUR, username || ''); }
    function getCurrent() { return localStorage.getItem(KEY_CUR) || ''; }

    function showModal(modal, show = true) {
        if (!modal) return;
        modal.setAttribute('aria-hidden', show ? 'false' : 'true');
    }

    function openLogin() { showModal(modalLogin, true); }
    function openSignup() { showModal(modalSignup, true); }
    function openProfile() { showModal(modalProfile, true); }

    // UI 업데이트
    function renderUserUI() {
        const cur = getCurrent();
        const users = getUsers();
        if (cur && users[cur]) {
            userAvatar.src = users[cur].avatar || 'images/default-avatar.png';
            userAvatar.style.display = 'inline-block';
            userNickEl.textContent = users[cur].nick || cur;
            userBtn.title = '프로필 열기';
        } else {
            userAvatar.style.display = 'none';
            userAvatar.src = 'images/default-avatar.png';
            userNickEl.textContent = '로그인'; // 로그인 안 했을 때 표시
            userBtn.title = '로그인';
        }
    }

    // 이벤트: 헤더 버튼 클릭 -> 로그인 또는 프로필
    userBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        const cur = getCurrent();
        if (cur) {
            // 열기: 프로필
            const users = getUsers();
            const u = users[cur] || {};
            const preview = document.getElementById('profile-preview');
            const nickInput = document.getElementById('profile-nick');
            preview.src = u.avatar || 'images/default-avatar.png';
            nickInput.value = u.nick || cur;
            openProfile();
        } else {
            openLogin();
        }
    });

    // 모달 닫기 버튼들
    document.querySelectorAll('.modal-close').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const modal = e.target.closest('.modal');
            if (modal) modal.setAttribute('aria-hidden', 'true');
        });
    });

    // 로그인 처리
    document.getElementById('login-submit').addEventListener('click', async () => {
        const username = document.getElementById('login-username').value.trim();
        const password = document.getElementById('login-password').value;
        const users = getUsers();
        if (!username || !password) { alert('아이디와 비밀번호를 입력하세요'); return; }
        const hash = await sha256Hex(password);
        if (users[username] && users[username].password === hash) {
            setCurrent(username);
            renderUserUI();
            showModal(modalLogin, false);
        } else {
            alert('아이디 또는 비밀번호가 올바르지 않습니다');
        }
    });

    // 회원가입 열기
    document.getElementById('open-signup').addEventListener('click', () => {
        showModal(modalLogin, false);
        openSignup();
    });

    // 회원가입 처리
    document.getElementById('signup-submit').addEventListener('click', async () => {
        const username = document.getElementById('signup-username').value.trim();
        const password = document.getElementById('signup-password').value;
        const nick = document.getElementById('signup-nick').value.trim() || username;
        if (!username || !password) { alert('아이디와 비밀번호를 입력하세요'); return; }
        const users = getUsers();
        if (users[username]) { alert('이미 존재하는 아이디입니다'); return; }
        const hash = await sha256Hex(password);
        users[username] = { password: hash, nick, avatar: '' }; // password는 해시
        saveUsers(users);
        setCurrent(username);
        renderUserUI();
        showModal(modalSignup, false);
    });

    // 프로필 사진 업로드 미리보기 + 저장 준비
    const uploadInput = document.getElementById('profile-upload');
    let stagedAvatarData = null;
    if (uploadInput) {
        uploadInput.addEventListener('change', (e) => {
            const f = e.target.files && e.target.files[0];
            if (!f) return;
            const fr = new FileReader();
            fr.onload = () => {
                stagedAvatarData = fr.result;
                const preview = document.getElementById('profile-preview');
                if (preview) preview.src = stagedAvatarData;
            };
            fr.readAsDataURL(f);
        });
    }

    // 프로필 저장
    document.getElementById('save-profile').addEventListener('click', () => {
        const cur = getCurrent();
        if (!cur) { alert('로그인 후 사용하세요'); return; }
        const users = getUsers();
        if (!users[cur]) users[cur] = { password: '', nick: cur, avatar: '' };
        const nickInput = document.getElementById('profile-nick').value.trim();
        if (nickInput) users[cur].nick = nickInput;
        if (stagedAvatarData) users[cur].avatar = stagedAvatarData;
        saveUsers(users);
        stagedAvatarData = null;
        renderUserUI();
        showModal(modalProfile, false);
    });

    // 로그아웃
    document.getElementById('logout-btn').addEventListener('click', () => {
        if (!confirm('로그아웃하시겠습니까?')) return;
        setCurrent('');
        renderUserUI();
        showModal(modalProfile, false);
    });

    // 클릭하면 모달 닫기 (백그라운드 클릭)
    document.querySelectorAll('.modal').forEach(m => {
        m.addEventListener('click', (e) => {
            if (e.target === m) m.setAttribute('aria-hidden', 'true');
        });
    });

    // 초기 렌더
    renderUserUI();

})();

// 간단 SHA-256 해시 함수 (브라우저 SubtleCrypto) - async 제거하고 Promise 반환
function sha256Hex(str) {
    const encoder = new TextEncoder();
    return crypto.subtle.digest('SHA-256', encoder.encode(str))
        .then(hashBuffer => {
            const hashArray = Array.from(new Uint8Array(hashBuffer));
            return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
        });
}

// 보안 유틸리티 함수들 (encrypt/decrypt을 Promise 기반으로 변경)
const SecurityUtil = {
    generateKey: function() {
        const key = crypto.getRandomValues(new Uint8Array(32));
        return Array.from(key).map(b => b.toString(16).padStart(2, '0')).join('');
    },

    encrypt: function(data, key) {
        try {
            const iv = crypto.getRandomValues(new Uint8Array(12));
            const encoded = new TextEncoder().encode(JSON.stringify(data));
            return crypto.subtle.importKey(
                'raw',
                new TextEncoder().encode(key),
                { name: 'AES-GCM' },
                false,
                ['encrypt']
            ).then(cryptoKey => {
                return crypto.subtle.encrypt(
                    { name: 'AES-GCM', iv: iv },
                    cryptoKey,
                    encoded
                ).then(encrypted => {
                    return {
                        data: Array.from(new Uint8Array(encrypted)),
                        iv: Array.from(iv)
                    };
                });
            });
        } catch (err) {
            return Promise.reject(err);
        }
    },

    decrypt: function(encryptedData, key, iv) {
        try {
            return crypto.subtle.importKey(
                'raw',
                new TextEncoder().encode(key),
                { name: 'AES-GCM' },
                false,
                ['decrypt']
            ).then(cryptoKey => {
                return crypto.subtle.decrypt(
                    { name: 'AES-GCM', iv: new Uint8Array(iv) },
                    cryptoKey,
                    new Uint8Array(encryptedData)
                ).then(decryptedBuffer => {
                    return JSON.parse(new TextDecoder().decode(decryptedBuffer));
                });
            });
        } catch (err) {
            return Promise.reject(err);
        }
    },

    obfuscate: function(data) {
        const obfuscated = btoa(unescape(encodeURIComponent(JSON.stringify(data))))
            .split('').reverse().join('');
        return obfuscated.replace(/=/g, '$');
    },

    deobfuscate: function(obfuscatedData) {
        const deobfuscated = obfuscatedData.replace(/\$/g, '=')
            .split('').reverse().join('');
        return JSON.parse(decodeURIComponent(escape(atob(deobfuscated))));
    }
};

// 보안 스토리지 관리자
const SecureStorage = {
    key: SecurityUtil.generateKey(),
    
    save: function(key, data) {
        return new Promise((resolve, reject) => {
            try {
                SecurityUtil.encrypt(data, SecureStorage.key)
                    .then(encrypted => {
                        const obfuscated = SecurityUtil.obfuscate({
                            data: encrypted.data,
                            iv: encrypted.iv,
                            timestamp: Date.now()
                        });
                        
                        const request = indexedDB.open('SecureDB', 1);
                        
                        request.onupgradeneeded = (event) => {
                            const db = event.target.result;
                            if (!db.objectStoreNames.contains('secureData')) {
                                db.createObjectStore('secureData');
                            }
                        };

                        request.onsuccess = (event) => {
                            const db = event.target.result;
                            const transaction = db.transaction(['secureData'], 'readwrite');
                            const store = transaction.objectStore('secureData');
                            store.put(obfuscated, key);
                            resolve();
                        };

                        request.onerror = () => {
                            reject('데이터베이스 오류');
                        };
                    })
                    .catch(error => {
                        reject('암호화 오류');
                    });
            } catch (error) {
                reject('저장 오류');
            }
        });
    },

    load: function(key) {
        return new Promise((resolve, reject) => {
            const request = indexedDB.open('SecureDB', 1);
            
            request.onsuccess = (event) => {
                const db = event.target.result;
                const transaction = db.transaction(['secureData'], 'readonly');
                const store = transaction.objectStore('secureData');
                const getRequest = store.get(key);

                getRequest.onsuccess = () => {
                    try {
                        if (!getRequest.result) {
                            resolve(null);
                            return;
                        }

                        const deobfuscated = SecurityUtil.deobfuscate(getRequest.result);
                        SecurityUtil.decrypt(
                            deobfuscated.data,
                            SecureStorage.key,
                            deobfuscated.iv
                        )
                        .then(decrypted => {
                            resolve(decrypted);
                        })
                        .catch(() => {
                            reject('복호화 오류');
                        });
                    } catch (error) {
                        reject('데이터 처리 오류');
                    }
                };

                getRequest.onerror = () => {
                    reject('데이터 로드 오류');
                };
            };

            request.onerror = () => {
                reject('데이터베이스 오류');
            };
        });
    }
};

// 사용자 관리 함수 수정
function saveUser(userData) {
    return SecureStorage.load('users')
        .then(users => {
            users = users || [];
            users.push(userData);
            return SecureStorage.save('users', users);
        });
}

function getUsers() {
    return SecureStorage.load('users')
        .then(users => users || []);
}

// 회원가입 처리 함수 수정
function handleSignup(username, password) {
    return new Promise((resolve, reject) => {
        if (!username || !password) {
            reject('아이디와 비밀번호를 모두 입력해주세요.');
            return;
        }

        if (username.length < 4) {
            reject('아이디는 4자 이상이어야 합니다.');
            return;
        }

        if (password.length < 6) {
            reject('비밀번호는 6자 이상이어야 합니다.');
            return;
        }

        getUsers()
            .then(users => {
                if (users.some(user => user.username === username)) {
                    reject('이미 사용 중인 아이디입니다.');
                    return;
                }

                sha256Hex(password)
                    .then(hashedPassword => {
                        return saveUser({
                            username,
                            password: hashedPassword,
                            createdAt: new Date().toISOString()
                        });
                    })
                    .then(() => {
                        resolve(true);
                    })
                    .catch(() => {
                        reject('회원가입 처리 중 오류가 발생했습니다.');
                    });
            })
            .catch(() => {
                reject('사용자 정보 확인 중 오류가 발생했습니다.');
            });
    });
}

// --- 관리자 모드 단축키 ---
document.addEventListener('DOMContentLoaded', function () {
    console.log('script.js loaded');

    // 관리자 모드 단축키: Ctrl+Alt+M 또는 Ctrl+Shift+M 모두 허용
    document.addEventListener('keydown', function (e) {
        const key = e.key ? e.key.toLowerCase() : '';
        // Ctrl + Alt + M
        if (e.ctrlKey && e.altKey && key === 'm') {
            e.preventDefault();
            console.log('단축키 감지: Ctrl+Alt+M');
            openAdminTrigger();
        }
        // Ctrl + Shift + M (대체/백업)
        if (e.ctrlKey && e.shiftKey && key === 'm') {
            e.preventDefault();
            console.log('단축키 감지: Ctrl+Shift+M');
            openAdminTrigger();
        }
    });

    function openAdminTrigger() {
        const modalLogin = document.getElementById('modal-login');
        if (modalLogin) {
            // 모달 내용이 없으면 스크립트에서 채우도록 하는 코드가 있어야 함
            modalLogin.setAttribute('aria-hidden', 'false');
            const adminTrigger = document.getElementById('admin-mode-trigger');
            if (adminTrigger) {
                adminTrigger.style.display = 'block';
                console.log('admin-mode-trigger 표시됨');
            } else {
                console.log('admin-mode-trigger 요소가 없음 — modalLogin innerHTML이 정상적으로 설정되었는지 확인하세요');
            }
        } else {
            console.log('modal-login 요소를 찾을 수 없음');
        }
    }

    // 기존 modal 초기화 코드가 이 DOMContentLoaded 내부에 있어야 함
    // ...existing modal setup code...
});

// 관리자 모드 관련 UI/이벤트 안전하게 설정
(function() {
    const ADMIN_CODE = 'S3cur3@dm1n2025!!'; // 테스트용(실환경에서는 서버 검증으로 대체)
    const ADMIN_ATTEMPT_KEY = 'admin_attempt_data';
    const LOCKOUT_DURATION = 24 * 60 * 60 * 1000;

    function getAdminAttemptData() {
        try {
            const raw = localStorage.getItem(ADMIN_ATTEMPT_KEY);
            return raw ? JSON.parse(raw) : { attempts: 0, lockedUntil: null };
        } catch (e) { return { attempts: 0, lockedUntil: null }; }
    }
    function setAdminAttemptData(data) {
        try { localStorage.setItem(ADMIN_ATTEMPT_KEY, JSON.stringify(data)); } catch (e) {}
    }
    function isLocked() {
        const d = getAdminAttemptData();
        if (d.lockedUntil && Date.now() < d.lockedUntil) {
            const hrs = Math.ceil((d.lockedUntil - Date.now()) / (1000 * 60 * 60));
            return `관리자 코드 잠금: ${hrs}시간 남음`;
        }
        return false;
    }

    function openModal(id) {
        const m = document.getElementById(id);
        if (m) m.setAttribute('aria-hidden', 'false');
    }
    function closeModal(element) {
        const m = element.closest('.modal');
        if (m) m.setAttribute('aria-hidden', 'true');
    }

    document.addEventListener('DOMContentLoaded', function() {
        console.log('[script] DOMContentLoaded');

        // 디버그: 모달 요소 존재 확인
        const modalLogin = document.getElementById('modal-login');
        const adminTrigger = document.getElementById('admin-mode-trigger');
        const enterAdminBtn = document.getElementById('enter-admin-mode');
        const modalAdmin = document.getElementById('modal-admin');

        console.log('[script] modal-login:', !!modalLogin, 'adminTrigger:', !!adminTrigger, 'enterBtn:', !!enterAdminBtn, 'modal-admin:', !!modalAdmin);

        // 단축키 허용: Ctrl+Alt+M 또는 Ctrl+Shift+M
        document.addEventListener('keydown', function(e) {
            const key = e.key ? e.key.toLowerCase() : '';
            if ((e.ctrlKey && e.altKey && key === 'm') || (e.ctrlKey && e.shiftKey && key === 'm')) {
                e.preventDefault();
                console.log('[script] 관리자 단축키 감지');
                if (modalLogin) {
                    openModal('modal-login');
                    const trigger = document.getElementById('admin-mode-trigger');
                    if (trigger) trigger.style.display = 'block';
                } else {
                    console.warn('[script] modal-login 요소 없음');
                }
            }
        });

        // 이벤트 위임: 동적으로 생성되거나 이미 있는 버튼 모두 처리
        document.addEventListener('click', function(e) {
            const target = e.target;

            // 모달 닫기
            if (target.classList && target.classList.contains('modal-close')) {
                const modal = target.closest('.modal');
                if (modal) modal.setAttribute('aria-hidden', 'true');
                return;
            }

            // 관리자 모드 진입 버튼
            if (target.id === 'enter-admin-mode') {
                // 잠금 확인
                const lockMsg = isLocked();
                if (lockMsg) {
                    alert(lockMsg);
                    return;
                }

                const codeInput = document.getElementById('admin-mode-code');
                const code = codeInput ? codeInput.value : '';
                console.log('[script] 관리자 코드 입력 시도');

                if (!code) {
                    alert('관리자 코드를 입력하세요.');
                    return;
                }

                if (code === ADMIN_CODE) {
                    // 성공 처리: 잠금 해제 및 관리자 패널 열기
                    setAdminAttemptData({ attempts: 0, lockedUntil: null });
                    if (document.getElementById('modal-admin')) {
                        openModal('modal-admin');
                        // 숨김 해제
                        const adminSetup = document.getElementById('admin-setup-section');
                        if (adminSetup) adminSetup.style.display = 'block';
                        // 로그인 모달 숨기기
                        if (document.getElementById('modal-login')) document.getElementById('modal-login').setAttribute('aria-hidden', 'true');
                        // 숨겨진 트리거 숨김
                        if (document.getElementById('admin-mode-trigger')) document.getElementById('admin-mode-trigger').style.display = 'none';
                    }
                    alert('관리자 모드 활성화됨');
                } else {
                    // 실패 시 잠금 설정
                    const now = Date.now();
                    setAdminAttemptData({ attempts: 1, lockedUntil: now + LOCKOUT_DURATION });
                    alert('잘못된 관리자 코드. 24시간 동안 차단됩니다.');
                    // 입력 비활성화
                    if (codeInput) { codeInput.value = ''; codeInput.disabled = true; }
                    target.disabled = true;
                }
                return;
            }

            // 모든 계정 삭제 버튼 (관리자 전용)
            if (target.id === 'delete-all-accounts') {
                const confirmed = confirm('정말로 모든 계정을 삭제합니까? 이 작업은 되돌릴 수 없습니다.');
                if (!confirmed) return;
                // 클라이언트 테스트 환경일 경우 local storage/IndexedDB에 저장된 사용자 제거
                try {
                    // indexedDB 키 이름 사용 중이면 제거 시도
                    try { indexedDB.deleteDatabase('SecureDB'); } catch (e) {}
                    try { localStorage.removeItem('sc_users_v1'); localStorage.removeItem('sc_current_user_v1'); } catch(e){}
                    alert('로컬에 저장된 계정 데이터가 삭제되었습니다 (테스트 환경).');
                    // 관리자 패널 닫기
                    if (document.getElementById('modal-admin')) document.getElementById('modal-admin').setAttribute('aria-hidden', 'true');
                    location.reload();
                } catch (err) {
                    console.error('계정 삭제 실패', err);
                    alert('계정 삭제 중 오류가 발생했습니다. 콘솔을 확인하세요.');
                }
                return;
            }

            // 회원가입 열기/전환 등 기존 기능은 기존 코드에서 처리될 것
        });

        // 페이지 로드 시 잠금 상태가 있으면 입력 비활성화
        const lockMsg = isLocked();
        if (lockMsg) {
            const codeInput = document.getElementById('admin-mode-code');
            const enterBtn = document.getElementById('enter-admin-mode');
            if (codeInput) codeInput.disabled = true;
            if (enterBtn) enterBtn.disabled = true;
            console.log('[script] 관리자 코드 입력 비활성화 - 잠금 상태');
        }
    });
})();