/* app.js - shared frontend logic for login / register / chat
   Put this file next to login.html, register.html, chat.html
   Make sure to set API_BASE to your backend address (e.g. http://localhost:5000)
*/

const API_BASE = "http://localhost:5000"; // <- غَيّره إن لزم

function qs(id){ return document.getElementById(id); }
function apiFetch(path, opts = {}) {
  const headers = opts.headers || {};
  const token = localStorage.getItem('connexa_token');
  if(token) headers['Authorization'] = 'Bearer ' + token;
  headers['Content-Type'] = headers['Content-Type'] || 'application/json';
  opts.headers = headers;
  return fetch(API_BASE + path, opts);
}

function escapeHtml(s){ return String(s||'').replace(/[&<>"']/g, c=>({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }

/* ---------- LOGIN PAGE ---------- */
if(document.body.classList.contains('login-page')){
  const loginForm = qs('loginForm');
  const emailEl = qs('email');
  const passEl = qs('password');
  if(loginForm){
    loginForm.addEventListener('submit', async (e)=>{
      e.preventDefault();
      const email = emailEl.value.trim(), password = passEl.value.trim();
      if(!email || !password) return alert('Email and password required');
      try{
        const res = await apiFetch('/api/login', { method: 'POST', body: JSON.stringify({ email, password }) });
        const j = await res.json();
        if(!res.ok) return alert(j.msg || 'Login failed');
        localStorage.setItem('connexa_token', j.access_token);
        localStorage.setItem('connexa_user', JSON.stringify(j.user));
        // redirect to chat
        window.location.href = 'chat.html';
      }catch(err){ alert('Network error: ' + err.message); }
    });
  }
}

/* ---------- REGISTER PAGE ---------- */
if(document.body.classList.contains('register-page')){
  const form = qs('registerForm');
  if(form){
    form.addEventListener('submit', async (e)=>{
      e.preventDefault();
      const username = qs('username').value.trim();
      const email = qs('email').value.trim();
      const password = qs('password').value.trim();
      if(!username || !email || !password) return alert('All fields required');
      try{
        const res = await apiFetch('/api/register', { method: 'POST', body: JSON.stringify({ username, email, password }) });
        const j = await res.json();
        if(!res.ok) return alert(j.msg || 'Register failed');
        localStorage.setItem('connexa_token', j.access_token);
        localStorage.setItem('connexa_user', JSON.stringify(j.user));
        window.location.href = 'chat.html';
      }catch(err){ alert('Network error: ' + err.message); }
    });
  }
}

/* ---------- CHAT & CONTACTS PAGE (single file chat.html) ---------- */
if(document.body.classList.contains('chat-page')){
  // elements
  const userList = qs('userList');
  const messageContainer = qs('messageContainer');
  const chatHeader = qs('chatHeader');
  const messageForm = qs('messageForm');
  const messageInput = qs('messageInput');
  const newConvBtn = qs('newConvBtn');
  const logoutBtn = qs('logoutBtn');

  let socket = null;
  let currentConv = null;
  const user = JSON.parse(localStorage.getItem('connexa_user') || 'null');
  const token = localStorage.getItem('connexa_token');

  if(!token || !user) {
    alert('Not logged in');
    window.location.href = 'login.html';
  }

  logoutBtn.addEventListener('click', ()=> {
    localStorage.removeItem('connexa_token');
    localStorage.removeItem('connexa_user');
    localStorage.removeItem('connexa_conv');
    window.location.href = 'login.html';
  });

  async function loadConversations(){
    try {
      const res = await apiFetch('/api/conversations');
      if(res.status === 401) { alert('Not logged in'); logoutBtn.click(); return; }
      const convs = await res.json();
      userList.innerHTML = '';
      if(!convs || convs.length === 0) {
        userList.innerHTML = '<div class="small" style="padding:12px">No conversations yet</div>';
        return;
      }
      convs.forEach(c => {
        const li = document.createElement('li');
        li.dataset.conv = c.id;
        li.innerHTML = `<img src="https://i.pravatar.cc/44?img=${c.id+2}" class="avatar" />
                        <div><div class="username">${escapeHtml(c.title || ('Chat #' + c.id))}</div>
                        <div class="small">${c.is_group ? 'Group' : '1:1'}</div></div>`;
        li.addEventListener('click', ()=> selectConversation(c.id, c.title));
        userList.appendChild(li);
      });
    } catch(err) {
      console.error(err);
      alert('Failed to load conversations');
    }
  }

  async function selectConversation(convId, title){
    currentConv = convId;
    localStorage.setItem('connexa_conv', convId);
    chatHeader.textContent = title || ('Chat #' + convId);
    Array.from(userList.querySelectorAll('li')).forEach(li => li.classList.toggle('active', +li.dataset.conv === +convId));
    await loadMessages(convId);
    joinSocketRoom(convId);
  }

  async function loadMessages(convId){
    if(!convId) return;
    try {
      const res = await apiFetch('/api/conversations/' + convId + '/messages');
      if(res.status === 403) { alert('You are not a participant'); return; }
      const msgs = await res.json();
      messageContainer.innerHTML = '';
      msgs.forEach(m => renderMessage(m));
      messageContainer.scrollTop = messageContainer.scrollHeight;
    } catch(err) {
      console.warn(err);
      alert('Failed to load messages');
    }
  }

  function renderMessage(m){
    const div = document.createElement('div');
    const meId = user ? user.id : null;
    div.className = 'message ' + ((meId && +meId === +m.sender_id) ? 'sent' : 'received');
    div.innerHTML = `<div class="text">${escapeHtml(m.body)}</div>`;
    const timeSpan = document.createElement('span');
    timeSpan.className = 'time';
    timeSpan.textContent = m.created_at ? new Date(m.created_at).toLocaleString() : '';
    div.appendChild(timeSpan);
    messageContainer.appendChild(div);
    messageContainer.scrollTop = messageContainer.scrollHeight;
  }

  async function sendMessage(text){
    if(!text || !currentConv) return;
    if(socket && socket.connected){
      socket.emit('send_message', { conversation_id: parseInt(currentConv), sender_id: user ? user.id : null, body: text });
      messageInput.value = '';
      return;
    }
    try {
      const res = await apiFetch('/api/conversations/' + currentConv + '/messages', { method: 'POST', body: JSON.stringify({ body: text }) });
      const j = await res.json();
      if(!res.ok) return alert(j.msg || 'Send failed');
      renderMessage(j);
      messageInput.value = '';
    } catch(err) {
      alert('Send failed: ' + err.message);
    }
  }

  messageForm.addEventListener('submit', (e)=> {
    e.preventDefault();
    const t = (messageInput.value || '').trim();
    if(!t) return;
    sendMessage(t);
  });

  newConvBtn.addEventListener('click', async ()=>{
    const ids = prompt('Participant IDs (comma-separated), include your id: (your id = ' + (user ? user.id : 'unknown') + ')');
    if(!ids) return;
    const list = ids.split(',').map(x => parseInt(x.trim())).filter(Boolean);
    const title = prompt('Conversation title (optional):') || '';
    try {
      const res = await apiFetch('/api/conversations', { method: 'POST', body: JSON.stringify({ title, participant_ids: list }) });
      const j = await res.json();
      if(!res.ok) return alert(j.msg || 'Create failed');
      await loadConversations();
      selectConversation(j.id, j.title);
    } catch(err) {
      alert('Create failed');
    }
  });

  // Socket.IO
  function connectSocket(){
    if(!token) return;
    socket = io(API_BASE, { auth: { token } });
    socket.on('connect', ()=> {
      console.log('socket connected', socket.id);
      const convId = localStorage.getItem('connexa_conv');
      if(convId) joinSocketRoom(parseInt(convId));
    });
    socket.on('new_message', (m) => {
      if(+m.conversation_id === +currentConv) renderMessage(m);
      else console.log('new message in other conv', m);
    });
    socket.on('joined_room', (d) => console.log('joined', d));
    socket.on('error', (e) => console.warn('socket error', e));
  }

  function joinSocketRoom(convId){
    if(socket && socket.connected) socket.emit('join_room', { conversation_id: parseInt(convId) });
  }

  (async function init(){
    await loadConversations();
    connectSocket();
    const cv = localStorage.getItem('connexa_conv');
    if(cv) {
      setTimeout(()=> {
        const el = Array.from(userList.children).find(li => +li.dataset.conv === +cv);
        const title = el ? (el.querySelector('.username').textContent) : ('Chat #' + cv);
        selectConversation(cv, title);
      }, 200);
    }
  })();
}
