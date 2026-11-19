// Funcoes compartilhadas por todas as telas
function sair() { localStorage.removeItem('token'); localStorage.removeItem('nome'); window.location.href = 'login.html'; }

async function api(url, metodo = 'GET', corpo) {
    const resp = await fetch(url, {
        method: metodo,
        headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + localStorage.getItem('token') },
        body: corpo ? JSON.stringify(corpo) : undefined
    });
    const dados = await resp.json();
    if (resp.status === 401) {            // token expirado ou invalido
        alert(dados.erro);
        sair();
        throw new Error(dados.erro);
    }
    if (!resp.ok) { alert(dados.erro); throw new Error(dados.erro); }
    return dados;
}

// Chamado no inicio de cada tela protegida
function protegerPagina() {
    if (!localStorage.getItem('token')) { window.location.href = 'login.html'; return; }
    document.getElementById('usuarioLogado').textContent = localStorage.getItem('nome');
}

function cabecalho(titulo) {
    return `<header><strong>🐾 Clínica Veterinária - ${titulo}</strong>
      <span>Usuário: <b id="usuarioLogado"></b> | <a href="home.html">Início</a> | <a href="#" onclick="sair()">Sair</a></span></header>`;
}
const fmtCPF = (c) => c.replace(/(\d{3})(\d{3})(\d{3})(\d{2})/, '$1.$2.$3-$4');
