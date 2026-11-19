const express = require('express');
const knex = require('knex');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());
app.use(express.static('public'));

// ---------- CONFIGURACOES ----------
const JWT_SECRET = 'saep_jwt_segredo';          // segredo para assinar o token
const TEMPO_TOKEN = '30m';                       // token expira em 30 minutos
const CHAVE_CPF = crypto.createHash('sha256').update('saep_clinica_chave_secreta').digest(); // 32 bytes (AES-256)

const db = knex({
    client: 'mysql2',
    connection: { host: 'localhost', port: 3306, user: 'admin', password: '123456', database: 'saep_db' }
});

// ---------- FUNCOES AUXILIARES ----------
const hash = (t) => crypto.createHash('sha256').update(t).digest('hex');

function criptografar(texto) {
    const iv = crypto.randomBytes(16);
    const c = crypto.createCipheriv('aes-256-cbc', CHAVE_CPF, iv);
    return iv.toString('hex') + ':' + Buffer.concat([c.update(texto, 'utf8'), c.final()]).toString('hex');
}
function descriptografar(valor) {
    const [iv, dados] = valor.split(':');
    const d = crypto.createDecipheriv('aes-256-cbc', CHAVE_CPF, Buffer.from(iv, 'hex'));
    return Buffer.concat([d.update(Buffer.from(dados, 'hex')), d.final()]).toString('utf8');
}
function cpfValido(cpf) {
    if (!/^\d{11}$/.test(cpf) || /^(\d)\1{10}$/.test(cpf)) return false;
    for (let t = 9; t < 11; t++) {
        let soma = 0;
        for (let i = 0; i < t; i++) soma += Number(cpf[i]) * (t + 1 - i);
        const dig = ((soma * 10) % 11) % 10;
        if (dig !== Number(cpf[t])) return false;
    }
    return true;
}
const soDigitos = (t) => String(t || '').replace(/\D/g, '');

// ---------- LOGIN ----------
app.post('/api/login', async (req, res) => {
    const { usuario, senha } = req.body;
    if (!usuario || !senha) return res.status(400).json({ erro: 'Informe usuário e senha.' });
    const u = await db('USUARIO').where({ USUARIO: usuario }).first();
    if (!u) return res.status(401).json({ erro: 'Usuário não encontrado.' });
    if (u.SENHA !== hash(senha)) return res.status(401).json({ erro: 'Senha incorreta.' });
    const token = jwt.sign({ id: u.ID, nome: u.NOME }, JWT_SECRET, { expiresIn: TEMPO_TOKEN });
    res.json({ token, nome: u.NOME });
});

// ---------- MIDDLEWARE: exige token valido nas rotas abaixo ----------
app.use('/api', (req, res, next) => {
    const token = (req.headers.authorization || '').replace('Bearer ', '');
    try {
        req.usuario = jwt.verify(token, JWT_SECRET);
        next();
    } catch (e) {
        const msg = e.name === 'TokenExpiredError' ? 'Sessão expirada. Faça login novamente.' : 'Não autenticado.';
        res.status(401).json({ erro: msg });
    }
});

app.get('/api/me', (req, res) => res.json({ nome: req.usuario.nome }));

// ---------- TUTORES ----------
function validarTutor(b) {
    if (!b.nome || b.nome.trim().length < 3) return 'Nome é obrigatório (mínimo 3 letras).';
    if (!cpfValido(soDigitos(b.cpf))) return 'CPF inválido.';
    if (soDigitos(b.telefone).length < 10) return 'Telefone inválido (informe DDD + número).';
    if (!/^\S+@\S+\.\S+$/.test(b.email || '')) return 'E-mail inválido.';
    return null;
}

app.get('/api/tutores', async (req, res) => {
    const q = db('TUTOR').orderBy('NOME');
    if (req.query.busca) q.where('NOME', 'like', `%${req.query.busca}%`);
    const lista = await q;
    res.json(lista.map(t => ({
        id: t.ID, nome: t.NOME, cpf: descriptografar(t.CPF_CRIPTOGRAFADO),
        telefone: t.TELEFONE, email: t.EMAIL
    })));
});

app.post('/api/tutores', async (req, res) => {
    const erro = validarTutor(req.body);
    if (erro) return res.status(400).json({ erro });
    const cpf = soDigitos(req.body.cpf);
    if (await db('TUTOR').where({ CPF_HASH: hash(cpf) }).first())
        return res.status(409).json({ erro: 'Já existe um tutor com este CPF.' });
    await db('TUTOR').insert({
        NOME: req.body.nome.trim(), CPF_CRIPTOGRAFADO: criptografar(cpf), CPF_HASH: hash(cpf),
        TELEFONE: req.body.telefone, EMAIL: req.body.email
    });
    res.status(201).json({ ok: true });
});

app.put('/api/tutores/:id', async (req, res) => {
    const erro = validarTutor(req.body);
    if (erro) return res.status(400).json({ erro });
    const cpf = soDigitos(req.body.cpf);
    const outro = await db('TUTOR').where({ CPF_HASH: hash(cpf) }).whereNot({ ID: req.params.id }).first();
    if (outro) return res.status(409).json({ erro: 'Já existe outro tutor com este CPF.' });
    await db('TUTOR').where({ ID: req.params.id }).update({
        NOME: req.body.nome.trim(), CPF_CRIPTOGRAFADO: criptografar(cpf), CPF_HASH: hash(cpf),
        TELEFONE: req.body.telefone, EMAIL: req.body.email
    });
    res.json({ ok: true });
});

app.delete('/api/tutores/:id', async (req, res) => {
    const pets = await db('PET').where({ ID_TUTOR: req.params.id }).first();
    if (pets) return res.status(409).json({ erro: 'Não é possível excluir: o tutor possui pets cadastrados.' });
    await db('TUTOR').where({ ID: req.params.id }).del();
    res.json({ ok: true });
});

// ---------- PETS ----------
function validarPet(b) {
    if (!b.nome || b.nome.trim().length < 2) return 'Nome do pet é obrigatório.';
    if (!b.especie || !b.especie.trim()) return 'Espécie é obrigatória.';
    if (!b.raca || !b.raca.trim()) return 'Raça é obrigatória.';
    if (!b.data_nascimento || isNaN(new Date(b.data_nascimento))) return 'Data de nascimento inválida.';
    if (new Date(b.data_nascimento) > new Date()) return 'Data de nascimento não pode ser futura.';
    if (!b.id_tutor) return 'Selecione o tutor.';
    return null;
}

app.get('/api/pets', async (req, res) => {
    const q = db('PET').join('TUTOR', 'TUTOR.ID', 'PET.ID_TUTOR')
        .select('PET.ID as id', 'PET.NOME as nome', 'PET.ESPECIE as especie', 'PET.RACA as raca',
            db.raw("DATE_FORMAT(PET.DATA_NASCIMENTO,'%Y-%m-%d') as data_nascimento"),
            'PET.ID_TUTOR as id_tutor', 'TUTOR.NOME as tutor')
        .orderBy('PET.NOME');
    if (req.query.busca) q.where('PET.NOME', 'like', `%${req.query.busca}%`);
    res.json(await q);
});

app.post('/api/pets', async (req, res) => {
    const erro = validarPet(req.body);
    if (erro) return res.status(400).json({ erro });
    const dup = await db('PET').where({ ID_TUTOR: req.body.id_tutor, NOME: req.body.nome.trim() }).first();
    if (dup) return res.status(409).json({ erro: 'Este tutor já possui um pet com esse nome.' });
    await db('PET').insert({
        NOME: req.body.nome.trim(), ESPECIE: req.body.especie, RACA: req.body.raca,
        DATA_NASCIMENTO: req.body.data_nascimento, ID_TUTOR: req.body.id_tutor
    });
    res.status(201).json({ ok: true });
});

app.put('/api/pets/:id', async (req, res) => {
    const erro = validarPet(req.body);
    if (erro) return res.status(400).json({ erro });
    const dup = await db('PET').where({ ID_TUTOR: req.body.id_tutor, NOME: req.body.nome.trim() })
        .whereNot({ ID: req.params.id }).first();
    if (dup) return res.status(409).json({ erro: 'Este tutor já possui um pet com esse nome.' });
    await db('PET').where({ ID: req.params.id }).update({
        NOME: req.body.nome.trim(), ESPECIE: req.body.especie, RACA: req.body.raca,
        DATA_NASCIMENTO: req.body.data_nascimento, ID_TUTOR: req.body.id_tutor
    });
    res.json({ ok: true });
});

app.delete('/api/pets/:id', async (req, res) => {
    const ag = await db('AGENDAMENTO').where({ ID_PET: req.params.id }).first();
    if (ag) return res.status(409).json({ erro: 'Não é possível excluir: o pet possui agendamentos.' });
    await db('PET').where({ ID: req.params.id }).del();
    res.json({ ok: true });
});

// ---------- AGENDAMENTOS ----------
function validarAgendamento(b) {
    if (!b.id_pet) return 'Selecione o pet.';
    if (!b.data_hora || isNaN(new Date(b.data_hora))) return 'Data e hora inválidas.';
    if (!b.motivo || b.motivo.trim().length < 3) return 'Informe o motivo do atendimento.';
    if (!['AGENDADO', 'REALIZADO', 'CANCELADO'].includes(b.status || 'AGENDADO')) return 'Status inválido.';
    return null;
}

app.get('/api/agendamentos', async (req, res) => {
    const q = db('AGENDAMENTO')
        .join('PET', 'PET.ID', 'AGENDAMENTO.ID_PET')
        .join('TUTOR', 'TUTOR.ID', 'PET.ID_TUTOR')
        .join('USUARIO', 'USUARIO.ID', 'AGENDAMENTO.ID_USUARIO')
        .select('AGENDAMENTO.ID as id',
            db.raw("DATE_FORMAT(AGENDAMENTO.DATA_HORA,'%Y-%m-%dT%H:%i') as data_hora"),
            'AGENDAMENTO.MOTIVO as motivo', 'AGENDAMENTO.STATUS as status',
            'AGENDAMENTO.ID_PET as id_pet', 'PET.NOME as pet', 'TUTOR.NOME as tutor', 'USUARIO.NOME as atendente')
        .orderBy('AGENDAMENTO.DATA_HORA');
    if (req.query.busca) q.where('PET.NOME', 'like', `%${req.query.busca}%`).orWhere('TUTOR.NOME', 'like', `%${req.query.busca}%`);
    res.json(await q);
});

app.post('/api/agendamentos', async (req, res) => {
    const erro = validarAgendamento(req.body);
    if (erro) return res.status(400).json({ erro });
    const dup = await db('AGENDAMENTO').where({ ID_PET: req.body.id_pet, DATA_HORA: req.body.data_hora }).first();
    if (dup) return res.status(409).json({ erro: 'Este pet já tem agendamento nesse horário.' });
    await db('AGENDAMENTO').insert({
        DATA_HORA: req.body.data_hora, MOTIVO: req.body.motivo.trim(),
        STATUS: req.body.status || 'AGENDADO', ID_PET: req.body.id_pet, ID_USUARIO: req.usuario.id
    });
    res.status(201).json({ ok: true });
});

app.put('/api/agendamentos/:id', async (req, res) => {
    const erro = validarAgendamento(req.body);
    if (erro) return res.status(400).json({ erro });
    const dup = await db('AGENDAMENTO').where({ ID_PET: req.body.id_pet, DATA_HORA: req.body.data_hora })
        .whereNot({ ID: req.params.id }).first();
    if (dup) return res.status(409).json({ erro: 'Este pet já tem agendamento nesse horário.' });
    await db('AGENDAMENTO').where({ ID: req.params.id }).update({
        DATA_HORA: req.body.data_hora, MOTIVO: req.body.motivo.trim(),
        STATUS: req.body.status || 'AGENDADO', ID_PET: req.body.id_pet
    });
    res.json({ ok: true });
});

app.delete('/api/agendamentos/:id', async (req, res) => {
    await db('AGENDAMENTO').where({ ID: req.params.id }).del();
    res.json({ ok: true });
});

// ---------- INICIO ----------
app.get('/', (req, res) => res.redirect('/login.html'));

app.listen(8080, async () => {
    console.log('Serviço rodando em http://localhost:8080');
    try { await db.raw('select 1'); console.log('Conexão com o banco OK!'); }
    catch (e) { console.log('Erro ao conectar ao banco:', e.message); }
});
