const express = require("express");
const mysql = require("mysql2");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
const cors = require("cors");
const jwt = require("jsonwebtoken"); 

const app = express();
app.use(bodyParser.json());
app.use(cors());

const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "root",
  database: "login_db",
});

db.connect((err) => {
  if (err) {
    console.error("Erro ao conectar ao banco de dados:", err);
    process.exit(1);
  }
  console.log("Conectado ao banco de dados");
});

// Middleware para verificar o token
const verificarToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) {
    return res.status(403).json({ mensagem: "Token não fornecido!" });
  }

  jwt.verify(token, 'seu-segredo-aqui', (err, decoded) => {
    if (err) {
      return res.status(401).json({ mensagem: "Token inválido!" });
    }
    req.usuarioId = decoded.id;
    next();
  });
};

// Rota para login
app.post("/login", (req, res) => {
  const { usuario, senha } = req.body;

  if (!usuario || !senha) {
    return res.status(400).json({ mensagem: "Usuário e senha são obrigatórios!" });
  }

  const sql = "SELECT * FROM usuarios WHERE usuario = ?";
  db.query(sql, [usuario], async (err, results) => {
    if (err) {
      return res.status(500).json({ mensagem: "Erro no banco de dados", erro: err });
    }

    if (results.length === 0) {
      return res.status(404).json({ mensagem: "Usuário não encontrado" });
    }

    const usuarioEncontrado = results[0];
    const senhaValida = await bcrypt.compare(senha, usuarioEncontrado.senha);

    if (senhaValida) {
      // Gerar o token JWT
      const token = jwt.sign({ id: usuarioEncontrado.id, usuario: usuarioEncontrado.usuario }, 'seu-segredo-aqui', { expiresIn: '1h' });
      res.json({ mensagem: "Login realizado com sucesso!", token });
    } else {
      res.status(401).json({ mensagem: "Senha inválida" });
    }
  });
});

// Rota para registrar usuário
app.post("/registrar", async (req, res) => {
  const { usuario, senha } = req.body;

  if (!usuario || !senha) {
    return res.status(400).json({ mensagem: "Usuário e senha são obrigatórios!" });
  }

  try {
    const senhaCriptografada = await bcrypt.hash(senha, 10);
    const sql = "INSERT INTO usuarios (usuario, senha) VALUES (?, ?)";
    db.query(sql, [usuario, senhaCriptografada], (err) => {
      if (err) {
        if (err.code === "ER_DUP_ENTRY") {
          return res.status(400).json({ mensagem: "Usuário já existe" });
        }
        return res.status(500).json({ mensagem: "Erro ao registrar o usuário", erro: err });
      }
      res.json({ mensagem: "Usuário registrado com sucesso!" });
    });
  } catch (erro) {
    res.status(500).json({ mensagem: "Erro ao criptografar a senha", erro: erro.message });
  }
});

// Rota protegida
app.get("/protegida", verificarToken, (req, res) => {
  res.json({ mensagem: "Esta é uma rota protegida!", usuarioId: req.usuarioId });
});

// Inicialização do servidor
const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Servidor rodando em http://localhost:${PORT}`);
});
