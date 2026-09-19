// BLOCO 1/10 - BASE DO SISTEMA, BANCO, EVENTOS,
// MIKROTIKS E PLANOS
// ============================================================

const express = require("express");
const axios = require("axios");
const Database = require("better-sqlite3");
const basicAuth = require("express-basic-auth");
const crypto = require("crypto");
const QRCode = require("qrcode");
const path = require("path");
const fs = require("fs");

require("dotenv").config();

const app = express();

// Railway encaminha as requisicoes por um proxy confiavel.
// Configure TRUST_PROXY_HOPS=0 quando executar sem proxy reverso.
const trustProxyHops = Number(process.env.TRUST_PROXY_HOPS ?? 1);
if (!Number.isInteger(trustProxyHops) || trustProxyHops < 0 || trustProxyHops > 5) {
  throw new Error("TRUST_PROXY_HOPS deve ser um inteiro entre 0 e 5");
}
app.set("trust proxy", trustProxyHops);

const missingRequiredEnv = ["ADMIN_USER", "ADMIN_PASSWORD", "MP_ACCESS_TOKEN", "MP_WEBHOOK_SECRET"]
  .filter(name => !String(process.env[name] || "").trim());

if (process.env.NODE_ENV === "production" && missingRequiredEnv.length) {
  throw new Error(
    `Configure as variaveis obrigatorias antes de iniciar: ${missingRequiredEnv.join(", ")}`
  );
}

if (missingRequiredEnv.length) {
  console.warn(
    `Configuracao incompleta para producao: ${missingRequiredEnv.join(", ")}`
  );
}

const adminUser = String(process.env.ADMIN_USER || "admin").trim();
const adminPassword = String(process.env.ADMIN_PASSWORD || "").trim();
const adminPasswordCharacterClasses = [
  /[a-z]/.test(adminPassword),
  /[A-Z]/.test(adminPassword),
  /[0-9]/.test(adminPassword),
  /[^a-zA-Z0-9]/.test(adminPassword)
].filter(Boolean).length;
if (
  adminPassword
  && (
    adminPassword.length < 14
    || adminPasswordCharacterClasses < 3
    || /^(.)\1+$/.test(adminPassword)
    || ["troque-esta-senha", "admin", "password"].includes(adminPassword.toLowerCase())
  )
) {
  throw new Error("ADMIN_PASSWORD deve ter ao menos 14 caracteres e combinar 3 tipos: letras minusculas, maiusculas, numeros e simbolos");
}

const adminBasicAuth = basicAuth({
  users: {
    [adminUser]: adminPassword || crypto.randomBytes(32).toString("hex")
  },
  challenge: true
});

// SessÃµes administrativas: o Basic Auth continua aceito durante a migraÃ§Ã£o.
const adminSessions = new Map();
function adminAuth(req, res, next) {
  const token = String(req.headers.cookie || "").split(";").map(v => v.trim()).find(v => v.startsWith("wifi_admin_session="))?.split("=")[1];
  const session = token ? adminSessions.get(token) : null;
  if (session && session.expiresAt > Date.now()) {
    req.adminUser = session.username;
    req.adminRole = session.role;
    return next();
  }
  return res.status(401).json({ ok:false, error:"SessÃ£o expirada. FaÃ§a login novamente." });
}

function requireRole(...allowed) {
  return (req, res, next) => {
    if (allowed.includes(req.adminRole || "admin")) return next();
    return res.status(403).json({ ok:false, error:"Sem permissÃ£o para esta operaÃ§Ã£o" });
  };
}

const rateLimitBuckets = new Map();

function createRateLimiter({ windowMs, max, keyFor, message }) {
  return (req, res, next) => {
    const identity = String(keyFor(req) || "").trim();
    if (!identity) {
      return res.status(400).json({ ok: false, error: "Identificador de cliente invalido" });
    }

    const key = `${req.baseUrl}${req.path}:${identity}`;
    const now = Date.now();
    let bucket = rateLimitBuckets.get(key);
    if (!bucket || bucket.resetAt <= now) {
      bucket = { count: 0, resetAt: now + windowMs };
      rateLimitBuckets.set(key, bucket);
    }

    bucket.count += 1;
    res.setHeader("RateLimit-Limit", String(max));
    res.setHeader("RateLimit-Remaining", String(Math.max(0, max - bucket.count)));
    res.setHeader("RateLimit-Reset", String(Math.ceil(bucket.resetAt / 1000)));

    if (bucket.count > max) {
      res.setHeader("Retry-After", String(Math.max(1, Math.ceil((bucket.resetAt - now) / 1000))));
      return res.status(429).json({ ok: false, error: message });
    }

    if (rateLimitBuckets.size > 10000) {
      for (const [bucketKey, value] of rateLimitBuckets) {
        if (value.resetAt <= now) rateLimitBuckets.delete(bucketKey);
      }
    }

    return next();
  };
}

const limitPixByIp = createRateLimiter({
  windowMs: 60 * 1000,
  max: 30,
  keyFor: req => req.ip,
  message: "Muitas tentativas de pagamento. Aguarde um minuto."
});
const limitPixByClient = createRateLimiter({
  windowMs: 60 * 1000,
  max: 5,
  keyFor: req => req.body?.client_id,
  message: "Este aparelho gerou muitos PIX. Aguarde um minuto."
});
const limitRecoveryByIp = createRateLimiter({
  windowMs: 15 * 60 * 1000,
  max: 30,
  keyFor: req => req.ip,
  message: "Muitas tentativas de recuperacao. Aguarde 15 minutos."
});
const limitRecoveryByClient = createRateLimiter({
  windowMs: 15 * 60 * 1000,
  max: 5,
  keyFor: req => req.body?.client_id,
  message: "Muitas tentativas de recuperacao para este aparelho."
});


// ============================================================
// V15.7 - CORS DO PORTAL LOCAL MIKROTIK
//
// O login.html passa a poder ser servido por 10.50.0.1 e chamar
// as APIs HTTPS do Railway.
//
// SeguranÃ§a:
// - libera somente a origem local do HotSpot atual;
// - nÃ£o libera o Admin por CORS;
// - aceita apenas mÃ©todos necessÃ¡rios ao portal.
// ============================================================

const PORTAL_CORS_ORIGINS =
  new Set([
    "http://10.50.0.1",
    "https://10.50.0.1",
    "http://wifi.pago",
    "https://wifi.pago"
  ]);


app.use(
  (req, res, next) => {

    const origin =
      String(
        req.headers.origin || ""
      ).trim();


    if(
      origin
      &&
      PORTAL_CORS_ORIGINS.has(
        origin
      )
    ){

      res.setHeader(
        "Access-Control-Allow-Origin",
        origin
      );

      res.setHeader(
        "Vary",
        "Origin"
      );

      res.setHeader(
        "Access-Control-Allow-Methods",
        "GET,POST,OPTIONS"
      );

      res.setHeader(
        "Access-Control-Allow-Headers",
        "Content-Type"
      );

      res.setHeader(
        "Access-Control-Max-Age",
        "600"
      );

    }


    if(
      req.method ===
      "OPTIONS"
    ){

      if(
        origin
        &&
        PORTAL_CORS_ORIGINS.has(
          origin
        )
      ){

        return res
          .status(204)
          .end();

      }


      return res
        .status(403)
        .end();

    }


    next();

  }
);


app.use(express.json());

app.use(
  express.urlencoded({
    extended: true
  })
);

// ============================================================
// CONFIGURAÃ‡Ã•ES GERAIS
// ============================================================

const TEMP_MINUTES = 3;

const TEMP_RETRY_WAIT_MINUTES = 5;

const TEMP_MAX_ATTEMPTS_PER_HOUR = 2;


// ============================================================
// BANCO DE DADOS
// Railway Volume montado em /app/data
// ============================================================

const dataDir =
  process.env.DATA_DIR ||
  path.join(
    __dirname,
    "data"
  );

fs.mkdirSync(
  dataDir,
  {
    recursive: true
  }
);

const db =
  new Database(
    path.join(
      dataDir,
      "wifi.db"
    )
  );

// Codigos impressos sao credenciais de acesso. Mantemos uma copia recuperavel
// criptografada no banco para permitir reimpressao somente pelo painel admin.
const voucherPrintKeyPath = path.join(dataDir, "voucher-print.key");
let voucherPrintKey;
try {
  voucherPrintKey = fs.readFileSync(voucherPrintKeyPath);
} catch (error) {
  if (error.code !== "ENOENT") throw error;
  voucherPrintKey = crypto.randomBytes(32);
  try {
    fs.writeFileSync(voucherPrintKeyPath, voucherPrintKey, { flag: "wx", mode: 0o600 });
  } catch (writeError) {
    if (writeError.code !== "EEXIST") throw writeError;
    voucherPrintKey = fs.readFileSync(voucherPrintKeyPath);
  }
}
if (voucherPrintKey.length !== 32) throw new Error("Chave de impressao de vouchers invalida");

function encryptVoucherPrintData(value) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", voucherPrintKey, iv);
  const encrypted = Buffer.concat([cipher.update(JSON.stringify(value), "utf8"), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), encrypted]).toString("base64");
}

function decryptVoucherPrintData(value) {
  const payload = Buffer.from(String(value || ""), "base64");
  if (payload.length < 29) throw new Error("Dados de impressao invalidos");
  const decipher = crypto.createDecipheriv("aes-256-gcm", voucherPrintKey, payload.subarray(0, 12));
  decipher.setAuthTag(payload.subarray(12, 28));
  return JSON.parse(Buffer.concat([decipher.update(payload.subarray(28)), decipher.final()]).toString("utf8"));
}

db.pragma(
  "journal_mode = WAL"
);

db.pragma(
  "foreign_keys = ON"
);

db.exec(`
  CREATE TABLE IF NOT EXISTS admin_audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor TEXT NOT NULL,
    method TEXT NOT NULL,
    route TEXT NOT NULL,
    status_code INTEGER NOT NULL,
    ip TEXT,
    created_at TEXT NOT NULL
  );

  CREATE INDEX IF NOT EXISTS idx_admin_audit_log_created_at
    ON admin_audit_log(created_at DESC);
`);


// ============================================================
// TABELA DE EVENTOS
//
// Cada evento possui:
// - seus prÃ³prios planos
// - uma Ãºnica MikroTik ativa
// - seus prÃ³prios pedidos
// ============================================================

db.exec(`
CREATE TABLE IF NOT EXISTS events (

  id INTEGER PRIMARY KEY AUTOINCREMENT,

  event_key TEXT UNIQUE NOT NULL,

  name TEXT NOT NULL,

  establishment_name TEXT,

  location TEXT,

  description TEXT,

  timezone TEXT NOT NULL DEFAULT 'America/Sao_Paulo',

  status TEXT NOT NULL DEFAULT 'active',

  created_at TEXT NOT NULL,

  updated_at TEXT NOT NULL

);
`);


// ============================================================
// TABELA DE MIKROTIKS
//
// Cada MikroTik pertence a um evento.
// REGRA OPERACIONAL: somente uma MikroTik ativa por evento.
//
// A coluna role Ã© mantida apenas por compatibilidade com o banco
// existente, mas novas MikroTiks sÃ£o sempre 'primary'.
// ============================================================

db.exec(`
CREATE TABLE IF NOT EXISTS routers (

  id INTEGER PRIMARY KEY AUTOINCREMENT,

  event_id INTEGER NOT NULL,

  router_key TEXT UNIQUE NOT NULL,

  name TEXT NOT NULL,

  identity TEXT,

  model TEXT,

  routeros_version TEXT,

  role TEXT NOT NULL DEFAULT 'primary',

  wan_interface TEXT,

  client_interface TEXT,

  wan_type TEXT,

  failover_enabled INTEGER NOT NULL DEFAULT 0,

  secondary_wan_interface TEXT,

  secondary_wan_type TEXT,

  wan_pppoe_user TEXT,
  wan_pppoe_password TEXT,
  wan_static_address TEXT,
  wan_static_gateway TEXT,

  secondary_wan_pppoe_user TEXT,
  secondary_wan_pppoe_password TEXT,
  secondary_wan_static_address TEXT,
  secondary_wan_static_gateway TEXT,

  client_network TEXT,

  client_gateway TEXT,

  hotspot_dns_name TEXT DEFAULT '',

  hotspot_ssl_certificate TEXT DEFAULT '',

  dhcp_pool_start TEXT,

  dhcp_pool_end TEXT,

  token TEXT,

  status TEXT NOT NULL DEFAULT 'active',

  created_at TEXT NOT NULL,

  updated_at TEXT NOT NULL,

  FOREIGN KEY(event_id)
    REFERENCES events(id)

);
`);




// ============================================================
// MIGRAÃ‡Ã•ES DA TABELA ROUTERS - FAILOVER
// ============================================================

function ensureRouterColumn(
  columnName,
  definition
){

  const columns =
    db.prepare(
      "PRAGMA table_info(routers)"
    ).all();

  const exists =
    columns.some(
      column =>
        column.name ===
        columnName
    );

  if(!exists){

    db.exec(
      `ALTER TABLE routers ADD COLUMN ${columnName} ${definition}`
    );

    console.log(
      "Tabela routers atualizada:",
      columnName
    );

  }

}


ensureRouterColumn(
  "failover_enabled",
  "INTEGER NOT NULL DEFAULT 0"
);

ensureRouterColumn(
  "secondary_wan_interface",
  "TEXT"
);

ensureRouterColumn(
  "secondary_wan_type",
  "TEXT"
);


ensureRouterColumn(
  "wan_pppoe_user",
  "TEXT"
);

ensureRouterColumn(
  "wan_pppoe_password",
  "TEXT"
);

ensureRouterColumn(
  "wan_static_address",
  "TEXT"
);

ensureRouterColumn(
  "wan_static_gateway",
  "TEXT"
);

ensureRouterColumn(
  "secondary_wan_pppoe_user",
  "TEXT"
);

ensureRouterColumn(
  "secondary_wan_pppoe_password",
  "TEXT"
);

ensureRouterColumn(
  "secondary_wan_static_address",
  "TEXT"
);

ensureRouterColumn(
  "secondary_wan_static_gateway",
  "TEXT"
);


// ============================================================
// TABELA DE PORTAS / INTERFACES DAS MIKROTIKS
//
// Cada porta fÃ­sica passa a ter uma funÃ§Ã£o prÃ³pria.
//
// FunÃ§Ãµes usadas:
//
// wan_primary
//     Link principal de Internet.
//
// wan_secondary
//     Link secundÃ¡rio para failover.
//
// hotspot
//     SaÃ­da para clientes / APs. VÃ¡rias portas podem pertencer
//     Ã  mesma bridge de clientes.
//
// free
//     Porta livre, sem configuraÃ§Ã£o automÃ¡tica.
//
// Valores antigos 'interlink' e 'uplink' sÃ£o migrados para 'free'.
// A tabela Ã© separada de routers para nÃ£o limitar o projeto
// a equipamentos de 5 portas.
// ============================================================

db.exec(`
CREATE TABLE IF NOT EXISTS router_ports (

  id INTEGER PRIMARY KEY AUTOINCREMENT,

  router_id INTEGER NOT NULL,

  interface_name TEXT NOT NULL,

  port_number INTEGER,

  function TEXT NOT NULL DEFAULT 'free',

  bridge_name TEXT,

  enabled INTEGER NOT NULL DEFAULT 1,

  notes TEXT,

  created_at TEXT NOT NULL,

  updated_at TEXT NOT NULL,

  FOREIGN KEY(router_id)
    REFERENCES routers(id)
    ON DELETE CASCADE,

  UNIQUE(
    router_id,
    interface_name
  )

);
`);


// ============================================================
// TABELA DE LIBERACOES POR MIKROTIK
//
// O pagamento pertence ao EVENTO.
// Esta tabela funciona como FILA/ESTADO da MikroTik Ãºnica do evento.
//
// Estados principais:
// pending  -> aguardando aplicaÃ§Ã£o pela MikroTik
// active   -> acesso aplicado
// expired  -> acesso encerrado
//
// A tabela Ã© mantida porque as rotas /pending, /ack e /expire-ack
// usam estes registros para controlar ALLOW e EXPIRE.
// ============================================================

db.exec(`
CREATE TABLE IF NOT EXISTS router_access_grants (

  id INTEGER PRIMARY KEY AUTOINCREMENT,

  order_id INTEGER NOT NULL,

  event_id INTEGER NOT NULL,

  router_id INTEGER NOT NULL,

  client_id TEXT,

  mac TEXT,

  ip TEXT,

  status TEXT NOT NULL DEFAULT 'pending',

  requested_at TEXT NOT NULL,

  applied_at TEXT,

  last_seen_at TEXT,

  expired_at TEXT,

  updated_at TEXT NOT NULL,

  FOREIGN KEY(order_id)
    REFERENCES orders(id)
    ON DELETE CASCADE,

  FOREIGN KEY(event_id)
    REFERENCES events(id)
    ON DELETE CASCADE,

  FOREIGN KEY(router_id)
    REFERENCES routers(id)
    ON DELETE CASCADE,

  UNIQUE(
    order_id,
    router_id
  )

);
`);


// ============================================================
// TABELA DE PLANOS POR EVENTO
//
// Futuramente o portal buscarÃ¡ os planos diretamente desta
// tabela.
//
// Por enquanto o objeto PLANS continua existindo para manter
// compatibilidade total com o sistema atual.
// ============================================================

db.exec(`
CREATE TABLE IF NOT EXISTS event_plans (

  id INTEGER PRIMARY KEY AUTOINCREMENT,

  event_id INTEGER NOT NULL,

  plan_key TEXT NOT NULL,

  name TEXT NOT NULL,

  amount REAL NOT NULL,

  minutes INTEGER NOT NULL,

  rate_limit TEXT NOT NULL,

  mikrotik_profile TEXT NOT NULL,

  description TEXT,

  sort_order INTEGER NOT NULL DEFAULT 0,

  active INTEGER NOT NULL DEFAULT 1,

  created_at TEXT NOT NULL,

  updated_at TEXT NOT NULL,

  FOREIGN KEY(event_id)
    REFERENCES events(id),

  UNIQUE(
    event_id,
    plan_key
  )

);
`);


// ============================================================
// TABELA DE PEDIDOS / PAGAMENTOS
// ============================================================

db.exec(`
CREATE TABLE IF NOT EXISTS orders (

  id INTEGER PRIMARY KEY AUTOINCREMENT,

  external_ref TEXT UNIQUE NOT NULL,

  event_id INTEGER,

  router_id INTEGER,

  client_id TEXT,

  plan_id TEXT NOT NULL,

  amount REAL NOT NULL,

  minutes INTEGER NOT NULL,

  rate_limit TEXT NOT NULL,

  mac TEXT,

  original_mac TEXT,

  effective_mac TEXT,

  ip TEXT,

  payer_email TEXT,

  mp_payment_id TEXT,

  mp_order_id TEXT,

  status TEXT NOT NULL DEFAULT 'pending',

  qr_code TEXT,

  qr_code_base64 TEXT,

  created_at TEXT NOT NULL,

  approved_at TEXT,

  access_json TEXT,

  temp_status TEXT,

  temp_requested_at TEXT,

  temp_granted_at TEXT,

  temp_expires_at TEXT,

  portal_last_seen_at TEXT,

  access_expires_at TEXT,

  access_expired_at TEXT

);
`);

// Campanhas de anÃºncios exibidas no portal Wi-Fi.
// As imagens ficam no diretÃ³rio de dados; a tabela guarda apenas metadados.
db.exec(`
CREATE TABLE IF NOT EXISTS ad_campaigns (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id INTEGER,
  name TEXT NOT NULL,
  image_path TEXT NOT NULL,
  target_url TEXT,
  starts_at TEXT,
  ends_at TEXT,
  active INTEGER NOT NULL DEFAULT 1,
  impressions INTEGER NOT NULL DEFAULT 0,
  clicks INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY(event_id) REFERENCES events(id)
);
CREATE INDEX IF NOT EXISTS idx_ad_campaigns_event_active
  ON ad_campaigns(event_id, active, starts_at, ends_at);
`);

// Revendedores e regras de comissÃ£o por evento.
db.exec(`
CREATE TABLE IF NOT EXISTS resellers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id INTEGER,
  name TEXT NOT NULL,
  phone TEXT,
  email TEXT,
  commission_percent REAL NOT NULL DEFAULT 0,
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY(event_id) REFERENCES events(id)
);
CREATE INDEX IF NOT EXISTS idx_resellers_event_active ON resellers(event_id, active);
`);

db.exec(`
CREATE TABLE IF NOT EXISTS pppoe_subscribers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id INTEGER,
  login TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  phone TEXT,
  plan_name TEXT NOT NULL,
  monthly_amount REAL NOT NULL DEFAULT 0,
  due_day INTEGER NOT NULL DEFAULT 10,
  status TEXT NOT NULL DEFAULT 'active',
  last_payment_at TEXT,
  next_due_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY(event_id) REFERENCES events(id)
);
CREATE INDEX IF NOT EXISTS idx_pppoe_subscribers_event_status ON pppoe_subscribers(event_id,status);
`);

db.exec(`
CREATE TABLE IF NOT EXISTS payment_terminals (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id INTEGER,
  name TEXT NOT NULL,
  provider TEXT NOT NULL DEFAULT 'manual',
  serial_number TEXT,
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY(event_id) REFERENCES events(id)
);
CREATE TABLE IF NOT EXISTS terminal_transactions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  terminal_id INTEGER NOT NULL,
  reseller_id INTEGER,
  order_id INTEGER,
  amount REAL NOT NULL DEFAULT 0,
  method TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'approved',
  external_ref TEXT,
  created_at TEXT NOT NULL,
  refunded_at TEXT,
  FOREIGN KEY(terminal_id) REFERENCES payment_terminals(id)
);
CREATE INDEX IF NOT EXISTS idx_terminal_transactions_status ON terminal_transactions(status,created_at);
`);

db.exec(`
CREATE TABLE IF NOT EXISTS panel_users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  display_name TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'reseller',
  reseller_id INTEGER,
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY(reseller_id) REFERENCES resellers(id)
);
CREATE INDEX IF NOT EXISTS idx_panel_users_active ON panel_users(active,role);
`);

// Vouchers sao emitidos em lotes por evento e consumidos uma unica vez.
db.exec(`
CREATE TABLE IF NOT EXISTS voucher_batches (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id INTEGER NOT NULL,
  first_number INTEGER NOT NULL,
  last_number INTEGER NOT NULL,
  plan_id TEXT NOT NULL,
  plan_name TEXT NOT NULL,
  minutes INTEGER NOT NULL,
  rate_limit TEXT NOT NULL,
  mikrotik_profile TEXT NOT NULL,
  amount REAL NOT NULL DEFAULT 0,
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  deleted_at TEXT,
  FOREIGN KEY(event_id) REFERENCES events(id)
);
CREATE TABLE IF NOT EXISTS vouchers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  batch_id INTEGER NOT NULL,
  event_id INTEGER NOT NULL,
  serial_number INTEGER NOT NULL,
  code_hash TEXT NOT NULL UNIQUE,
  code_last4 TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'unused',
  created_at TEXT NOT NULL,
  redeemed_at TEXT,
  redeemed_order_id INTEGER,
  redeemed_client_id TEXT,
  redeemed_mac TEXT,
  redeemed_ip TEXT,
  FOREIGN KEY(batch_id) REFERENCES voucher_batches(id),
  FOREIGN KEY(event_id) REFERENCES events(id),
  FOREIGN KEY(redeemed_order_id) REFERENCES orders(id)
);
CREATE INDEX IF NOT EXISTS idx_vouchers_batch ON vouchers(batch_id, serial_number);
CREATE INDEX IF NOT EXISTS idx_vouchers_status ON vouchers(event_id, status);
`);

if(!db.prepare("PRAGMA table_info(voucher_batches)").all().some(column => column.name === "amount")){
  db.exec("ALTER TABLE voucher_batches ADD COLUMN amount REAL NOT NULL DEFAULT 0");
}
if(!db.prepare("PRAGMA table_info(voucher_batches)").all().some(column => column.name === "deleted_at")){
  db.exec("ALTER TABLE voucher_batches ADD COLUMN deleted_at TEXT");
}
if(!db.prepare("PRAGMA table_info(voucher_batches)").all().some(column => column.name === "print_data_encrypted")){
  db.exec("ALTER TABLE voucher_batches ADD COLUMN print_data_encrypted TEXT");
}


// ============================================================
// DADOS CADASTRAIS DOS CLIENTES DO PORTAL
//
// O CLIENT_ID Ã© a identidade principal do navegador.
// Nome / telefone / e-mail pertencem ao cliente, nÃ£o ao MAC.
// Assim, se o celular trocar o MAC privado, os dados continuam
// associados ao mesmo cliente.
// ============================================================

db.exec(`
CREATE TABLE IF NOT EXISTS customers (

  client_id TEXT PRIMARY KEY,

  name TEXT,

  phone TEXT,

  email TEXT,

  created_at TEXT NOT NULL,

  updated_at TEXT NOT NULL,

  last_seen_at TEXT NOT NULL

);
`);

// ============================================================
// V14.1 - FUNIL DE CONVERSAO
//
// Registra a jornada do cliente sem alterar o fluxo atual
// de PIX, cortesia ou liberacao da MikroTik.
//
// Nesta primeira etapa criamos somente a infraestrutura
// persistente do funil. As rotas e pontos de coleta serao
// ligados nos proximos blocos.
// ============================================================

db.exec(`
CREATE TABLE IF NOT EXISTS funnel_events (

  id INTEGER PRIMARY KEY AUTOINCREMENT,

  event_id INTEGER,
  router_id INTEGER,

  client_id TEXT,

  mac TEXT,
  ip TEXT,

  order_id INTEGER,
  order_ref TEXT,

  step TEXT NOT NULL,

  plan_id TEXT,

  source TEXT NOT NULL DEFAULT 'backend',

  metadata_json TEXT,

  created_at TEXT NOT NULL,

  FOREIGN KEY(event_id)
    REFERENCES events(id),

  FOREIGN KEY(router_id)
    REFERENCES routers(id),

  FOREIGN KEY(order_id)
    REFERENCES orders(id)
    ON DELETE SET NULL

);
`);


// ============================================================
// INDICES DO FUNIL
// ============================================================

db.exec(`

CREATE INDEX IF NOT EXISTS idx_funnel_event_created
ON funnel_events(
  event_id,
  created_at
);

CREATE INDEX IF NOT EXISTS idx_funnel_client
ON funnel_events(
  client_id,
  created_at
);

CREATE INDEX IF NOT EXISTS idx_funnel_step
ON funnel_events(
  event_id,
  step,
  created_at
);

CREATE INDEX IF NOT EXISTS idx_funnel_order
ON funnel_events(
  order_id,
  created_at
);

CREATE INDEX IF NOT EXISTS idx_funnel_router
ON funnel_events(
  router_id,
  created_at
);

`);


// ============================================================
// V15 - ETAPAS OFICIAIS DO FUNIL COMPLETO
// ============================================================
//
//  1 HOTSPOT_DETECTED
//  2 PORTAL_OPENED
//  3 REGISTRATION_STARTED
//  4 REGISTRATION_COMPLETED
//  5 PLAN_SELECTED
//  6 PIX_GENERATED
//  7 PIX_COPIED
//  8 TEMPORARY_ACCESS_REQUESTED
//  9 TEMPORARY_ACCESS_APPLIED
// 10 INTERNET_CONFIRMED
// 11 PAYMENT_APPROVED
// 12 PAID_PLAN_APPLIED
// 13 NAVIGATION_AFTER_PAYMENT
// 14 ACCESS_EXPIRED
//
// TEMPORARY_ACCESS_FAILED e um evento auxiliar de diagnostico e
// nao entra na contagem das 14 etapas principais.
// ============================================================

const FUNNEL_STEPS =
  new Set([
    "HOTSPOT_DETECTED",
    "PORTAL_OPENED",
    "REGISTRATION_STARTED",
    "REGISTRATION_COMPLETED",
    "VOUCHER_REDEEMED",
    "PLAN_SELECTED",
    "PIX_GENERATED",
    "PIX_COPIED",
    "TEMPORARY_ACCESS_REQUESTED",
    "TEMPORARY_ACCESS_APPLIED",
    "INTERNET_CONFIRMED",
    "PAYMENT_APPROVED",
    "PAID_PLAN_APPLIED",
    "NAVIGATION_AFTER_PAYMENT",
    "ACCESS_EXPIRED",
    "TEMPORARY_ACCESS_FAILED"
  ]);


// ============================================================
// COMPATIBILIDADE COM NOMES USADOS NAS PRIMEIRAS VERSOES DO FUNIL
// ============================================================

const FUNNEL_STEP_ALIASES = {
  CUSTOMER_REGISTERED:
    "REGISTRATION_COMPLETED",
  PIX_COPY_CLICKED:
    "PIX_COPIED",
  TEMP_ACCESS_REQUESTED:
    "TEMPORARY_ACCESS_REQUESTED",
  TEMP_ACCESS_GRANTED:
    "TEMPORARY_ACCESS_APPLIED",
  TEMP_ACCESS_FAILED:
    "TEMPORARY_ACCESS_FAILED",
  ACCESS_APPLIED:
    "PAID_PLAN_APPLIED"
};


function normalizeFunnelStep(value){

  const raw =
    String(value || "")
      .trim()
      .toUpperCase();

  return (
    FUNNEL_STEP_ALIASES[raw]
    ||
    raw
  );
}



// ============================================================
// LOG DE INICIALIZACAO DO FUNIL
// ============================================================

console.log(
  "FUNIL V15:",
  db.prepare(
    "SELECT COUNT(*) AS total FROM funnel_events"
  ).get().total,
  "eventos registrados"
);



// ============================================================
// COMANDOS ADMINISTRATIVOS PARA A MIKROTIK
//
// BYPASS
//     LiberaÃ§Ã£o administrativa permanente.
//
// UNBYPASS
//     Remove somente a liberaÃ§Ã£o administrativa.
//
// BLOCK_NOW
//     Bloqueio imediato.
//
// TEMP_ADMIN
//     LiberaÃ§Ã£o administrativa temporÃ¡ria.
//
// Como existe somente uma MikroTik ativa por evento, estes
// comandos continuam usando a fila administrativa atual.
// ============================================================

db.exec(`
CREATE TABLE IF NOT EXISTS admin_commands (

  id INTEGER PRIMARY KEY AUTOINCREMENT,

  command_ref TEXT UNIQUE NOT NULL,

  command_type TEXT NOT NULL,

  mac TEXT NOT NULL,

  device_name TEXT,

  status TEXT NOT NULL DEFAULT 'pending',

  created_at TEXT NOT NULL,

  applied_at TEXT

);
`);


// ============================================================
// MIGRAÃ‡Ã•ES DA TABELA ORDERS
// ============================================================

function ensureColumn(
  columnName,
  definition
) {

  const columns =
    db.prepare(
      "PRAGMA table_info(orders)"
    ).all();


  const exists =
    columns.some(
      column =>
        column.name ===
        columnName
    );


  if(
    !exists
  ) {

    db.exec(
      `ALTER TABLE orders ADD COLUMN ${columnName} ${definition}`
    );


    console.log(
      "Banco atualizado:",
      columnName
    );

  }

}


// ============================================================
// COLUNAS DE EVENTO / MIKROTIK
// ============================================================

ensureColumn(
  "event_id",
  "INTEGER"
);

ensureColumn(
  "router_id",
  "INTEGER"
);


// ============================================================
// COLUNAS EXISTENTES
// ============================================================

ensureColumn(
  "client_id",
  "TEXT"
);

ensureColumn(
  "mp_order_id",
  "TEXT"
);

ensureColumn("reseller_id", "INTEGER");
ensureColumn("commission_percent", "REAL NOT NULL DEFAULT 0");
ensureColumn("commission_amount", "REAL NOT NULL DEFAULT 0");

ensureColumn(
  "original_mac",
  "TEXT"
);

ensureColumn(
  "effective_mac",
  "TEXT"
);

ensureColumn(
  "temp_status",
  "TEXT"
);

ensureColumn(
  "temp_requested_at",
  "TEXT"
);

ensureColumn(
  "temp_granted_at",
  "TEXT"
);

ensureColumn(
  "temp_expires_at",
  "TEXT"
);


// ============================================================
// PRESENÃ‡A DO PORTAL / PIX ABERTO
// ============================================================

ensureColumn(
  "portal_last_seen_at",
  "TEXT"
);


// ============================================================
// TEMPO CORRIDO DOS PLANOS PIX
// ============================================================

ensureColumn(
  "access_expires_at",
  "TEXT"
);

ensureColumn(
  "access_expired_at",
  "TEXT"
);

ensureColumn("payment_method", "TEXT NOT NULL DEFAULT 'pix'");
ensureColumn("voucher_id", "INTEGER");
ensureColumn("voucher_batch_id", "INTEGER");
ensureColumn("voucher_serial", "INTEGER");


// ============================================================
// ÃNDICES
// ============================================================

db.exec(`

CREATE INDEX IF NOT EXISTS idx_orders_client_id
ON orders(client_id);

CREATE INDEX IF NOT EXISTS idx_orders_mac
ON orders(mac);

CREATE INDEX IF NOT EXISTS idx_orders_external_ref
ON orders(external_ref);

CREATE INDEX IF NOT EXISTS idx_orders_access_expires_at
ON orders(access_expires_at);

CREATE INDEX IF NOT EXISTS idx_orders_event_id
ON orders(event_id);

CREATE INDEX IF NOT EXISTS idx_orders_router_id
ON orders(router_id);


CREATE INDEX IF NOT EXISTS idx_customers_email
ON customers(email);

CREATE INDEX IF NOT EXISTS idx_customers_phone
ON customers(phone);


CREATE INDEX IF NOT EXISTS idx_routers_event_id
ON routers(event_id);

CREATE INDEX IF NOT EXISTS idx_routers_router_key
ON routers(router_key);

CREATE INDEX IF NOT EXISTS idx_router_ports_router_id
ON router_ports(router_id);

CREATE INDEX IF NOT EXISTS idx_router_ports_function
ON router_ports(function);




CREATE INDEX IF NOT EXISTS idx_router_access_grants_router
ON router_access_grants(router_id);

CREATE INDEX IF NOT EXISTS idx_router_access_grants_event
ON router_access_grants(event_id);

CREATE INDEX IF NOT EXISTS idx_router_access_grants_order
ON router_access_grants(order_id);

CREATE INDEX IF NOT EXISTS idx_router_access_grants_status
ON router_access_grants(status);

CREATE INDEX IF NOT EXISTS idx_router_access_grants_client
ON router_access_grants(client_id);


CREATE INDEX IF NOT EXISTS idx_event_plans_event_id
ON event_plans(event_id);

CREATE INDEX IF NOT EXISTS idx_event_plans_active
ON event_plans(active);

`);


// ============================================================
// PLANOS DE ACESSO ATUAIS
//
// IMPORTANTE:
//
// Estes planos continuam exatamente como estavam.
//
// As rotas atuais ainda poderÃ£o usar PLANS normalmente.
// Portanto nÃ£o estamos alterando o funcionamento do portal
// ou do Mercado Pago nesta etapa.
// ============================================================

const PLANS = {

  "1h": {

    id: "1h",

    name: "1 hora",

    amount: 5.00,

    minutes: 60,

    rate: "10M/10M",

    mikrotikProfile:
      "PLANO-1H"

  },


  "4h": {

    id: "4h",

    name: "4 horas",

    amount: 10.00,

    minutes: 240,

    rate: "10M/10M",

    mikrotikProfile:
      "PLANO-4H"

  },


  "12h": {

    id: "12h",

    name: "12 horas",

    amount: 15.00,

    minutes: 720,

    rate: "15M/15M",

    mikrotikProfile:
      "PLANO-12H"

  },


  "24h": {

    id: "24h",

    name: "24 horas",

    amount: 20.00,

    minutes: 1440,

    rate: "20M/20M",

    mikrotikProfile:
      "PLANO-24H"

  }

};


// ============================================================
// CRIAR / LOCALIZAR EVENTO PADRÃƒO
//
// Este evento representa a instalaÃ§Ã£o que jÃ¡ estÃ¡ funcionando
// atualmente.
//
// Ele sÃ³ serÃ¡ criado se ainda nÃ£o existir.
// ============================================================

function ensureDefaultEvent() {

  const existing =
    db.prepare(`

      SELECT *

      FROM events

      WHERE event_key=?

      LIMIT 1

    `).get(
      "principal"
    );


  if(
    existing
  ) {

    return existing;

  }


  const now =
    new Date().toISOString();


  const result =
    db.prepare(`

      INSERT INTO events (

        event_key,

        name,

        establishment_name,

        location,

        description,

        timezone,

        status,

        created_at,

        updated_at

      )

      VALUES (
        ?, ?, ?, ?, ?, ?, ?, ?, ?
      )

    `).run(

      "principal",

      "Wi-Fi Pago Principal",

      "Wi-Fi Pago",

      "",

      "InstalaÃ§Ã£o principal do sistema",

      "America/Sao_Paulo",

      "active",

      now,

      now

    );


  return db.prepare(`

    SELECT *

    FROM events

    WHERE id=?

    LIMIT 1

  `).get(
    Number(
      result.lastInsertRowid
    )
  );

}


// ============================================================
// EVENTO PADRÃƒO
// ============================================================

const DEFAULT_EVENT =
  ensureDefaultEvent();


// ============================================================
// CRIAR / LOCALIZAR MIKROTIK PADRÃƒO
//
// Representa a MikroTik Ãºnica do evento padrÃ£o.
// ============================================================

function ensureDefaultRouter() {

  const existing =
    db.prepare(`

      SELECT *

      FROM routers

      WHERE router_key=?

      LIMIT 1

    `).get(
      "principal"
    );


  if(
    existing
  ) {

    return existing;

  }


  const now =
    new Date().toISOString();


  const result =
    db.prepare(`

      INSERT INTO routers (

        event_id,

        router_key,

        name,

        identity,

        model,

        routeros_version,

        role,

        token,

        status,

        created_at,

        updated_at

      )

      VALUES (
        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
      )

    `).run(

      DEFAULT_EVENT.id,

      "principal",

      "MikroTik Principal",

      "RB750Gr3-WIFI-PAGO",

      "RB750Gr3",

      "6",

      "primary",

      process.env.MIKROTIK_POLL_TOKEN || "",

      "active",

      now,

      now

    );


  return db.prepare(`

    SELECT *

    FROM routers

    WHERE id=?

    LIMIT 1

  `).get(
    Number(
      result.lastInsertRowid
    )
  );

}


// ============================================================
// MIKROTIK PADRÃƒO
// ============================================================

const DEFAULT_ROUTER =
  ensureDefaultRouter();


// ============================================================
// TOPOLOGIA - DESCOBRIR QUANTIDADE PADRÃƒO DE PORTAS
//
// Nesta primeira versÃ£o reconhecemos os modelos mais comuns.
// Modelos desconhecidos recebem 5 portas inicialmente e depois
// poderÃ£o ser ajustados pela interface administrativa.
// ============================================================

function routerDefaultPortCount(model) {

  const normalized =
    String(
      model || ""
    )
      .trim()
      .toUpperCase();


  const knownModels = {

    "RB750GR3":
      5,

    "HEX":
      5,

    "RB760IGS":
      5,

    "HEX S":
      5,

    "RB5009UG+S+IN":
      8,

    "RB4011IGS+RM":
      10

  };


  return (
    knownModels[normalized] ||
    5
  );

}


// ============================================================
// TOPOLOGIA - CRIAR PORTAS INICIAIS DE UMA MIKROTIK
//
// IMPORTANTE:
// NÃ£o altera a configuraÃ§Ã£o fÃ­sica da MikroTik.
//
// Apenas cria no banco a representaÃ§Ã£o das interfaces para que
// o painel e o futuro gerador de script possam trabalhar.
//
// Para equipamentos jÃ¡ existentes:
//
// - wan_interface vira funÃ§Ã£o "wan"
// - client_interface vira funÃ§Ã£o "hotspot"
// - demais portas ficam "free"
// ============================================================

function ensureRouterPorts(router) {

  if(
    !router
    ||
    !router.id
  ) {

    return;
  }


  const existingCount =
    db.prepare(`

      SELECT COUNT(*) AS total

      FROM router_ports

      WHERE router_id=?

    `).get(
      router.id
    )?.total || 0;


  if(
    existingCount > 0
  ) {

    return;
  }


  const totalPorts =
    routerDefaultPortCount(
      router.model
    );


  const now =
    new Date().toISOString();


  const insertPort =
    db.prepare(`

      INSERT OR IGNORE INTO router_ports (

        router_id,
        interface_name,
        port_number,
        function,
        bridge_name,
        enabled,
        notes,
        created_at,
        updated_at

      )

      VALUES (
        ?, ?, ?, ?, ?, ?, ?, ?, ?
      )

    `);


  const transaction =
    db.transaction(
      () => {

        for(
          let portNumber = 1;
          portNumber <= totalPorts;
          portNumber++
        ) {

          const interfaceName =
            `ether${portNumber}`;


          let portFunction =
            "free";


          let bridgeName =
            null;


          if(
            router.wan_interface
            &&
            interfaceName ===
              router.wan_interface
          ) {

            portFunction =
              "wan_primary";

          }


          if(
            router.secondary_wan_interface
            &&
            interfaceName ===
              router.secondary_wan_interface
          ) {

            portFunction =
              "wan_secondary";

          }


          if(
            router.client_interface
            &&
            interfaceName ===
              router.client_interface
          ) {

            portFunction =
              "hotspot";

            bridgeName =
              "bridge-clientes";

          }


          insertPort.run(

            router.id,

            interfaceName,

            portNumber,

            portFunction,

            bridgeName,

            1,

            "",

            now,

            now

          );
        }

      }
    );


  transaction();
}


// ============================================================
// TOPOLOGIA - MIGRAR MIKROTIKS JÃ CADASTRADAS
//
// Isso mantÃ©m compatibilidade com o banco atual.
//
// Nenhuma MikroTik existente Ã© apagada ou recriada.
// Apenas criamos os registros de portas que ainda nÃ£o existem.
// ============================================================

function ensureExistingRouterPorts() {

  const routers =
    db.prepare(`

      SELECT *

      FROM routers

      ORDER BY id ASC

    `).all();


  for(
    const router
    of routers
  ) {

    ensureRouterPorts(
      router
    );

  }

}


ensureExistingRouterPorts();


// ============================================================
// MIGRAÃ‡ÃƒO - REMOVER FUNÃ‡Ã•ES ANTIGAS DE INTERLIGAÃ‡ÃƒO
//
// O projeto agora usa somente:
// wan_primary / wan_secondary / hotspot / free
//
// NÃ£o apagamos portas nem MikroTiks. Apenas transformamos
// interlink/uplink antigos em portas livres.
// ============================================================


db.prepare(`

  UPDATE router_ports

  SET
    function='wan_primary',
    updated_at=?

  WHERE function='wan'

`).run(
  new Date().toISOString()
);


db.prepare(`

  UPDATE router_ports

  SET
    function='free',
    bridge_name=NULL,
    updated_at=?

  WHERE function IN (
    'interlink',
    'uplink'
  )

`).run(
  new Date().toISOString()
);


// ============================================================
// REGRA - UMA MIKROTIK ATIVA POR EVENTO
//
// Para bancos que jÃ¡ possuÃ­am mÃºltiplas MKs no mesmo evento,
// preservamos UMA:
// 1) primeiro role='primary'
// 2) depois menor id
//
// As demais ficam status='inactive'.
// Nada Ã© apagado do banco.
// ============================================================

function enforceSingleActiveRouterPerEvent() {

  const events =
    db.prepare(`

      SELECT id

      FROM events

      ORDER BY id ASC

    `).all();


  const deactivate =
    db.prepare(`

      UPDATE routers

      SET
        status='inactive',
        updated_at=?

      WHERE
        event_id=?
        AND id<>?
        AND status='active'

    `);


  const transaction =
    db.transaction(
      () => {

        const now =
          new Date().toISOString();

        for(
          const event
          of events
        ) {

          const keep =
            db.prepare(`

              SELECT *

              FROM routers

              WHERE
                event_id=?
                AND status='active'

              ORDER BY
                CASE
                  WHEN role='primary' THEN 0
                  ELSE 1
                END,
                id ASC

              LIMIT 1

            `).get(
              event.id
            );

          if(
            keep
          ) {

            deactivate.run(
              now,
              event.id,
              keep.id
            );

          }

        }

      }
    );


  transaction();

}


enforceSingleActiveRouterPerEvent();


// ============================================================
// COPIAR OS 4 PLANOS ATUAIS PARA O EVENTO PADRÃƒO
//
// INSERT OR IGNORE impede duplicaÃ§Ã£o apÃ³s reiniciar/deployar
// novamente.
// ============================================================

function ensureDefaultEventPlans() {

  const insert =
    db.prepare(`

      INSERT OR IGNORE INTO event_plans (

        event_id,

        plan_key,

        name,

        amount,

        minutes,

        rate_limit,

        mikrotik_profile,

        description,

        sort_order,

        active,

        created_at,

        updated_at

      )

      VALUES (
        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
      )

    `);


  const now =
    new Date().toISOString();


  let sortOrder =
    1;


  for(
    const plan
    of Object.values(
      PLANS
    )
  ) {

    insert.run(

      DEFAULT_EVENT.id,

      plan.id,

      plan.name,

      plan.amount,

      plan.minutes,

      plan.rate,

      plan.mikrotikProfile,

      plan.name,

      sortOrder,

      1,

      now,

      now

    );


    sortOrder++;

  }

}


ensureDefaultEventPlans();


// ============================================================
// ASSOCIAR PEDIDOS ANTIGOS AO EVENTO PADRÃƒO
//
// NÃ£o alteramos nenhum valor, pagamento ou referÃªncia.
//
// Apenas preenchemos event_id e router_id nos registros que
// ainda nÃ£o possuem essas informaÃ§Ãµes.
// ============================================================

db.prepare(`

  UPDATE orders

  SET event_id=?

  WHERE event_id IS NULL

`).run(
  DEFAULT_EVENT.id
);


db.prepare(`

  UPDATE orders

  SET router_id=?

  WHERE router_id IS NULL

`).run(
  DEFAULT_ROUTER.id
);


// ============================================================
// FILA MIKROTIK - CRIAR GRANTS PARA PEDIDOS EXISTENTES
//
// Esta migraÃ§Ã£o NÃƒO altera o direito de acesso dos pedidos.
//
// Para pedidos que jÃ¡ possuem router_id, criamos o registro
// correspondente em router_access_grants.
//
// O status Ã© inferido apenas para preservar o estado atual:
// - approved_pending_router => pending
// - approved               => active
// ============================================================

function ensureExistingRouterAccessGrants() {

  const rows =
    db.prepare(`

      SELECT
        id,
        event_id,
        router_id,
        client_id,
        mac,
        effective_mac,
        ip,
        status,
        approved_at,
        created_at

      FROM orders

      WHERE
        event_id IS NOT NULL
        AND
        router_id IS NOT NULL
        AND
        status IN (
          'approved_pending_router',
          'approved'
        )

      ORDER BY id ASC

    `).all();


  const insert =
    db.prepare(`

      INSERT OR IGNORE INTO router_access_grants (

        order_id,
        event_id,
        router_id,
        client_id,
        mac,
        ip,
        status,
        requested_at,
        applied_at,
        last_seen_at,
        expired_at,
        updated_at

      )

      VALUES (
        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
      )

    `);


  const now =
    new Date().toISOString();


  const transaction =
    db.transaction(
      () => {

        for(
          const row
          of rows
        ) {

          const grantStatus =
            row.status ===
            "approved"
              ? "active"
              : "pending";


          const requestedAt =
            row.approved_at
            ||
            row.created_at
            ||
            now;


          insert.run(

            row.id,

            row.event_id,

            row.router_id,

            row.client_id || null,

            row.effective_mac
            ||
            row.mac
            ||
            null,

            row.ip || null,

            grantStatus,

            requestedAt,

            grantStatus ===
            "active"
              ? requestedAt
              : null,

            grantStatus ===
            "active"
              ? requestedAt
              : null,

            null,

            now

          );
        }

      }
    );


  transaction();

}


ensureExistingRouterAccessGrants();


// ============================================================
// CLIENTES ANTIGOS - APROVEITAR E-MAIL JÃ EXISTENTE
//
// Pedidos antigos nÃ£o possuem nome/telefone, entÃ£o nÃ£o inventamos.
// Apenas criamos o cadastro pelo CLIENT_ID com o e-mail disponÃ­vel.
// Novos acessos completarÃ£o nome e telefone automaticamente.
// ============================================================

try {

  const oldClients =
    db.prepare(`

      SELECT
        client_id,
        payer_email,
        MIN(created_at) AS first_seen,
        MAX(created_at) AS last_seen

      FROM orders

      WHERE
        client_id IS NOT NULL
        AND TRIM(client_id) <> ''

      GROUP BY client_id

    `).all();


  const insertOldCustomer =
    db.prepare(`

      INSERT OR IGNORE INTO customers (
        client_id,
        name,
        phone,
        email,
        created_at,
        updated_at,
        last_seen_at
      )

      VALUES (
        ?, NULL, NULL, ?, ?, ?, ?
      )

    `);


  const customerBackfill =
    db.transaction(
      rows => {

        for(
          const row
          of rows
        ) {

          const firstSeen =
            row.first_seen
            ||
            new Date().toISOString();

          const lastSeen =
            row.last_seen
            ||
            firstSeen;

          insertOldCustomer.run(
            row.client_id,
            row.payer_email || null,
            firstSeen,
            lastSeen,
            lastSeen
          );

        }

      }
    );


  customerBackfill(
    oldClients
  );

}
catch(error) {

  console.error(
    "Erro ao migrar clientes antigos:",
    error
  );

}


// ============================================================
// LOG DE INICIALIZAÃ‡ÃƒO
//
// Estes logs confirmam no Railway que a estrutura principal
// foi carregada corretamente.
// ============================================================

console.log(

  "EVENTO PADRÃƒO:",

  DEFAULT_EVENT.id,

  DEFAULT_EVENT.name

);


console.log(

  "MIKROTIK PADRÃƒO:",

  DEFAULT_ROUTER.id,

  DEFAULT_ROUTER.name

);


console.log(

  "TOPOLOGIA MIKROTIK:",

  db.prepare(
    "SELECT COUNT(*) AS total FROM router_ports"
  ).get().total,

  "portas cadastradas"

);


console.log(

  "FILA MIKROTIK:",

  db.prepare(
    "SELECT COUNT(*) AS total FROM router_access_grants"
  ).get().total,

  "liberaÃ§Ãµes registradas"

);


// ============================================================
// FIM DO BLOCO 1/10


// BLOCO 2/10 - FUNÃ‡Ã•ES AUXILIARES E AUTENTICAÃ‡ÃƒO
// MULTI-MIKROTIK / ROAMING POR EVENTO
// ============================================================


// ============================================================
// DATA / HORA
// ============================================================

function nowIso() {

  return new Date()
    .toISOString();

}


function addMinutesIso(
  minutes
) {

  return new Date(

    Date.now()

    +

    Number(
      minutes
    )

    *

    60

    *

    1000

  ).toISOString();

}


// ============================================================
// REFERÃŠNCIA ÃšNICA DOS PEDIDOS
// ============================================================

function randomRef() {

  return (

    "wifi_"

    +

    crypto.randomUUID()

  );

}


// ============================================================
// MODO TESTE / PRODUÃ‡ÃƒO
// ============================================================

function isTestMode() {

  return String(

    process.env.MP_TEST_MODE

    ||

    "false"

  ).toLowerCase() === "true";

}


// ============================================================
// NORMALIZAR MAC ADDRESS
//
// Aceita, por exemplo:
//
// aa:bb:cc:dd:ee:ff
// AA-BB-CC-DD-EE-FF
// AABBCCDDEEFF
//
// Retorna:
//
// AA:BB:CC:DD:EE:FF
// ============================================================

function normalizeMac(
  value
) {

  if (
    !value
  ) {

    return "";

  }

  const clean =

    String(
      value
    )

      .trim()

      .toUpperCase()

      .replace(
        /[^0-9A-F]/g,
        ""
      );


  if (
    clean.length !== 12
  ) {

    return "";

  }


  return clean

    .match(
      /.{2}/g
    )

    .join(
      ":"
    );

}


// ============================================================
// NORMALIZAR IP
// ============================================================

function normalizeIp(
  value
) {

  const ip =

    String(

      value

      ||

      ""

    ).trim();


  if (

    !/^(\d{1,3}\.){3}\d{1,3}$/.test(
      ip
    )

  ) {

    return "";

  }


  const parts =

    ip

      .split(
        "."
      )

      .map(
        Number
      );


  if (

    parts.some(

      number =>

        number < 0

        ||

        number > 255

    )

  ) {

    return "";

  }


  return ip;

}


// ============================================================
// NORMALIZAR CLIENT_ID
//
// O client_id identifica o navegador/dispositivo no portal.
// A cortesia e o roaming usam esse identificador como uma das
// identidades principais do cliente.
//
// IMPORTANTE:
// O client_id sozinho nÃ£o substitui MAC/IP em todas as etapas.
// Ele serve como identidade persistente do navegador dentro do
// evento para permitir continuidade de acesso entre MikroTiks.
// ============================================================

function normalizeClientId(
  value
) {

  const clientId =

    String(

      value

      ||

      ""

    )

      .trim()

      .replace(

        /[^a-zA-Z0-9_-]/g,

        ""

      );


  if (

    clientId.length < 10

    ||

    clientId.length > 100

  ) {

    return "";

  }


  return clientId;

}


// ============================================================
// TEXTO SEGURO PARA PROTOCOLO MIKROTIK
//
// O protocolo utiliza "|" como separador.
// Portanto removemos "|" e quebras de linha.
// ============================================================

function safeText(
  value
) {

  return String(

    value

    ||

    ""

  )

    .replace(
      /\|/g,
      ""
    )

    .replace(
      /\r?\n/g,
      " "
    )

    .trim();

}


// ============================================================
// COMPARAÃ‡ÃƒO DE VALORES MONETÃRIOS
// ============================================================

function sameMoney(
  valueA,
  valueB
) {

  const a =
    Number(
      valueA
    );

  const b =
    Number(
      valueB
    );


  return (

    Number.isFinite(
      a
    )

    &&

    Number.isFinite(
      b
    )

    &&

    Math.abs(
      a - b
    ) < 0.001

  );

}


// ============================================================
// COMPARAÃ‡ÃƒO SEGURA DE SEGREDOS
//
// Evita comparaÃ§Ã£o simples de tokens.
//
// Se os tamanhos forem diferentes, retorna false.
// ============================================================

function safeSecretEqual(
  valueA,
  valueB
) {

  const a =
    Buffer.from(
      String(
        valueA || ""
      ),
      "utf8"
    );


  const b =
    Buffer.from(
      String(
        valueB || ""
      ),
      "utf8"
    );


  if(
    a.length === 0
    ||
    b.length === 0
    ||
    a.length !== b.length
  ) {

    return false;

  }


  return crypto
    .timingSafeEqual(
      a,
      b
    );

}


// ============================================================
// IDENTIFICAÃ‡ÃƒO DA MIKROTIK NA REQUISIÃ‡ÃƒO
//
// NOVO PADRÃƒO:
//
// x-router-key
// x-mikrotik-token
//
// TambÃ©m aceitamos para diagnÃ³stico:
//
// ?router_key=...
// ?token=...
//
// O router_key identifica QUAL MikroTik estÃ¡ falando.
// O token confirma que aquela MikroTik Ã© legÃ­tima.
// ============================================================

function getMikrotikRequestCredentials(
  req
) {

  const routerKey =
    safeText(

      req.headers[
        "x-router-key"
      ]

      ||

      req.query.router_key

      ||

      req.query.routerKey

      ||

      ""

    )
      .slice(
        0,
        150
      );


  const token =
    String(

      req.headers[
        "x-mikrotik-token"
      ]

      ||

      req.query.token

      ||

      ""

    )
      .trim()
      .slice(
        0,
        300
      );


  return {

    routerKey,
    token

  };

}


// ============================================================
// LOCALIZAR MIKROTIK PELO ROUTER_KEY
// ============================================================

function findMikrotikByRouterKey(
  routerKey
) {

  const key =
    String(
      routerKey || ""
    )
      .trim();


  if(
    !key
  ) {

    return null;

  }


  return db.prepare(`

    SELECT *

    FROM routers

    WHERE
      router_key=?
      AND status='active'

    LIMIT 1

  `).get(
    key
  ) || null;

}


// ============================================================
// AUTENTICAÃ‡ÃƒO INDIVIDUAL DA MIKROTIK
//
// Retorna:
//
// {
//   ok: true,
//   mode: "router",
//   router: {...},
//   event_id: 1,
//   router_id: 2
// }
//
// ou, durante a transiÃ§Ã£o:
//
// {
//   ok: true,
//   mode: "legacy",
//   router: null,
//   event_id: null,
//   router_id: null
// }
//
// O modo legacy usa MIKROTIK_POLL_TOKEN e existe apenas para
// manter a MikroTik atual funcionando enquanto migramos os
// scripts para router_key + token individual.
// ============================================================

function authenticateMikrotik(
  req
) {

  const credentials =
    getMikrotikRequestCredentials(
      req
    );


  // ==========================================================
  // NOVO MODO
  // ROUTER_KEY + TOKEN EXCLUSIVO DA MIKROTIK
  // ==========================================================

  if(
    credentials.routerKey
    &&
    credentials.token
  ) {

    const router =
      findMikrotikByRouterKey(
        credentials.routerKey
      );


    if(
      router
      &&
      router.token
      &&
      safeSecretEqual(
        router.token,
        credentials.token
      )
    ) {

      return {

        ok:
          true,

        mode:
          "router",

        router,

        router_id:
          Number(
            router.id
          ),

        event_id:
          Number(
            router.event_id
          )

      };

    }

  }


  // ==========================================================
  // COMPATIBILIDADE TEMPORÃRIA
  // TOKEN GLOBAL ANTIGO DO RAILWAY
  //
  // Isso evita derrubar a instalaÃ§Ã£o atual antes de gerarmos
  // o novo script da MikroTik.
  // ==========================================================

  const legacyToken =
    process.env
      .MIKROTIK_POLL_TOKEN;


  if(
    legacyToken
    &&
    credentials.token
    &&
    safeSecretEqual(
      legacyToken,
      credentials.token
    )
  ) {

    return {

      ok:
        true,

      mode:
        "legacy",

      router:
        null,

      router_id:
        null,

      event_id:
        null

    };

  }


  return {

    ok:
      false,

    mode:
      "invalid",

    router:
      null,

    router_id:
      null,

    event_id:
      null

  };

}


// ============================================================
// COMPATIBILIDADE COM AS ROTAS EXISTENTES
//
// VÃ¡rias rotas atuais jÃ¡ chamam:
//
// isMikrotikAuthorized(req)
//
// Mantemos essa funÃ§Ã£o para nÃ£o quebrar os blocos antigos.
//
// Depois, no BLOCO 6/10, passaremos a usar diretamente:
//
// authenticateMikrotik(req)
//
// para separar as filas por MikroTik/evento.
// ============================================================

function isMikrotikAuthorized(
  req
) {

  return Boolean(
    authenticateMikrotik(
      req
    )?.ok
  );

}


// ============================================================
// OBTER A MIKROTIK AUTENTICADA
//
// Ãštil nas novas rotas multi-MikroTik.
//
// Retorna null quando:
// - credenciais invÃ¡lidas;
// - requisiÃ§Ã£o ainda estÃ¡ no modo legacy;
// - router_key nÃ£o corresponde a uma MK ativa.
// ============================================================

function getAuthenticatedMikrotik(
  req
) {

  const auth =
    authenticateMikrotik(
      req
    );


  if(
    !auth.ok
    ||
    auth.mode !==
    "router"
    ||
    !auth.router
  ) {

    return null;

  }


  return auth.router;

}


// ============================================================
// OBTER EVENTO DA MIKROTIK AUTENTICADA
//
// Isso serÃ¡ usado no roaming.
//
// A MikroTik nÃ£o escolhe o evento manualmente.
// O evento vem do vÃ­nculo salvo no banco:
//
// routers.event_id
// ============================================================

function getAuthenticatedMikrotikEventId(
  req
) {

  const auth =
    authenticateMikrotik(
      req
    );


  if(
    !auth.ok
    ||
    auth.mode !==
    "router"
    ||
    !auth.event_id
  ) {

    return null;

  }


  return Number(
    auth.event_id
  );

}


// ============================================================
// LOG AUXILIAR DE AUTENTICAÃ‡ÃƒO
//
// NÃ£o imprime o token.
// ============================================================

function logMikrotikAuthentication(
  req,
  prefix
) {

  const auth =
    authenticateMikrotik(
      req
    );


  if(
    !auth.ok
  ) {

    console.warn(
      prefix ||
      "MIKROTIK AUTH:",
      "NEGADA"
    );


    return auth;

  }


  if(
    auth.mode ===
    "router"
  ) {

    console.log(
      prefix ||
      "MIKROTIK AUTH:",
      "OK",
      "ROUTER=" +
        auth.router.router_key,
      "ID=" +
        auth.router_id,
      "EVENTO=" +
        auth.event_id
    );

  }


  else {

    console.log(
      prefix ||
      "MIKROTIK AUTH:",
      "OK",
      "MODO=LEGACY"
    );

  }


  return auth;

}


// ============================================================
// AUTENTICAÃ‡ÃƒO DO PAINEL ADMINISTRATIVO
//
// VariÃ¡veis do Railway:
//
// ADMIN_USER
// ADMIN_PASSWORD
// ============================================================

// ============================================================
// V15 - FUNIL: REGISTRADOR CENTRAL
// ============================================================

function normalizeFunnelMetadata(
  value
) {

  if(
    !value
    ||
    typeof value !== "object"
    ||
    Array.isArray(value)
  ) {

    return null;

  }


  try {

    const text =
      JSON.stringify(
        value
      );


    if(
      text.length > 4000
    ) {

      return JSON.stringify({
        truncated:
          true
      });

    }


    return text;

  }


  catch {

    return null;

  }

}


// ============================================================
// REGISTRAR EVENTO DO FUNIL
// ============================================================

function recordFunnelEvent({

  eventId = null,

  routerId = null,

  clientId = null,

  mac = null,

  ip = null,

  orderId = null,

  orderRef = null,

  step,

  planId = null,

  source = "backend",

  metadata = null

}) {

  const normalizedStep =
    normalizeFunnelStep(
      step
    );


  if(
    !FUNNEL_STEPS.has(
      normalizedStep
    )
  ) {

    console.warn(
      "FUNIL: etapa ignorada:",
      normalizedStep
    );


    return null;

  }


  const normalizedClientId =

    normalizeClientId(
      clientId
    );


  const normalizedMac =

    normalizeMac(
      mac
    );


  const normalizedIp =

    normalizeIp(
      ip
    );


  const createdAt =

    nowIso();


  const result =

    db.prepare(`

      INSERT INTO funnel_events (

        event_id,

        router_id,

        client_id,

        mac,

        ip,

        order_id,

        order_ref,

        step,

        plan_id,

        source,

        metadata_json,

        created_at

      )

      VALUES (
        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
      )

    `).run(

      eventId || null,

      routerId || null,

      normalizedClientId || null,

      normalizedMac || null,

      normalizedIp || null,

      orderId || null,

      orderRef
        ? String(
            orderRef
          ).slice(
            0,
            120
          )
        : null,

      normalizedStep,

      planId
        ? String(
            planId
          ).slice(
            0,
            120
          )
        : null,

      String(
        source || "backend"
      ).slice(
        0,
        40
      ),

      normalizeFunnelMetadata(
        metadata
      ),

      createdAt

    );


  return {

    id:
      Number(
        result.lastInsertRowid
      ),

    step:
      normalizedStep,

    created_at:
      createdAt

  };

}



// ============================================================
// V15 - REGISTRO IDempotente / COM JANELA DE DEDUPLICACAO
// ============================================================

function recordFunnelEventOnce({
  eventId = null,
  routerId = null,
  clientId = null,
  mac = null,
  ip = null,
  orderId = null,
  orderRef = null,
  step,
  planId = null,
  source = "backend",
  metadata = null,
  dedupeWindowSeconds = 0,
  dedupeByOrder = true
}) {

  const normalizedStep =
    normalizeFunnelStep(step);

  if(
    !FUNNEL_STEPS.has(normalizedStep)
  ) {
    return null;
  }

  const normalizedClientId =
    normalizeClientId(clientId);

  const normalizedMac =
    normalizeMac(mac);

  let existing = null;

  if(
    dedupeByOrder
    &&
    Number(orderId) > 0
  ) {

    existing =
      db.prepare(`
        SELECT id, step, created_at
        FROM funnel_events
        WHERE
          order_id=?
          AND step=?
        ORDER BY id DESC
        LIMIT 1
      `).get(
        Number(orderId),
        normalizedStep
      ) || null;

  }
  else if(
    Number(eventId) > 0
    &&
    (
      normalizedClientId
      ||
      normalizedMac
    )
    &&
    Number(dedupeWindowSeconds) > 0
  ) {

    const cutoff =
      new Date(
        Date.now()
        -
        Number(dedupeWindowSeconds) * 1000
      ).toISOString();

    if(normalizedClientId){
      existing =
        db.prepare(`
          SELECT id, step, created_at
          FROM funnel_events
          WHERE
            event_id=?
            AND client_id=?
            AND step=?
            AND created_at>=?
          ORDER BY id DESC
          LIMIT 1
        `).get(
          Number(eventId),
          normalizedClientId,
          normalizedStep,
          cutoff
        ) || null;
    }
    else{
      existing =
        db.prepare(`
          SELECT id, step, created_at
          FROM funnel_events
          WHERE
            event_id=?
            AND mac=?
            AND step=?
            AND created_at>=?
          ORDER BY id DESC
          LIMIT 1
        `).get(
          Number(eventId),
          normalizedMac,
          normalizedStep,
          cutoff
        ) || null;
    }
  }

  if(existing){
    return {
      id:Number(existing.id),
      step:existing.step,
      created_at:existing.created_at,
      duplicate:true
    };
  }

  return recordFunnelEvent({
    eventId,
    routerId,
    clientId:normalizedClientId || clientId,
    mac:normalizedMac || mac,
    ip,
    orderId,
    orderRef,
    step:normalizedStep,
    planId,
    source,
    metadata
  });
}


// ============================================================
// V15 - CORRELACIONAR PRESENCA NA MIKROTIK COM O FUNIL
//
// hotspotMacs: /ip hotspot host -> etapa 1
// activeMacs : /ip hotspot active -> etapas 10 e 13
// ============================================================

function processFunnelPresenceForRouter(
  router,
  hotspotMacs,
  activeMacs,
  observedAt
){

  const eventId =
    Number(router?.event_id || 0);

  const routerId =
    Number(router?.id || 0);

  if(
    !eventId
    ||
    !routerId
  ){
    return;
  }

  const observedMs =
    Date.parse(observedAt || "");

  const nowMs =
    Number.isFinite(observedMs)
      ? observedMs
      : Date.now();

  const findLatestOrderByMac =
    db.prepare(`
      SELECT *
      FROM orders
      WHERE
        event_id=?
        AND (
          effective_mac=?
          OR mac=?
          OR original_mac=?
        )
      ORDER BY id DESC
      LIMIT 1
    `);

  const findActiveGrant =
    db.prepare(`
      SELECT id
      FROM router_access_grants
      WHERE
        order_id=?
        AND router_id=?
        AND status='active'
      ORDER BY id DESC
      LIMIT 1
    `);

  for(
    const rawMac
    of Array.isArray(hotspotMacs)
      ? hotspotMacs
      : []
  ){

    const mac =
      normalizeMac(rawMac);

    if(!mac){
      continue;
    }

    const order =
      findLatestOrderByMac.get(
        eventId,
        mac,
        mac,
        mac
      ) || null;

    recordFunnelEventOnce({
      eventId,
      routerId,
      clientId:order?.client_id || null,
      mac,
      ip:order?.ip || null,
      step:"HOTSPOT_DETECTED",
      planId:order?.plan_id || null,
      source:"mikrotik_hotspot_host",
      metadata:{
        observed_at:observedAt || nowIso(),
        router_key:router.router_key || null
      },
      dedupeWindowSeconds:900,
      dedupeByOrder:false
    });
  }

  for(
    const rawMac
    of Array.isArray(activeMacs)
      ? activeMacs
      : []
  ){

    const mac =
      normalizeMac(rawMac);

    if(!mac){
      continue;
    }

    const order =
      findLatestOrderByMac.get(
        eventId,
        mac,
        mac,
        mac
      ) || null;

    if(!order){
      continue;
    }

    const tempExpiresMs =
      Date.parse(
        order.temp_expires_at || ""
      );

    if(
      order.temp_status === "granted"
      &&
      (
        !Number.isFinite(tempExpiresMs)
        ||
        tempExpiresMs > nowMs
      )
    ){

      recordFunnelEventOnce({
        eventId,
        routerId,
        clientId:order.client_id,
        mac,
        ip:order.ip,
        orderId:order.id,
        orderRef:order.external_ref,
        step:"INTERNET_CONFIRMED",
        planId:order.plan_id,
        source:"mikrotik_hotspot_active",
        metadata:{
          observed_at:observedAt || nowIso(),
          phase:"temporary_access"
        }
      });
    }

    const accessExpiresMs =
      Date.parse(
        order.access_expires_at || ""
      );

    if(
      order.status === "approved"
      &&
      !order.access_expired_at
      &&
      Number.isFinite(accessExpiresMs)
      &&
      accessExpiresMs > nowMs
      &&
      findActiveGrant.get(
        order.id,
        routerId
      )
    ){

      recordFunnelEventOnce({
        eventId,
        routerId,
        clientId:order.client_id,
        mac,
        ip:order.ip,
        orderId:order.id,
        orderRef:order.external_ref,
        step:"NAVIGATION_AFTER_PAYMENT",
        planId:order.plan_id,
        source:"mikrotik_hotspot_active",
        metadata:{
          observed_at:observedAt || nowIso(),
          phase:"paid_access"
        }
      });
    }
  }
}


// ============================================================
// FIM DO BLOCO 2/10

// BLOCO 3/10 - CONTROLE DAS CORTESIAS
// ============================================================

// IDENTIDADE PRINCIPAL:
// client_id do navegador.
//
// O MAC e o IP podem mudar.
//
// REGRAS ATUAIS:
//
// - Cortesia: TEMP_MINUTES
// - Espera apÃ³s cortesia: TEMP_RETRY_WAIT_MINUTES
// - MÃ¡ximo por hora: TEMP_MAX_ATTEMPTS_PER_HOUR
//
// ============================================================


function getTemporaryAccessDecision(
  clientId
) {

  // ==========================================================
  // NORMALIZAR IDENTIDADE
  // ==========================================================

  const normalizedClientId =
    normalizeClientId(
      clientId
    );


  if (
    !normalizedClientId
  ) {

    return {

      eligible:
        false,

      reason:
        "invalid_client",

      attempts_last_hour:
        0,

      retry_after_seconds:
        0

    };

  }


  // ==========================================================
  // TEMPO ATUAL
  // ==========================================================

  const now =
    Date.now();


  const oneHourAgo =

    now

    -

    60

    *

    60

    *

    1000;


  // ==========================================================
  // BUSCAR HISTÃ“RICO DO CLIENT_ID
  // ==========================================================

  const rows =

    db.prepare(`

      SELECT

        id,

        external_ref,

        client_id,

        temp_status,

        temp_requested_at,

        temp_granted_at,

        temp_expires_at

      FROM orders

      WHERE client_id=?

      ORDER BY id DESC

      LIMIT 100

    `).all(
      normalizedClientId
    );


  // ==========================================================
  // RECUPERAR CORTESIA PENDENTE TRAVADA
  //
  // Uma solicitaÃ§Ã£o "pending" existe apenas enquanto aguardamos
  // a MikroTik aplicar a cortesia.
  //
  // Se por falha de comunicaÃ§Ã£o / deploy / reinÃ­cio ela ficar
  // pendente por mais de 2 minutos, nÃ£o pode bloquear o cliente
  // indefinidamente.
  //
  // IMPORTANTE:
  // - nÃ£o conta como cortesia utilizada;
  // - nÃ£o altera o limite de 2 por hora;
  // - nÃ£o altera a espera de 5 minutos apÃ³s cortesia concedida;
  // - apenas limpa um estado tÃ©cnico que ficou travado.
  // ==========================================================

  const TEMP_PENDING_TIMEOUT_MS =
    2
    *
    60
    *
    1000;


  for(
    const row
    of rows
  ){

    if(
      row.temp_status !==
        "pending"
    ){
      continue;
    }


    const requestedAtMs =
      Date.parse(
        row.temp_requested_at || ""
      );


    const isStalePending =
      !Number.isFinite(
        requestedAtMs
      )
      ||
      (
        now
        -
        requestedAtMs
      ) >
      TEMP_PENDING_TIMEOUT_MS;


    if(
      !isStalePending
    ){
      continue;
    }


    db.prepare(`
      UPDATE orders
      SET temp_status='failed_timeout'
      WHERE id=?
        AND temp_status='pending'
    `).run(
      row.id
    );


    row.temp_status =
      "failed_timeout";


    console.warn(
      "CORTESIA PENDING EXPIRADA:",
      row.external_ref,
      "CLIENT=" +
        normalizedClientId
    );

  }


  // ==========================================================
  // VERIFICAR SE JÃ EXISTE UMA CORTESIA PENDENTE
  // ==========================================================

  const pending =

    rows.find(

      row =>

        row.temp_status ===
        "pending"

    );


  if (
    pending
  ) {

    return {

      eligible:
        false,

      reason:
        "pending",

      attempts_last_hour:
        0,

      retry_after_seconds:
        0

    };

  }


  // ==========================================================
  // CONTAR TENTATIVAS NA ÃšLTIMA HORA
  // ==========================================================

  const attemptsLastHour =

    rows.filter(

      row => {


        const dateValue =

          row.temp_granted_at

          ||

          row.temp_requested_at;


        if (
          !dateValue
        ) {

          return false;

        }


        const timestamp =

          Date.parse(
            dateValue
          );


        if (

          !Number.isFinite(
            timestamp
          )

        ) {

          return false;

        }


        if (

          timestamp <
          oneHourAgo

        ) {

          return false;

        }


        return (

          row.temp_status ===
            "granted"

          ||

          row.temp_status ===
            "replaced_by_paid_plan"

          ||

          row.temp_status ===
            "cancelled_by_paid_plan"

        );

      }

    );


  // ==========================================================
  // LIMITE DE TENTATIVAS POR HORA
  // ==========================================================

  if (

    attemptsLastHour.length

    >=

    TEMP_MAX_ATTEMPTS_PER_HOUR

  ) {


    const timestamps =

      attemptsLastHour

        .map(

          row =>

            Date.parse(

              row.temp_granted_at

              ||

              row.temp_requested_at

            )

        )

        .filter(
          Number.isFinite
        )

        .sort(

          (a, b) =>
            a - b

        );


    let retryAfterSeconds =
      0;


    if (
      timestamps.length
    ) {


      const releaseAt =

        timestamps[0]

        +

        60

        *

        60

        *

        1000;


      retryAfterSeconds =

        Math.max(

          0,

          Math.ceil(

            (

              releaseAt

              -

              now

            )

            /

            1000

          )

        );

    }


    return {

      eligible:
        false,

      reason:
        "hour_limit",

      attempts_last_hour:
        attemptsLastHour.length,

      retry_after_seconds:
        retryAfterSeconds

    };

  }


  // ==========================================================
  // LOCALIZAR ÃšLTIMA CORTESIA UTILIZADA
  // ==========================================================

  const previous =

    rows.find(

      row =>

        row.temp_status ===
          "granted"

        ||

        row.temp_status ===
          "replaced_by_paid_plan"

        ||

        row.temp_status ===
          "cancelled_by_paid_plan"

    );


  // ==========================================================
  // VERIFICAR TEMPO DE ESPERA APÃ“S A CORTESIA
  // ==========================================================

  if (
    previous
  ) {


    let previousEnd =

      Date.parse(

        previous.temp_expires_at

        ||

        ""

      );


    // ========================================================
    // COMPATIBILIDADE COM REGISTROS ANTIGOS
    //
    // Caso temp_expires_at esteja vazio,
    // calcula o fim usando o horÃ¡rio inicial.
    // ========================================================

    if (

      !Number.isFinite(
        previousEnd
      )

    ) {


      const startedAt =

        Date.parse(

          previous.temp_granted_at

          ||

          previous.temp_requested_at

          ||

          ""

        );


      if (

        Number.isFinite(
          startedAt
        )

      ) {


        previousEnd =

          startedAt

          +

          TEMP_MINUTES

          *

          60

          *

          1000;

      }

    }


    if (

      Number.isFinite(
        previousEnd
      )

    ) {


      const nextAllowed =

        previousEnd

        +

        TEMP_RETRY_WAIT_MINUTES

        *

        60

        *

        1000;


      if (

        now <
        nextAllowed

      ) {


        return {

          eligible:
            false,

          reason:
            "wait",

          attempts_last_hour:
            attemptsLastHour.length,

          retry_after_seconds:

            Math.ceil(

              (

                nextAllowed

                -

                now

              )

              /

              1000

            )

        };

      }

    }

  }


  // ==========================================================
  // CORTESIA LIBERADA
  // ==========================================================

  return {

    eligible:
      true,

    reason:
      "allowed",

    attempts_last_hour:
      attemptsLastHour.length,

    retry_after_seconds:
      0

  };

}


// ============================================================
// FIM DO BLOCO 3/10

// BLOCO 4/10 - HEALTH, PLANOS E BASE MERCADO PAGO
// ============================================================


// ============================================================
// HEALTH
// ============================================================

app.use((req, res, next) => {
  res.on("finish", () => {
    const method = String(req.method || "").toUpperCase();
    const actor = req.auth?.user;
    if (
      !actor
      || !req.path.startsWith("/admin/api/")
      || !["POST", "PUT", "PATCH", "DELETE"].includes(method)
    ) {
      return;
    }

    const route = String(req.baseUrl || "") + String(req.route?.path || req.path);
    try {
      const result = db.prepare(`
        INSERT INTO admin_audit_log (
          actor, method, route, status_code, ip, created_at
        ) VALUES (?, ?, ?, ?, ?, ?)
      `).run(
        String(actor).slice(0, 100),
        method,
        route.slice(0, 300),
        Number(res.statusCode || 0),
        String(req.ip || "").slice(0, 100),
        nowIso()
      );

      if (Number(result.lastInsertRowid) % 250 === 0) {
        db.prepare(`
          DELETE FROM admin_audit_log
          WHERE id NOT IN (
            SELECT id FROM admin_audit_log ORDER BY id DESC LIMIT 5000
          )
        `).run();
      }
    } catch (error) {
      console.error("Falha ao registrar auditoria administrativa:", error.message);
    }
  });

  next();
});

app.get(
  "/health",
  (req, res) => {

    res.json({

      status:
        "ok",

      service:
        "wifi-pago-mikrotik",

      payment_mode:
        isTestMode()
          ? "test"
          : "production",

      temp_access_minutes:
        TEMP_MINUTES,

      temp_retry_wait_minutes:
        TEMP_RETRY_WAIT_MINUTES,

      temp_max_attempts_per_hour:
        TEMP_MAX_ATTEMPTS_PER_HOUR,

      identity_mode:
        "client_id",

      protocol_version:
        3,

      database_path:
        path.join(
          dataDir,
          "wifi.db"
        ),

      time:
        nowIso()

    });

  }
);


// ============================================================
// API DE PLANOS
//
// NOVO:
// - Se receber event_key/router_key, retorna somente os planos
//   cadastrados no evento.
// - Se nÃ£o receber contexto, mantÃ©m compatibilidade com os
//   planos antigos de PLANS.
// ============================================================

app.get(
  "/api/plans",
  (req, res) => {

    try {

      const eventKey =
        String(
          req.query.event_key ||
          req.query.event ||
          ""
        ).trim();

      const routerKey =
        String(
          req.query.router_key ||
          req.query.router ||
          ""
        ).trim();


      // ========================================================
      // PORTAL DE EVENTO
      // ========================================================

      if (
        eventKey
        ||
        routerKey
      ) {

        const context =
          resolvePortalContext(
            eventKey,
            routerKey
          );


        if (
          !context.ok
        ) {

          return res
            .status(400)
            .json({
              error:
                context.error
            });

        }


        const plans =
          db.prepare(`

            SELECT

              plan_key,
              name,
              amount,
              minutes,
              rate_limit,
              mikrotik_profile,
              description,
              subtitle,
              highlight,
              sort_order

            FROM event_plans

            WHERE

              event_id=?
              AND active=1
              AND deleted_at IS NULL

            ORDER BY

              sort_order ASC,
              id ASC

          `).all(
            context.event.id
          );


        return res.json(

          plans.map(
            plan => ({

              id:
                plan.plan_key,

              name:
                plan.name,

              amount:
                Number(
                  plan.amount
                ),

              minutes:
                Number(
                  plan.minutes
                ),

              rate:
                plan.rate_limit,

              mikrotik_profile:
                plan.mikrotik_profile,

              description:
                plan.description || "",

              subtitle:
                plan.subtitle || "",

              highlight:
                plan.highlight || ""

            })
          )

        );

      }


      // ========================================================
      // COMPATIBILIDADE COM INSTALAÃ‡ÃƒO ANTIGA
      //
      // Portais antigos que chamam apenas /api/plans continuam
      // recebendo os planos globais PLANS.
      // ========================================================

      return res.json(

        Object
          .values(
            PLANS
          )
          .map(

            plan => ({

              id:
                plan.id,

              name:
                plan.name,

              amount:
                Number(
                  plan.amount
                ),

              minutes:
                Number(
                  plan.minutes
                ),

              rate:
                plan.rate

            })

          )

      );


    }
    catch(error) {

      console.error(
        "Erro ao carregar planos:",
        error
      );


      return res
        .status(500)
        .json({
          error:
            "Erro ao carregar os planos"
        });

    }

  }
);


// ============================================================
// MERCADO PAGO
// BUSCAR ORDER PELO ID
// ============================================================

async function getOrder(
  orderId
) {

  const response =
    await axios.get(

      `https://api.mercadopago.com/v1/orders/${encodeURIComponent(orderId)}`,

      {

        headers: {

          Authorization:
            `Bearer ${process.env.MP_ACCESS_TOKEN}`

        },

        timeout:
          15000

      }

    );


  return response.data;

}


// ============================================================
// PROCESSAR STATUS DO PAGAMENTO
// ============================================================

async function processOrderStatus(
  mpOrder
) {

  const externalRef =
    String(

      mpOrder.external_reference

      ||

      ""

    ).trim();


  if (
    !externalRef
  ) {

    return;

  }


  const localOrder =

    db.prepare(

      "SELECT * FROM orders WHERE external_ref=?"

    ).get(

      externalRef

    );


  if (
    !localOrder
  ) {

    return;

  }


  if (

    localOrder.status ===
    "approved"

  ) {

    return;

  }


  // ==========================================================
  // TODOS OS PAGAMENTOS DA ORDER
  // ==========================================================

  const payments =

    Array.isArray(
      mpOrder
        .transactions
        ?.payments
    )

      ? mpOrder
          .transactions
          .payments

      : [];


  // ==========================================================
  // PRIMEIRO PAGAMENTO DA ORDER
  //
  // Mantido para preservar a validaÃ§Ã£o atual.
  // ==========================================================

  const transaction =

    payments[0]

    ||

    {};


  // ==========================================================
  // VALIDAR STATUS DA ORDER
  // ==========================================================

  const orderCredited =

    mpOrder.status ===
      "processed"

    &&

    mpOrder.status_detail ===
      "accredited";


  // ==========================================================
  // VALIDAR STATUS DA TRANSAÃ‡ÃƒO
  // ==========================================================

  const transactionCredited =

    transaction.status ===
      "processed"

    &&

    transaction.status_detail ===
      "accredited";


  // ==========================================================
  // VALIDAR VALOR
  // ==========================================================

  const expectedAmount =

    Number(
      localOrder.amount
    );


  const paidAmount =

    transaction.paid_amount

    ??

    transaction.amount;


  const orderAmount =

    mpOrder.total_amount;


  const amountMatches =

    sameMoney(

      paidAmount,

      expectedAmount

    )

    &&

    sameMoney(

      orderAmount,

      expectedAmount

    );


  // ==========================================================
  // DIAGNÃ“STICO MERCADO PAGO
  // ==========================================================

  console.log(

    "MP DEBUG ORDER:",

    JSON.stringify({

      external_reference:
        externalRef,

      order_id:
        mpOrder.id || null,

      order_type:
        mpOrder.type || null,

      order_status:
        mpOrder.status || null,

      order_status_detail:
        mpOrder.status_detail || null,

      total_amount:
        mpOrder.total_amount ?? null,

      payments_count:
        payments.length,

      payments:

        payments.map(

          (
            payment,
            index
          ) => ({

            index:
              index,

            id:
              payment.id || null,

            reference_id:
              payment.reference_id || null,

            status:
              payment.status || null,

            status_detail:
              payment.status_detail || null,

            amount:
              payment.amount ?? null,

            paid_amount:
              payment.paid_amount ?? null,

            payment_method:

              payment.payment_method

                ? {

                    id:
                      payment.payment_method.id || null,

                    type:
                      payment.payment_method.type || null

                  }

                : null

          })

        )

    })

  );


  console.log(

    "MP PAYMENTS COUNT:",

    externalRef,

    payments.length

  );


  payments.forEach(

    (
      payment,
      index
    ) => {

      console.log(

        "MP PAYMENT:",

        externalRef,

        "index=" +
          index,

        "id=" +
          (
            payment.id ||
            "null"
          ),

        "reference=" +
          (
            payment.reference_id ||
            "null"
          ),

        "status=" +
          (
            payment.status ||
            "null"
          ) +
          "/" +
          (
            payment.status_detail ||
            "null"
          ),

        "amount=" +
          (
            payment.amount ??
            "null"
          ),

        "paid_amount=" +
          (
            payment.paid_amount ??
            "null"
          ),

        "method=" +
          (
            payment
              .payment_method
              ?.id

            ||

            "null"
          )

      );

    }

  );


  // ==========================================================
  // LOG RESUMIDO DA VALIDAÃ‡ÃƒO
  // ==========================================================

  console.log(

    "VALIDAÃ‡ÃƒO MP:",

    externalRef,

    "order=" +
      mpOrder.status +
      "/" +
      mpOrder.status_detail,

    "transaction=" +
      transaction.status +
      "/" +
      transaction.status_detail,

    "esperado=" +
      expectedAmount,

    "pago=" +
      paidAmount

  );


  // ==========================================================
  // MODO DE TESTE
  //
  // Em teste, nunca liberar internet real.
  // ==========================================================

  if (
    isTestMode()
  ) {

    const testStatus =

      orderCredited

      &&

      transactionCredited

        ? "test_approved_no_release"

        : (

            mpOrder.status

            ||

            transaction.status

            ||

            "test_pending"

          );


    db.prepare(`

      UPDATE orders

      SET status=?

      WHERE external_ref=?

    `).run(

      testStatus,

      externalRef

    );


    return;

  }


  // ==========================================================
  // PRODUÃ‡ÃƒO
  // ==========================================================

  const reallyPaid =

    orderCredited

    &&

    transactionCredited

    &&

    amountMatches;


  if (
    !reallyPaid
  ) {

    let status =

      mpOrder.status

      ||

      transaction.status

      ||

      "pending";


    if (

      orderCredited

      ||

      transactionCredited

    ) {

      status =
        "payment_validation_failed";

    }


    db.prepare(`

      UPDATE orders

      SET status=?

      WHERE external_ref=?

    `).run(

      status,

      externalRef

    );


    return;

  }


  // ==========================================================
  // PAGAMENTO APROVADO
  //
  // Se existia cortesia do mesmo client_id,
  // marca como substituÃ­da/cancelada pelo plano pago.
  // ==========================================================

  if (
    localOrder.client_id
  ) {

    db.prepare(`

      UPDATE orders

      SET

        temp_status='cancelled_by_paid_plan'

      WHERE

        client_id=?

        AND

        temp_status IN (
          'pending',
          'granted'
        )

    `).run(

      localOrder.client_id

    );

  }


  // ==========================================================
  // AGUARDAR LIBERAÃ‡ÃƒO NA MIKROTIK
  // ==========================================================

  const approvedAt =
    nowIso();


  db.prepare(`

    UPDATE orders

    SET

      status='approved_pending_router',

      approved_at=
        COALESCE(
          approved_at,
          ?
        )

    WHERE external_ref=?

  `).run(

    approvedAt,

    externalRef

  );


  // ==========================================================
  // V15 - FUNIL: PAGAMENTO APROVADO
  //
  // O Mercado Pago pode reenviar o mesmo webhook.
  // Gravamos esta etapa apenas uma vez por pedido.
  // ==========================================================

  const paymentFunnelExists =
    db.prepare(`
      SELECT id
      FROM funnel_events
      WHERE
        order_id=?
        AND step='PAYMENT_APPROVED'
      LIMIT 1
    `).get(
      localOrder.id
    );


  if(
    !paymentFunnelExists
  ) {

    recordFunnelEvent({
      eventId:
        localOrder.event_id,
      routerId:
        localOrder.router_id,
      clientId:
        localOrder.client_id,
      mac:
        localOrder.effective_mac
        ||
        localOrder.mac,
      ip:
        localOrder.ip,
      orderId:
        localOrder.id,
      orderRef:
        externalRef,
      step:
        "PAYMENT_APPROVED",
      planId:
        localOrder.plan_id,
      source:
        "mercadopago",
      metadata: {
        approved_at:
          approvedAt,
        mp_order_id:
          mpOrder.id || null,
        mp_payment_id:
          transaction.id || null,
        amount:
          expectedAmount
      }
    });

  }


  console.log(

    "PIX REAL CONFIRMADO - AGUARDANDO MIKROTIK:",

    externalRef,

    "CLIENT=" +
      localOrder.client_id,

    "MAC=" +
      localOrder.mac,

    "IP=" +
      localOrder.ip

  );

}




// ============================================================
// POLLING AUTOMÃTICO DE SEGURANÃ‡A DOS PIX PENDENTES
//
// O backend consulta sozinho o Mercado Pago.
// NÃ£o depende do portal continuar aberto no celular.
//
// Intervalo: 5 segundos
// Janela: pedidos dos Ãºltimos 10 minutos
// ============================================================

const MP_PENDING_POLL_INTERVAL_MS =
  5000;

let mpPendingPollRunning =
  false;


// ============================================================
// BUSCAR PEDIDOS PIX RECENTES AINDA NÃƒO FINALIZADOS
// ============================================================

function getPendingMercadoPagoOrders() {

  return db.prepare(`

    SELECT

      id,
      external_ref,
      mp_order_id,
      mp_payment_id,
      status,
      created_at

    FROM orders

    WHERE

      COALESCE(
        mp_order_id,
        mp_payment_id,
        ''
      ) <> ''

      AND

      status NOT IN (
        'approved',
        'approved_pending_router',
        'approved_missing_mac',
        'payment_validation_failed',
        'test_approved_no_release'
      )

      AND

      datetime(created_at) >=
        datetime(
          'now',
          '-10 minutes'
        )

    ORDER BY
      id DESC

    LIMIT 20

  `).all();

}


// ============================================================
// EXECUTAR UMA RODADA DO POLLING
// ============================================================

async function pollPendingMercadoPagoOrders() {

  if (
    mpPendingPollRunning
  ) {

    return;

  }


  mpPendingPollRunning =
    true;


  try {

    const pendingOrders =
      getPendingMercadoPagoOrders();


    if (
      pendingOrders.length > 0
    ) {

      console.log(

        "MP POLL BACKEND: CICLO",

        "pendentes=" +
          pendingOrders.length

      );

    }


    for (
      const order
      of pendingOrders
    ) {

      const orderId =

        order.mp_order_id

        ||

        order.mp_payment_id;


      if (
        !orderId
      ) {

        continue;

      }


      try {

        const mpOrder =
          await getOrder(
            orderId
          );


        await processOrderStatus(
          mpOrder
        );


        const updated =
          db.prepare(`

            SELECT status

            FROM orders

            WHERE id=?

            LIMIT 1

          `).get(
            order.id
          );


        if (
          updated?.status ===
          "approved_pending_router"
        ) {

          console.log(

            "MP POLL BACKEND: PAGAMENTO CONFIRMADO",

            order.external_ref

          );

        }

      }
      catch(error) {

        console.warn(

          "MP POLL BACKEND: ERRO",

          order.external_ref,

          error.response
            ?.data
          ||
          error.message

        );

      }

    }

  }
  finally {

    mpPendingPollRunning =
      false;

  }

}


// ============================================================
// ATIVAR POLLING
// ============================================================

console.log(

  "MP POLL BACKEND: ATIVO",

  "intervalo=5s",

  "janela=30min"

);


setTimeout(

  () => {

    pollPendingMercadoPagoOrders()
      .catch(
        error => {

          console.error(

            "MP POLL BACKEND: ERRO INICIAL",

            error.message

          );

        }
      );

  },

  2000

);


const mpPendingPollTimer =
  setInterval(

    () => {

      pollPendingMercadoPagoOrders()
        .catch(
          error => {

            console.error(

              "MP POLL BACKEND: ERRO GERAL",

              error.message

            );

          }
        );

    },

    MP_PENDING_POLL_INTERVAL_MS

  );


if (
  typeof mpPendingPollTimer.unref ===
  "function"
) {

  mpPendingPollTimer.unref();

}

// ============================================================
// FIM DO BLOCO 4/10

// BLOCO 5/10 - CRIAR PIX E CONSULTAR PEDIDO
// ============================================================
// V16.11 - COOKIE DE RECUPERACAO ASSINADO PELO BACKEND
//
// Objetivo:
// - manter uma segunda identidade persistente alem do client_id JS;
// - o cookie e HttpOnly, portanto nao depende de localStorage;
// - o valor e assinado por HMAC e nao pode ser forjado pelo cliente;
// - serve APENAS para recuperar uma compra ainda valida no mesmo evento;
// - nunca cria tempo novo e nunca libera outro evento.
//
// RECOVERY_COOKIE_SECRET e recomendado. Se nao existir, usamos
// ADMIN_PASSWORD como fallback persistente para nao quebrar o deploy atual.
// ============================================================

const RECOVERY_COOKIE_NAME =
  "wifi_pago_recovery";

const RECOVERY_COOKIE_MAX_AGE_SECONDS =
  60 * 60 * 24 * 30;

const RECOVERY_COOKIE_SECRET =
  String(
    process.env.RECOVERY_COOKIE_SECRET
    || process.env.ADMIN_PASSWORD
    || ""
  ).trim();


function parseCookieHeader(req) {

  const result = {};

  const raw =
    String(
      req?.headers?.cookie || ""
    );

  for(const part of raw.split(";")) {

    const index = part.indexOf("=");

    if(index <= 0) {
      continue;
    }

    const key =
      part.slice(0,index).trim();

    const value =
      part.slice(index + 1).trim();

    if(!key) {
      continue;
    }

    try {
      result[key] = decodeURIComponent(value);
    }
    catch(error) {
      result[key] = value;
    }

  }

  return result;

}


function signRecoveryPayload(payload) {

  if(!RECOVERY_COOKIE_SECRET) {
    return "";
  }

  return crypto
    .createHmac(
      "sha256",
      RECOVERY_COOKIE_SECRET
    )
    .update(payload)
    .digest("base64url");

}


function createRecoveryCookieToken(
  clientId,
  eventId
) {

  const normalizedClientId =
    normalizeClientId(clientId);

  const normalizedEventId =
    Number(eventId);

  if(
    !normalizedClientId
    || !Number.isInteger(normalizedEventId)
    || normalizedEventId <= 0
    || !RECOVERY_COOKIE_SECRET
  ) {
    return "";
  }

  const payloadObject = {
    c: normalizedClientId,
    e: normalizedEventId,
    i: Date.now()
  };

  const payload =
    Buffer.from(
      JSON.stringify(payloadObject),
      "utf8"
    ).toString("base64url");

  const signature =
    signRecoveryPayload(payload);

  if(!signature) {
    return "";
  }

  return payload + "." + signature;

}


function readRecoveryCookie(req) {

  try {

    if(!RECOVERY_COOKIE_SECRET) {
      return null;
    }

    const cookies =
      parseCookieHeader(req);

    const token =
      String(
        cookies[RECOVERY_COOKIE_NAME] || ""
      ).trim();

    const dot =
      token.lastIndexOf(".");

    if(dot <= 0) {
      return null;
    }

    const payload =
      token.slice(0,dot);

    const signature =
      token.slice(dot + 1);

    const expected =
      signRecoveryPayload(payload);

    if(
      !expected
      || signature.length !== expected.length
      || !crypto.timingSafeEqual(
        Buffer.from(signature),
        Buffer.from(expected)
      )
    ) {
      return null;
    }

    const decoded =
      JSON.parse(
        Buffer.from(
          payload,
          "base64url"
        ).toString("utf8")
      );

    const clientId =
      normalizeClientId(decoded?.c);

    const eventId =
      Number(decoded?.e);

    const issuedAt =
      Number(decoded?.i);

    if(
      !clientId
      || !Number.isInteger(eventId)
      || eventId <= 0
      || !Number.isFinite(issuedAt)
    ) {
      return null;
    }

    if(
      Date.now() - issuedAt
      > RECOVERY_COOKIE_MAX_AGE_SECONDS * 1000
    ) {
      return null;
    }

    return {
      clientId,
      eventId,
      issuedAt
    };

  }
  catch(error) {
    return null;
  }

}


function setRecoveryCookie(
  res,
  clientId,
  eventId
) {

  const token =
    createRecoveryCookieToken(
      clientId,
      eventId
    );

  if(!token) {
    return false;
  }

  const attributes = [
    RECOVERY_COOKIE_NAME + "=" + encodeURIComponent(token),
    "Max-Age=" + RECOVERY_COOKIE_MAX_AGE_SECONDS,
    "Path=/",
    "HttpOnly",
    "SameSite=Lax",
    "Secure"
  ];

  res.append(
    "Set-Cookie",
    attributes.join("; ")
  );

  return true;

}




// V12: DADOS DO CLIENTE + RECONEXÃƒO POR CLIENT_ID
// REGRA OPERACIONAL: 1 EVENTO = 1 MIKROTIK
// ============================================================


// ============================================================
// PORTAL - RESOLVER EVENTO E MIKROTIK
//
// NOVO PADRÃƒO QUE O PORTAL PODERÃ ENVIAR:
//
// event_key
// router_key
//
// COMPATIBILIDADE:
// Enquanto o portal atual ainda nÃ£o envia esses campos,
// usamos automaticamente:
// - DEFAULT_EVENT
// - DEFAULT_ROUTER
// ============================================================

function resolvePortalContext(
  eventKeyValue,
  routerKeyValue
) {

  const requestedEventKey =
    safeText(
      eventKeyValue || ""
    )
      .slice(
        0,
        150
      );


  const requestedRouterKey =
    safeText(
      routerKeyValue || ""
    )
      .slice(
        0,
        150
      );


  let event =
    null;


  // ==========================================================
  // Se veio router_key, usamos apenas para descobrir o evento.
  // A escolha final da MikroTik sera sempre a UNICA MK ativa
  // daquele evento.
  // ==========================================================

  if(
    requestedRouterKey
  ) {

    const requestedRouter =
      db.prepare(`

        SELECT *

        FROM routers

        WHERE
          router_key=?
          AND status='active'

        LIMIT 1

      `).get(
        requestedRouterKey
      ) || null;


    if(
      requestedRouter
    ) {

      event =
        db.prepare(`

          SELECT *

          FROM events

          WHERE
            id=?
            AND status='active'

          LIMIT 1

        `).get(
          requestedRouter.event_id
        ) || null;

    }

  }


  // ==========================================================
  // Se o portal informou event_key, ele identifica o evento.
  // ==========================================================

  if(
    !event
    &&
    requestedEventKey
  ) {

    event =
      db.prepare(`

        SELECT *

        FROM events

        WHERE
          event_key=?
          AND status='active'

        LIMIT 1

      `).get(
        requestedEventKey
      ) || null;

  }


  // ==========================================================
  // Compatibilidade com a instalacao principal atual.
  // ==========================================================

  if(
    !event
  ) {

    event =
      db.prepare(`

        SELECT *

        FROM events

        WHERE
          id=?
          AND status='active'

        LIMIT 1

      `).get(
        DEFAULT_EVENT.id
      ) || null;

  }


  if(
    !event
  ) {

    return {

      ok:
        false,

      error:
        "Evento nÃ£o encontrado",

      event:
        null,

      router:
        null

    };

  }


  // ==========================================================
  // REGRA NOVA: 1 EVENTO = 1 MIKROTIK.
  // Se houver dados antigos com mais de uma MK ativa, usamos
  // primeiro a primary e depois o menor ID.
  // ==========================================================

  const router =
    db.prepare(`

      SELECT *

      FROM routers

      WHERE
        event_id=?
        AND status='active'

      ORDER BY
        CASE
          WHEN role='primary' THEN 0
          ELSE 1
        END,
        id ASC

      LIMIT 1

    `).get(
      event.id
    ) || null;


  if(
    !router
  ) {

    return {

      ok:
        false,

      error:
        "Este evento nÃ£o possui MikroTik ativa",

      event,

      router:
        null

    };

  }


  return {

    ok:
      true,

    event,

    router

  };

}


// ============================================================
// PORTAL - LOCALIZAR PLANO DO EVENTO
//
// Primeiro usamos event_plans.
// No evento padrÃ£o, PLANS continua como fallback.
// ============================================================

function resolveEventPlan(
  eventId,
  planId
) {

  const key =
    safeText(
      planId || ""
    )
      .slice(
        0,
        100
      );


  if(
    !key
  ) {

    return null;

  }


  const eventPlan =
    db.prepare(`

      SELECT *

      FROM event_plans

      WHERE
        event_id=?
        AND plan_key=?
        AND active=1
        AND deleted_at IS NULL

      LIMIT 1

    `).get(
      eventId,
      key
    );


  if(
    eventPlan
  ) {

    return {

      id:
        eventPlan.plan_key,

      name:
        eventPlan.name,

      amount:
        Number(
          eventPlan.amount
        ),

      minutes:
        Number(
          eventPlan.minutes
        ),

      rate:
        eventPlan.rate_limit,

      mikrotikProfile:
        eventPlan.mikrotik_profile,

      description:
        eventPlan.description || ""

    };

  }


  if(
    Number(
      eventId
    ) ===
    Number(
      DEFAULT_EVENT.id
    )
  ) {

    const legacy =
      PLANS[
        key
      ];


    if(
      legacy
    ) {

      return {

        id:
          legacy.id,

        name:
          legacy.name,

        amount:
          Number(
            legacy.amount
          ),

        minutes:
          Number(
            legacy.minutes
          ),

        rate:
          legacy.rate,

        mikrotikProfile:
          legacy.mikrotikProfile,

        description:
          legacy.name

      };

    }

  }


  return null;

}


// ============================================================
// PORTAL - DADOS CADASTRAIS DO CLIENTE
// ============================================================

function normalizeCustomerName(
  value
) {

  return String(
    value || ""
  )
    .replace(
      /\s+/g,
      " "
    )
    .trim()
    .slice(
      0,
      80
    );

}


function normalizeCustomerPhone(
  value
) {

  let digits =
    String(
      value || ""
    )
      .replace(
        /\D/g,
        ""
      );

  // Brasil: se vier somente DDD + nÃºmero, prefixamos 55.
  if(
    digits.length === 10
    ||
    digits.length === 11
  ) {
    digits =
      "55" +
      digits;
  }

  if(
    digits.length < 12
    ||
    digits.length > 13
  ) {
    return "";
  }

  return digits;

}


function normalizeCustomerEmail(
  value
) {

  const email =
    String(
      value || ""
    )
      .trim()
      .toLowerCase()
      .slice(
        0,
        160
      );

  if(
    !/^[^\s@]+@[^\s@]+\.[^\s@]+$/
      .test(
        email
      )
  ) {
    return "";
  }

  return email;

}


function upsertCustomerProfile({
  clientId,
  name,
  phone,
  email
}) {

  const normalizedClientId =
    normalizeClientId(
      clientId
    );

  if(
    !normalizedClientId
  ) {
    return null;
  }

  const now =
    nowIso();


  db.prepare(`

    INSERT INTO customers (
      client_id,
      name,
      phone,
      email,
      created_at,
      updated_at,
      last_seen_at
    )

    VALUES (
      ?, ?, ?, ?, ?, ?, ?
    )

    ON CONFLICT(client_id)
    DO UPDATE SET
      name=COALESCE(NULLIF(excluded.name,''), customers.name),
      phone=COALESCE(NULLIF(excluded.phone,''), customers.phone),
      email=COALESCE(NULLIF(excluded.email,''), customers.email),
      updated_at=excluded.updated_at,
      last_seen_at=excluded.last_seen_at

  `).run(
    normalizedClientId,
    name || null,
    phone || null,
    email || null,
    now,
    now,
    now
  );


  return db.prepare(`

    SELECT *
    FROM customers
    WHERE client_id=?
    LIMIT 1

  `).get(
    normalizedClientId
  ) || null;

}


// ============================================================
// PORTAL - LOCALIZAR ACESSO PAGO AINDA VÃLIDO
//
// REGRA:
// mesmo client_id + mesmo evento + plano ainda nÃ£o vencido.
//
// NÃƒO usamos router_id para definir o direito de acesso.
// router_id apenas indica onde o cliente comprou / estÃ¡ entrando.
// ============================================================

function findActivePaidAccess(
  eventId,
  clientId
) {

  const normalizedClientId =
    normalizeClientId(
      clientId
    );


  if(
    !normalizedClientId
  ) {

    return null;

  }


  const now =
    nowIso();


  return db.prepare(`

    SELECT *

    FROM orders

    WHERE
      event_id=?
      AND client_id=?
      AND status='approved'
      AND access_expires_at IS NOT NULL
      AND access_expired_at IS NULL
      AND access_expires_at > ?

    ORDER BY
      access_expires_at DESC,
      id DESC

    LIMIT 1

  `).get(
    eventId,
    normalizedClientId,
    now
  ) || null;

}



// ============================================================
// V16.4 - RECUPERAR ACESSO PAGO POR TELEFONE + E-MAIL
//
// Usado quando o navegador cativo perdeu o client_id apÃ³s uma
// troca de MAC privado.
//
// SeguranÃ§a:
// - exige telefone E e-mail vÃ¡lidos;
// - considera somente plano pago ainda ativo;
// - restringe ao mesmo evento;
// - nÃ£o reinicia o relÃ³gio do plano.
// ============================================================

function findActivePaidAccessByContact(
  eventId,
  phone,
  email,
  name = ""
) {

  const normalizedPhone =
    normalizeCustomerPhone(
      phone
    );

  const normalizedEmail =
    normalizeCustomerEmail(
      email
    );

  const normalizedName =
    normalizeCustomerName(
      name
    );

  if(
    !normalizedPhone
    ||
    !normalizedEmail
  ) {

    console.log(
      "RECOVERY V16.13: dados invalidos",
      "EVENTO=" + eventId,
      "PHONE_OK=" + Boolean(normalizedPhone),
      "EMAIL_OK=" + Boolean(normalizedEmail)
    );

    return null;

  }

  const nowMs =
    Date.now();

  const candidates =
    db.prepare(`

      SELECT
        o.*,
        c.name AS profile_name,
        c.phone AS profile_phone,
        c.email AS profile_email

      FROM orders o

      LEFT JOIN customers c
        ON c.client_id=o.client_id

      WHERE
        o.event_id=?
        AND o.status IN (
          'approved',
          'approved_pending_router'
        )
        AND o.approved_at IS NOT NULL
        AND o.access_expired_at IS NULL

      ORDER BY
        o.id DESC

      LIMIT 50

    `).all(
      eventId
    );

  console.log(
    "RECOVERY V16.13: candidatos",
    "EVENTO=" + eventId,
    "TOTAL=" + candidates.length
  );

  const validMatches = [];

  for(
    const candidate
    of candidates
  ) {

    const candidateEmail =
      normalizeCustomerEmail(
        candidate.customer_email
        ||
        candidate.payer_email
        ||
        candidate.profile_email
        ||
        ""
      );

    const candidatePhone =
      normalizeCustomerPhone(
        candidate.customer_phone
        ||
        candidate.profile_phone
        ||
        ""
      );

    const candidateName =
      normalizeCustomerName(
        candidate.customer_name
        ||
        candidate.profile_name
        ||
        ""
      );

    let expiresMs =
      Date.parse(
        candidate.access_expires_at
        ||
        ""
      );

    let reconstructedExpiration =
      false;

    if(
      !Number.isFinite(
        expiresMs
      )
    ) {

      const approvedMs =
        Date.parse(
          candidate.approved_at
          ||
          ""
        );

      const minutes =
        Number(
          candidate.minutes
          ||
          0
        );

      if(
        Number.isFinite(
          approvedMs
        )
        &&
        Number.isFinite(
          minutes
        )
        &&
        minutes > 0
      ) {

        expiresMs =
          approvedMs
          +
          (
            minutes
            *
            60
            *
            1000
          );

        reconstructedExpiration =
          true;

      }

    }

    if(
      !Number.isFinite(
        expiresMs
      )
    ) {

      console.log(
        "RECOVERY V16.13: rejeitado sem vencimento",
        candidate.external_ref
      );

      continue;

    }

    if(
      expiresMs <=
      nowMs
    ) {

      console.log(
        "RECOVERY V16.13: rejeitado expirado",
        candidate.external_ref,
        "EXPIRA=" +
          new Date(
            expiresMs
          ).toISOString()
      );

      continue;

    }

    if(
      !candidateEmail
      ||
      candidateEmail !==
        normalizedEmail
    ) {

      console.log(
        "RECOVERY V16.13: rejeitado email",
        candidate.external_ref
      );

      continue;

    }

    if(
      candidatePhone
      &&
      candidatePhone !==
        normalizedPhone
    ) {

      console.log(
        "RECOVERY V16.13: rejeitado telefone",
        candidate.external_ref
      );

      continue;

    }

    if(
      !candidatePhone
      &&
      candidateName
    ) {

      if(
        !normalizedName
        ||
        candidateName.toLowerCase()
        !==
        normalizedName.toLowerCase()
      ) {

        console.log(
          "RECOVERY V16.13: rejeitado nome legado",
          candidate.external_ref
        );

        continue;

      }

    }

    validMatches.push({
      candidate,
      expiresMs,
      reconstructedExpiration
    });

    console.log(
      "RECOVERY V16.13: candidato valido",
      candidate.external_ref,
      "LEGACY_EXPIRATION=" +
        reconstructedExpiration,
      "EXPIRA=" +
        new Date(
          expiresMs
        ).toISOString()
    );

  }

  if(
    validMatches.length !==
    1
  ) {

    console.log(
      "RECOVERY V16.13: nao recuperado",
      "EVENTO=" + eventId,
      "MATCHES=" + validMatches.length
    );

    return null;

  }

  const match =
    validMatches[0];

  const candidate =
    match.candidate;

  if(
    match.reconstructedExpiration
    &&
    !candidate.access_expires_at
  ) {

    const reconstructedIso =
      new Date(
        match.expiresMs
      ).toISOString();

    db.prepare(`

      UPDATE orders

      SET
        access_expires_at=?

      WHERE
        id=?
        AND (
          access_expires_at IS NULL
          OR
          TRIM(access_expires_at)=''
        )

    `).run(
      reconstructedIso,
      candidate.id
    );

    candidate.access_expires_at =
      reconstructedIso;

    console.log(
      "RECOVERY V16.13: vencimento legado reconstruido",
      candidate.external_ref,
      reconstructedIso
    );

  }

  candidate.recovery_customer_name =
    candidate.customer_name
    ||
    candidate.profile_name
    ||
    "";

  candidate.recovery_customer_phone =
    candidate.customer_phone
    ||
    candidate.profile_phone
    ||
    "";

  candidate.recovery_customer_email =
    candidate.customer_email
    ||
    candidate.profile_email
    ||
    candidate.payer_email
    ||
    "";

  console.log(
    "RECOVERY V16.13: ACESSO ENCONTRADO",
    candidate.external_ref,
    "CLIENT_ANTIGO=" +
      String(
        candidate.client_id
        ||
        ""
      ),
    "EXPIRA=" +
      String(
        candidate.access_expires_at
        ||
        ""
      )
  );

  return candidate;

}


// ============================================================
// PORTAL - CRIAR / ATUALIZAR GRANT DA MIKROTIK DO EVENTO
//
// Se o cliente jÃ¡ possui plano vÃ¡lido no evento, garantimos que
// exista um grant para a Ãºnica MikroTik daquele evento.
//
// Se jÃ¡ existe grant ACTIVE, apenas atualizamos MAC/IP/last_seen.
//
// Se havia grant EXPIRED/INVALID mas o plano global continua
// vÃ¡lido, reabrimos como PENDING.
// ============================================================

function ensureRouterGrant(
  order,
  router,
  mac,
  ip
) {

  if(
    !order
    ||
    !router
  ) {

    return null;

  }


  const normalizedMac =
    normalizeMac(
      mac
      ||
      order.effective_mac
      ||
      order.mac
      ||
      order.original_mac
    );


  const normalizedIp =
    normalizeIp(
      ip
      ||
      order.ip
    );


  const now =
    nowIso();


  let grant =
    db.prepare(`

      SELECT *

      FROM router_access_grants

      WHERE
        order_id=?
        AND router_id=?

      LIMIT 1

    `).get(
      order.id,
      router.id
    );


  if(
    !grant
  ) {

    db.prepare(`

      INSERT INTO router_access_grants (

        order_id,
        event_id,
        router_id,
        client_id,
        mac,
        ip,
        status,
        requested_at,
        applied_at,
        last_seen_at,
        expired_at,
        updated_at

      )

      VALUES (
        ?, ?, ?, ?, ?, ?, 'pending', ?, NULL, ?, NULL, ?
      )

    `).run(

      order.id,
      order.event_id,
      router.id,
      order.client_id || null,
      normalizedMac || null,
      normalizedIp || null,
      now,
      now,
      now

    );


    grant =
      db.prepare(`

        SELECT *

        FROM router_access_grants

        WHERE
          order_id=?
          AND router_id=?

        LIMIT 1

      `).get(
        order.id,
        router.id
      );


    return grant || null;

  }


  if(
    grant.status ===
    "active"
  ) {

    // ========================================================
    // RECONEXÃƒO / MAC PRIVADO ALTERADO
    //
    // O direito ao plano pertence ao CLIENT_ID, nÃ£o ao MAC.
    // Se o mesmo cliente voltar com outro MAC privado,
    // reabrimos apenas o grant da MikroTik como pending.
    // access_expires_at NÃƒO Ã© alterado, entÃ£o sÃ³ o tempo
    // restante serÃ¡ aplicado.
    // ========================================================

    const previousMac =
      normalizeMac(
        grant.mac
      );

    const macChanged =
      Boolean(
        normalizedMac
        &&
        previousMac
        &&
        normalizedMac !==
          previousMac
      );


    if(
      macChanged
    ) {

      db.prepare(`

        UPDATE router_access_grants

        SET
          status='pending',
          mac=?,
          ip=COALESCE(?, ip),
          requested_at=?,
          applied_at=NULL,
          last_seen_at=?,
          expired_at=NULL,
          updated_at=?

        WHERE id=?

      `).run(

        normalizedMac,
        normalizedIp || null,
        now,
        now,
        now,
        grant.id

      );


      console.log(
        "ROAMING MAC DETECTADO:",
        order.external_ref,
        "CLIENT=" +
          String(
            order.client_id || ""
          ),
        "MAC_ANTIGO=" +
          String(
            previousMac || ""
          ),
        "MAC_NOVO=" +
          String(
            normalizedMac || ""
          ),
        "IP_NOVO=" +
          String(
            normalizedIp || ""
          )
      );

    }

    else {

      db.prepare(`

        UPDATE router_access_grants

        SET
          mac=COALESCE(?, mac),
          ip=COALESCE(?, ip),
          last_seen_at=?,
          updated_at=?

        WHERE id=?

      `).run(

        normalizedMac || null,
        normalizedIp || null,
        now,
        now,
        grant.id

      );

    }

  }


  else if(
    [
      "expired",
      "invalid_client_data"
    ].includes(
      grant.status
    )
  ) {

    db.prepare(`

      UPDATE router_access_grants

      SET
        status='pending',
        mac=COALESCE(?, mac),
        ip=COALESCE(?, ip),
        requested_at=?,
        applied_at=NULL,
        last_seen_at=?,
        expired_at=NULL,
        updated_at=?

      WHERE id=?

    `).run(

      normalizedMac || null,
      normalizedIp || null,
      now,
      now,
      now,
      grant.id

    );

  }


  else {

    db.prepare(`

      UPDATE router_access_grants

      SET
        mac=COALESCE(?, mac),
        ip=COALESCE(?, ip),
        last_seen_at=?,
        updated_at=?

      WHERE id=?

    `).run(

      normalizedMac || null,
      normalizedIp || null,
      now,
      now,
      grant.id

    );

  }


  return db.prepare(`

    SELECT *

    FROM router_access_grants

    WHERE id=?

  `).get(
    grant.id
  ) || null;

}


// ============================================================
// PORTAL - RESUMO DO ACESSO ATIVO
// ============================================================

function buildActiveAccessResponse(
  order,
  router,
  grant
) {

  const expiresMs =
    Date.parse(
      order.access_expires_at
    );


  const remainingSeconds =
    Number.isFinite(
      expiresMs
    )
      ? Math.max(
          0,
          Math.floor(
            (
              expiresMs
              -
              Date.now()
            )
            /
            1000
          )
        )
      : 0;


  return {

    active:
      remainingSeconds > 0,

    order:
      order.external_ref,

    event_id:
      Number(
        order.event_id
      ),

    router_id:
      Number(
        router.id
      ),

    router_key:
      router.router_key,

    plan_id:
      order.plan_id,

    expires_at:
      order.access_expires_at,

    remaining_seconds:
      remainingSeconds,

    remaining_minutes:
      Math.max(
        0,
        Math.ceil(
          remainingSeconds
          /
          60
        )
      ),

    grant_status:
      grant?.status || null

  };

}


// ============================================================
// V15 - PORTAL -> FUNIL DE CONVERSAO
//
// O navegador registra somente etapas que realmente acontecem
// na interface. Etapas financeiras e da MikroTik sao gravadas
// exclusivamente pelo backend/ACK/heartbeat.
// ============================================================

app.post(
  "/api/funnel/event",
  (req, res) => {

    try {

      const step =
        normalizeFunnelStep(
          req.body?.step
        );


      const PORTAL_FUNNEL_STEPS =
        new Set([
          "PORTAL_OPENED",
          "REGISTRATION_STARTED",
          "REGISTRATION_COMPLETED",
          "PLAN_SELECTED",
          "PIX_COPIED"
        ]);


      if(
        !PORTAL_FUNNEL_STEPS.has(step)
      ) {

        return res
          .status(400)
          .json({
            ok:false,
            error:"Etapa do funil invalida"
          });

      }


      const context =
        resolvePortalContext(
          req.body?.event_key,
          req.body?.router_key
        );


      if(
        !context.ok
      ) {

        return res
          .status(400)
          .json({
            ok:false,
            error:context.error
          });

      }


      const normalizedClientId =
        normalizeClientId(
          req.body?.client_id
        );

      const normalizedMac =
        normalizeMac(
          req.body?.mac
        );

      const normalizedIp =
        normalizeIp(
          req.body?.ip
        );


      // ======================================================
      // V15.4 - SALVAR CADASTRO MESMO SEM GERAR / PAGAR PIX
      //
      // REGISTRATION_COMPLETED acontece antes da criacao do PIX.
      // Assim o cliente passa a existir no painel mesmo que ele
      // abandone o funil antes do pagamento.
      // ======================================================

      let customerSaved =
        false;


      if(
        step ===
        "REGISTRATION_COMPLETED"
        &&
        normalizedClientId
      ){

        const normalizedCustomerName =
          normalizeCustomerName(
            req.body?.customer_name
          );

        const normalizedCustomerPhone =
          normalizeCustomerPhone(
            req.body?.customer_phone
          );

        const normalizedCustomerEmail =
          normalizeCustomerEmail(
            req.body?.email
          );


        if(
          normalizedCustomerName.length >= 2
          &&
          normalizedCustomerPhone
          &&
          normalizedCustomerEmail
        ){

          upsertCustomerProfile({
            clientId:
              normalizedClientId,
            name:
              normalizedCustomerName,
            phone:
              normalizedCustomerPhone,
            email:
              normalizedCustomerEmail
          });

          customerSaved =
            true;

        }

      }


      const orderRef =
        String(
          req.body?.order
          ||
          req.body?.order_ref
          ||
          ""
        ).trim();


      let orderRow =
        null;


      if(
        orderRef
      ) {

        orderRow =
          db.prepare(`
            SELECT *
            FROM orders
            WHERE
              external_ref=?
              AND event_id=?
            LIMIT 1
          `).get(
            orderRef,
            context.event.id
          ) || null;

      }


      // Liga a deteccao feita pela MikroTik ao CLIENT_ID assim que
      // o portal consegue identificar o navegador.
      if(
        step === "PORTAL_OPENED"
        &&
        normalizedClientId
        &&
        normalizedMac
      ){
        const cutoff =
          new Date(
            Date.now() - 30 * 60 * 1000
          ).toISOString();

        db.prepare(`
          UPDATE funnel_events
          SET client_id=?
          WHERE
            event_id=?
            AND router_id=?
            AND step='HOTSPOT_DETECTED'
            AND mac=?
            AND client_id IS NULL
            AND created_at>=?
        `).run(
          normalizedClientId,
          context.event.id,
          context.router.id,
          normalizedMac,
          cutoff
        );
      }


      const saved =
        recordFunnelEventOnce({
          eventId:
            context.event.id,
          routerId:
            context.router.id,
          clientId:
            normalizedClientId
            ||
            orderRow?.client_id
            ||
            null,
          mac:
            normalizedMac
            ||
            orderRow?.effective_mac
            ||
            orderRow?.mac
            ||
            null,
          ip:
            normalizedIp
            ||
            orderRow?.ip
            ||
            null,
          orderId:
            orderRow?.id
            ||
            null,
          orderRef:
            orderRow?.external_ref
            ||
            orderRef
            ||
            null,
          step,
          planId:
            req.body?.plan_id
            ||
            orderRow?.plan_id
            ||
            null,
          source:
            "portal",
          metadata:
            req.body?.metadata
            ||
            null,
          dedupeWindowSeconds:
            30,
          dedupeByOrder:
            Boolean(orderRow?.id)
        });


      return res.json({
        ok:true,
        funnel_event_id:
          saved?.id || null,
        step:
          saved?.step || step,
        customer_saved:
          customerSaved
      });

    }
    catch(error) {

      console.error(
        "FUNIL PORTAL: erro ao registrar etapa:",
        error
      );

      return res
        .status(500)
        .json({
          ok:false,
          error:"Erro ao registrar etapa do funil"
        });

    }

  }
);


// ============================================================
// VERIFICAR ACESSO ANTES DE MOSTRAR / GERAR PIX
//
// FUTURO PORTAL:
// POST /api/access/check
//
// Body:
// {
//   client_id,
//   mac,
//   ip,
//   event_key,
//   router_key
// }
//
// Se existir plano vÃ¡lido, garante o grant da MikroTik do evento.
// ============================================================

app.post(
  "/api/access/check",
  (req, res) => {

    try {

      const context =
        resolvePortalContext(
          req.body?.event_key,
          req.body?.router_key
        );


      if(
        !context.ok
      ) {

        return res
          .status(
            400
          )
          .json({

            ok:
              false,

            error:
              context.error

          });

      }


      const normalizedClientId =
        normalizeClientId(
          req.body?.client_id
        );


      const normalizedMac =
        normalizeMac(
          req.body?.mac
        );


      const normalizedIp =
        normalizeIp(
          req.body?.ip
        );


      if(
        !normalizedClientId
      ) {

        return res
          .status(
            400
          )
          .json({

            ok:
              false,

            error:
              "Identificador do cliente invÃ¡lido"

          });

      }


      let activeOrder =
        findActivePaidAccess(
          context.event.id,
          normalizedClientId
        );


      // ======================================================
      // V16.17 - MIGRACAO AUTOMATICA DA IDENTIDADE ANTIGA
      //
      // Quando o DEVICE_ID persistente foi restaurado, o portal
      // pode enviar tambÃ©m o client_id antigo que ainda estava
      // salvo no navegador do dominio Railway.
      //
      // Se esse client_id antigo possui um plano pago ainda ativo
      // no MESMO evento, o direito de acesso e migrado uma unica
      // vez para o DEVICE_ID atual.
      //
      // Isso evita pedir nome/telefone/e-mail para clientes que
      // ja pagaram antes da restauracao do DEVICE_ID.
      // ======================================================

      let recoveredByLegacyIdentity =
        false;

      const normalizedLegacyClientId =
        normalizeClientId(
          req.body?.legacy_client_id
        );


      if(
        !activeOrder
        &&
        normalizedLegacyClientId
        &&
        normalizedLegacyClientId !==
          normalizedClientId
      ) {

        const legacyOrder =
          findActivePaidAccess(
            context.event.id,
            normalizedLegacyClientId
          );


        if(
          legacyOrder
        ) {

          const legacyCustomer =
            db.prepare(`

              SELECT *

              FROM customers

              WHERE client_id=?

              LIMIT 1

            `).get(
              normalizedLegacyClientId
            ) || null;


          const migrationNow =
            nowIso();


          const migrateLegacyIdentity =
            db.transaction(
              () => {

                if(
                  legacyCustomer
                ) {

                  upsertCustomerProfile({
                    clientId:
                      normalizedClientId,
                    name:
                      legacyCustomer.name || "",
                    phone:
                      legacyCustomer.phone || "",
                    email:
                      legacyCustomer.email || ""
                  });

                }


                db.prepare(`

                  UPDATE orders

                  SET
                    client_id=?,
                    effective_mac=?,
                    ip=?,
                    portal_last_seen_at=?

                  WHERE id=?

                `).run(
                  normalizedClientId,
                  normalizedMac,
                  normalizedIp,
                  migrationNow,
                  legacyOrder.id
                );


                db.prepare(`

                  UPDATE router_access_grants

                  SET
                    client_id=?,
                    updated_at=?

                  WHERE order_id=?

                `).run(
                  normalizedClientId,
                  migrationNow,
                  legacyOrder.id
                );

              }
            );


          migrateLegacyIdentity();


          activeOrder =
            db.prepare(`

              SELECT *

              FROM orders

              WHERE id=?

              LIMIT 1

            `).get(
              legacyOrder.id
            ) || null;


          recoveredByLegacyIdentity =
            Boolean(
              activeOrder
            );


          if(
            recoveredByLegacyIdentity
          ) {

            console.log(
              "V16.17 DEVICE_ID MIGRATION:",
              activeOrder.external_ref,
              "CLIENT_ANTIGO=" +
                normalizedLegacyClientId,
              "CLIENT_NOVO=" +
                normalizedClientId,
              "MAC_NOVO=" +
                String(
                  normalizedMac || ""
                )
            );

          }

        }

      }


      // ======================================================
      // V16.11 - RECUPERACAO AUTOMATICA VIA COOKIE HTTPONLY
      //
      // Se o captive portal perdeu o client_id JS e criou outro,
      // tentamos a identidade assinada pelo backend.
      // O cookie so vale para o mesmo evento e somente para um
      // pedido pago que ainda nao venceu.
      // ======================================================

      let recoveredByCookie =
        false;

      if(
        !activeOrder
      ) {

        const recoveryIdentity =
          readRecoveryCookie(req);

        if(
          recoveryIdentity
          && recoveryIdentity.eventId === Number(context.event.id)
          && recoveryIdentity.clientId !== normalizedClientId
        ) {

          const recoveryOrder =
            findActivePaidAccess(
              context.event.id,
              recoveryIdentity.clientId
            );

          if(recoveryOrder) {

            const oldCustomer =
              db.prepare(`
                SELECT *
                FROM customers
                WHERE client_id=?
                LIMIT 1
              `).get(
                recoveryIdentity.clientId
              );

            const now =
              nowIso();

            const migrate =
              db.transaction(
                () => {

                  if(oldCustomer) {
                    upsertCustomerProfile({
                      clientId: normalizedClientId,
                      name: oldCustomer.name || "",
                      phone: oldCustomer.phone || "",
                      email: oldCustomer.email || ""
                    });
                  }

                  db.prepare(`
                    UPDATE orders
                    SET
                      client_id=?,
                      effective_mac=?,
                      ip=?,
                      portal_last_seen_at=?
                    WHERE id=?
                  `).run(
                    normalizedClientId,
                    normalizedMac,
                    normalizedIp,
                    now,
                    recoveryOrder.id
                  );

                  db.prepare(`
                    UPDATE router_access_grants
                    SET
                      client_id=?,
                      updated_at=?
                    WHERE order_id=?
                  `).run(
                    normalizedClientId,
                    now,
                    recoveryOrder.id
                  );

                }
              );

            migrate();

            activeOrder =
              db.prepare(`
                SELECT *
                FROM orders
                WHERE id=?
                LIMIT 1
              `).get(
                recoveryOrder.id
              );

            recoveredByCookie =
              Boolean(activeOrder);

            if(recoveredByCookie) {
              console.log(
                "V16.11 RECOVERY COOKIE:",
                activeOrder.external_ref,
                "CLIENT_ANTIGO=" + recoveryIdentity.clientId,
                "CLIENT_NOVO=" + normalizedClientId,
                "MAC_NOVO=" + normalizedMac
              );
            }

          }

        }

      }


      if(
        !activeOrder
      ) {

        return res.json({

          ok:
            true,

          active:
            false,

          event: {

            id:
              Number(
                context.event.id
              ),

            event_key:
              context.event.event_key,

            name:
              context.event.name

          },

          router: {

            id:
              Number(
                context.router.id
              ),

            router_key:
              context.router.router_key,

            name:
              context.router.name

          }

        });

      }


      setRecoveryCookie(
        res,
        normalizedClientId,
        context.event.id
      );


      const grant =
        ensureRouterGrant(
          activeOrder,
          context.router,
          normalizedMac,
          normalizedIp
        );


      return res.json({

        ok:
          true,

        recovered_by_cookie:
          recoveredByCookie,

        recovered_by_legacy_identity:
          recoveredByLegacyIdentity,

        ...buildActiveAccessResponse(
          activeOrder,
          context.router,
          grant
        )

      });

    }


    catch(error) {

      console.error(
        "Erro ao verificar acesso ativo:",
        error
      );


      return res
        .status(
          500
        )
        .json({

          ok:
            false,

          error:
            "Erro ao verificar acesso ativo"

        });

    }

  }
);



// ============================================================
// V16.4 - RECUPERAR PLANO ATIVO APÃ“S TROCA DE MAC
//
// POST /api/access/recover
//
// Body:
// {
//   client_id,
//   phone,
//   email,
//   mac,
//   ip,
//   event_key,
//   router_key
// }
//
// Se telefone + e-mail identificarem um plano ainda vÃ¡lido:
// - migra o pedido ativo para o novo client_id;
// - atualiza o grant para o novo client_id;
// - envia o novo MAC/IP para ensureRouterGrant();
// - o grant volta para pending se o MAC mudou;
// - a MikroTik recebe ALLOW apenas com o tempo restante.
// ============================================================

app.post(
  "/api/access/recover",
  limitRecoveryByIp,
  limitRecoveryByClient,
  (req, res) => {

    try {

      const context =
        resolvePortalContext(
          req.body?.event_key,
          req.body?.router_key
        );


      if(
        !context.ok
      ) {

        return res
          .status(400)
          .json({
            ok:false,
            error:context.error
          });

      }


      const normalizedClientId =
        normalizeClientId(
          req.body?.client_id
        );

      const normalizedPhone =
        normalizeCustomerPhone(
          req.body?.phone
        );

      const normalizedEmail =
        normalizeCustomerEmail(
          req.body?.email
        );

      const normalizedMac =
        normalizeMac(
          req.body?.mac
        );

      const normalizedIp =
        normalizeIp(
          req.body?.ip
        );


      if(
        !normalizedClientId
      ) {

        return res
          .status(400)
          .json({
            ok:false,
            error:"Identificador do cliente invÃ¡lido"
          });

      }


      if(
        !normalizedPhone
      ) {

        return res
          .status(400)
          .json({
            ok:false,
            error:"Informe um telefone vÃ¡lido com DDD"
          });

      }


      if(
        !normalizedEmail
      ) {

        return res
          .status(400)
          .json({
            ok:false,
            error:"Informe o mesmo e-mail usado no pagamento"
          });

      }


      if(
        !normalizedMac
        ||
        !normalizedIp
      ) {

        return res
          .status(400)
          .json({
            ok:false,
            error:"MAC ou IP atual invÃ¡lido"
          });

      }


      const activeOrder =
        findActivePaidAccessByContact(
          context.event.id,
          normalizedPhone,
          normalizedEmail,
          normalizeCustomerName(
            req.body?.customer_name || ""
          )
        );


      if(
        !activeOrder
      ) {

        return res.json({
          ok:true,
          active:false,
          recovered:false,
          error:
            "Nenhum plano ativo foi encontrado para este telefone e e-mail."
        });

      }


      const oldClientId =
        normalizeClientId(
          activeOrder.client_id
        );


      const now =
        nowIso();


      const transaction =
        db.transaction(
          () => {

            // Cria/atualiza o cadastro no NOVO client_id.
            upsertCustomerProfile({
              clientId:
                normalizedClientId,
              name:
                activeOrder.recovery_customer_name
                ||
                "",
              phone:
                normalizedPhone,
              email:
                normalizedEmail
            });


            // O direito de acesso passa a acompanhar o novo client_id.
            db.prepare(`

              UPDATE orders

              SET
                client_id=?,
                effective_mac=?,
                ip=?,
                portal_last_seen_at=?

              WHERE id=?

            `).run(
              normalizedClientId,
              normalizedMac,
              normalizedIp,
              now,
              activeOrder.id
            );


            db.prepare(`

              UPDATE router_access_grants

              SET
                client_id=?,
                updated_at=?

              WHERE order_id=?

            `).run(
              normalizedClientId,
              now,
              activeOrder.id
            );

          }
        );


      transaction();


      const refreshedOrder =
        db.prepare(`

          SELECT *

          FROM orders

          WHERE id=?

          LIMIT 1

        `).get(
          activeOrder.id
        );


      const grant =
        ensureRouterGrant(
          refreshedOrder,
          context.router,
          normalizedMac,
          normalizedIp
        );


      console.log(
        "ACESSO RECUPERADO:",
        refreshedOrder.external_ref,
        "CLIENT_ANTIGO=" +
          String(oldClientId || ""),
        "CLIENT_NOVO=" +
          normalizedClientId,
        "MAC_NOVO=" +
          normalizedMac
      );


      setRecoveryCookie(
        res,
        normalizedClientId,
        context.event.id
      );


      return res.json({
        ok:true,
        recovered:true,
        previous_client_id:
          oldClientId || null,
        ...buildActiveAccessResponse(
          refreshedOrder,
          context.router,
          grant
        )
      });

    }


    catch(error) {

      console.error(
        "Erro ao recuperar acesso ativo:",
        error
      );


      return res
        .status(500)
        .json({
          ok:false,
          error:"Erro ao recuperar o acesso"
        });

    }

  }
);


// ============================================================
// CRIAR PIX
// ============================================================

app.post(
  "/api/pix",
  limitPixByIp,
  limitPixByClient,
  async (req, res) => {

    try {

      const {

        plan_id,

        mac,

        ip,

        customer_name,

        customer_phone,

        email,

        client_id,

        event_key,

        router_key

      } = req.body;


      // ======================================================
      // IDENTIFICAR EVENTO E MIKROTIK
      // ======================================================

      const context =
        resolvePortalContext(
          event_key,
          router_key
        );


      if(
        !context.ok
      ) {

        return res
          .status(
            400
          )
          .json({

            error:
              context.error

          });

      }


      // ======================================================
      // VALIDAR PLANO DO EVENTO
      // ======================================================

      const plan =
        resolveEventPlan(
          context.event.id,
          plan_id
        );


      if (
        !plan
      ) {

        return res
          .status(
            400
          )
          .json({

            error:
              "Plano invÃ¡lido para este evento"

          });

      }


      // ======================================================
      // NORMALIZAR DADOS DO CLIENTE
      // ======================================================

      const normalizedMac =

        normalizeMac(
          mac
        );


      const normalizedIp =

        normalizeIp(
          ip
        );


      const normalizedClientId =

        normalizeClientId(
          client_id
        );


      if (

        !normalizedMac

        ||

        !normalizedIp

      ) {

        return res
          .status(
            400
          )
          .json({

            error:
              "MAC ou IP invÃ¡lido"

          });

      }


      if (
        !normalizedClientId
      ) {

        return res
          .status(
            400
          )
          .json({

            error:
              "Identificador do cliente invÃ¡lido"

          });

      }


      // ======================================================
      // VALIDAR DADOS CADASTRAIS
      // ======================================================

      const normalizedCustomerName =
        normalizeCustomerName(
          customer_name
        );

      const normalizedCustomerPhone =
        normalizeCustomerPhone(
          customer_phone
        );

      const normalizedCustomerEmail =
        normalizeCustomerEmail(
          email
        );


      if(
        normalizedCustomerName.length < 2
      ) {

        return res
          .status(
            400
          )
          .json({
            error:
              "Informe seu nome"
          });

      }


      if(
        !normalizedCustomerPhone
      ) {

        return res
          .status(
            400
          )
          .json({
            error:
              "Informe um telefone vÃ¡lido com DDD"
          });

      }


      if(
        !normalizedCustomerEmail
      ) {

        return res
          .status(
            400
          )
          .json({
            error:
              "Informe um e-mail vÃ¡lido"
          });

      }


      const customer =
        upsertCustomerProfile({
          clientId:
            normalizedClientId,
          name:
            normalizedCustomerName,
          phone:
            normalizedCustomerPhone,
          email:
            normalizedCustomerEmail
        });


      // ======================================================
      // V15 - FUNIL: CADASTRO CONCLUIDO + PLANO SELECIONADO
      // ======================================================

      recordFunnelEventOnce({
        eventId:
          context.event.id,
        routerId:
          context.router.id,
        clientId:
          normalizedClientId,
        mac:
          normalizedMac,
        ip:
          normalizedIp,
        step:
          "REGISTRATION_COMPLETED",
        planId:
          plan.id,
        source:
          "backend",
        metadata: {
          has_name:
            Boolean(normalizedCustomerName),
          has_phone:
            Boolean(normalizedCustomerPhone),
          has_email:
            Boolean(normalizedCustomerEmail)
        },
        dedupeWindowSeconds:
          120,
        dedupeByOrder:
          false
      });


      recordFunnelEventOnce({
        eventId:
          context.event.id,
        routerId:
          context.router.id,
        clientId:
          normalizedClientId,
        mac:
          normalizedMac,
        ip:
          normalizedIp,
        step:
          "PLAN_SELECTED",
        planId:
          plan.id,
        source:
          "backend_order",
        metadata:{
          plan_name:
            plan.name || plan.id,
          amount:
            Number(plan.amount),
          minutes:
            Number(plan.minutes)
        },
        dedupeWindowSeconds:
          30,
        dedupeByOrder:
          false
      });


      // ======================================================
      // ACESSO EXISTENTE:
      // ANTES DE CRIAR OUTRO PIX, VERIFICAR SE O CLIENTE
      // JÃ POSSUI PLANO PAGO E VÃLIDO NESTE MESMO EVENTO.
      //
      // IMPORTANTE:
      // O plano ativo prevalece mesmo que o usuÃ¡rio tenha
      // clicado em outro plano na tela.
      // NÃ£o criamos nova cobranÃ§a enquanto o acesso atual
      // ainda estiver vÃ¡lido.
      // ======================================================

      const activeOrder =
        findActivePaidAccess(
          context.event.id,
          normalizedClientId
        );


      if(
        activeOrder
      ) {

        const grant =
          ensureRouterGrant(
            activeOrder,
            context.router,
            normalizedMac,
            normalizedIp
          );


        console.log(

          "ACESSO EXISTENTE: plano ainda valido reutilizado",

          "EVENTO=" +
            context.event.event_key,

          "ROUTER=" +
            context.router.router_key,

          "CLIENT=" +
            normalizedClientId,

          "ORDER=" +
            activeOrder.external_ref,

          "GRANT=" +
            (
              grant?.status
              ||
              "unknown"
            )

        );


        setRecoveryCookie(
          res,
          normalizedClientId,
          context.event.id
        );


        return res.json({

          ok:
            true,

          reused_access:
            true,

          payment_required:
            false,

          customer: {
            client_id:
              customer?.client_id || normalizedClientId,
            name:
              customer?.name || normalizedCustomerName,
            phone:
              customer?.phone || normalizedCustomerPhone,
            email:
              customer?.email || normalizedCustomerEmail
          },

          ...buildActiveAccessResponse(
            activeOrder,
            context.router,
            grant
          )

        });

      }


      // ======================================================
      // V16.9 - RECUPERACAO AUTOMATICA SEM CLIENT_ID ANTIGO
      //
      // Se o navegador cativo perdeu cookie/localStorage e criou
      // um novo client_id (por exemplo apos "Esquecer rede" ou
      // troca de MAC privado), ainda NAO criamos um novo PIX.
      //
      // Antes de cobrar, procuramos um plano pago e ainda valido
      // neste mesmo evento pelo telefone + e-mail informados no
      // cadastro normal do portal. Se encontrar:
      // - transfere o pedido para o novo client_id;
      // - atualiza MAC/IP atuais;
      // - reaproveita somente o tempo restante;
      // - ensureRouterGrant() recoloca o grant como PENDING se
      //   necessario, para a MikroTik autorizar o novo MAC;
      // - responde reused_access=true e NENHUM PIX e criado.
      // ======================================================

      const recoverableOrder =
        findActivePaidAccessByContact(
          context.event.id,
          normalizedCustomerPhone,
          normalizedCustomerEmail,
          normalizedCustomerName
        );


      if(
        recoverableOrder
      ) {

        const previousClientId =
          normalizeClientId(
            recoverableOrder.client_id
          );

        const recoveryNow =
          nowIso();


        const recoveryTransaction =
          db.transaction(
            () => {

              // Mantem o cadastro no NOVO client_id.
              upsertCustomerProfile({
                clientId:
                  normalizedClientId,
                name:
                  normalizedCustomerName,
                phone:
                  normalizedCustomerPhone,
                email:
                  normalizedCustomerEmail
              });


              // O direito de acesso passa a acompanhar a nova
              // identidade do navegador e o novo MAC/IP.
              db.prepare(`

                UPDATE orders

                SET
                  client_id=?,
                  effective_mac=?,
                  ip=?,
                  portal_last_seen_at=?

                WHERE id=?

              `).run(
                normalizedClientId,
                normalizedMac,
                normalizedIp,
                recoveryNow,
                recoverableOrder.id
              );


              db.prepare(`

                UPDATE router_access_grants

                SET
                  client_id=?,
                  updated_at=?

                WHERE order_id=?

              `).run(
                normalizedClientId,
                recoveryNow,
                recoverableOrder.id
              );

            }
          );


        recoveryTransaction();


        const recoveredOrder =
          db.prepare(`

            SELECT *

            FROM orders

            WHERE id=?

            LIMIT 1

          `).get(
            recoverableOrder.id
          );


        const recoveredGrant =
          ensureRouterGrant(
            recoveredOrder,
            context.router,
            normalizedMac,
            normalizedIp
          );


        console.log(
          "ACESSO RECUPERADO AUTOMATICAMENTE ANTES DO PIX",
          "EVENTO=" +
            context.event.event_key,
          "ORDER=" +
            recoveredOrder.external_ref,
          "CLIENT_ANTIGO=" +
            String(previousClientId || ""),
          "CLIENT_NOVO=" +
            normalizedClientId,
          "MAC_NOVO=" +
            normalizedMac
        );


        setRecoveryCookie(
          res,
          normalizedClientId,
          context.event.id
        );


        return res.json({

          ok:
            true,

          reused_access:
            true,

          recovered_access:
            true,

          payment_required:
            false,

          previous_client_id:
            previousClientId || null,

          customer: {
            client_id:
              normalizedClientId,
            name:
              normalizedCustomerName,
            phone:
              normalizedCustomerPhone,
            email:
              normalizedCustomerEmail
          },

          ...buildActiveAccessResponse(
            recoveredOrder,
            context.router,
            recoveredGrant
          )

        });

      }


      // ======================================================
      // REFERÃŠNCIAS DO NOVO PEDIDO
      // ======================================================

      const externalRef =
        randomRef();


      const idempotencyKey =
        crypto.randomUUID();


      const payerEmail =

        normalizedCustomerEmail

        ||

        process.env
          .MP_PAYER_EMAIL

        ||

        "cliente@email.com";


      let amount;

      let payer;


      // ======================================================
      // MODO TESTE
      // ======================================================

      if (
        isTestMode()
      ) {

        amount =
          "50.00";


        payer = {

          email:
            "test_user_br@testuser.com",

          first_name:
            "APRO"

        };

      }


      // ======================================================
      // PRODUÃ‡ÃƒO
      // ======================================================

      else {

        amount =

          Number(
            plan.amount
          ).toFixed(
            2
          );


        payer = {

          email:
            payerEmail

        };

      }


      // ======================================================
      // PAYLOAD MERCADO PAGO
      // ======================================================

      const orderBody = {

        type:
          "online",

        external_reference:
          externalRef,

        total_amount:
          amount,

        processing_mode:
          "automatic",

        payer,

        transactions: {

          payments: [

            {

              amount,

              payment_method: {

                id:
                  "pix",

                type:
                  "bank_transfer"

              },

              expiration_time:
                "PT1H"

            }

          ]

        }

      };


      // ======================================================
      // CRIAR ORDER NO MERCADO PAGO
      // ======================================================

      const response =

        await axios.post(

          "https://api.mercadopago.com/v1/orders",

          orderBody,

          {

            headers: {

              Authorization:
                `Bearer ${process.env.MP_ACCESS_TOKEN}`,

              "Content-Type":
                "application/json",

              "X-Idempotency-Key":
                idempotencyKey

            },

            timeout:
              15000

          }

        );


      const mpOrder =
        response.data;


      const transaction =

        mpOrder
          .transactions
          ?.payments?.[0]

        ||

        {};


      const paymentMethod =

        transaction
          .payment_method

        ||

        {};


      // ======================================================
      // DECIDIR SE PODE RECEBER CORTESIA
      //
      // Nesta etapa mantemos a regra atual de cortesia.
      // ======================================================

      let tempEligible =
        false;


      let tempStatus =
        null;


      let tempRequestedAt =
        null;


      let tempDecision = {

        eligible:
          false,

        reason:
          "disabled",

        attempts_last_hour:
          0,

        retry_after_seconds:
          0

      };


      if (
        !isTestMode()
      ) {

        tempDecision =

          getTemporaryAccessDecision(
            normalizedClientId
          );


        tempEligible =
          tempDecision
            .eligible;


        if (
          tempEligible
        ) {

          // ====================================================
          // NOVO FLUXO
          //
          // O PIX Ã© criado primeiro e a cortesia fica aguardando.
          // Ela sÃ³ serÃ¡ solicitada quando o cliente tocar em
          // "COPIAR PIX E LIBERAR INTERNET".
          // ====================================================

          tempStatus =
            "awaiting_activation";


          tempRequestedAt =
            null;

        }


        else {

          tempStatus =

            "blocked_"

            +

            tempDecision
              .reason;

        }

      }


      else {

        tempStatus =
          "disabled_test";

      }


      // ======================================================
      // SALVAR PEDIDO LOCALMENTE
      //
      // NOVO:
      // event_id = evento do portal
      // router_id = MK onde a compra comeÃ§ou
      // ======================================================

      const insertResult =
        db.prepare(`

          INSERT INTO orders (

            external_ref,

            event_id,

            router_id,

            client_id,

            plan_id,

            amount,

            minutes,

            rate_limit,

            mac,

            original_mac,

            effective_mac,

            ip,

            payer_email,

            mp_payment_id,

            mp_order_id,

            status,

            qr_code,

            qr_code_base64,

            created_at,

            temp_status,

            temp_requested_at

          )

          VALUES (

            ?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?

          )

        `).run(

          externalRef,

          context.event.id,

          context.router.id,

          normalizedClientId,

          plan.id,

          plan.amount,

          plan.minutes,

          plan.rate,

          normalizedMac,

          normalizedMac,

          null,

          normalizedIp,

          payerEmail,

          String(

            transaction.id

            ||

            mpOrder.id

          ),

          String(
            mpOrder.id
          ),

          mpOrder.status

          ||

          "pending",

          paymentMethod
            .qr_code

          ||

          "",

          paymentMethod
            .qr_code_base64

          ||

          "",

          nowIso(),

          tempStatus,

          tempRequestedAt

        );


      // ======================================================
      // V15 - FUNIL: PIX GERADO
      // ======================================================

      recordFunnelEventOnce({
        eventId:
          context.event.id,
        routerId:
          context.router.id,
        clientId:
          normalizedClientId,
        mac:
          normalizedMac,
        ip:
          normalizedIp,
        orderId:
          Number(
            insertResult.lastInsertRowid
          ),
        orderRef:
          externalRef,
        step:
          "PIX_GENERATED",
        planId:
          plan.id,
        source:
          "backend",
        metadata: {
          amount:
            Number(plan.amount),
          minutes:
            Number(plan.minutes),
          rate_limit:
            plan.rate || "",
          temp_status:
            tempStatus
        }
      });


      // ======================================================
      // Se houver cortesia pendente, ela continua sendo
      // processada pela MikroTik onde o pedido foi criado.
      //
      // O grant pago serÃ¡ criado quando o Mercado Pago aprovar
      // ou pela compatibilidade da fila no BLOCO 6.
      // ======================================================

      console.log(

        "PIX criado:",

        externalRef,

        "EVENTO=" +
          context.event.event_key,

        "ROUTER=" +
          context.router.router_key,

        "CLIENT=" +
          normalizedClientId,

        "MAC=" +
          normalizedMac,

        "IP=" +
          normalizedIp,

        "TEMP=" +
          tempStatus,

        "ORDER_ID_LOCAL=" +
          Number(
            insertResult.lastInsertRowid
          )

      );


      // ======================================================
      // RETORNO PARA O PORTAL
      // ======================================================

      return res.json({

        ok:
          true,

        reused_access:
          false,

        payment_required:
          true,

        event: {

          id:
            Number(
              context.event.id
            ),

          event_key:
            context.event.event_key,

          name:
            context.event.name

        },

        router: {

          id:
            Number(
              context.router.id
            ),

          router_key:
            context.router.router_key,

          name:
            context.router.name

        },

        customer: {
          client_id:
            customer?.client_id || normalizedClientId,
          name:
            customer?.name || normalizedCustomerName,
          phone:
            customer?.phone || normalizedCustomerPhone,
          email:
            customer?.email || normalizedCustomerEmail
        },

        order:
          externalRef,

        order_id:
          mpOrder.id,

        payment_id:

          transaction.id

          ||

          null,

        status:
          mpOrder.status,

        status_detail:

          mpOrder.status_detail

          ||

          "",

        qr_code:

          paymentMethod
            .qr_code

          ||

          "",

        qr_code_base64:

          paymentMethod
            .qr_code_base64

          ||

          "",

        ticket_url:

          paymentMethod
            .ticket_url

          ||

          "",

        temporary_access: {

          status:
            tempStatus,

          eligible:
            tempEligible,

          minutes:

            tempEligible

              ? TEMP_MINUTES

              : 0,

          retry_wait_minutes:
            TEMP_RETRY_WAIT_MINUTES,

          max_attempts_per_hour:
            TEMP_MAX_ATTEMPTS_PER_HOUR,

          reason:
            tempDecision
              .reason,

          attempts_last_hour:
            tempDecision
              .attempts_last_hour,

          retry_after_seconds:
            tempDecision
              .retry_after_seconds

        }

      });

    }


    catch(error) {

      console.error(

        "Erro PIX:",

        error.response
          ?.data

        ||

        error.message

      );


      return res
        .status(
          500
        )
        .json({

          error:
            "Falha ao gerar PIX",

          detail:

            error.response
              ?.data

            ||

            error.message

        });

    }

  }

);


// ============================================================
// ATIVAR CORTESIA APÃ“S COPIAR O PIX
//
// /api/pix cria o PIX sem iniciar a cortesia.
// Ao tocar em "COPIAR PIX E LIBERAR INTERNET", o portal chama
// este endpoint. SÃ³ entÃ£o a cortesia vira "pending" e entra
// na fila da MikroTik.
// ============================================================

app.post(
  "/api/temp/activate",
  async (req, res) => {

    try {

      const externalRef =
        String(
          req.body?.order ||
          req.body?.external_ref ||
          ""
        ).trim();

      const normalizedClientId =
        normalizeClientId(
          req.body?.client_id || ""
        );


      if (
        !externalRef
        ||
        !normalizedClientId
      ) {

        return res
          .status(400)
          .json({
            ok:
              false,
            error:
              "Pedido ou cliente invÃ¡lido"
          });

      }


      const order =
        db.prepare(`

          SELECT *

          FROM orders

          WHERE
            external_ref=?
            AND client_id=?

          LIMIT 1

        `).get(
          externalRef,
          normalizedClientId
        );


      if (
        !order
      ) {

        return res
          .status(404)
          .json({
            ok:
              false,
            error:
              "Pedido nÃ£o encontrado"
          });

      }


      // ========================================================
      // PAGAMENTO JÃ CONFIRMADO
      // ========================================================

      if (
        order.status ===
          "approved"
        ||
        order.status ===
          "approved_pending_router"
        ||
        order.status ===
          "approved_missing_mac"
      ) {

        return res.json({
          ok:
            true,
          payment_already_confirmed:
            true,
          temporary_access: {
            status:
              order.temp_status,
            eligible:
              false,
            minutes:
              0
          }
        });

      }


      // ========================================================
      // CORTESIA JÃ PENDENTE
      // ========================================================

      if (
        order.temp_status ===
          "pending"
      ) {

        return res.json({
          ok:
            true,
          temporary_access: {
            status:
              "pending",
            eligible:
              true,
            minutes:
              TEMP_MINUTES,
            reason:
              "pending"
          }
        });

      }


      // ========================================================
      // CORTESIA JÃ LIBERADA
      //
      // SÃ³ considerar "granted" enquanto os 3 minutos
      // realmente ainda estiverem ativos.
      // Se jÃ¡ expirou, continua abaixo e reavalia:
      // - espera de 5 minutos
      // - limite de 2 cortesias por hora
      // ========================================================

      if (
        order.temp_status ===
          "granted"
      ) {

        const tempExpiresMs =
          Date.parse(
            order.temp_expires_at ||
              ""
          );


        if (
          Number.isFinite(
            tempExpiresMs
          )
          &&
          Date.now() <
            tempExpiresMs
        ) {

          return res.json({
            ok:
              true,
            temporary_access: {
              status:
                "granted",
              eligible:
                true,
              minutes:
                TEMP_MINUTES,
              granted_at:
                order.temp_granted_at,
              expires_at:
                order.temp_expires_at
            }
          });

        }

        // Cortesia antiga jÃ¡ terminou.
        // NÃ£o retorna "granted": continua para reavaliar
        // a espera e o limite por hora.

      }


      // ========================================================
      // NÃƒO REATIVAR SE O PLANO PAGO JÃ SUBSTITUIU A CORTESIA
      // ========================================================

      if (
        order.temp_status ===
          "cancelled_by_paid_plan"
        ||
        order.temp_status ===
          "replaced_by_paid_plan"
      ) {

        return res
          .status(409)
          .json({
            ok:
              false,
            error:
              "A cortesia deste pedido nÃ£o pode mais ser ativada"
          });

      }


      // ========================================================
      // REAVALIAR AS REGRAS NO MOMENTO DO CLIQUE
      // ========================================================

      const tempDecision =
        getTemporaryAccessDecision(
          normalizedClientId
        );


      if (
        !tempDecision.eligible
      ) {

        const blockedStatus =
          "blocked_" +
          tempDecision.reason;


        db.prepare(`

          UPDATE orders

          SET temp_status=?

          WHERE external_ref=?

        `).run(
          blockedStatus,
          externalRef
        );


        recordFunnelEvent({
          eventId:
            order.event_id,
          routerId:
            order.router_id,
          clientId:
            order.client_id,
          mac:
            order.effective_mac
            ||
            order.mac,
          ip:
            order.ip,
          orderId:
            order.id,
          orderRef:
            order.external_ref,
          step:
            "TEMPORARY_ACCESS_FAILED",
          planId:
            order.plan_id,
          source:
            "backend",
          metadata: {
            reason:
              tempDecision.reason,
            retry_after_seconds:
              tempDecision.retry_after_seconds,
            attempts_last_hour:
              tempDecision.attempts_last_hour
          }
        });


        return res.json({
          ok:
            true,
          temporary_access: {
            status:
              blockedStatus,
            eligible:
              false,
            minutes:
              0,
            reason:
              tempDecision.reason,
            attempts_last_hour:
              tempDecision.attempts_last_hour,
            retry_after_seconds:
              tempDecision.retry_after_seconds,
            retry_wait_minutes:
              TEMP_RETRY_WAIT_MINUTES,
            max_attempts_per_hour:
              TEMP_MAX_ATTEMPTS_PER_HOUR
          }
        });

      }


      // ========================================================
      // ATIVAR CORTESIA
      // ========================================================

      const requestedAt =
        nowIso();


      db.prepare(`

        UPDATE orders

        SET
          temp_status='pending',
          temp_requested_at=?,
          temp_granted_at=NULL,
          temp_expires_at=NULL

        WHERE external_ref=?

      `).run(
        requestedAt,
        externalRef
      );


      recordFunnelEventOnce({
        eventId:
          order.event_id,
        routerId:
          order.router_id,
        clientId:
          order.client_id,
        mac:
          order.effective_mac
          ||
          order.mac,
        ip:
          order.ip,
        orderId:
          order.id,
        orderRef:
          order.external_ref,
        step:
          "TEMPORARY_ACCESS_REQUESTED",
        planId:
          order.plan_id,
        source:
          "backend",
        metadata: {
          requested_at:
            requestedAt,
          minutes:
            TEMP_MINUTES
        }
      });


      console.log(
        "CORTESIA SOLICITADA APÃ“S COPIAR PIX:",
        externalRef,
        "CLIENT=" +
          normalizedClientId
      );


      return res.json({
        ok:
          true,
        temporary_access: {
          status:
            "pending",
          eligible:
            true,
          minutes:
            TEMP_MINUTES,
          reason:
            "requested",
          requested_at:
            requestedAt,
          retry_wait_minutes:
            TEMP_RETRY_WAIT_MINUTES,
          max_attempts_per_hour:
            TEMP_MAX_ATTEMPTS_PER_HOUR
        }
      });

    }
    catch(error) {

      console.error(
        "Erro ao ativar cortesia:",
        error
      );


      return res
        .status(500)
        .json({
          ok:
            false,
          error:
            "Erro ao ativar cortesia"
        });

    }

  }
);


// ============================================================
// CONSULTAR PEDIDO
// ============================================================

const limitVoucherByIp = createRateLimiter({
  windowMs: 15 * 60 * 1000,
  max: 8,
  keyFor: req => req.ip,
  message: "Muitas tentativas de voucher. Aguarde alguns minutos."
});
const limitVoucherByClient = createRateLimiter({
  windowMs: 15 * 60 * 1000,
  max: 5,
  keyFor: req => req.body?.client_id,
  message: "Muitas tentativas neste aparelho. Aguarde alguns minutos."
});

function normalizeVoucherCode(value){
  return String(value || "").replace(/\D/g, "");
}

app.post("/api/voucher/redeem", limitVoucherByIp, limitVoucherByClient, (req, res) => {
  try{
    const context = resolvePortalContext(req.body?.event_key, req.body?.router_key);
    if(!context.ok) return res.status(400).json({ok:false, error:context.error});

    const code = normalizeVoucherCode(req.body?.code);
    if(!/^\d{6}$/.test(code)) return res.status(400).json({ok:false, error:"Informe os seis nÃºmeros do voucher."});

    const name = normalizeCustomerName(req.body?.customer_name);
    const phone = normalizeCustomerPhone(req.body?.customer_phone);
    const email = normalizeCustomerEmail(req.body?.email);
    const clientId = normalizeClientId(req.body?.client_id);
    const mac = normalizeMac(req.body?.mac);
    const ip = normalizeIp(req.body?.ip);
    if(!name || name.length < 2 || !phone || !email || !clientId || !mac || !ip){
      return res.status(400).json({ok:false, error:"Confira seus dados e a conexÃ£o Wi-Fi antes de resgatar."});
    }

    const voucher = db.prepare(`
      SELECT v.*, b.plan_id, b.plan_name, b.minutes, b.rate_limit, b.mikrotik_profile, b.active AS batch_active
      FROM vouchers v JOIN voucher_batches b ON b.id=v.batch_id
      WHERE v.code_hash=? AND v.event_id=? LIMIT 1
    `).get(crypto.createHash("sha256").update(code).digest("hex"), context.event.id);
    if(!voucher || voucher.status !== "unused" || Number(voucher.batch_active) !== 1){
      return res.status(400).json({ok:false, error:"Voucher invÃ¡lido, jÃ¡ utilizado ou desativado."});
    }

    const now = nowIso();
    const externalRef = "VCH_" + crypto.randomUUID();
    const createVoucherOrder = db.transaction(() => {
      const reservation = db.prepare("UPDATE vouchers SET status='redeeming' WHERE id=? AND status='unused'").run(voucher.id);
      if(!reservation.changes) throw new Error("VOUCHER_ALREADY_USED");
      db.prepare(`
        INSERT INTO customers (client_id,name,phone,email,created_at,updated_at,last_seen_at)
        VALUES (?,?,?,?,?,?,?)
        ON CONFLICT(client_id) DO UPDATE SET name=excluded.name, phone=excluded.phone,
          email=excluded.email, updated_at=excluded.updated_at, last_seen_at=excluded.last_seen_at
      `).run(clientId, name, phone, email, now, now, now);
      const inserted = db.prepare(`
        INSERT INTO orders (external_ref,event_id,router_id,client_id,plan_id,amount,minutes,rate_limit,
          mac,original_mac,effective_mac,ip,payer_email,status,created_at,payment_method,voucher_id,voucher_batch_id,voucher_serial)
        VALUES (?,?,?,?,?,0,?,?,?,?,?,?,?,'approved_pending_router',?,'voucher',?,?,?)
      `).run(externalRef, context.event.id, context.router.id, clientId, voucher.plan_id,
        voucher.minutes, voucher.rate_limit, mac, mac, mac, ip, email, now, voucher.id, voucher.batch_id, voucher.serial_number);
      const orderId = Number(inserted.lastInsertRowid);
      db.prepare(`UPDATE vouchers SET status='redeemed',redeemed_at=?,redeemed_order_id=?,redeemed_client_id=?,redeemed_mac=?,redeemed_ip=? WHERE id=?`)
        .run(now, orderId, clientId, mac, ip, voucher.id);
      const order = db.prepare("SELECT * FROM orders WHERE id=?").get(orderId);
      ensureInitialRouterGrant(order, context.router.id);
      return order;
    });
    const order = createVoucherOrder();
    recordFunnelEvent({eventId:context.event.id,routerId:context.router.id,clientId,mac,ip,orderId:order.id,orderRef:externalRef,step:"VOUCHER_REDEEMED",planId:voucher.plan_id,metadata:{voucher_serial:voucher.serial_number,batch_id:voucher.batch_id},source:"portal"});

    return res.json({ok:true, order:externalRef, voucher:true, plan_name:voucher.plan_name,
      router:{id:context.router.id,router_key:context.router.router_key}, status:order.status});
  }
  catch(error){
    if(error.message === "VOUCHER_ALREADY_USED") return res.status(400).json({ok:false,error:"Este voucher acabou de ser utilizado."});
    console.error("Falha no resgate de voucher:", error);
    return res.status(500).json({ok:false,error:"NÃ£o foi possÃ­vel ativar o voucher agora."});
  }
});

app.get(
  "/api/order/:ref",
  async (req, res) => {

    try {

      // ======================================================
      // BUSCAR PEDIDO LOCAL
      // ======================================================

      let order =

        db.prepare(

          "SELECT * FROM orders WHERE external_ref=?"

        ).get(

          req.params.ref

        );


      if (
        !order
      ) {

        return res
          .status(
            404
          )
          .json({

            error:
              "Pedido nÃ£o encontrado"

          });

      }


      // ======================================================
      // PRESENÃ‡A DO PORTAL / PIX ABERTO
      //
      // O index.html jÃ¡ consulta esta rota continuamente
      // enquanto o QR PIX estÃ¡ aberto.
      // ======================================================

      const portalNow =
        Date.now();


      const previousPortalSeen =
        Date.parse(
          order.portal_last_seen_at || ""
        );


      if(
        !Number.isFinite(
          previousPortalSeen
        )
        ||
        (
          portalNow
          -
          previousPortalSeen
        ) >= 5000
      ){

        const portalSeenAt =
          nowIso();


        db.prepare(`

          UPDATE orders

          SET
            portal_last_seen_at=?

          WHERE id=?

        `).run(

          portalSeenAt,

          order.id

        );


        order.portal_last_seen_at =
          portalSeenAt;

      }


      // ======================================================
      // STATUS QUE NÃƒO PRECISAM MAIS CONSULTAR O MP
      // ======================================================

      const stop =

        new Set([

          "approved",

          "approved_pending_router",

          "approved_missing_mac",

          "payment_validation_failed",

          "test_approved_no_release"

        ]);


      const orderId =

        order.mp_order_id

        ||

        order.mp_payment_id;


      // ======================================================
      // CONSULTAR MERCADO PAGO
      // ======================================================

      if (

        !stop.has(
          order.status
        )

        &&

        orderId

      ) {

        try {

          const mpOrder =

            await getOrder(
              orderId
            );


          await processOrderStatus(
            mpOrder
          );


          order =

            db.prepare(

              "SELECT * FROM orders WHERE external_ref=?"

            ).get(

              req.params.ref

            );

        }


        catch(error) {

          console.error(

            "Erro status MP:",

            error.response
              ?.data

            ||

            error.message

          );

        }

      }


      // ======================================================
      // INFORMAÃ‡ÃƒO DE ACESSO GERADA PELA MIKROTIK
      // ======================================================

      let access =
        null;


      if (
        order.access_json
      ) {

        try {

          access =

            JSON.parse(
              order.access_json
            );

        }


        catch {

          access =
            null;

        }

      }


      // ======================================================
      // GRANTS POR MIKROTIK
      //
      // Ãštil para o portal/painel saber em quais MKs o cliente
      // jÃ¡ foi liberado.
      // ======================================================

      const grants =
        order.event_id
          ? db.prepare(`

              SELECT

                g.id,
                g.router_id,
                r.router_key,
                r.name AS router_name,
                g.status,
                g.mac,
                g.ip,
                g.requested_at,
                g.applied_at,
                g.last_seen_at,
                g.expired_at

              FROM router_access_grants g

              JOIN routers r
                ON r.id=g.router_id

              WHERE g.order_id=?

              ORDER BY g.id ASC

            `).all(
              order.id
            )
          : [];


      // ======================================================
      // TEMPO RESTANTE
      // ======================================================

      let remainingSeconds =
        null;


      if(
        order.access_expires_at
      ) {

        const expiresAtMs =
          Date.parse(
            order.access_expires_at
          );


        if(
          Number.isFinite(
            expiresAtMs
          )
        ) {

          remainingSeconds =
            Math.max(
              0,
              Math.floor(
                (
                  expiresAtMs
                  -
                  Date.now()
                )
                /
                1000
              )
            );

        }

      }


      // ======================================================
      // V16.11 - SELAR IDENTIDADE APOS PAGAMENTO CONFIRMADO
      // ======================================================

      if(
        order.client_id
        && order.event_id
        && order.status === "approved"
        && order.access_expires_at
        && !order.access_expired_at
      ) {

        setRecoveryCookie(
          res,
          order.client_id,
          order.event_id
        );

      }


      // ======================================================
      // RESPOSTA PARA O PORTAL
      // ======================================================

      return res.json({

        order:
          order.external_ref,

        event_id:
          order.event_id,

        router_id:
          order.router_id,

        client_id:
          order.client_id,

        status:
          order.status,

        approved_at:
          order.approved_at,

        access_expires_at:
          order.access_expires_at,

        access_expired_at:
          order.access_expired_at,

        remaining_seconds:
          remainingSeconds,

        remaining_minutes:
          remainingSeconds === null
            ? null
            : Math.ceil(
                remainingSeconds / 60
              ),

        access,

        router_grants:
          grants,

        temporary_access: {

          status:
            order.temp_status,

          requested_at:
            order.temp_requested_at,

          granted_at:
            order.temp_granted_at,

          expires_at:
            order.temp_expires_at,

          effective_mac:
            order.effective_mac

        }

      });

    }


    catch(error) {

      console.error(

        "Erro ao consultar pedido:",

        error.message

      );


      return res
        .status(
          500
        )
        .json({

          error:
            "Erro ao consultar pedido"

        });

    }

  }

);


// ============================================================
// FIM DO BLOCO 5/10


// ============================================================
// BLOCO 6/10 - WEBHOOK MP + FILA MIKROTIK
// REGRA: 1 EVENTO = 1 MIKROTIK
//
// COMANDOS:
//
// TEMP
//   Cortesia automÃ¡tica.
//
// ALLOW
//   LiberaÃ§Ã£o de plano PIX pago.
//
// EXPIRE
//   Encerramento automÃ¡tico por TEMPO CORRIDO.
//
// PRIORIDADE DA FILA:
//
// 1 - EXPIRE
// 2 - ALLOW
// 3 - TEMP
//
// ============================================================


// ============================================================
// VALIDAR WEBHOOK MERCADO PAGO
// ============================================================

function validateMercadoPagoWebhook(req) {

  const secret =
    process.env.MP_WEBHOOK_SECRET;


  if (!secret) {

    return false;

  }


  const signature =
    req.headers["x-signature"];


  const requestId =
    req.headers["x-request-id"];


  if (!signature) {

    return false;

  }


  const parts = {};


  for (const item of signature.split(",")) {

    const index =
      item.indexOf("=");


    if (index < 0) {

      continue;

    }


    const key =
      item
        .slice(0, index)
        .trim();


    const value =
      item
        .slice(index + 1)
        .trim();


    parts[key] =
      value;

  }


  if (
    !parts.ts ||
    !parts.v1
  ) {

    return false;

  }


  const dataId =
    req.query["data.id"] ||
    req.query.data_id ||
    req.body?.data?.id ||
    "";


  let manifest =
    "";


  if (dataId) {

    manifest +=
      `id:${String(dataId).toLowerCase()};`;

  }


  if (requestId) {

    manifest +=
      `request-id:${requestId};`;

  }


  manifest +=
    `ts:${parts.ts};`;


  const generatedSignature =
    crypto
      .createHmac(
        "sha256",
        secret
      )
      .update(
        manifest
      )
      .digest(
        "hex"
      );


  try {

    const received =
      Buffer.from(
        String(parts.v1),
        "utf8"
      );


    const expected =
      Buffer.from(
        generatedSignature,
        "utf8"
      );


    if (
      received.length !==
      expected.length
    ) {

      return false;

    }


    return crypto.timingSafeEqual(
      received,
      expected
    );

  }


  catch {

    return false;

  }

}


// ============================================================
// WEBHOOK MERCADO PAGO
// ============================================================

app.post(
  "/api/webhook/mercadopago",
  async (req, res) => {

    // Responder rapidamente ao Mercado Pago.
    res.sendStatus(
      200
    );


    try {

      if (
        !validateMercadoPagoWebhook(
          req
        )
      ) {

        console.warn(
          "WEBHOOK MP: assinatura invÃ¡lida"
        );

        return;

      }


      const dataId =
        req.query["data.id"] ||
        req.query.data_id ||
        req.body?.data?.id ||
        "";


      if (!dataId) {

        console.warn(
          "WEBHOOK MP: data.id ausente"
        );

        return;

      }


      const mpOrder =
        await getOrder(
          dataId
        );


      await processOrderStatus(
        mpOrder
      );

    }


    catch(error) {

      console.error(

        "Erro webhook Mercado Pago:",

        error.response?.data ||

        error.message

      );

    }

  }
);


// ============================================================
// MIKROTIK
// FILA DA MIKROTIK DO EVENTO - 1 EVENTO = 1 MIKROTIK
//
// NOVO MODO:
//   x-router-key
//   x-mikrotik-token
//
// COMPATIBILIDADE:
// A MikroTik antiga continua podendo usar apenas o token global
// durante a migraÃ§Ã£o. Nesse caso usamos a MikroTik padrÃ£o.
//
// FORMATOS:
//
// EXPIRE|MAC|IP|PERFIL|MINUTOS|REF
// ALLOW|MAC|IP|PERFIL|MINUTOS|REF
// TEMP|MAC|IP|PERFIL|MINUTOS|REF
//
// PRIORIDADE:
// 1 - EXPIRE
// 2 - ALLOW
// 3 - TEMP
// ============================================================


// ============================================================
// RESOLVER A MIKROTIK ÃšNICA DO EVENTO
// ============================================================

function resolvePollingRouter(req) {

  const auth =
    authenticateMikrotik(req);


  if(
    !auth.ok
  ) {

    return {
      ok: false,
      auth,
      router: null
    };

  }


  if(
    auth.mode === "router"
    &&
    auth.router
  ) {

    const activeRouter =
      db.prepare(`

        SELECT *

        FROM routers

        WHERE
          id=?
          AND event_id=?
          AND status='active'

        LIMIT 1

      `).get(
        auth.router.id,
        auth.router.event_id
      );

    if(
      activeRouter
    ) {

      return {
        ok: true,
        auth,
        router: activeRouter
      };

    }

  }


  // Compatibilidade temporÃ¡ria com a instalaÃ§Ã£o atual.
  // O token global antigo Ã© associado Ã  MikroTik padrÃ£o.
  if(
    auth.mode === "legacy"
  ) {

    const router =
      db.prepare(`

        SELECT *

        FROM routers

        WHERE
          id=?
          AND status='active'

        LIMIT 1

      `).get(
        DEFAULT_ROUTER.id
      );


    if(
      router
    ) {

      return {
        ok: true,
        auth,
        router
      };

    }

  }


  return {
    ok: false,
    auth,
    router: null
  };

}


// ============================================================
// PERFIL DO PLANO
//
// Primeiro tenta o plano configurÃ¡vel do evento.
// Se nÃ£o existir, mantÃ©m compatibilidade com PLANS.
// ============================================================


// ============================================================
// RATE-LIMIT MIKROTIK
//
// NO PAINEL:
//   DOWNLOAD/UPLOAD
//
// NO ROUTEROS HOTSPOT:
//   UPLOAD/DOWNLOAD
//
// Exemplo:
//   Painel   10M/5M
//   MikroTik 5M/10M
// ============================================================

function mikrotikRateLimit(
  value
) {

  const text =
    String(
      value || ""
    ).trim();

  if(
    !text
  ) {

    return "";

  }


  const parts =
    text.split("/");


  if(
    parts.length !== 2
    ||
    !parts[0]
    ||
    !parts[1]
  ) {

    return safeText(
      text
    );

  }


  return safeText(
    parts[1].trim()
    +
    "/"
    +
    parts[0].trim()
  );

}


function getMikrotikPlanForOrder(order) {

  if(
    !order
  ) {

    return null;

  }

  if(order.payment_method === "voucher" && order.voucher_batch_id){
    const voucherPlan = db.prepare("SELECT mikrotik_profile,minutes,rate_limit FROM voucher_batches WHERE id=?").get(order.voucher_batch_id);
    if(voucherPlan) return {
      mikrotikProfile:voucherPlan.mikrotik_profile,
      minutes:Number(order.minutes || voucherPlan.minutes),
      rateLimit:mikrotikRateLimit(order.rate_limit || voucherPlan.rate_limit || "")
    };
  }


  if(
    order.event_id
  ) {

    const eventPlan =
      db.prepare(`

        SELECT *

        FROM event_plans

        WHERE
          event_id=?
          AND plan_key=?

        LIMIT 1

      `).get(
        order.event_id,
        order.plan_id
      );


    if(
      eventPlan
    ) {

      return {
        mikrotikProfile:
          eventPlan.mikrotik_profile,

        minutes:
          Number(
            order.minutes
            ||
            eventPlan.minutes
          ),

        rateLimit:
          mikrotikRateLimit(
            order.rate_limit
            ||
            eventPlan.rate_limit
            ||
            ""
          )
      };

    }

  }


  const legacyPlan =
    PLANS[
      order.plan_id
    ];


  if(
    !legacyPlan
  ) {

    return null;

  }


  return {
    mikrotikProfile:
      legacyPlan.mikrotikProfile,

    minutes:
      Number(
        order.minutes
        ||
        legacyPlan.minutes
      ),

    rateLimit:
      mikrotikRateLimit(
        order.rate_limit
        ||
        legacyPlan.rate
        ||
        ""
      )
  };

}


// ============================================================
// GARANTIR GRANT PARA A MIKROTIK ÃšNICA DO EVENTO
// ============================================================

function ensureInitialRouterGrant(
  order,
  routerId
) {

  if(
    !order
    ||
    !order.id
    ||
    !order.event_id
    ||
    !routerId
  ) {

    return null;

  }


  const now =
    nowIso();


  db.prepare(`

    INSERT OR IGNORE INTO router_access_grants (

      order_id,
      event_id,
      router_id,
      client_id,
      mac,
      ip,
      status,
      requested_at,
      applied_at,
      last_seen_at,
      expired_at,
      updated_at

    )

    VALUES (
      ?, ?, ?, ?, ?, ?, 'pending', ?, NULL, NULL, NULL, ?
    )

  `).run(

    order.id,
    order.event_id,
    routerId,
    order.client_id || null,

    normalizeMac(
      order.effective_mac
      ||
      order.mac
      ||
      order.original_mac
    ) || null,

    normalizeIp(
      order.ip
    ) || null,

    now,
    now

  );


  return db.prepare(`

    SELECT *

    FROM router_access_grants

    WHERE
      order_id=?
      AND router_id=?

    LIMIT 1

  `).get(
    order.id,
    routerId
  ) || null;

}


// ============================================================
// MIKROTIK - RESSINCRONIZAR APÃ“S REBOOT
//
// A MikroTik chama esta rota uma vez apÃ³s iniciar.
// Planos PIX ainda vÃ¡lidos voltam para a fila "pending".
// O /pending recalcula o tempo restante usando access_expires_at.
// Planos vencidos nÃ£o sÃ£o renovados e a expiraÃ§Ã£o original
// nunca Ã© alterada.
// ============================================================

app.get(
  "/api/mikrotik/resync",
  (req, res) => {

    const polling =
      resolvePollingRouter(req);


    if(
      !polling.ok
      ||
      !polling.router
    ) {

      return res
        .status(401)
        .type("text/plain")
        .send("UNAUTHORIZED");

    }


    const router =
      polling.router;


    const routerId =
      Number(
        router.id
      );


    const eventId =
      Number(
        router.event_id
      );


    const currentTime =
      nowIso();


    try {

      const result =
        db.prepare(`

          UPDATE router_access_grants

          SET
            status='pending',
            updated_at=?

          WHERE
            router_id=?
            AND event_id=?
            AND status='active'

            AND order_id IN (

              SELECT id

              FROM orders

              WHERE
                event_id=?
                AND status='approved'
                AND access_expires_at IS NOT NULL
                AND access_expires_at > ?

            )

        `).run(

          currentTime,
          routerId,
          eventId,
          eventId,
          currentTime

        );


      const total =
        Number(
          result.changes || 0
        );


      console.log(
        "MIKROTIK RESYNC:",
        "ROUTER=" + router.router_key,
        "EVENTO=" + eventId,
        "PLANOS=" + total,
        "HORA=" + currentTime
      );


      return res
        .type("text/plain")
        .send(
          "RESYNC|" + total
        );

    }


    catch(error) {

      console.error(
        "MIKROTIK RESYNC ERRO:",
        error.message
      );


      return res
        .status(500)
        .type("text/plain")
        .send("RESYNC_ERROR");

    }

  }
);


// ============================================================
// MIKROTIK - BUSCAR PRÃ“XIMO COMANDO
// ============================================================

app.get(
  "/api/mikrotik/pending",
  (req, res) => {

    const polling =
      resolvePollingRouter(req);


    if(
      !polling.ok
      ||
      !polling.router
    ) {

      return res
        .status(401)
        .type("text/plain")
        .send("UNAUTHORIZED");

    }


    const router =
      polling.router;


    const routerId =
      Number(
        router.id
      );


    const eventId =
      Number(
        router.event_id
      );


    res.set(
      "Cache-Control",
      "no-store"
    );


    const currentTime =
      nowIso();


    // ========================================================
    // GARANTIR QUE PEDIDOS ANTIGOS PENDENTES DAQUELA MK
    // TENHAM GRANT NA NOVA FILA.
    // ========================================================

    const legacyPendingOrders =
      db.prepare(`

        SELECT *

        FROM orders

        WHERE
          event_id=?
          AND router_id=?
          AND status='approved_pending_router'

        ORDER BY id ASC

      `).all(
        eventId,
        routerId
      );


    for(
      const order
      of legacyPendingOrders
    ) {

      ensureInitialRouterGrant(
        order,
        routerId
      );

    }


    // ========================================================
    // PRIORIDADE 1 - EXPIRE
    //
    // A MikroTik do evento expira os acessos que ela aplicou.
    // O pedido Ã© encerrado apÃ³s o grant da MikroTik do evento ser expirado.
    // ========================================================

    const expiredGrant =
      db.prepare(`

        SELECT
          g.*,
          o.external_ref,
          o.plan_id,
          o.minutes,
          o.effective_mac AS order_effective_mac,
          o.mac AS order_mac,
          o.original_mac,
          o.ip AS order_ip,
          o.access_expires_at,
          o.payment_method,
          o.voucher_batch_id

        FROM router_access_grants g

        JOIN orders o
          ON o.id=g.order_id

        WHERE
          g.router_id=?
          AND g.event_id=?
          AND g.status='active'
          AND o.status='approved'
          AND o.access_expires_at IS NOT NULL
          AND o.access_expires_at <= ?

        ORDER BY o.access_expires_at ASC

        LIMIT 1

      `).get(
        routerId,
        eventId,
        currentTime
      );


    if(
      expiredGrant
    ) {

      const mac =
        normalizeMac(

          expiredGrant.mac
          ||
          expiredGrant.order_effective_mac
          ||
          expiredGrant.order_mac
          ||
          expiredGrant.original_mac

        );


      const ip =
        normalizeIp(

          expiredGrant.ip
          ||
          expiredGrant.order_ip

        );


      const plan =
        getMikrotikPlanForOrder(
          expiredGrant
        );


      if(
        mac
        &&
        plan
        &&
        plan.mikrotikProfile
      ) {

        const response = [

          "EXPIRE",
          mac,
          ip || "0.0.0.0",
          plan.mikrotikProfile,
          Number(expiredGrant.minutes) || 0,
          expiredGrant.external_ref

        ].join("|");


        console.log(

          "MIKROTIK EXPIRE PENDING:",
          "ROUTER=" + router.router_key,
          response

        );


        return res
          .type("text/plain")
          .send(response);

      }


      console.error(

        "EXPIRE sem dados vÃ¡lidos:",
        expiredGrant.external_ref,
        "ROUTER=" + router.router_key

      );

    }


    // ========================================================
    // PRIORIDADE 2 - ALLOW
    //
    // Busca o grant pendente da MikroTik Ãºnica deste evento.
    // ========================================================

    const paidGrant =
      db.prepare(`

        SELECT
          g.*,
          o.external_ref,
          o.plan_id,
          o.minutes,
          o.status AS order_status,
          o.effective_mac AS order_effective_mac,
          o.mac AS order_mac,
          o.original_mac,
          o.ip AS order_ip,
          o.access_expires_at,
          o.payment_method,
          o.voucher_batch_id

        FROM router_access_grants g

        JOIN orders o
          ON o.id=g.order_id

        WHERE
          g.router_id=?
          AND g.event_id=?
          AND g.status='pending'
          AND o.status IN (
            'approved_pending_router',
            'approved'
          )

        ORDER BY g.id ASC

        LIMIT 1

      `).get(
        routerId,
        eventId
      );


    if(
      paidGrant
    ) {

      const mac =
        normalizeMac(

          paidGrant.mac
          ||
          paidGrant.order_effective_mac
          ||
          paidGrant.order_mac
          ||
          paidGrant.original_mac

        );


      const ip =
        normalizeIp(

          paidGrant.ip
          ||
          paidGrant.order_ip

        );


      const plan =
        getMikrotikPlanForOrder(
          paidGrant
        );


      if(
        !mac
        ||
        !ip
        ||
        !plan
        ||
        !plan.mikrotikProfile
      ) {

        db.prepare(`

          UPDATE router_access_grants

          SET
            status='invalid_client_data',
            updated_at=?

          WHERE id=?

        `).run(
          nowIso(),
          paidGrant.id
        );


        console.warn(

          "ALLOW com dados invÃ¡lidos:",
          paidGrant.external_ref,
          "ROUTER=" + router.router_key

        );

      }


      else {

        // Se o plano jÃ¡ iniciou, enviamos somente o tempo restante.
        // Nunca reiniciamos o relÃ³gio.
        let minutesToSend =
          Number(
            paidGrant.minutes
          );


        if(
          paidGrant.access_expires_at
        ) {

          const remainingMs =
            Date.parse(
              paidGrant.access_expires_at
            )
            -
            Date.now();


          minutesToSend =
            Math.max(
              1,
              Math.ceil(
                remainingMs / 60000
              )
            );

        }


        const response = [

          "ALLOW",
          mac,
          ip,
          plan.mikrotikProfile,
          minutesToSend,
          paidGrant.external_ref,
          plan.rateLimit || ""

        ].join("|");


        console.log(

          "MIKROTIK ALLOW PENDING:",
          "ROUTER=" + router.router_key,
          response

        );


        return res
          .type("text/plain")
          .send(response);

      }

    }


    // ========================================================
    // PRIORIDADE 3 - CORTESIA
    //
    // A cortesia fica vinculada Ã  MikroTik Ãºnica do evento.
    // ========================================================

    const temporaryOrder =
      db.prepare(`

        SELECT *

        FROM orders

        WHERE
          event_id=?
          AND router_id=?
          AND temp_status='pending'

        ORDER BY id ASC

        LIMIT 1

      `).get(
        eventId,
        routerId
      );


    if(
      temporaryOrder
    ) {

      const mac =
        normalizeMac(

          temporaryOrder.effective_mac
          ||
          temporaryOrder.mac
          ||
          temporaryOrder.original_mac

        );


      const ip =
        normalizeIp(
          temporaryOrder.ip
        );


      const plan =
        getMikrotikPlanForOrder(
          temporaryOrder
        );


      if(
        !mac
        ||
        !ip
        ||
        !plan
        ||
        !plan.mikrotikProfile
      ) {

        db.prepare(`

          UPDATE orders

          SET temp_status='invalid_client_data'

          WHERE id=?

        `).run(
          temporaryOrder.id
        );


        console.warn(

          "TEMP com dados invÃ¡lidos:",
          temporaryOrder.external_ref,
          "ROUTER=" + router.router_key

        );

      }


      else {

        const response = [

          "TEMP",
          mac,
          ip,
          plan.mikrotikProfile,
          TEMP_MINUTES,
          temporaryOrder.external_ref,
          plan.rateLimit || ""

        ].join("|");


        console.log(

          "MIKROTIK TEMP PENDING:",
          "ROUTER=" + router.router_key,
          response

        );


        return res
          .type("text/plain")
          .send(response);

      }

    }


    return res
      .type("text/plain")
      .send("NONE");

  }
);


// ============================================================
// MIKROTIK - CONFIRMAR TEMP OU ALLOW
// ============================================================

app.get(
  "/api/mikrotik/ack",
  (req, res) => {

    const polling =
      resolvePollingRouter(req);


    if(
      !polling.ok
      ||
      !polling.router
    ) {

      return res
        .status(401)
        .type("text/plain")
        .send("UNAUTHORIZED");

    }


    const router =
      polling.router;


    const routerId =
      Number(
        router.id
      );


    const eventId =
      Number(
        router.event_id
      );


    const ref =
      safeText(

        req.headers["x-command-ref"]
        ||
        req.headers["x-order-ref"]
        ||
        req.query.ref
        ||
        ""

      );


    const effectiveMac =
      normalizeMac(

        req.headers["x-effective-mac"]
        ||
        req.query.mac
        ||
        ""

      );


    if(
      !ref
    ) {

      return res
        .status(400)
        .type("text/plain")
        .send("MISSING_REF");

    }


    const order =
      db.prepare(`

        SELECT *

        FROM orders

        WHERE
          external_ref=?
          AND event_id=?

        LIMIT 1

      `).get(
        ref,
        eventId
      );


    if(
      !order
    ) {

      return res
        .status(404)
        .type("text/plain")
        .send("ORDER_NOT_FOUND");

    }


    if(
      effectiveMac
    ) {

      db.prepare(`

        UPDATE orders

        SET effective_mac=?

        WHERE external_ref=?

      `).run(
        effectiveMac,
        ref
      );

    }


    // ========================================================
    // ACK DO PLANO PIX
    // ========================================================

    let grant =
      db.prepare(`

        SELECT *

        FROM router_access_grants

        WHERE
          order_id=?
          AND router_id=?

        LIMIT 1

      `).get(
        order.id,
        routerId
      );


    if(
      order.status === "approved_pending_router"
      &&
      !grant
    ) {

      grant =
        ensureInitialRouterGrant(
          order,
          routerId
        );

    }


    if(
      grant
      &&
      grant.status === "pending"
      &&
      (
        order.status === "approved_pending_router"
        ||
        order.status === "approved"
      )
    ) {

      const confirmedAt =
        nowIso();


      const planMinutes =
        Number(
          order.minutes
        );


      if(
        !Number.isFinite(planMinutes)
        ||
        planMinutes <= 0
      ) {

        console.error(

          "MIKROTIK ACK: minutos invÃ¡lidos:",
          ref,
          order.minutes

        );


        return res
          .status(500)
          .type("text/plain")
          .send("INVALID_MINUTES");

      }


      let expiresAt =
        order.access_expires_at;


      // O relÃ³gio comeÃ§a apenas no PRIMEIRO ACK.
      if(
        !expiresAt
      ) {

        expiresAt =
          new Date(

            Date.now()
            +
            planMinutes * 60 * 1000

          ).toISOString();

      }


      const access = {

        type:
          "paid",

        event_id:
          eventId,

        first_router_id:
          order.router_id || routerId,

        last_router_id:
          routerId,

        mac:
          effectiveMac
          ||
          order.effective_mac
          ||
          order.mac,

        profile:
          getMikrotikPlanForOrder(order)
            ?.mikrotikProfile
          ||
          "",

        minutes:
          planMinutes,

        confirmed_at:
          order.approved_at
          ||
          confirmedAt,

        expires_at:
          expiresAt,

        time_mode:
          "wall_clock",

        roaming:
          false

      };


      const transaction =
        db.transaction(
          () => {

            db.prepare(`

              UPDATE router_access_grants

              SET
                status='active',
                mac=COALESCE(?, mac),
                ip=COALESCE(?, ip),
                applied_at=?,
                last_seen_at=?,
                expired_at=NULL,
                updated_at=?

              WHERE
                id=?
                AND router_id=?

            `).run(

              effectiveMac || null,
              normalizeIp(order.ip) || null,
              confirmedAt,
              confirmedAt,
              confirmedAt,
              grant.id,
              routerId

            );


            db.prepare(`

              UPDATE orders

              SET
                status='approved',
                effective_mac=
                  COALESCE(
                    ?,
                    effective_mac,
                    mac
                  ),
                access_json=?,
                access_expires_at=?,
                access_expired_at=NULL

              WHERE id=?

            `).run(

              effectiveMac || null,
              JSON.stringify(access),
              expiresAt,
              order.id

            );

          }
        );


      transaction();


      // ======================================================
      // V15 - FUNIL: ACESSO PAGO APLICADO NA MIKROTIK
      // ======================================================

      const accessAppliedExists =
        db.prepare(`
          SELECT id
          FROM funnel_events
          WHERE
            order_id=?
            AND router_id=?
            AND step='ACCESS_APPLIED'
          LIMIT 1
        `).get(
          order.id,
          routerId
        );


      if(
        !accessAppliedExists
      ) {

        recordFunnelEvent({
          eventId:
            eventId,
          routerId:
            routerId,
          clientId:
            order.client_id,
          mac:
            effectiveMac
            ||
            order.effective_mac
            ||
            order.mac,
          ip:
            order.ip,
          orderId:
            order.id,
          orderRef:
            order.external_ref,
          step:
            "PAID_PLAN_APPLIED",
          planId:
            order.plan_id,
          source:
            "mikrotik_ack",
          metadata: {
            applied_at:
              confirmedAt,
            expires_at:
              expiresAt,
            router_key:
              router.router_key
          }
        });

      }


      console.log(

        "MIKROTIK: PLANO PIX CONFIRMADO",
        ref,
        "ROUTER=" + router.router_key,
        "EVENTO=" + eventId,
        "EXPIRA=" + expiresAt

      );


      return res
        .type("text/plain")
        .send("OK");

    }


    // ========================================================
    // ACK DA CORTESIA
    // ========================================================

    if(
      order.temp_status === "pending"
      &&
      Number(order.router_id) === routerId
    ) {

      const grantedAt =
        nowIso();


      const expiresAt =
        addMinutesIso(
          TEMP_MINUTES
        );


      db.prepare(`

        UPDATE orders

        SET
          temp_status='granted',
          temp_granted_at=?,
          temp_expires_at=?,
          effective_mac=
            COALESCE(
              ?,
              effective_mac,
              mac
            )

        WHERE external_ref=?

      `).run(

        grantedAt,
        expiresAt,
        effectiveMac || null,
        ref

      );


      const tempGrantedExists =
        db.prepare(`
          SELECT id
          FROM funnel_events
          WHERE
            order_id=?
            AND step='TEMP_ACCESS_GRANTED'
          LIMIT 1
        `).get(
          order.id
        );


      if(
        !tempGrantedExists
      ) {

        recordFunnelEvent({
          eventId:
            eventId,
          routerId:
            routerId,
          clientId:
            order.client_id,
          mac:
            effectiveMac
            ||
            order.effective_mac
            ||
            order.mac,
          ip:
            order.ip,
          orderId:
            order.id,
          orderRef:
            order.external_ref,
          step:
            "TEMPORARY_ACCESS_APPLIED",
          planId:
            order.plan_id,
          source:
            "mikrotik_ack",
          metadata: {
            granted_at:
              grantedAt,
            expires_at:
              expiresAt,
            minutes:
              TEMP_MINUTES,
            router_key:
              router.router_key
          }
        });

      }


      console.log(

        "MIKROTIK: CORTESIA CONFIRMADA",
        ref,
        "ROUTER=" + router.router_key,
        "EXPIRA=" + expiresAt

      );


      return res
        .type("text/plain")
        .send("OK");

    }


    // ACK repetido do mesmo grant Ã© seguro.
    if(
      grant
      &&
      grant.status === "active"
    ) {

      db.prepare(`

        UPDATE router_access_grants

        SET
          last_seen_at=?,
          updated_at=?

        WHERE id=?

      `).run(
        nowIso(),
        nowIso(),
        grant.id
      );


      return res
        .type("text/plain")
        .send("OK");

    }


    return res
      .type("text/plain")
      .send("ALREADY_PROCESSED");

  }
);


// ============================================================
// MIKROTIK - CONFIRMAR EXPIRE
//
// A MikroTik Ãºnica do evento confirma o prÃ³prio grant.
// O pedido recebe access_expired_at apÃ³s o encerramento desse acesso.
// ============================================================

app.get(
  "/api/mikrotik/expire-ack",
  (req, res) => {

    const polling =
      resolvePollingRouter(req);


    if(
      !polling.ok
      ||
      !polling.router
    ) {

      return res
        .status(401)
        .type("text/plain")
        .send("UNAUTHORIZED");

    }


    const router =
      polling.router;


    const routerId =
      Number(
        router.id
      );


    const eventId =
      Number(
        router.event_id
      );


    const ref =
      safeText(

        req.headers["x-command-ref"]
        ||
        req.headers["x-order-ref"]
        ||
        req.query.ref
        ||
        ""

      );


    const effectiveMac =
      normalizeMac(

        req.headers["x-effective-mac"]
        ||
        req.query.mac
        ||
        ""

      );


    if(
      !ref
    ) {

      return res
        .status(400)
        .type("text/plain")
        .send("MISSING_REF");

    }


    const order =
      db.prepare(`

        SELECT *

        FROM orders

        WHERE
          external_ref=?
          AND event_id=?

        LIMIT 1

      `).get(
        ref,
        eventId
      );


    if(
      !order
    ) {

      return res
        .status(404)
        .type("text/plain")
        .send("ORDER_NOT_FOUND");

    }


    const grant =
      db.prepare(`

        SELECT *

        FROM router_access_grants

        WHERE
          order_id=?
          AND router_id=?

        LIMIT 1

      `).get(
        order.id,
        routerId
      );


    if(
      !grant
    ) {

      return res
        .type("text/plain")
        .send("OK");

    }


    if(
      grant.status === "expired"
    ) {

      return res
        .type("text/plain")
        .send("OK");

    }


    const expiredAt =
      nowIso();


    const transaction =
      db.transaction(
        () => {

          db.prepare(`

            UPDATE router_access_grants

            SET
              status='expired',
              mac=COALESCE(?, mac),
              expired_at=?,
              updated_at=?

            WHERE
              id=?
              AND router_id=?

          `).run(

            effectiveMac || null,
            expiredAt,
            expiredAt,
            grant.id,
            routerId

          );


          const remaining =
            db.prepare(`

              SELECT COUNT(*) AS total

              FROM router_access_grants

              WHERE
                order_id=?
                AND status IN (
                  'pending',
                  'active'
                )

            `).get(
              order.id
            );


          if(
            Number(
              remaining.total
            ) === 0
          ) {

            db.prepare(`

              UPDATE orders

              SET
                access_expired_at=?,
                effective_mac=
                  COALESCE(
                    ?,
                    effective_mac,
                    mac
                  )

              WHERE id=?

            `).run(

              expiredAt,
              effectiveMac || null,
              order.id

            );

          }

        }
      );


    transaction();


    recordFunnelEventOnce({
      eventId:
        eventId,
      routerId:
        routerId,
      clientId:
        order.client_id,
      mac:
        effectiveMac
        ||
        order.effective_mac
        ||
        order.mac,
      ip:
        order.ip,
      orderId:
        order.id,
      orderRef:
        order.external_ref,
      step:
        "ACCESS_EXPIRED",
      planId:
        order.plan_id,
      source:
        "mikrotik_expire_ack",
      metadata:{
        expired_at:
          expiredAt,
        router_key:
          router.router_key
      }
    });


    console.log(

      "MIKROTIK: GRANT EXPIRADO",
      ref,
      "ROUTER=" + router.router_key,
      "EVENTO=" + eventId,
      "EM=" + expiredAt

    );


    return res
      .type("text/plain")
      .send("OK");

  }
);


// ============================================================
// FIM DO BLOCO 6/10

// BLOCO 7/10 - ADMINISTRAÃ‡ÃƒO DE DISPOSITIVOS
// V13: DADOS DO CLIENTE + BANDA NA LIBERAÃ‡ÃƒO MANUAL
//
// COMANDOS:
//
// BYPASS
//   LiberaÃ§Ã£o administrativa permanente.
//
// UNBYPASS
//   Remove somente o bypass administrativo.
//
// BLOCK_NOW
//   Corta o dispositivo imediatamente.
//
// TEMP_ADMIN
//   LiberaÃ§Ã£o administrativa temporÃ¡ria.
//
// A LISTA DE DISPOSITIVOS AGORA MOSTRA:
//
// - dispositivos administrativos
// - clientes com plano PIX
//
// ============================================================


// ============================================================
// GARANTIR COLUNA DE TEMPO NOS COMANDOS ADMIN
// ============================================================

function ensureAdminCommandColumn(
  columnName,
  definition
) {

  const columns =
    db.prepare(
      "PRAGMA table_info(admin_commands)"
    ).all();


  const exists =
    columns.some(
      column =>
        column.name === columnName
    );


  if(
    !exists
  ){

    db.exec(
      `ALTER TABLE admin_commands ADD COLUMN ${columnName} ${definition}`
    );


    console.log(
      "Banco admin_commands atualizado:",
      columnName
    );

  }

}


ensureAdminCommandColumn(
  "minutes",
  "INTEGER"
);

ensureAdminCommandColumn(
  "event_id",
  "INTEGER"
);

ensureAdminCommandColumn(
  "router_id",
  "INTEGER"
);

ensureAdminCommandColumn(
  "rate_limit",
  "TEXT"
);


// ============================================================
// LIMPEZA VISUAL DO HISTÃ“RICO DE ACESSOS
//
// NÃ£o apagamos orders, pagamentos ou logs.
// Apenas guardamos a partir de quando a tabela "Acessos e
// histÃ³rico deste evento" deve comeÃ§ar a mostrar registros.
//
// PIX ainda ativos sÃ£o preservados mesmo sendo anteriores ao
// corte.
// ============================================================

db.exec(`

CREATE TABLE IF NOT EXISTS event_device_history_cleanup (

  event_id INTEGER PRIMARY KEY,

  cleared_at TEXT NOT NULL,

  FOREIGN KEY(event_id)
    REFERENCES events(id)
    ON DELETE CASCADE

);

`);


// ============================================================
// TEMPOS PERMITIDOS
// ============================================================

const ADMIN_TEMP_MINUTES =
  new Set([

    30,

    60,

    240,

    720,

    1440

  ]);


function normalizeAdminRateLimit(
  value
){

  const text =
    String(
      value || ""
    )
      .trim()
      .toUpperCase();


  const match =
    text.match(
      /^(\d{1,4})M\/(\d{1,4})M$/
    );


  if(!match){
    return "";
  }


  const download = Number(match[1]);
  const upload = Number(match[2]);


  if(
    !Number.isInteger(download)
    ||
    !Number.isInteger(upload)
    ||
    download < 1
    ||
    upload < 1
    ||
    download > 1000
    ||
    upload > 1000
  ){
    return "";
  }


  return download + "M/" + upload + "M";

}


// ============================================================
// CRIAR COMANDO ADMINISTRATIVO
// ============================================================

function resolveAdminCommandTarget(eventIdValue){

  const eventId =
    positiveId(eventIdValue);

  if(!eventId){
    return {ok:false,status:400,error:"Evento invÃ¡lido"};
  }

  const event =
    db.prepare(`
      SELECT *
      FROM events
      WHERE id=? AND status='active'
      LIMIT 1
    `).get(eventId);

  if(!event){
    return {ok:false,status:404,error:"Evento nÃ£o encontrado ou inativo"};
  }

  const router =
    db.prepare(`
      SELECT *
      FROM routers
      WHERE event_id=? AND status='active'
      ORDER BY id ASC
      LIMIT 1
    `).get(eventId);

  if(!router){
    return {ok:false,status:409,error:"Este evento nÃ£o possui MikroTik ativa"};
  }

  return {
    ok:true,
    event,
    router,
    eventId:Number(event.id),
    routerId:Number(router.id)
  };
}


function createAdminCommand(
  eventId,
  routerId,
  commandType,
  mac,
  deviceName,
  minutes = null,
  rateLimit = null
){

  const commandRef =
    "admin_" + crypto.randomUUID();

  db.prepare(`
    INSERT INTO admin_commands (
      command_ref,
      command_type,
      mac,
      device_name,
      minutes,
      rate_limit,
      event_id,
      router_id,
      status,
      created_at
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?)
  `).run(
    commandRef,
    commandType,
    mac,
    deviceName,
    minutes,
    rateLimit || null,
    eventId,
    routerId,
    nowIso()
  );

  return commandRef;
}


// ============================================================
// LIBERAÃ‡ÃƒO PERMANENTE
// ============================================================

app.post(
  "/admin/api/devices/bypass",
  adminAuth,
  (req, res) => {

    try {

      const target =
        resolveAdminCommandTarget(
          req.body?.event_id
        );

      if(!target.ok){
        return res
          .status(target.status)
          .json({
            ok:false,
            error:target.error
          });
      }


      const mac =
        normalizeMac(
          req.body?.mac
        );


      const deviceName =
        String(

          req.body?.device_name

          ||

          "Dispositivo liberado"

        )
          .trim()
          .slice(
            0,
            60
          );


      if(
        !mac
      ){

        return res
          .status(
            400
          )
          .json({

            ok:
              false,

            error:
              "MAC invÃ¡lido"

          });

      }


      const commandRef =
        createAdminCommand(

          target.eventId,

          target.routerId,

          "BYPASS",

          mac,

          deviceName

        );


      return res.json({

        ok:
          true,

        command_ref:
          commandRef,

        command_type:
          "BYPASS",

        event_id:
          target.eventId,

        router_id:
          target.routerId,

        mac,

        device_name:
          deviceName,

        status:
          "pending"

      });

    }


    catch(error){

      console.error(
        "Erro BYPASS:",
        error
      );


      return res
        .status(
          500
        )
        .json({

          ok:
            false,

          error:
            "Erro ao criar liberaÃ§Ã£o"

        });

    }

  }
);


// ============================================================
// LIBERAÃ‡ÃƒO MANUAL PERMANENTE COM CONTROLE DE BANDA
// ============================================================

app.post(
  "/admin/api/devices/manual",
  adminAuth,
  (req, res) => {

    try {

      const target =
        resolveAdminCommandTarget(
          req.body?.event_id
        );

      if(!target.ok){
        return res.status(target.status).json({ok:false,error:target.error});
      }

      const mac = normalizeMac(req.body?.mac);

      const deviceName =
        String(req.body?.device_name || "Dispositivo manual")
          .trim()
          .slice(0,60);

      const rateLimit =
        normalizeAdminRateLimit(req.body?.rate_limit);

      if(!mac){
        return res.status(400).json({ok:false,error:"MAC invÃ¡lido"});
      }

      if(!rateLimit){
        return res.status(400).json({ok:false,error:"Banda invÃ¡lida"});
      }

      const commandRef =
        createAdminCommand(
          target.eventId,
          target.routerId,
          "MANUAL_ADMIN",
          mac,
          deviceName,
          null,
          rateLimit
        );

      return res.json({
        ok:true,
        command_ref:commandRef,
        command_type:"MANUAL_ADMIN",
        event_id:target.eventId,
        router_id:target.routerId,
        mac,
        device_name:deviceName,
        rate_limit:rateLimit,
        status:"pending"
      });

    }
    catch(error){
      console.error("Erro MANUAL_ADMIN:",error);
      return res.status(500).json({ok:false,error:"Erro ao criar liberaÃ§Ã£o manual"});
    }

  }
);


// ============================================================
// LIBERAÃ‡ÃƒO TEMPORÃRIA
// ============================================================

app.post(
  "/admin/api/devices/temp",
  adminAuth,
  (req, res) => {

    try {

      const target =
        resolveAdminCommandTarget(
          req.body?.event_id
        );

      if(!target.ok){
        return res
          .status(target.status)
          .json({
            ok:false,
            error:target.error
          });
      }


      const mac =
        normalizeMac(
          req.body?.mac
        );


      const deviceName =
        String(

          req.body?.device_name

          ||

          "Dispositivo temporÃ¡rio"

        )
          .trim()
          .slice(
            0,
            60
          );


      const minutes =
        Number(
          req.body?.minutes
        );


      const rateLimit =
        normalizeAdminRateLimit(
          req.body?.rate_limit
        );


      if(
        !mac
      ){

        return res
          .status(
            400
          )
          .json({

            ok:
              false,

            error:
              "MAC invÃ¡lido"

          });

      }


      if(
        !ADMIN_TEMP_MINUTES.has(
          minutes
        )
      ){

        return res
          .status(
            400
          )
          .json({

            ok:
              false,

            error:
              "Tempo de liberaÃ§Ã£o invÃ¡lido"

          });

      }


      if(!rateLimit){
        return res.status(400).json({ok:false,error:"Banda invÃ¡lida"});
      }


      const commandRef =
        createAdminCommand(

          target.eventId,

          target.routerId,

          "TEMP_ADMIN",

          mac,

          deviceName,

          minutes,

          rateLimit

        );


      return res.json({

        ok:
          true,

        command_ref:
          commandRef,

        command_type:
          "TEMP_ADMIN",

        event_id:
          target.eventId,

        router_id:
          target.routerId,

        mac,

        device_name:
          deviceName,

        minutes,

        rate_limit:
          rateLimit,

        status:
          "pending"

      });

    }


    catch(error){

      console.error(
        "Erro TEMP_ADMIN:",
        error
      );


      return res
        .status(
          500
        )
        .json({

          ok:
            false,

          error:
            "Erro ao criar liberaÃ§Ã£o temporÃ¡ria"

        });

    }

  }
);


// ============================================================
// REMOVER LIBERAÃ‡ÃƒO ADMINISTRATIVA
// ============================================================

app.post(
  "/admin/api/devices/remove",
  adminAuth,
  (req, res) => {

    try {

      const target =
        resolveAdminCommandTarget(
          req.body?.event_id
        );

      if(!target.ok){
        return res
          .status(target.status)
          .json({
            ok:false,
            error:target.error
          });
      }


      const mac =
        normalizeMac(
          req.body?.mac
        );


      const deviceName =
        String(

          req.body?.device_name

          ||

          "Dispositivo"

        )
          .trim()
          .slice(
            0,
            60
          );


      if(
        !mac
      ){

        return res
          .status(
            400
          )
          .json({

            ok:
              false,

            error:
              "MAC invÃ¡lido"

          });

      }


      const commandRef =
        createAdminCommand(

          target.eventId,

          target.routerId,

          "UNBYPASS",

          mac,

          deviceName

        );


      return res.json({

        ok:
          true,

        command_ref:
          commandRef,

        command_type:
          "UNBYPASS",

        event_id:
          target.eventId,

        router_id:
          target.routerId,

        mac,

        device_name:
          deviceName,

        status:
          "pending"

      });

    }


    catch(error){

      console.error(
        "Erro UNBYPASS:",
        error
      );


      return res
        .status(
          500
        )
        .json({

          ok:
            false,

          error:
            "Erro ao solicitar remoÃ§Ã£o"

        });

    }

  }
);


// ============================================================
// BLOQUEAR AGORA
// ============================================================

app.post(
  "/admin/api/devices/block-now",
  adminAuth,
  (req, res) => {

    try {

      const target =
        resolveAdminCommandTarget(
          req.body?.event_id
        );

      if(!target.ok){
        return res
          .status(target.status)
          .json({
            ok:false,
            error:target.error
          });
      }


      const mac =
        normalizeMac(
          req.body?.mac
        );


      const deviceName =
        String(

          req.body?.device_name

          ||

          "Dispositivo"

        )
          .trim()
          .slice(
            0,
            60
          );


      if(
        !mac
      ){

        return res
          .status(
            400
          )
          .json({

            ok:
              false,

            error:
              "MAC invÃ¡lido"

          });

      }


      const commandRef =
        createAdminCommand(

          target.eventId,

          target.routerId,

          "BLOCK_NOW",

          mac,

          deviceName

        );


      return res.json({

        ok:
          true,

        command_ref:
          commandRef,

        command_type:
          "BLOCK_NOW",

        event_id:
          target.eventId,

        router_id:
          target.routerId,

        mac,

        device_name:
          deviceName,

        status:
          "pending"

      });

    }


    catch(error){

      console.error(
        "Erro BLOCK_NOW:",
        error
      );


      return res
        .status(
          500
        )
        .json({

          ok:
            false,

          error:
            "Erro ao solicitar bloqueio"

        });

    }

  }
);


// ============================================================
// LIMPAR HISTÃ“RICO VISUAL DA TABELA DE ACESSOS
//
// Regra:
// - nÃ£o apaga pagamentos;
// - nÃ£o apaga Logs;
// - nÃ£o altera MikroTik;
// - nÃ£o remove plano PIX ativo;
// - somente define um novo ponto inicial para a tabela.
// ============================================================

app.post(
  "/admin/api/devices/clear-history",
  adminAuth,
  (req, res) => {

    try {

      const eventId =
        positiveId(
          req.body?.event_id
        );


      if(
        !eventId
      ){

        return res
          .status(400)
          .json({
            ok:false,
            error:"Evento invÃ¡lido"
          });

      }


      const event =
        db.prepare(`

          SELECT id

          FROM events

          WHERE id=?

          LIMIT 1

        `).get(
          eventId
        );


      if(
        !event
      ){

        return res
          .status(404)
          .json({
            ok:false,
            error:"Evento nÃ£o encontrado"
          });

      }


      const clearedAt =
        nowIso();


      db.prepare(`

        INSERT INTO event_device_history_cleanup (
          event_id,
          cleared_at
        )

        VALUES (?, ?)

        ON CONFLICT(event_id)
        DO UPDATE SET
          cleared_at=excluded.cleared_at

      `).run(
        eventId,
        clearedAt
      );


      const activePix =
        db.prepare(`

          SELECT COUNT(*) AS total

          FROM orders

          WHERE
            event_id=?
            AND (
              status='approved_pending_router'
              OR (
                status='approved'
                AND access_expires_at IS NOT NULL
                AND access_expired_at IS NULL
                AND access_expires_at > ?
              )
            )

        `).get(
          eventId,
          clearedAt
        );


      console.log(
        "HISTÃ“RICO DE ACESSOS LIMPO:",
        "EVENTO=" + eventId,
        "CORTE=" + clearedAt,
        "PIX_ATIVOS=" +
          Number(
            activePix?.total || 0
          )
      );


      return res.json({
        ok:true,
        event_id:eventId,
        cleared_at:clearedAt,
        active_pix_kept:
          Number(
            activePix?.total || 0
          )
      });

    }

    catch(error){

      console.error(
        "Erro ao limpar histÃ³rico de acessos:",
        error
      );


      return res
        .status(500)
        .json({
          ok:false,
          error:"Erro ao limpar histÃ³rico de acessos"
        });

    }

  }
);


// ============================================================
// RESTAURAR HISTÃ“RICO VISUAL DA TABELA DE ACESSOS
//
// Remove somente o ponto de corte criado por
// "Limpar histÃ³rico da tabela".
//
// NÃƒO apaga ou recria:
// - orders / pagamentos;
// - clientes;
// - logs;
// - comandos da MikroTik;
// - planos PIX.
// ============================================================

app.post(
  "/admin/api/devices/restore-history",
  adminAuth,
  (req, res) => {

    try {

      const eventId =
        positiveId(
          req.body?.event_id
        );


      if(
        !eventId
      ){

        return res
          .status(400)
          .json({
            ok:false,
            error:"Evento invÃ¡lido"
          });
      }


      const event =
        db.prepare(`

          SELECT id

          FROM events

          WHERE id=?

          LIMIT 1

        `).get(
          eventId
        );


      if(
        !event
      ){

        return res
          .status(404)
          .json({
            ok:false,
            error:"Evento nÃ£o encontrado"
          });
      }


      const result =
        db.prepare(`

          DELETE FROM event_device_history_cleanup

          WHERE event_id=?

        `).run(
          eventId
        );


      console.log(
        "HISTÃ“RICO DE ACESSOS RESTAURADO:",
        "EVENTO=" + eventId,
        "REGISTROS_DE_CORTE_REMOVIDOS=" +
          Number(
            result.changes || 0
          )
      );


      return res.json({
        ok:true,
        event_id:eventId,
        restored:true,
        changes:Number(
          result.changes || 0
        )
      });

    }

    catch(error){

      console.error(
        "Erro ao restaurar histÃ³rico de acessos:",
        error
      );


      return res
        .status(500)
        .json({
          ok:false,
          error:"Erro ao restaurar histÃ³rico de acessos"
        });
    }

  }
);


// ============================================================
// LISTAR DISPOSITIVOS
//
// JUNTA:
//
// 1 - ADMINISTRATIVOS
// 2 - PLANOS PIX
//
// ============================================================

app.get(
  "/admin/api/devices",
  adminAuth,
  (req, res) => {

    try {

      const eventId =
        positiveId(
          req.query?.event_id
        );

      if(!eventId){
        return res
          .status(400)
          .json({
            error:"Evento invÃ¡lido"
          });
      }


      const now =
        Date.now();


      const cleanupRow =
        db.prepare(`

          SELECT cleared_at

          FROM event_device_history_cleanup

          WHERE event_id=?

          LIMIT 1

        `).get(
          eventId
        )
        ||
        null;


      const cleanupAt =
        cleanupRow?.cleared_at
        ||
        null;


      const cleanupAtMs =
        cleanupAt
          ? Date.parse(
              cleanupAt
            )
          : NaN;


      // ======================================================
      // DISPOSITIVOS ADMINISTRATIVOS
      // ======================================================

      const adminRows =
        db.prepare(`

          SELECT

            id,

            command_ref,

            command_type,

            mac,

            device_name,

            minutes,

            rate_limit,

            status,

            created_at,

            applied_at

          FROM admin_commands

          WHERE event_id=?

          ORDER BY id DESC

          LIMIT 200

        `).all(
          eventId
        );


      // UNBYPASS / BLOCK_NOW sÃ£o comandos de transiÃ§Ã£o.
      // Quando eles pertencem a uma liberaÃ§Ã£o administrativa
      // anterior, serÃ£o incorporados ao prÃ³prio card original.
      const absorbedAdminActionRefs =
        new Set();


      const adminDevices =
        adminRows.map(
          row => {

            let expiresAt =
              null;

            let remainingSeconds =
              null;

            let expired =
              false;


            const rowMac =
              normalizeMac(
                row.mac
              );


            const isAdminRelease =
              (
                row.command_type ===
                  "BYPASS"
                ||
                row.command_type ===
                  "MANUAL_ADMIN"
                ||
                row.command_type ===
                  "TEMP_ADMIN"
              );


            let endCommand =
              null;


            if(
              isAdminRelease
              &&
              rowMac
            ){

              const startMs =
                Date.parse(
                  row.applied_at
                  ||
                  row.created_at
                  ||
                  ""
                );


              const nextRelease =
                adminRows
                  .filter(
                    candidate => {

                      if(
                        candidate.id <=
                          row.id
                      ){
                        return false;
                      }


                      if(
                        ![
                          "BYPASS",
                          "MANUAL_ADMIN",
                          "TEMP_ADMIN"
                        ].includes(
                          candidate.command_type
                        )
                      ){
                        return false;
                      }


                      return (
                        normalizeMac(
                          candidate.mac
                        ) ===
                          rowMac
                      );

                    }
                  )
                  .sort(
                    (a, b) =>
                      a.id - b.id
                  )[0]
                ||
                null;


              const nextReleaseMs =
                nextRelease
                  ? Date.parse(
                      nextRelease.applied_at
                      ||
                      nextRelease.created_at
                      ||
                      ""
                    )
                  : NaN;


              endCommand =
                adminRows
                  .filter(
                    candidate => {

                      if(
                        candidate.id <=
                          row.id
                      ){
                        return false;
                      }


                      if(
                        ![
                          "UNBYPASS",
                          "BLOCK_NOW"
                        ].includes(
                          candidate.command_type
                        )
                      ){
                        return false;
                      }


                      if(
                        normalizeMac(
                          candidate.mac
                        ) !==
                          rowMac
                      ){
                        return false;
                      }


                      const endMs =
                        Date.parse(
                          candidate.applied_at
                          ||
                          candidate.created_at
                          ||
                          ""
                        );


                      if(
                        Number.isFinite(
                          startMs
                        )
                        &&
                        Number.isFinite(
                          endMs
                        )
                        &&
                        endMs <
                          startMs
                      ){
                        return false;
                      }


                      if(
                        Number.isFinite(
                          nextReleaseMs
                        )
                        &&
                        Number.isFinite(
                          endMs
                        )
                        &&
                        endMs >=
                          nextReleaseMs
                      ){
                        return false;
                      }


                      return true;

                    }
                  )
                  .sort(
                    (a, b) =>
                      a.id - b.id
                  )[0]
                ||
                null;


              if(
                endCommand?.command_ref
              ){
                absorbedAdminActionRefs.add(
                  endCommand.command_ref
                );
              }

            }


            if(

              row.command_type ===
              "TEMP_ADMIN"

              &&

              row.status ===
              "applied"

              &&

              row.applied_at

              &&

              Number(
                row.minutes
              ) > 0

            ){

              const appliedAtMs =
                Date.parse(
                  row.applied_at
                );


              if(
                Number.isFinite(
                  appliedAtMs
                )
              ){

                const expiresAtMs =

                  appliedAtMs

                  +

                  Number(
                    row.minutes
                  )

                  *

                  60

                  *

                  1000;


                expiresAt =
                  new Date(
                    expiresAtMs
                  ).toISOString();


                remainingSeconds =
                  Math.max(

                    0,

                    Math.ceil(

                      (
                        expiresAtMs
                        -
                        now
                      )

                      /

                      1000

                    )

                  );


                expired =
                  remainingSeconds === 0;

              }

            }


            let mergedStatus =
              row.status;


            let endedAt =
              null;


            let endType =
              null;


            if(
              endCommand
            ){

              endedAt =
                endCommand.applied_at
                ||
                null;


              endType =
                endCommand.command_type;


              if(
                endCommand.status ===
                  "pending"
              ){

                mergedStatus =
                  endCommand.command_type ===
                    "BLOCK_NOW"
                    ? "blocking"
                    : "removing";

              }


              else if(
                endCommand.status ===
                  "applied"
              ){

                if(
                  endCommand.command_type ===
                    "BLOCK_NOW"
                ){

                  mergedStatus =
                    "blocked";

                }

                else if(
                  String(
                    endCommand.command_ref || ""
                  ).startsWith(
                    "admin_expire_"
                  )
                ){

                  mergedStatus =
                    "expired";

                  expired =
                    true;

                }

                else{

                  mergedStatus =
                    "removed";

                }


                remainingSeconds =
                  0;

              }

            }


            return {

              ...row,

              status:
                mergedStatus,

              source:
                "admin",

              payment_type:
                "admin",

              expires_at:
                expiresAt,

              remaining_seconds:
                remainingSeconds,

              expired:
                expired,

              ended_at:
                endedAt,

              end_command_type:
                endType,

              end_command_ref:
                endCommand?.command_ref
                ||
                null

            };

          }
        );


      // ======================================================
      // CLIENTES PIX
      //
      // Consideramos pedidos que chegaram a ser aprovados.
      //
      // Cada compra Ã© um registro independente.
      // ======================================================

      const pixRows =
        db.prepare(`

          SELECT

            o.id,

            o.external_ref,

            o.client_id,

            o.plan_id,

            o.amount,

            o.payment_method,

            o.voucher_serial,

            o.minutes,

            o.rate_limit,

            o.mac,

            o.original_mac,

            o.effective_mac,

            o.ip,

            o.status,

            o.created_at,

            o.approved_at,

            o.access_json,

            o.access_expires_at,

            o.access_expired_at,

            c.name AS customer_name,

            c.phone AS customer_phone,

            c.email AS customer_email

          FROM orders o

          LEFT JOIN customers c
            ON c.client_id=o.client_id

          WHERE

            o.event_id=?

            AND o.status IN (
              'approved',
              'approved_pending_router'
            )

          ORDER BY o.id DESC

          LIMIT 200

        `).all(
          eventId
        );


      // BLOCK_NOW aplicado sobre um PIX serÃ¡ incorporado ao
      // prÃ³prio registro PIX. Assim nÃ£o mostramos dois cards para
      // o mesmo acesso.
      const absorbedBlockRefs =
        new Set();


      const pixDevices =
        pixRows.map(
          row => {

            const mac =
              normalizeMac(

                row.effective_mac

                ||

                row.mac

                ||

                row.original_mac

              );


            const plan =
              PLANS[
                row.plan_id
              ];


            let confirmedAt =
              row.approved_at ||
              null;


            let expiresAt =
              row.access_expires_at ||
              null;


            // =================================================
            // BLOQUEIO MANUAL APLICADO DEPOIS DESTE PIX
            //
            // adminRows estÃ¡ em ordem decrescente, entÃ£o find()
            // retorna o bloqueio mais recente compatÃ­vel.
            // Um bloqueio antigo nÃ£o afeta uma compra nova porque
            // exigimos applied_at >= horÃ¡rio de liberaÃ§Ã£o do PIX.
            // =================================================

            const confirmedAtMs =
              Date.parse(
                confirmedAt
                ||
                row.created_at
                ||
                ""
              );


            const blockCommand =
              adminRows.find(
                adminRow => {

                  if(
                    adminRow.command_type !==
                      "BLOCK_NOW"
                    ||
                    adminRow.status !==
                      "applied"
                  ){
                    return false;
                  }


                  if(
                    normalizeMac(
                      adminRow.mac
                    ) !== mac
                  ){
                    return false;
                  }


                  const blockAtMs =
                    Date.parse(
                      adminRow.applied_at
                      ||
                      ""
                    );


                  if(
                    !Number.isFinite(
                      blockAtMs
                    )
                  ){
                    return false;
                  }


                  if(
                    Number.isFinite(
                      confirmedAtMs
                    )
                    &&
                    blockAtMs <
                      confirmedAtMs
                  ){
                    return false;
                  }


                  return true;

                }
              )
              ||
              null;

            const pendingBlockCommand =
              adminRows.find(
                adminRow => {
                  if(
                    adminRow.command_type !== "BLOCK_NOW"
                    || adminRow.status !== "pending"
                    || normalizeMac(adminRow.mac) !== mac
                  ){
                    return false;
                  }

                  const requestedAtMs = Date.parse(adminRow.created_at || "");
                  return !Number.isFinite(confirmedAtMs)
                    || !Number.isFinite(requestedAtMs)
                    || requestedAtMs >= confirmedAtMs;
                }
              ) || null;

            if(pendingBlockCommand?.command_ref){
              absorbedBlockRefs.add(pendingBlockCommand.command_ref);
            }


            const blocked =
              Boolean(
                blockCommand
              );


            if(
              blockCommand?.command_ref
            ){
              absorbedBlockRefs.add(
                blockCommand.command_ref
              );
            }


            let accessData =
              null;


            // =================================================
            // TENTAR LER ACCESS_JSON
            // =================================================

            if(
              row.access_json
            ){

              try {

                accessData =
                  JSON.parse(
                    row.access_json
                  );


                if(
                  accessData?.confirmed_at
                ){

                  confirmedAt =
                    accessData.confirmed_at;

                }


                if(
                  accessData?.expires_at
                ){

                  expiresAt =
                    accessData.expires_at;

                }

              }

              catch(error){

                console.warn(
                  "ADMIN: access_json invÃ¡lido:",
                  row.external_ref
                );

              }

            }


            // =================================================
            // TEMPO RESTANTE
            // =================================================

            let remainingSeconds =
              blocked
                ? 0
                : null;


            let expired =
              false;


            if(
              !blocked
              &&
              expiresAt
            ){

              const expiresAtMs =
                Date.parse(
                  expiresAt
                );


              if(
                Number.isFinite(
                  expiresAtMs
                )
              ){

                remainingSeconds =
                  Math.max(

                    0,

                    Math.ceil(

                      (
                        expiresAtMs
                        -
                        now
                      )

                      /

                      1000

                    )

                  );


                expired =

                  remainingSeconds === 0

                  ||

                  Boolean(
                    row.access_expired_at
                  );

              }

            }


            // =================================================
            // NOME DO PLANO
            // =================================================

            const planName =

              plan?.name

              ||

              (
                Number(
                  row.minutes
                ) === 60

                ?

                "1 hora"

                :

                `${row.minutes} minutos`
              );


            // =================================================
            // FORMATO COMPATÃVEL COM A TELA ATUAL
            // =================================================

            return {

              id:
                `pix_${row.id}`,

              command_ref:
                row.external_ref,

              command_type:
                "PIX",

              mac:
                mac,

              device_name:
                row.payment_method === "voucher"
                  ? `Cliente Voucher #${Number(row.voucher_serial) || "?"}`
                  : "Cliente PIX",

              minutes:
                Number(
                  row.minutes
                ),

              status:
                blocked
                  ? "blocked"
                  : (
                      expired
                        ? "expired"
                        : pendingBlockCommand
                          ? "blocking"
                          : row.status
                    ),

              blocked:
                blocked,

              blocked_at:
                blockCommand?.applied_at || row.access_expired_at || null,

              block_command_ref:
                blockCommand?.command_ref
                ||
                null,

              created_at:
                row.created_at,

              applied_at:
                confirmedAt,

              expires_at:
                expiresAt,

              remaining_seconds:
                remainingSeconds,

              expired:
                blocked
                  ? false
                  : expired,

              source:
                "pix",

              payment_type:
                row.payment_method || "pix",

              payment_method:
                row.payment_method || "pix",

              voucher_serial:
                row.voucher_serial || null,

              plan_id:
                row.plan_id,

              plan_name:
                planName,

              amount:
                Number(
                  row.amount
                ),

              rate_limit:
                row.rate_limit,

              ip:
                row.ip,

              approved_at:
                row.approved_at,

              confirmed_at:
                confirmedAt,

              access_expires_at:
                expiresAt,

              access_expired_at:
                row.access_expired_at,

              client_id:
                row.client_id,

              customer: {
                client_id:
                  row.client_id || null,

                name:
                  row.customer_name || "",

                phone:
                  row.customer_phone || "",

                email:
                  row.customer_email || ""
              },

              customer_name:
                row.customer_name || "",

              customer_phone:
                row.customer_phone || "",

              customer_email:
                row.customer_email || "",

              external_ref:
                row.external_ref

            };

          }
        );


      // ======================================================
      // JUNTAR AS DUAS LISTAS
      // ======================================================

      const visibleAdminDevices =
        adminDevices.filter(
          device =>
            !absorbedBlockRefs.has(
              device.command_ref
            )
            &&
            !absorbedAdminActionRefs.has(
              device.command_ref
            )
        );


      const result = [

        ...pixDevices,

        ...visibleAdminDevices

      ];


      // ======================================================
      // APLICAR LIMPEZA VISUAL DA TABELA
      //
      // Sempre preservamos:
      // - PIX aprovado ainda dentro do prazo;
      // - PIX jÃ¡ pago aguardando aplicaÃ§Ã£o na MikroTik.
      //
      // Demais registros sÃ³ aparecem se forem posteriores ao
      // Ãºltimo "Limpar histÃ³rico da tabela".
      // ======================================================

      const visibleResult =
        result.filter(
          device => {

            const isActivePaidPix =
              (
                device.source ===
                  "pix"
                &&
                (
                  device.status ===
                    "approved_pending_router"
                  ||
                  (
                    device.status ===
                      "approved"
                    &&
                    !device.expired
                    &&
                    Number(
                      device.remaining_seconds
                    ) > 0
                  )
                )
              );


            if(
              isActivePaidPix
            ){

              return true;

            }


            if(
              !Number.isFinite(
                cleanupAtMs
              )
            ){

              return true;

            }


            const recordTime =
              Date.parse(

                device.ended_at
                ||
                device.blocked_at
                ||
                device.applied_at
                ||
                device.created_at
                ||
                ""

              );


            return (
              Number.isFinite(
                recordTime
              )
              &&
              recordTime >
                cleanupAtMs
            );

          }
        );


      // ======================================================
      // ORDENAR PELO REGISTRO MAIS RECENTE
      // ======================================================

      visibleResult.sort(
        (a, b) => {

          const dateA =
            Date.parse(
              a.applied_at ||
              a.created_at ||
              0
            ) || 0;


          const dateB =
            Date.parse(
              b.applied_at ||
              b.created_at ||
              0
            ) || 0;


          return dateB - dateA;

        }
      );


      return res.json(
        visibleResult
      );

    }


    catch(error){

      console.error(
        "Erro ao listar dispositivos:",
        error
      );


      return res
        .status(
          500
        )
        .json({

          error:
            "Erro ao listar dispositivos"

        });

    }

  }
);



// ============================================================
// EXPIRAR TEMP_ADMIN POR TEMPO CORRIDO
//
// Regra:
// - TEMP_ADMIN comeÃ§a a contar quando recebe ACK (applied_at).
// - Quando applied_at + minutes vence, o backend cria um
//   UNBYPASS automÃ¡tico para a MESMA MikroTik.
// - A MikroTik recebe esse UNBYPASS no ADMIN-PULL e remove o
//   ip-binding administrativo.
// - O EXISTS impede criar mais de um corte automÃ¡tico para o
//   mesmo TEMP_ADMIN.
// ============================================================

function enqueueExpiredAdminTemporaryAccess(
  eventId,
  routerId
){

  const now =
    nowIso();


  const expiredRows =
    db.prepare(`

      SELECT
        t.id,
        t.command_ref,
        t.mac,
        t.device_name,
        t.minutes,
        t.applied_at

      FROM admin_commands t

      WHERE
        t.event_id=?
        AND t.router_id=?
        AND t.command_type='TEMP_ADMIN'
        AND t.status='applied'
        AND t.applied_at IS NOT NULL
        AND COALESCE(t.minutes, 0) > 0

        AND datetime(
          t.applied_at,
          '+' || CAST(t.minutes AS INTEGER) || ' minutes'
        ) <= datetime(?)

        AND NOT EXISTS (

          SELECT 1

          FROM admin_commands x

          WHERE
            x.event_id=t.event_id
            AND x.router_id=t.router_id
            AND x.mac=t.mac
            AND x.command_type IN (
              'UNBYPASS',
              'BLOCK_NOW'
            )
            AND x.created_at >= t.applied_at

        )

      ORDER BY t.id ASC

      LIMIT 50

    `).all(
      eventId,
      routerId,
      now
    );


  for(
    const row of expiredRows
  ){

    const commandRef =
      "admin_expire_" +
      crypto.randomUUID();


    db.prepare(`

      INSERT INTO admin_commands (
        command_ref,
        command_type,
        mac,
        device_name,
        minutes,
        event_id,
        router_id,
        status,
        created_at
      )

      VALUES (
        ?, 'UNBYPASS', ?, ?, NULL, ?, ?, 'pending', ?
      )

    `).run(
      commandRef,
      row.mac,
      (
        row.device_name
        ||
        "LiberaÃ§Ã£o temporÃ¡ria"
      ),
      eventId,
      routerId,
      now
    );


    console.log(
      "ADMIN TEMP EXPIRADO:",
      row.mac,
      "TEMP_REF=" + row.command_ref,
      "UNBYPASS_REF=" + commandRef
    );

  }


  return expiredRows.length;

}


// ============================================================
// MIKROTIK - BUSCAR COMANDO ADMIN DA SUA FILA
// ============================================================

app.get(
  "/api/mikrotik/admin-pending",
  (req, res) => {

    const polling =
      resolvePollingRouter(req);

    if(
      !polling.ok
      ||
      !polling.router
    ){
      return res
        .status(401)
        .type("text/plain")
        .send("UNAUTHORIZED");
    }

    const router =
      polling.router;


    // Antes de entregar o prÃ³ximo comando, verifica se existe
    // TEMP_ADMIN vencido e enfileira o UNBYPASS automÃ¡tico.
    enqueueExpiredAdminTemporaryAccess(
      router.event_id,
      router.id
    );


    res.set(
      "Cache-Control",
      "no-store"
    );

    res.type(
      "text/plain"
    );

    const command =
      db.prepare(`
        SELECT *
        FROM admin_commands
        WHERE
          status='pending'
          AND event_id=?
          AND router_id=?
        ORDER BY id ASC
        LIMIT 1
      `).get(
        router.event_id,
        router.id
      );

    if(!command){
      return res.send("NONE");
    }

    if(
      command.command_type ===
      "TEMP_ADMIN"
    ){
      return res.send(
        [
          "TEMP_ADMIN",
          safeText(command.mac),
          safeText(command.device_name),
          Number(command.minutes),
          safeText(command.rate_limit),
          safeText(command.command_ref)
        ].join("|")
      );
    }


    if(
      command.command_type ===
      "MANUAL_ADMIN"
    ){
      return res.send(
        [
          "MANUAL_ADMIN",
          safeText(command.mac),
          safeText(command.device_name),
          safeText(command.rate_limit),
          safeText(command.command_ref)
        ].join("|")
      );
    }


    return res.send(
      [
        safeText(command.command_type),
        safeText(command.mac),
        safeText(command.device_name),
        safeText(command.command_ref)
      ].join("|")
    );
  }
);


// ============================================================
// MIKROTIK - CONFIRMAR COMANDO ADMIN DA SUA FILA
// ============================================================

app.get(
  "/api/mikrotik/admin-ack",
  (req, res) => {

    const polling =
      resolvePollingRouter(req);

    if(
      !polling.ok
      ||
      !polling.router
    ){
      return res
        .status(401)
        .type("text/plain")
        .send("UNAUTHORIZED");
    }

    const router =
      polling.router;

    const commandRef =
      String(
        req.headers["x-command-ref"]
        ||
        req.query.ref
        ||
        ""
      ).trim();

    if(!commandRef){
      return res
        .status(400)
        .type("text/plain")
        .send("BAD_REQUEST");
    }

    const command =
      db.prepare(`
        SELECT *
        FROM admin_commands
        WHERE
          command_ref=?
          AND event_id=?
          AND router_id=?
        LIMIT 1
      `).get(
        commandRef,
        router.event_id,
        router.id
      );

    if(!command){
      return res
        .status(404)
        .type("text/plain")
        .send("NOT_FOUND");
    }

    const ackTime =
      (
        command.status === "applied"
        &&
        command.applied_at
      )
        ? command.applied_at
        : nowIso();


    if(
      command.status !==
      "applied"
    ){
      db.prepare(`
        UPDATE admin_commands
        SET
          status='applied',
          applied_at=?
        WHERE
          command_ref=?
          AND event_id=?
          AND router_id=?
      `).run(
        ackTime,
        commandRef,
        router.event_id,
        router.id
      );
    }


    // ========================================================
    // BLOCK_NOW TAMBÃ‰M ENCERRA O DIREITO DE ACESSO PIX
    //
    // A MikroTik jÃ¡ cortou a navegaÃ§Ã£o. Aqui sincronizamos o
    // backend para que:
    // - o PIX nÃ£o continue aparecendo como ativo;
    // - o portal nÃ£o reutilize o plano bloqueado;
    // - o grant da MikroTik fique encerrado.
    // ========================================================

    if(
      command.command_type ===
      "BLOCK_NOW"
    ){

      const blockedMac =
        normalizeMac(
          command.mac
        );


      if(
        blockedMac
      ){

        const activePixOrders =
          db.prepare(`

            SELECT
              id,
              mac,
              original_mac,
              effective_mac

            FROM orders

            WHERE
              event_id=?
              AND status IN (
                'approved',
                'approved_pending_router'
              )
              AND access_expires_at IS NOT NULL
              AND access_expired_at IS NULL
              AND access_expires_at > ?

            ORDER BY id DESC

          `).all(
            router.event_id,
            ackTime
          );


        const matchingOrders =
          activePixOrders.filter(
            row =>
              normalizeMac(
                row.effective_mac
                ||
                row.mac
                ||
                row.original_mac
              ) === blockedMac
          );


        for(
          const order
          of matchingOrders
        ){

          db.prepare(`

            UPDATE orders

            SET
              access_expired_at=?

            WHERE
              id=?
              AND access_expired_at IS NULL

          `).run(
            ackTime,
            order.id
          );


          db.prepare(`

            UPDATE router_access_grants

            SET
              status='expired',
              expired_at=?,
              updated_at=?

            WHERE
              order_id=?
              AND event_id=?
              AND router_id=?
              AND status<>'expired'

          `).run(
            ackTime,
            ackTime,
            order.id,
            router.event_id,
            router.id
          );


          console.log(
            "ADMIN BLOCK PIX ENCERRADO:",
            blockedMac,
            "ORDER=" + order.id,
            "REF=" + commandRef
          );

        }

      }

    }


    console.log(
      "ADMIN ACK:",
      command.command_type,
      command.mac,
      "EVENTO=" + router.event_id,
      "ROUTER=" + router.router_key,
      "REF=" + commandRef
    );

    return res
      .type("text/plain")
      .send("OK");
  }
);



// ============================================================
// DADOS DO CLIENTE PELO CLIENT_ID
//
// Usado pelo submenu "Dados do cliente" no painel.
// Retorna cadastro + pagamentos + linha do tempo do funil.
// ============================================================

app.get(
  "/admin/api/customers/:clientId",
  adminAuth,
  (req, res) => {

    try {

      const clientId =
        normalizeClientId(
          req.params?.clientId
        );


      if(
        !clientId
      ) {

        return res
          .status(
            400
          )
          .json({
            ok:false,
            error:"CLIENT_ID invÃ¡lido"
          });

      }


      const customer =
        db.prepare(`

          SELECT
            client_id,
            name,
            phone,
            email,
            created_at,
            updated_at,
            last_seen_at

          FROM customers

          WHERE client_id=?

          LIMIT 1

        `).get(
          clientId
        )
        ||
        null;


      const payments =
        db.prepare(`

          SELECT
            o.external_ref,
            o.event_id,
            e.name AS event_name,
            o.plan_id,
            COALESCE(p.name,o.plan_id) AS plan_name,
            o.amount,
            o.payment_method,
            o.voucher_serial,
            o.minutes,
            o.rate_limit,
            o.effective_mac,
            o.mac,
            o.ip,
            o.status,
            o.created_at,
            o.approved_at,
            o.access_expires_at,
            o.access_expired_at

          FROM orders o

          LEFT JOIN events e
            ON e.id=o.event_id
          LEFT JOIN event_plans p
            ON p.event_id=o.event_id AND p.plan_key=o.plan_id

          WHERE
            o.client_id=?

          ORDER BY
            o.id DESC

          LIMIT 50

        `).all(
          clientId
        );


      const funnel =
        db.prepare(`
          SELECT
            f.id,
            f.event_id,
            e.name AS event_name,
            f.router_id,
            r.name AS router_name,
            r.router_key,
            f.client_id,
            f.mac,
            f.ip,
            f.order_id,
            f.order_ref,
            f.step,
            f.plan_id,
            f.source,
            f.metadata_json,
            f.created_at
          FROM funnel_events f
          LEFT JOIN events e
            ON e.id=f.event_id
          LEFT JOIN routers r
            ON r.id=f.router_id
          WHERE f.client_id=?
          ORDER BY f.id DESC
          LIMIT 200
        `).all(
          clientId
        ).map(
          item => {
            let metadata = null;
            try{
              metadata =
                item.metadata_json
                  ? JSON.parse(item.metadata_json)
                  : null;
            }catch(error){
              metadata = null;
            }
            return {
              ...item,
              metadata
            };
          }
        );


      const totalPaid =
        payments
          .filter(
            item =>
              [
                "approved",
                "approved_pending_router"
              ].includes(
                item.status
              )
          )
          .reduce(
            (total, item) =>
              total
              +
              Number(
                item.amount || 0
              ),
            0
          );


      return res.json({
        ok:true,
        customer,
        summary:{
          payments_count:
            payments.length,
          total_paid:
            Number(
              totalPaid.toFixed(2)
            ),
          last_payment:
            payments[0] || null
        },
        payments,
        funnel
      });

    }
    catch(error) {

      console.error(
        "Erro ao buscar dados do cliente:",
        error
      );

      return res
        .status(
          500
        )
        .json({
          ok:false,
          error:"Erro ao buscar dados do cliente"
        });

    }

  }
);



// ============================================================
// V15 - ADMIN - EVENTOS DO FUNIL
// ============================================================

app.get(
  "/admin/api/funnel/events",
  adminAuth,
  (req, res) => {
    try{
      const eventId =
        positiveId(
          req.query.event_id
        );

      const limit =
        Math.max(
          1,
          Math.min(
            1000,
            Number(req.query.limit || 300)
          )
        );

      const rows =
        eventId
          ? db.prepare(`
              SELECT f.*, e.name AS event_name, r.name AS router_name, r.router_key
              FROM funnel_events f
              LEFT JOIN events e ON e.id=f.event_id
              LEFT JOIN routers r ON r.id=f.router_id
              WHERE f.event_id=?
              ORDER BY f.id DESC
              LIMIT ?
            `).all(eventId, limit)
          : db.prepare(`
              SELECT f.*, e.name AS event_name, r.name AS router_name, r.router_key
              FROM funnel_events f
              LEFT JOIN events e ON e.id=f.event_id
              LEFT JOIN routers r ON r.id=f.router_id
              ORDER BY f.id DESC
              LIMIT ?
            `).all(limit);

      return res.json({
        ok:true,
        count:rows.length,
        events:rows.map(row => {
          let metadata = null;
          try{
            metadata = row.metadata_json
              ? JSON.parse(row.metadata_json)
              : null;
          }catch(error){
            metadata = null;
          }
          return {
            ...row,
            metadata
          };
        })
      });
    }
    catch(error){
      console.error(
        "Erro ao listar funil:",
        error
      );
      return res.status(500).json({
        ok:false,
        error:"Erro ao listar funil"
      });
    }
  }
);


app.get(
  "/admin/api/funnel/summary",
  adminAuth,
  (req, res) => {
    try{
      const eventId =
        positiveId(
          req.query.event_id
        );

      const officialSteps = [
        "HOTSPOT_DETECTED",
        "PORTAL_OPENED",
        "REGISTRATION_STARTED",
        "REGISTRATION_COMPLETED",
        "PLAN_SELECTED",
        "PIX_GENERATED",
        "PIX_COPIED",
        "TEMPORARY_ACCESS_REQUESTED",
        "TEMPORARY_ACCESS_APPLIED",
        "INTERNET_CONFIRMED",
        "PAYMENT_APPROVED",
        "PAID_PLAN_APPLIED",
        "NAVIGATION_AFTER_PAYMENT",
        "ACCESS_EXPIRED"
      ];

      const rows =
        eventId
          ? db.prepare(`
              SELECT step, COUNT(*) AS total
              FROM funnel_events
              WHERE event_id=?
              GROUP BY step
            `).all(eventId)
          : db.prepare(`
              SELECT step, COUNT(*) AS total
              FROM funnel_events
              GROUP BY step
            `).all();

      const totals = {};
      for(const step of officialSteps){
        totals[step] = 0;
      }
      for(const row of rows){
        const step = normalizeFunnelStep(row.step);
        if(Object.prototype.hasOwnProperty.call(totals, step)){
          totals[step] += Number(row.total || 0);
        }
      }

      return res.json({
        ok:true,
        event_id:eventId || null,
        steps:officialSteps,
        totals
      });
    }
    catch(error){
      console.error(
        "Erro ao resumir funil:",
        error
      );
      return res.status(500).json({
        ok:false,
        error:"Erro ao resumir funil"
      });
    }
  }
);


// ============================================================
// FIM DO BLOCO 7/10
// ============================================================

// ============================================================
// BLOCO 8/10 - DEBUG, PAINEL ADMIN, STATUS E HISTORICO DOS LINKS
// ============================================================


// ============================================================
// TABELA DE STATUS ATUAL DOS LINKS
//
// Mantemos apenas o estado atual.
//
// id = 1
// ============================================================

db.exec(`

CREATE TABLE IF NOT EXISTS internet_status (

  id INTEGER PRIMARY KEY,

  provider_status TEXT,

  starlink_status TEXT,

  active_link TEXT,

  failover_status TEXT,

  provider_ping TEXT,

  starlink_ping TEXT,

  updated_at TEXT

);

`);


// ============================================================
// TABELA DE HISTORICO DO FAILOVER
//
// EVENTOS:
//
// provider_down
// provider_up
// failover_to_starlink
// failback_to_provider
// internet_down
// ============================================================

db.exec(`

CREATE TABLE IF NOT EXISTS internet_events (

  id INTEGER PRIMARY KEY AUTOINCREMENT,

  event_type TEXT NOT NULL,

  previous_provider_status TEXT,

  new_provider_status TEXT,

  previous_starlink_status TEXT,

  new_starlink_status TEXT,

  previous_active_link TEXT,

  new_active_link TEXT,

  previous_failover_status TEXT,

  new_failover_status TEXT,

  created_at TEXT NOT NULL

);

`);


// ============================================================
// INDICES
// ============================================================

db.exec(`

CREATE INDEX IF NOT EXISTS idx_internet_events_created_at
ON internet_events(created_at);

CREATE INDEX IF NOT EXISTS idx_internet_events_type
ON internet_events(event_type);

`);


// ============================================================
// GARANTIR REGISTRO INICIAL
// ============================================================

const internetStatusExists =
  db.prepare(`

    SELECT id

    FROM internet_status

    WHERE id=1

  `).get();


if(
  !internetStatusExists
){

  db.prepare(`

    INSERT INTO internet_status (

      id,

      provider_status,

      starlink_status,

      active_link,

      failover_status,

      provider_ping,

      starlink_ping,

      updated_at

    )

    VALUES (

      1,

      'unknown',

      'unknown',

      'unknown',

      'automatic',

      NULL,

      NULL,

      ?

    )

  `).run(
    nowIso()
  );

}


// ============================================================
// NORMALIZAR STATUS DO LINK
// ============================================================

function normalizeLinkStatus(value){

  const status =
    String(
      value || ""
    )
      .trim()
      .toLowerCase();


  if(
    [
      "online",
      "offline",
      "standby",
      "unknown"
    ].includes(
      status
    )
  ){

    return status;

  }


  return "unknown";

}


// ============================================================
// NORMALIZAR LINK ATIVO
// ============================================================

function normalizeActiveLink(value){

  const active =
    String(
      value || ""
    )
      .trim()
      .toLowerCase();


  if(
    [
      "provider",
      "starlink",
      "none",
      "unknown"
    ].includes(
      active
    )
  ){

    return active;

  }


  return "unknown";

}


// ============================================================
// NORMALIZAR FAILOVER
// ============================================================

function normalizeFailoverStatus(value){

  const status =
    String(
      value || ""
    )
      .trim()
      .toLowerCase();


  if(
    [
      "automatic",
      "provider",
      "starlink",
      "failover",
      "unknown"
    ].includes(
      status
    )
  ){

    return status;

  }


  return "automatic";

}


// ============================================================
// REGISTRAR EVENTO
// ============================================================

function registerInternetEvent(
  eventType,
  previous,
  current,
  createdAt
){

  db.prepare(`

    INSERT INTO internet_events (

      event_type,

      previous_provider_status,

      new_provider_status,

      previous_starlink_status,

      new_starlink_status,

      previous_active_link,

      new_active_link,

      previous_failover_status,

      new_failover_status,

      created_at

    )

    VALUES (
      ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
    )

  `).run(

    eventType,

    previous?.provider_status || "unknown",

    current?.provider_status || "unknown",

    previous?.starlink_status || "unknown",

    current?.starlink_status || "unknown",

    previous?.active_link || "unknown",

    current?.active_link || "unknown",

    previous?.failover_status || "unknown",

    current?.failover_status || "unknown",

    createdAt

  );


  console.log(
    "INTERNET EVENT:",
    eventType,
    "DE=" + (
      previous?.active_link ||
      "unknown"
    ),
    "PARA=" + (
      current?.active_link ||
      "unknown"
    )
  );

}


// ============================================================
// DETECTAR MUDANCAS REAIS
//
// Evita gravar uma linha no historico a cada consulta
// da MikroTik.
//
// Registramos apenas acontecimentos importantes.
// ============================================================

function detectInternetEvents(
  previous,
  current,
  createdAt
){

  if(
    !previous
  ){

    return;

  }


  // ==========================================================
  // PROVEDOR CAIU
  // ==========================================================

  if(

    previous.provider_status !==
    "offline"

    &&

    current.provider_status ===
    "offline"

  ){

    registerInternetEvent(
      "provider_down",
      previous,
      current,
      createdAt
    );

  }


  // ==========================================================
  // PROVEDOR VOLTOU
  // ==========================================================

  if(

    previous.provider_status ===
    "offline"

    &&

    current.provider_status ===
    "online"

  ){

    registerInternetEvent(
      "provider_up",
      previous,
      current,
      createdAt
    );

  }


  // ==========================================================
  // STARLINK ASSUMIU
  // ==========================================================

  if(

    previous.active_link !==
    "starlink"

    &&

    current.active_link ===
    "starlink"

  ){

    registerInternetEvent(
      "failover_to_starlink",
      previous,
      current,
      createdAt
    );

  }


  // ==========================================================
  // PROVEDOR REASSUMIU
  // ==========================================================

  if(

    previous.active_link ===
    "starlink"

    &&

    current.active_link ===
    "provider"

  ){

    registerInternetEvent(
      "failback_to_provider",
      previous,
      current,
      createdAt
    );

  }


  // ==========================================================
  // NENHUM LINK ATIVO
  // ==========================================================

  if(

    previous.active_link !==
    "none"

    &&

    current.active_link ===
    "none"

  ){

    registerInternetEvent(
      "internet_down",
      previous,
      current,
      createdAt
    );

  }

}


// ============================================================
// INICIO DO DIA UTC
//
// Serve para os indicadores "hoje".
//
// A exibicao das datas continua sendo convertida pelo
// navegador para o horario local.
// ============================================================

function startOfTodayIso(){

  const now =
    new Date();


  now.setUTCHours(
    0,
    0,
    0,
    0
  );


  return now.toISOString();

}


// ============================================================
// CALCULAR TEMPO TOTAL NA STARLINK HOJE
//
// Retorna segundos.
// ============================================================

function calculateStarlinkSecondsToday(){

  const dayStart =
    startOfTodayIso();


  const dayStartMs =
    Date.parse(
      dayStart
    );


  const nowMs =
    Date.now();


  // ==========================================================
  // ESTADO EXISTENTE ANTES DO INICIO DO DIA
  // ==========================================================

  const previousSwitch =
    db.prepare(`

      SELECT *

      FROM internet_events

      WHERE

        event_type IN (
          'failover_to_starlink',
          'failback_to_provider'
        )

        AND

        created_at < ?

      ORDER BY id DESC

      LIMIT 1

    `).get(
      dayStart
    );


  let starlinkActive =
    Boolean(

      previousSwitch

      &&

      previousSwitch.event_type ===
      "failover_to_starlink"

    );


  let activeSinceMs =
    starlinkActive
      ? dayStartMs
      : null;


  let totalMs =
    0;


  // ==========================================================
  // TROCAS OCORRIDAS HOJE
  // ==========================================================

  const switches =
    db.prepare(`

      SELECT *

      FROM internet_events

      WHERE

        event_type IN (
          'failover_to_starlink',
          'failback_to_provider'
        )

        AND

        created_at >= ?

      ORDER BY id ASC

    `).all(
      dayStart
    );


  for(
    const event
    of switches
  ){

    const eventMs =
      Date.parse(
        event.created_at
      );


    if(
      !Number.isFinite(
        eventMs
      )
    ){

      continue;

    }


    // ========================================================
    // ENTROU NA STARLINK
    // ========================================================

    if(
      event.event_type ===
      "failover_to_starlink"
    ){

      if(
        !starlinkActive
      ){

        starlinkActive =
          true;


        activeSinceMs =
          Math.max(
            eventMs,
            dayStartMs
          );

      }

    }


    // ========================================================
    // SAIU DA STARLINK
    // ========================================================

    if(
      event.event_type ===
      "failback_to_provider"
    ){

      if(
        starlinkActive
        &&
        activeSinceMs !== null
      ){

        totalMs +=
          Math.max(
            0,
            eventMs -
            activeSinceMs
          );

      }


      starlinkActive =
        false;


      activeSinceMs =
        null;

    }

  }


  // ==========================================================
  // SE A STARLINK CONTINUA ATIVA AGORA
  // ==========================================================

  if(
    starlinkActive
    &&
    activeSinceMs !== null
  ){

    totalMs +=
      Math.max(
        0,
        nowMs -
        activeSinceMs
      );

  }


  return Math.floor(
    totalMs / 1000
  );

}


// ============================================================
// RESUMO DO FAILOVER
// ============================================================

function getInternetSummary(){

  const dayStart =
    startOfTodayIso();


  // ==========================================================
  // QUEDAS DO PROVEDOR HOJE
  // ==========================================================

  const dropsToday =
    db.prepare(`

      SELECT COUNT(*) AS total

      FROM internet_events

      WHERE

        event_type='provider_down'

        AND

        created_at >= ?

    `).get(
      dayStart
    );


  // ==========================================================
  // ULTIMA TROCA ENTRE PROVEDOR E STARLINK
  // ==========================================================

  const lastSwitch =
    db.prepare(`

      SELECT *

      FROM internet_events

      WHERE

        event_type IN (
          'failover_to_starlink',
          'failback_to_provider'
        )

      ORDER BY id DESC

      LIMIT 1

    `).get();


  return {

    provider_drops_today:
      Number(
        dropsToday?.total || 0
      ),

    last_switch_at:
      lastSwitch?.created_at ||
      null,

    last_switch_type:
      lastSwitch?.event_type ||
      null,

    starlink_seconds_today:
      calculateStarlinkSecondsToday()

  };

}


// ============================================================
// MIKROTIK
// ATUALIZAR STATUS DOS LINKS
//
// Aceita GET:
//
// /api/mikrotik/link-status
//   ?provider=online
//   &starlink=standby
//   &active=provider
//   &failover=automatic
//
// Tambem aceita POST JSON.
//
// Seguranca:
// x-mikrotik-token
// ============================================================

function updateInternetStatus(
  req,
  res
){

  if(
    !isMikrotikAuthorized(
      req
    )
  ){

    return res
      .status(
        401
      )
      .type(
        "text/plain"
      )
      .send(
        "UNAUTHORIZED"
      );

  }


  try{

    // ========================================================
    // ESTADO ANTERIOR
    // ========================================================

    const previousStatus =
      db.prepare(`

        SELECT

          provider_status,

          starlink_status,

          active_link,

          failover_status,

          provider_ping,

          starlink_ping,

          updated_at

        FROM internet_status

        WHERE id=1

      `).get();


    // ========================================================
    // ACEITAR QUERY OU BODY
    // ========================================================

    const providerStatus =
      normalizeLinkStatus(

        req.query.provider

        ||

        req.body?.provider

        ||

        "unknown"

      );


    const starlinkStatus =
      normalizeLinkStatus(

        req.query.starlink

        ||

        req.body?.starlink

        ||

        "unknown"

      );


    const activeLink =
      normalizeActiveLink(

        req.query.active

        ||

        req.body?.active

        ||

        "unknown"

      );


    const failoverStatus =
      normalizeFailoverStatus(

        req.query.failover

        ||

        req.body?.failover

        ||

        "automatic"

      );


    const providerPing =
      safeText(

        req.query.provider_ping

        ||

        req.body?.provider_ping

        ||

        ""

      );


    const starlinkPing =
      safeText(

        req.query.starlink_ping

        ||

        req.body?.starlink_ping

        ||

        ""

      );


    const updatedAt =
      nowIso();


    const currentStatus = {

      provider_status:
        providerStatus,

      starlink_status:
        starlinkStatus,

      active_link:
        activeLink,

      failover_status:
        failoverStatus,

      provider_ping:
        providerPing || null,

      starlink_ping:
        starlinkPing || null,

      updated_at:
        updatedAt

    };


    // ========================================================
    // DETECTAR EVENTOS ANTES DE SALVAR O NOVO ESTADO
    // ========================================================

    detectInternetEvents(

      previousStatus,

      currentStatus,

      updatedAt

    );


    // ========================================================
    // SALVAR STATUS ATUAL
    // ========================================================

    db.prepare(`

      UPDATE internet_status

      SET

        provider_status=?,

        starlink_status=?,

        active_link=?,

        failover_status=?,

        provider_ping=?,

        starlink_ping=?,

        updated_at=?

      WHERE id=1

    `).run(

      providerStatus,

      starlinkStatus,

      activeLink,

      failoverStatus,

      providerPing || null,

      starlinkPing || null,

      updatedAt

    );


    console.log(

      "LINK STATUS:",

      "PROVEDOR=" + providerStatus,

      "STARLINK=" + starlinkStatus,

      "ATIVO=" + activeLink,

      "FAILOVER=" + failoverStatus

    );


    return res
      .type(
        "text/plain"
      )
      .send(
        "OK"
      );

  }


  catch(error){

    console.error(

      "Erro ao atualizar status dos links:",

      error

    );


    return res
      .status(
        500
      )
      .type(
        "text/plain"
      )
      .send(
        "ERROR"
      );

  }

}


// ============================================================
// ROTA GET PARA MIKROTIK
// ============================================================

app.get(
  "/api/mikrotik/link-status",
  updateInternetStatus
);


// ============================================================
// ROTA POST PARA MIKROTIK
// ============================================================

app.post(
  "/api/mikrotik/link-status",
  updateInternetStatus
);


// ============================================================
// ADMIN
// CONSULTAR STATUS ATUAL DA INTERNET
//
// Mantem compatibilidade com o admin.html atual.
//
// Agora tambem retorna:
//
// provider_drops_today
// last_switch_at
// last_switch_type
// starlink_seconds_today
// ============================================================

app.get(
  "/admin/api/internet",
  adminAuth,
  (req, res) => {

    try{

      const status =
        db.prepare(`

          SELECT

            provider_status,

            starlink_status,

            active_link,

            failover_status,

            provider_ping,

            starlink_ping,

            updated_at

          FROM internet_status

          WHERE id=1

        `).get();


      const summary =
        getInternetSummary();


      if(
        !status
      ){

        return res.json({

          provider_status:
            "unknown",

          starlink_status:
            "unknown",

          active_link:
            "unknown",

          failover_status:
            "automatic",

          provider_ping:
            null,

          starlink_ping:
            null,

          updated_at:
            null,

          age_seconds:
            null,

          stale:
            true,

          ...summary

        });

      }


      // ======================================================
      // VERIFICAR IDADE DA ULTIMA ATUALIZACAO
      // ======================================================

      let ageSeconds =
        null;


      let stale =
        true;


      if(
        status.updated_at
      ){

        const updatedMs =
          Date.parse(
            status.updated_at
          );


        if(
          Number.isFinite(
            updatedMs
          )
        ){

          ageSeconds =
            Math.max(

              0,

              Math.floor(

                (
                  Date.now()
                  -
                  updatedMs
                )

                /

                1000

              )

            );


          // ==================================================
          // DESATUALIZADO APOS 90 SEGUNDOS
          // ==================================================

          stale =
            ageSeconds > 90;

        }

      }


      return res.json({

        ...status,

        age_seconds:
          ageSeconds,

        stale:
          stale,

        ...summary

      });

    }


    catch(error){

      console.error(

        "Erro ao carregar status da internet:",

        error

      );


      return res
        .status(
          500
        )
        .json({

          error:
            "Erro ao carregar status da internet"

        });

    }

  }
);


// ============================================================
// ADMIN
// HISTORICO DO FAILOVER
//
// Uso:
//
// /admin/api/internet/history
//
// Opcional:
//
// /admin/api/internet/history?limit=50
//
// Maximo:
// 200 eventos
// ============================================================

app.get(
  "/admin/api/internet/history",
  adminAuth,
  (req, res) => {

    try{

      let limit =
        Number(
          req.query.limit || 50
        );


      if(
        !Number.isFinite(
          limit
        )
      ){

        limit = 50;

      }


      limit =
        Math.max(
          1,
          Math.min(
            200,
            Math.floor(
              limit
            )
          )
        );


      const rows =
        db.prepare(`

          SELECT

            id,

            event_type,

            previous_provider_status,

            new_provider_status,

            previous_starlink_status,

            new_starlink_status,

            previous_active_link,

            new_active_link,

            previous_failover_status,

            new_failover_status,

            created_at

          FROM internet_events

          ORDER BY id DESC

          LIMIT ?

        `).all(
          limit
        );


      return res.json({

        ok:
          true,

        count:
          rows.length,

        summary:
          getInternetSummary(),

        events:
          rows

      });

    }


    catch(error){

      console.error(

        "Erro ao carregar historico da internet:",

        error

      );


      return res
        .status(
          500
        )
        .json({

          ok:
            false,

          error:
            "Erro ao carregar historico da internet"

        });

    }

  }
);


// ============================================================
// DEBUG POR CLIENT_ID
//
// Uso:
//
// /api/debug/client/SEU_CLIENT_ID
//
// Esta rota e protegida pelo login administrativo.
// ============================================================

app.get(
  "/api/debug/client/:clientId",
  adminAuth,
  (req, res) => {

    const clientId =
      normalizeClientId(
        req.params.clientId
      );


    if (
      !clientId
    ) {

      return res
        .status(
          400
        )
        .json({

          error:
            "client_id invÃ¡lido"

        });

    }


    const rows =

      db.prepare(`

        SELECT

          id,

          external_ref,

          client_id,

          plan_id,

          status,

          original_mac,

          effective_mac,

          mac,

          ip,

          temp_status,

          temp_requested_at,

          temp_granted_at,

          temp_expires_at,

          created_at,

          approved_at

        FROM orders

        WHERE client_id=?

        ORDER BY id DESC

        LIMIT 50

      `).all(
        clientId
      );


    return res.json({

      ok:
        true,

      client_id:
        clientId,

      temporary_access_decision:

        getTemporaryAccessDecision(
          clientId
        ),

      records:
        rows

    });

  }
);


// ============================================================
// ADMIN
// LISTAR PEDIDOS / PAGAMENTOS
// ============================================================

app.get(
  "/admin/api/audit",
  adminAuth,
  (req, res) => {
    const requestedLimit = Number(req.query.limit || 50);
    const limit = Math.max(
      1,
      Math.min(5000, Number.isFinite(requestedLimit) ? Math.floor(requestedLimit) : 50)
    );

    try {
      const entries = db.prepare(`
        SELECT id, actor, method, route, status_code, ip, created_at
        FROM admin_audit_log
        ORDER BY id DESC
        LIMIT ?
      `).all(limit);

      return res.json({ ok: true, entries });
    } catch (error) {
      console.error("Erro ao carregar auditoria administrativa:", error.message);
      return res.status(500).json({ ok: false, error: "Erro ao carregar auditoria" });
    }
  }
);

app.post("/admin/login", (req, res) => {
  try {
    const username = String(req.body?.username || "").trim();
    const password = String(req.body?.password || "");
    let role = null;
    if (username === adminUser && password === adminPassword) role = "admin";
    if (!role) {
      const user = db.prepare("SELECT * FROM panel_users WHERE username=? AND active=1").get(username);
      if (user) {
        const [salt, stored] = String(user.password_hash).split(":");
        const derived = crypto.scryptSync(password, salt, 64).toString("hex");
        if (stored && crypto.timingSafeEqual(Buffer.from(stored, "hex"), Buffer.from(derived, "hex"))) role = user.role;
      }
    }
    if (!role) return res.status(401).json({ ok:false, error:"UsuÃ¡rio ou senha invÃ¡lidos" });
    const token = crypto.randomBytes(32).toString("hex");
    adminSessions.set(token, { username, role, expiresAt: Date.now() + 8 * 60 * 60 * 1000 });
    res.setHeader("Set-Cookie", `wifi_admin_session=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=28800${process.env.NODE_ENV === "production" ? "; Secure" : ""}`);
    return res.json({ ok:true, username, role });
  } catch (error) { return res.status(500).json({ok:false,error:"Falha no login"}); }
});

app.post("/admin/logout", (req,res)=>{const token=String(req.headers.cookie||"").split(";").map(v=>v.trim()).find(v=>v.startsWith("wifi_admin_session="))?.split("=")[1];if(token)adminSessions.delete(token);res.setHeader("Set-Cookie","wifi_admin_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0");return res.json({ok:true});});
app.get("/admin/session", adminAuth, (req,res)=>res.json({ok:true,username:req.adminUser||adminUser,role:req.adminRole||"admin"}));

app.get("/api/ad-campaigns", (req, res) => {
  try {
    const eventKey = String(req.query.event_key || req.query.event || "").trim();
    const now = new Date().toISOString();
    const rows = db.prepare(`
      SELECT a.id, a.name, a.image_path, a.target_url
      FROM ad_campaigns a
      LEFT JOIN events e ON e.id=a.event_id
      WHERE a.active=1
        AND (a.starts_at IS NULL OR a.starts_at='' OR a.starts_at<=?)
        AND (a.ends_at IS NULL OR a.ends_at='' OR a.ends_at>=?)
        AND (?='' OR e.event_key=? OR a.event_id IS NULL)
      ORDER BY a.id DESC LIMIT 20
    `).all(now, now, eventKey, eventKey);
    return res.json({ ok: true, campaigns: rows });
  } catch (error) {
    console.error("Erro ao carregar anÃºncios pÃºblicos:", error.message);
    return res.status(500).json({ ok: false, campaigns: [] });
  }
});

app.post("/api/ad-campaigns/:id/:action", (req, res) => {
  try {
    const column = req.params.action === "click" ? "clicks" : req.params.action === "impression" ? "impressions" : null;
    if (!column) return res.status(400).json({ ok: false });
    db.prepare(`UPDATE ad_campaigns SET ${column}=${column}+1, updated_at=? WHERE id=?`).run(new Date().toISOString(), Number(req.params.id));
    return res.json({ ok: true });
  } catch (error) {
    return res.status(500).json({ ok: false });
  }
});

app.delete(
  "/admin/api/audit",
  adminAuth,
  (req, res) => {
    try {
      const result = db.prepare("DELETE FROM admin_audit_log").run();
      return res.json({ ok: true, deleted: Number(result.changes || 0) });
    } catch (error) {
      console.error("Erro ao limpar auditoria administrativa:", error.message);
      return res.status(500).json({ ok: false, error: "Erro ao limpar auditoria" });
    }
  }
);

// ============================================================
// CAMPANHAS DE ANÃšNCIOS
// ============================================================

app.get("/admin/api/ad-campaigns", adminAuth, (req, res) => {
  try {
    const eventId = Number(req.query.event_id || 0);
    const rows = db.prepare(`
      SELECT a.*, e.name AS event_name
      FROM ad_campaigns a
      LEFT JOIN events e ON e.id=a.event_id
      ${eventId > 0 ? "WHERE a.event_id=?" : ""}
      ORDER BY a.id DESC
    `).all(...(eventId > 0 ? [eventId] : []));
    return res.json({ ok: true, campaigns: rows });
  } catch (error) {
    console.error("Erro ao carregar campanhas:", error.message);
    return res.status(500).json({ ok: false, error: "Erro ao carregar campanhas" });
  }
});

app.post("/admin/api/ad-campaigns", adminAuth, (req, res) => {
  try {
    const body = req.body || {};
    const name = String(body.name || "").trim();
    const imagePath = String(body.image_path || "").trim();
    if (!name || !imagePath) return res.status(400).json({ ok: false, error: "Nome e imagem sÃ£o obrigatÃ³rios" });
    const now = new Date().toISOString();
    const result = db.prepare(`INSERT INTO ad_campaigns (event_id,name,image_path,target_url,starts_at,ends_at,active,created_at,updated_at) VALUES (?,?,?,?,?,?,1,?,?)`).run(
      Number(body.event_id) || null, name, imagePath, String(body.target_url || "").trim() || null,
      String(body.starts_at || "").trim() || null, String(body.ends_at || "").trim() || null, now, now
    );
    return res.status(201).json({ ok: true, id: Number(result.lastInsertRowid) });
  } catch (error) {
    console.error("Erro ao criar campanha:", error.message);
    return res.status(500).json({ ok: false, error: "Erro ao criar campanha" });
  }
});

app.patch("/admin/api/ad-campaigns/:id", adminAuth, (req, res) => {
  try {
    const id = Number(req.params.id);
    const body = req.body || {};
    const fields = [];
    const values = [];
    for (const [column, value] of [["name",body.name],["image_path",body.image_path],["target_url",body.target_url],["starts_at",body.starts_at],["ends_at",body.ends_at]]) {
      if (value !== undefined) { fields.push(`${column}=?`); values.push(String(value).trim() || null); }
    }
    if (body.active !== undefined) { fields.push("active=?"); values.push(body.active ? 1 : 0); }
    if (!fields.length) return res.status(400).json({ ok: false, error: "Nenhuma alteraÃ§Ã£o informada" });
    fields.push("updated_at=?"); values.push(new Date().toISOString(), id);
    const result = db.prepare(`UPDATE ad_campaigns SET ${fields.join(", ")} WHERE id=?`).run(...values);
    return res.json({ ok: true, updated: Number(result.changes || 0) });
  } catch (error) {
    console.error("Erro ao atualizar campanha:", error.message);
    return res.status(500).json({ ok: false, error: "Erro ao atualizar campanha" });
  }
});

app.delete("/admin/api/ad-campaigns/:id", adminAuth, (req, res) => {
  try {
    const result = db.prepare("DELETE FROM ad_campaigns WHERE id=?").run(Number(req.params.id));
    return res.json({ ok: true, deleted: Number(result.changes || 0) });
  } catch (error) {
    console.error("Erro ao excluir campanha:", error.message);
    return res.status(500).json({ ok: false, error: "Erro ao excluir campanha" });
  }
});

app.get("/admin/api/resellers", adminAuth, requireRole("admin","provider"), (req, res) => {
  try {
    const rows = db.prepare(`SELECT r.*, e.name AS event_name FROM resellers r LEFT JOIN events e ON e.id=r.event_id ORDER BY r.id DESC`).all();
    return res.json({ ok:true, resellers:rows });
  } catch (error) { return res.status(500).json({ok:false,error:"Erro ao carregar revendedores"}); }
});

app.post("/admin/api/resellers", adminAuth, requireRole("admin","provider"), (req, res) => {
  try {
    const body=req.body||{}; const name=String(body.name||"").trim();
    if(!name) return res.status(400).json({ok:false,error:"Nome Ã© obrigatÃ³rio"});
    const now=new Date().toISOString();
    const result=db.prepare(`INSERT INTO resellers (event_id,name,phone,email,commission_percent,created_at,updated_at) VALUES (?,?,?,?,?,?,?)`).run(Number(body.event_id)||null,name,String(body.phone||"").trim()||null,String(body.email||"").trim()||null,Math.max(0,Number(body.commission_percent)||0),now,now);
    return res.status(201).json({ok:true,id:Number(result.lastInsertRowid)});
  } catch(error){ return res.status(500).json({ok:false,error:"Erro ao criar revendedor"}); }
});

app.patch("/admin/api/resellers/:id", adminAuth, requireRole("admin","provider"), (req,res)=>{
  try { const b=req.body||{}, fields=[], vals=[]; for(const [c,v] of [["name",b.name],["phone",b.phone],["email",b.email],["event_id",b.event_id],["commission_percent",b.commission_percent]]) if(v!==undefined){fields.push(`${c}=?`);vals.push(c==="commission_percent"?Math.max(0,Number(v)||0):c==="event_id"?(Number(v)||null):String(v).trim()||null);} if(b.active!==undefined){fields.push("active=?");vals.push(b.active?1:0);} if(!fields.length)return res.status(400).json({ok:false,error:"Nenhuma alteraÃ§Ã£o informada"}); fields.push("updated_at=?");vals.push(new Date().toISOString(),Number(req.params.id)); const result=db.prepare(`UPDATE resellers SET ${fields.join(",")} WHERE id=?`).run(...vals); return res.json({ok:true,updated:Number(result.changes||0)}); } catch(error){return res.status(500).json({ok:false,error:"Erro ao atualizar revendedor"});}
});

app.delete("/admin/api/resellers/:id", adminAuth, requireRole("admin","provider"), (req,res)=>{ try { const result=db.prepare("DELETE FROM resellers WHERE id=?").run(Number(req.params.id)); return res.json({ok:true,deleted:Number(result.changes||0)}); } catch(error){return res.status(500).json({ok:false,error:"Erro ao excluir revendedor"});} });

app.get("/admin/api/resellers/report", adminAuth, requireRole("admin","provider"), (req,res)=>{
  try {
    const rows=db.prepare(`SELECT r.id,r.name,r.commission_percent,COUNT(o.id) AS sales,COALESCE(SUM(o.amount),0) AS gross,COALESCE(SUM(COALESCE(o.commission_amount, o.amount*r.commission_percent/100.0)),0) AS commission FROM resellers r LEFT JOIN orders o ON o.reseller_id=r.id AND o.status IN ('approved','paid','completed') GROUP BY r.id ORDER BY gross DESC`).all();
    return res.json({ok:true,report:rows});
  } catch(error){return res.status(500).json({ok:false,error:"Erro ao carregar relatÃ³rio de revendedores"});}
});

app.get("/admin/api/pppoe-subscribers", adminAuth, (req,res)=>{try{return res.json({ok:true,subscribers:db.prepare(`SELECT s.*,e.name AS event_name,CASE WHEN s.status='active' AND s.next_due_at IS NOT NULL AND datetime(s.next_due_at)<datetime('now') THEN 'overdue' ELSE s.status END AS computed_status FROM pppoe_subscribers s LEFT JOIN events e ON e.id=s.event_id ORDER BY s.id DESC`).all()});}catch(error){return res.status(500).json({ok:false,error:"Erro ao carregar assinantes"});}});
app.post("/admin/api/pppoe-subscribers", adminAuth, (req,res)=>{try{const b=req.body||{},login=String(b.login||"").trim(),name=String(b.name||"").trim(),plan=String(b.plan_name||"").trim();if(!login||!name||!plan)return res.status(400).json({ok:false,error:"Login, nome e plano sÃ£o obrigatÃ³rios"});const now=new Date().toISOString();const result=db.prepare(`INSERT INTO pppoe_subscribers (event_id,login,name,phone,plan_name,monthly_amount,due_day,next_due_at,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)`).run(Number(b.event_id)||null,login,name,String(b.phone||"").trim()||null,plan,Number(b.monthly_amount)||0,Math.min(31,Math.max(1,Number(b.due_day)||10)),b.next_due_at||null,now,now);return res.status(201).json({ok:true,id:Number(result.lastInsertRowid)});}catch(error){return res.status(400).json({ok:false,error:error.message.includes("UNIQUE")?"Login jÃ¡ cadastrado":"Erro ao criar assinante"});}});
app.patch("/admin/api/pppoe-subscribers/:id", adminAuth, (req,res)=>{try{const b=req.body||{},fields=[],vals=[];for(const [c,v] of [["name",b.name],["phone",b.phone],["plan_name",b.plan_name],["monthly_amount",b.monthly_amount],["due_day",b.due_day],["next_due_at",b.next_due_at],["status",b.status]])if(v!==undefined){fields.push(`${c}=?`);vals.push(["monthly_amount","due_day"].includes(c)?Number(v)||0:String(v).trim()||null);}if(!fields.length)return res.status(400).json({ok:false,error:"Nenhuma alteraÃ§Ã£o informada"});fields.push("updated_at=?");vals.push(new Date().toISOString(),Number(req.params.id));const result=db.prepare(`UPDATE pppoe_subscribers SET ${fields.join(",")} WHERE id=?`).run(...vals);return res.json({ok:true,updated:Number(result.changes||0)});}catch(error){return res.status(500).json({ok:false,error:"Erro ao atualizar assinante"});}});

app.get("/admin/api/payment-terminals", adminAuth, (req,res)=>{try{return res.json({ok:true,terminals:db.prepare(`SELECT t.*,e.name AS event_name FROM payment_terminals t LEFT JOIN events e ON e.id=t.event_id ORDER BY t.id DESC`).all()});}catch(error){return res.status(500).json({ok:false,error:"Erro ao carregar terminais"});}});
app.post("/admin/api/payment-terminals", adminAuth, (req,res)=>{try{const b=req.body||{},name=String(b.name||"").trim();if(!name)return res.status(400).json({ok:false,error:"Nome Ã© obrigatÃ³rio"});const now=new Date().toISOString();const r=db.prepare(`INSERT INTO payment_terminals (event_id,name,provider,serial_number,created_at,updated_at) VALUES (?,?,?,?,?,?)`).run(Number(b.event_id)||null,name,String(b.provider||"manual"),String(b.serial_number||"").trim()||null,now,now);return res.status(201).json({ok:true,id:Number(r.lastInsertRowid)});}catch(error){return res.status(500).json({ok:false,error:"Erro ao criar terminal"});}});
app.post("/admin/api/payment-terminals/:id/transactions", adminAuth, (req,res)=>{try{const b=req.body||{};const now=new Date().toISOString();const r=db.prepare(`INSERT INTO terminal_transactions (terminal_id,reseller_id,order_id,amount,method,status,external_ref,created_at) VALUES (?,?,?,?,?,?,?,?)`).run(Number(req.params.id),Number(b.reseller_id)||null,Number(b.order_id)||null,Number(b.amount)||0,String(b.method||"pix"),String(b.status||"approved"),String(b.external_ref||"").trim()||null,now);return res.status(201).json({ok:true,id:Number(r.lastInsertRowid)});}catch(error){return res.status(500).json({ok:false,error:"Erro ao registrar transaÃ§Ã£o"});}});
app.post("/admin/api/terminal-transactions/:id/refund", adminAuth, (req,res)=>{try{const r=db.prepare(`UPDATE terminal_transactions SET status='refunded',refunded_at=? WHERE id=? AND status='approved'`).run(new Date().toISOString(),Number(req.params.id));return res.json({ok:true,refunded:Number(r.changes||0)});}catch(error){return res.status(500).json({ok:false,error:"Erro ao estornar transaÃ§Ã£o"});}});

app.get("/admin/api/panel-users", adminAuth, requireRole("admin"), (req,res)=>{try{return res.json({ok:true,users:db.prepare(`SELECT id,username,display_name,role,reseller_id,active,created_at FROM panel_users ORDER BY id DESC`).all()});}catch(error){return res.status(500).json({ok:false,error:"Erro ao carregar usuÃ¡rios"});}});
app.post("/admin/api/panel-users", adminAuth, requireRole("admin"), (req,res)=>{try{const b=req.body||{},username=String(b.username||"").trim(),password=String(b.password||"");if(!username||password.length<8)return res.status(400).json({ok:false,error:"UsuÃ¡rio e senha de pelo menos 8 caracteres sÃ£o obrigatÃ³rios"});const salt=crypto.randomBytes(16).toString("hex"),hash=crypto.scryptSync(password,salt,64).toString("hex");const now=new Date().toISOString();const r=db.prepare(`INSERT INTO panel_users (username,password_hash,display_name,role,reseller_id,created_at,updated_at) VALUES (?,?,?,?,?,?,?)`).run(username,`${salt}:${hash}`,String(b.display_name||username),String(b.role||"reseller"),Number(b.reseller_id)||null,now,now);return res.status(201).json({ok:true,id:Number(r.lastInsertRowid)});}catch(error){return res.status(400).json({ok:false,error:error.message.includes("UNIQUE")?"UsuÃ¡rio jÃ¡ existe":"Erro ao criar usuÃ¡rio"});}});

app.get(
  "/admin/api/orders",
  adminAuth,
  (req, res) => {

    try {

      const rows =

        db.prepare(`

          SELECT

            o.*,

            e.name AS event_name,

            e.event_key AS event_key,

            r.name AS router_name,

            r.identity AS router_identity,

            r.router_key AS router_key

          FROM orders o

          LEFT JOIN events e
            ON e.id=o.event_id

          LEFT JOIN routers r
            ON r.id=o.router_id

          ORDER BY
            o.id DESC

          LIMIT 200

        `).all();


      const safeRows =

        rows.map(

          row => ({

            ...row,

            access_json:
              undefined

          })

        );


      return res.json(
        safeRows
      );

    }


    catch(error) {

      console.error(

        "Erro ao carregar pedidos do painel:",

        error

      );


      return res
        .status(
          500
        )
        .json({

          error:
            "Erro ao carregar pedidos"

        });

    }

  }
);


// ============================================================
// V14.1 - ADMIN: RESUMO DO FUNIL DE CONVERSAO
// ============================================================

app.get(
  "/admin/api/funnel/summary-advanced",
  adminAuth,
  (req, res) => {

    try {

      const eventId =
        Number(
          req.query?.event_id
        );


      if(
        !Number.isInteger(eventId)
        ||
        eventId <= 0
      ) {

        return res
          .status(400)
          .json({
            ok:false,
            error:"Evento invalido"
          });

      }


      const event =
        db.prepare(`
          SELECT id, event_key, name
          FROM events
          WHERE id=?
          LIMIT 1
        `).get(
          eventId
        );


      if(
        !event
      ) {

        return res
          .status(404)
          .json({
            ok:false,
            error:"Evento nao encontrado"
          });

      }


      const rows =
        db.prepare(`
          SELECT
            step,
            COUNT(*) AS total_events,
            COUNT(
              DISTINCT CASE
                WHEN client_id IS NOT NULL
                  AND TRIM(client_id) <> ''
                  THEN 'client:' || client_id
                WHEN mac IS NOT NULL
                  AND TRIM(mac) <> ''
                  THEN 'mac:' || mac
                ELSE 'event:' || id
              END
            ) AS unique_clients,
            MIN(created_at) AS first_at,
            MAX(created_at) AS last_at
          FROM funnel_events
          WHERE event_id=?
          GROUP BY step
        `).all(
          eventId
        );


      const steps = {};


      for(
        const step
        of FUNNEL_STEPS
      ) {

        steps[step] = {
          step,
          total_events:0,
          unique_clients:0,
          first_at:null,
          last_at:null
        };

      }


      for(
        const row
        of rows
      ) {

        steps[row.step] = {
          step:
            row.step,
          total_events:
            Number(row.total_events || 0),
          unique_clients:
            Number(row.unique_clients || 0),
          first_at:
            row.first_at || null,
          last_at:
            row.last_at || null
        };

      }


      const portalOpened =
        Number(
          steps.PORTAL_OPENED?.unique_clients || 0
        );

      const pixGenerated =
        Number(
          steps.PIX_GENERATED?.unique_clients || 0
        );

      const paymentApproved =
        Number(
          steps.PAYMENT_APPROVED?.unique_clients || 0
        );

      const accessApplied =
        Number(
          steps.ACCESS_APPLIED?.unique_clients || 0
        );


      const percent =
        (value, base) => {

          if(
            !base
          ) {
            return 0;
          }

          return Number(
            (
              value * 100 / base
            ).toFixed(1)
          );

        };


      return res.json({
        ok:true,
        event:{
          id:Number(event.id),
          event_key:event.event_key,
          name:event.name
        },
        steps,
        conversion:{
          portal_to_pix_percent:
            percent(
              pixGenerated,
              portalOpened
            ),
          pix_to_payment_percent:
            percent(
              paymentApproved,
              pixGenerated
            ),
          portal_to_payment_percent:
            percent(
              paymentApproved,
              portalOpened
            ),
          payment_to_access_percent:
            percent(
              accessApplied,
              paymentApproved
            )
        },
        generated_at:
          nowIso()
      });

    }
    catch(error) {

      console.error(
        "Erro ao carregar resumo do funil:",
        error
      );

      return res
        .status(500)
        .json({
          ok:false,
          error:"Erro ao carregar funil"
        });

    }

  }
);


// ============================================================
// V14.1 - ADMIN: LINHA DO TEMPO DO FUNIL
// ============================================================

app.get(
  "/admin/api/funnel/timeline",
  adminAuth,
  (req, res) => {

    try {

      const eventId =
        Number(
          req.query?.event_id
        );


      const requestedLimit =
        Number(
          req.query?.limit || 300
        );


      const limit =
        Math.max(
          1,
          Math.min(
            1000,
            Number.isFinite(requestedLimit)
              ? Math.floor(requestedLimit)
              : 300
          )
        );


      if(
        !Number.isInteger(eventId)
        ||
        eventId <= 0
      ) {

        return res
          .status(400)
          .json({
            ok:false,
            error:"Evento invalido"
          });

      }


      const rows =
        db.prepare(`
          SELECT
            f.id,
            f.event_id,
            f.router_id,
            f.client_id,
            f.mac,
            f.ip,
            f.order_id,
            f.order_ref,
            f.step,
            f.plan_id,
            f.source,
            f.metadata_json,
            f.created_at,
            c.name AS customer_name,
            c.phone AS customer_phone,
            c.email AS customer_email,
            r.name AS router_name,
            r.router_key AS router_key,
            o.status AS order_status,
            o.amount AS order_amount,
            o.payment_method AS order_payment_method,
            o.voucher_serial AS order_voucher_serial
          FROM funnel_events f
          LEFT JOIN customers c
            ON c.client_id=f.client_id
          LEFT JOIN routers r
            ON r.id=f.router_id
          LEFT JOIN orders o
            ON o.id=f.order_id
          WHERE f.event_id=?
          ORDER BY
            f.id DESC
          LIMIT ?
        `).all(
          eventId,
          limit
        );


      const timeline =
        rows.map(
          row => {

            let metadata =
              null;

            if(
              row.metadata_json
            ) {

              try {
                metadata =
                  JSON.parse(
                    row.metadata_json
                  );
              }
              catch {
                metadata =
                  null;
              }

            }

            return {
              ...row,
              metadata,
              metadata_json:undefined
            };

          }
        );


      return res.json({
        ok:true,
        event_id:eventId,
        total:timeline.length,
        timeline
      });

    }
    catch(error) {

      console.error(
        "Erro ao carregar timeline do funil:",
        error
      );

      return res
        .status(500)
        .json({
          ok:false,
          error:"Erro ao carregar timeline do funil"
        });

    }

  }
);


// ============================================================
// V15.4 - ADMIN: LOGS COMPLETOS DO FUNIL
//
// Retorna inclusive clientes que nunca chegaram a pagar.
// O Admin mistura estes eventos com os logs de pedidos existentes.
// ============================================================

app.get(
  "/admin/api/funnel/logs",
  adminAuth,
  (req, res) => {

    try {

      const requestedLimit =
        Number(
          req.query?.limit || 5000
        );

      const limit =
        Math.max(
          1,
          Math.min(
            10000,
            Number.isFinite(requestedLimit)
              ? Math.floor(requestedLimit)
              : 5000
          )
        );


      const rows =
        db.prepare(`

          SELECT
            f.id,
            f.event_id,
            f.router_id,
            f.client_id,
            f.mac,
            f.ip,
            f.order_id,
            f.order_ref,
            f.step,
            f.plan_id,
            f.source,
            f.metadata_json,
            f.created_at,

            e.name AS event_name,
            e.event_key AS event_key,

            r.name AS router_name,
            r.identity AS router_identity,
            r.router_key AS router_key,

            c.name AS customer_name,
            c.phone AS customer_phone,
            c.email AS customer_email,

            o.status AS order_status,
            o.amount AS order_amount,
            o.payment_method AS order_payment_method,
            o.voucher_serial AS order_voucher_serial,
            o.approved_at AS order_approved_at,

            CASE
              WHEN f.client_id IS NOT NULL
               AND EXISTS (
                 SELECT 1
                 FROM orders paid
                 WHERE
                   paid.client_id=f.client_id
                   AND paid.event_id=f.event_id
                   AND paid.status IN (
                     'approved',
                     'approved_pending_router'
                   )
               )
              THEN 1
              ELSE 0
            END AS customer_paid

          FROM funnel_events f

          LEFT JOIN events e
            ON e.id=f.event_id

          LEFT JOIN routers r
            ON r.id=f.router_id

          LEFT JOIN customers c
            ON c.client_id=f.client_id

          LEFT JOIN orders o
            ON o.id=f.order_id

          ORDER BY
            f.id DESC

          LIMIT ?

        `).all(
          limit
        );


      const logs =
        rows.map(
          row => {

            let metadata =
              null;

            if(
              row.metadata_json
            ){

              try{

                metadata =
                  JSON.parse(
                    row.metadata_json
                  );

              }
              catch{

                metadata =
                  null;

              }

            }


            return {
              ...row,
              customer_paid:
                Number(
                  row.customer_paid || 0
                ) === 1,
              metadata,
              metadata_json:
                undefined
            };

          }
        );


      return res.json({
        ok:true,
        total:
          logs.length,
        logs
      });

    }
    catch(error){

      console.error(
        "Erro ao carregar logs do funil:",
        error
      );

      return res
        .status(500)
        .json({
          ok:false,
          error:
            "Erro ao carregar logs do funil"
        });

    }

  }
);


// ============================================================
// PAINEL ADMINISTRATIVO
//
// Arquivo:
//
// /public/admin.html
//
// Protegido por:
// ADMIN_USER
// ADMIN_PASSWORD
// ============================================================

app.get(
  "/admin",
  adminAuth,
  (req, res) => {

    res.setHeader("Cache-Control", "no-store, max-age=0");

    res.sendFile(

      path.join(

        __dirname,

        "public",

        "admin.html"

      )

    );

  }
);

app.get(
  "/admin.html",
  adminAuth,
  (req, res) => {
    res.setHeader("Cache-Control", "no-store, max-age=0");
    return res.sendFile(path.join(__dirname, "public", "admin.html"));
  }
);

app.use(
  express.static(path.join(__dirname, "public"))
);


// ============================================================
// FIM DO BLOCO 8/10
// ============================================================

// ============================================================
// BLOCO 8.5/10 - ADMINISTRACAO MULTI-EVENTO - V16.3
// REGRA: 1 EVENTO = 1 MIKROTIK
// EVENTOS, MIKROTIK E PLANOS
// ============================================================


// ============================================================
// AUXILIAR
// ID NUMERICO POSITIVO
// ============================================================

function positiveId(value){

  const id =
    Number(
      value
    );


  if(
    !Number.isInteger(
      id
    )
    ||
    id <= 0
  ){

    return null;

  }


  return id;

}


// ============================================================
// AUXILIAR
// GERAR CHAVE AMIGAVEL
// ============================================================

function makeKey(value){

  let text =
    String(
      value || ""
    )
      .normalize(
        "NFD"
      )
      .replace(
        /[\u0300-\u036f]/g,
        ""
      )
      .toLowerCase()
      .trim()
      .replace(
        /[^a-z0-9]+/g,
        "-"
      )
      .replace(
        /^-+|-+$/g,
        ""
      );


  if(
    !text
  ){

    text =
      "item";

  }


  return text;

}


// ============================================================
// AUXILIAR
// LOCALIZAR EVENTO
// ============================================================

function getEventById(eventId){

  return db.prepare(`

    SELECT *

    FROM events

    WHERE id=?

    LIMIT 1

  `).get(
    eventId
  );

}


// ============================================================
// SINCRONIZACAO DE PLANOS COM A MIKROTIK
// ============================================================

function ensureEventPlanColumn(
  columnName,
  definition
){

  const columns =
    db.prepare(
      "PRAGMA table_info(event_plans)"
    ).all();


  const exists =
    columns.some(
      column =>
        column.name ===
        columnName
    );


  if(
    !exists
  ){

    db.exec(
      `ALTER TABLE event_plans ADD COLUMN ${columnName} ${definition}`
    );

  }

}


ensureEventPlanColumn(
  "deleted_at",
  "TEXT"
);

ensureEventPlanColumn(
  "subtitle",
  "TEXT NOT NULL DEFAULT ''"
);

ensureEventPlanColumn(
  "highlight",
  "TEXT NOT NULL DEFAULT ''"
);


db.exec(`

CREATE TABLE IF NOT EXISTS plan_sync_commands (

  id INTEGER PRIMARY KEY AUTOINCREMENT,

  command_ref TEXT UNIQUE NOT NULL,

  event_id INTEGER NOT NULL,

  router_id INTEGER NOT NULL,

  command_type TEXT NOT NULL,

  profile TEXT NOT NULL,

  rate_limit TEXT,

  status TEXT NOT NULL DEFAULT 'pending',

  created_at TEXT NOT NULL,

  applied_at TEXT,

  FOREIGN KEY(event_id)
    REFERENCES events(id)
    ON DELETE CASCADE,

  FOREIGN KEY(router_id)
    REFERENCES routers(id)
    ON DELETE CASCADE

);

CREATE INDEX IF NOT EXISTS idx_plan_sync_router_status
ON plan_sync_commands(router_id, status, id);

`);


function queuePlanSync(
  eventId,
  commandType,
  profile,
  rateLimit=""
){

  const router =
    db.prepare(`

      SELECT *

      FROM routers

      WHERE
        event_id=?
        AND status='active'

      ORDER BY id ASC

      LIMIT 1

    `).get(
      eventId
    );


  if(
    !router
    ||
    !profile
  ){

    return null;

  }


  // Mantemos somente a acao pendente mais nova por perfil.
  db.prepare(`

    DELETE FROM plan_sync_commands

    WHERE
      router_id=?
      AND profile=?
      AND status='pending'

  `).run(
    router.id,
    profile
  );


  const commandRef =
    "plan_"
    +
    crypto
      .randomBytes(12)
      .toString("hex");


  const result =
    db.prepare(`

      INSERT INTO plan_sync_commands (
        command_ref,
        event_id,
        router_id,
        command_type,
        profile,
        rate_limit,
        status,
        created_at
      )

      VALUES (?, ?, ?, ?, ?, ?, 'pending', ?)

    `).run(
      commandRef,
      eventId,
      router.id,
      commandType,
      profile,
      rateLimit || null,
      nowIso()
    );


  return {
    id:Number(result.lastInsertRowid),
    command_ref:commandRef,
    router_id:router.id
  };

}


// ============================================================
// MIKROTIK - PROXIMA SINCRONIZACAO DE PLANO
// ============================================================

app.get(
  "/api/mikrotik/plan-pending",
  (req, res) => {

    const auth =
      authenticateMikrotik(
        req
      );


    if(
      !auth?.ok
      ||
      !auth.router
    ){

      return res
        .status(401)
        .type("text/plain")
        .send("UNAUTHORIZED");

    }


    const command =
      db.prepare(`

        SELECT *

        FROM plan_sync_commands

        WHERE
          router_id=?
          AND event_id=?
          AND status='pending'

        ORDER BY id ASC

        LIMIT 1

      `).get(
        auth.router.id,
        auth.router.event_id
      );


    if(
      !command
    ){

      return res
        .type("text/plain")
        .send("NONE");

    }


    return res
      .type("text/plain")
      .send(
        [
          command.command_type,
          safeText(command.profile),
          safeText(mikrotikRateLimit(command.rate_limit || "")),
          command.command_ref
        ].join("|")
      );

  }
);


// ============================================================
// MIKROTIK - ACK DA SINCRONIZACAO DO PLANO
// ============================================================

app.get(
  "/api/mikrotik/plan-ack",
  (req, res) => {

    const auth =
      authenticateMikrotik(
        req
      );


    if(
      !auth?.ok
      ||
      !auth.router
    ){

      return res
        .status(401)
        .type("text/plain")
        .send("UNAUTHORIZED");

    }


    const commandRef =
      safeText(
        req.headers["x-command-ref"]
        ||
        req.query?.ref
        ||
        ""
      );


    if(
      !commandRef
    ){

      return res
        .status(400)
        .type("text/plain")
        .send("INVALID_REF");

    }


    const result =
      db.prepare(`

        UPDATE plan_sync_commands

        SET
          status='applied',
          applied_at=?

        WHERE
          command_ref=?
          AND router_id=?
          AND event_id=?
          AND status='pending'

      `).run(
        nowIso(),
        commandRef,
        auth.router.id,
        auth.router.event_id
      );


    return res
      .type("text/plain")
      .send(
        result.changes > 0
          ? "OK"
          : "NOT_FOUND"
      );

  }
);


// ============================================================
// ============================================================
// EVENTOS
// ============================================================
// ============================================================


// ============================================================
// LISTAR EVENTOS
//
// GET
// /admin/api/events
// ============================================================

app.get(
  "/admin/api/events",
  adminAuth,
  (req, res) => {

    try{

      const events =
        db.prepare(`

          SELECT

            e.*,

            (
              SELECT COUNT(*)

              FROM routers r

              WHERE r.event_id=e.id
                AND r.status='active'

            ) AS router_count,

            (
              SELECT COUNT(*)

              FROM event_plans p

              WHERE p.event_id=e.id
                AND p.active=1
                AND p.deleted_at IS NULL

            ) AS plan_count,

            (
              SELECT COUNT(*)

              FROM orders o

              WHERE o.event_id=e.id

            ) AS order_count

          FROM events e

          ORDER BY
            e.id ASC

        `).all();


      return res.json({

        ok:
          true,

        count:
          events.length,

        events:
          events

      });

    }


    catch(error){

      console.error(
        "Erro ao listar eventos:",
        error
      );


      return res
        .status(
          500
        )
        .json({

          ok:
            false,

          error:
            "Erro ao listar eventos"

        });

    }

  }
);


// ============================================================
// CRIAR EVENTO
//
// POST
// /admin/api/events
//
// JSON:
//
// {
//   "name":"Festa Municipal 2026",
//   "establishment_name":"Ronnet",
//   "location":"Centro de Eventos",
//   "description":"Wi-Fi do evento"
// }
// ============================================================

app.post(
  "/admin/api/events",
  adminAuth,
  (req, res) => {

    try{

      const name =
        String(
          req.body?.name || ""
        )
          .trim()
          .slice(
            0,
            100
          );


      if(
        !name
      ){

        return res
          .status(
            400
          )
          .json({

            ok:
              false,

            error:
              "Informe o nome do evento"

          });

      }


      let eventKey =
        makeKey(
          name
        );


      const existingKey =
        db.prepare(`

          SELECT id

          FROM events

          WHERE event_key=?

          LIMIT 1

        `).get(
          eventKey
        );


      if(
        existingKey
      ){

        eventKey =
          eventKey

          +

          "-"

          +

          crypto
            .randomBytes(
              3
            )
            .toString(
              "hex"
            );

      }


      const now =
        nowIso();


      const result =
        db.prepare(`

          INSERT INTO events (

            event_key,

            name,

            establishment_name,

            location,

            description,

            timezone,

            status,

            created_at,

            updated_at

          )

          VALUES (
            ?, ?, ?, ?, ?, ?, ?, ?, ?
          )

        `).run(

          eventKey,

          name,

          String(
            req.body?.establishment_name || ""
          )
            .trim()
            .slice(
              0,
              120
            ),

          String(
            req.body?.location || ""
          )
            .trim()
            .slice(
              0,
              160
            ),

          String(
            req.body?.description || ""
          )
            .trim()
            .slice(
              0,
              500
            ),

          String(
            req.body?.timezone ||
            "America/Sao_Paulo"
          )
            .trim()
            .slice(
              0,
              80
            ),

          "active",

          now,

          now

        );


      const event =
        getEventById(
          Number(
            result.lastInsertRowid
          )
        );


      return res
        .status(
          201
        )
        .json({

          ok:
            true,

          event:
            event

        });

    }


    catch(error){

      console.error(
        "Erro ao criar evento:",
        error
      );


      return res
        .status(
          500
        )
        .json({

          ok:
            false,

          error:
            "Erro ao criar evento"

        });

    }

  }
);


// ============================================================
// DETALHES DE UM EVENTO
//
// GET
// /admin/api/events/:eventId
// ============================================================

app.get(
  "/admin/api/events/:eventId",
  adminAuth,
  (req, res) => {

    try{

      const eventId =
        positiveId(
          req.params.eventId
        );


      if(
        !eventId
      ){

        return res
          .status(
            400
          )
          .json({

            ok:false,

            error:
              "Evento invÃ¡lido"

          });

      }


      const event =
        getEventById(
          eventId
        );


      if(
        !event
      ){

        return res
          .status(
            404
          )
          .json({

            ok:false,

            error:
              "Evento nÃ£o encontrado"

          });

      }


      const routers =
        db.prepare(`

          SELECT *

          FROM routers

          WHERE event_id=?

          ORDER BY id ASC

        `).all(
          eventId
        );


      const plans =
        db.prepare(`

          SELECT *

          FROM event_plans

          WHERE
            event_id=?
            AND deleted_at IS NULL

          ORDER BY
            sort_order ASC,
            id ASC

        `).all(
          eventId
        );


      return res.json({

        ok:
          true,

        event:
          event,

        routers:
          routers,

        plans:
          plans

      });

    }


    catch(error){

      console.error(
        "Erro ao carregar evento:",
        error
      );


      return res
        .status(
          500
        )
        .json({

          ok:false,

          error:
            "Erro ao carregar evento"

        });

    }

  }
);


// ============================================================
// EDITAR EVENTO
//
// PUT
// /admin/api/events/:eventId
// ============================================================

app.put(
  "/admin/api/events/:eventId",
  adminAuth,
  (req, res) => {

    try{

      const eventId =
        positiveId(
          req.params.eventId
        );


      const event =
        eventId
          ? getEventById(
              eventId
            )
          : null;


      if(
        !event
      ){

        return res
          .status(
            404
          )
          .json({

            ok:false,

            error:
              "Evento nÃ£o encontrado"

          });

      }


      const name =
        String(
          req.body?.name ||
          event.name
        )
          .trim()
          .slice(
            0,
            100
          );


      const status =
        req.body?.status ===
        "inactive"
          ? "inactive"
          : "active";


      db.prepare(`

        UPDATE events

        SET

          name=?,

          establishment_name=?,

          location=?,

          description=?,

          timezone=?,

          status=?,

          updated_at=?

        WHERE id=?

      `).run(

        name,

        String(
          req.body?.establishment_name ??
          event.establishment_name ??
          ""
        )
          .trim()
          .slice(
            0,
            120
          ),

        String(
          req.body?.location ??
          event.location ??
          ""
        )
          .trim()
          .slice(
            0,
            160
          ),

        String(
          req.body?.description ??
          event.description ??
          ""
        )
          .trim()
          .slice(
            0,
            500
          ),

        String(
          req.body?.timezone ??
          event.timezone ??
          "America/Sao_Paulo"
        )
          .trim()
          .slice(
            0,
            80
          ),

        status,

        nowIso(),

        eventId

      );


      return res.json({

        ok:
          true,

        event:
          getEventById(
            eventId
          )

      });

    }


    catch(error){

      console.error(
        "Erro ao editar evento:",
        error
      );


      return res
        .status(
          500
        )
        .json({

          ok:false,

          error:
            "Erro ao editar evento"

        });

    }

  }
);


// ============================================================
// ============================================================
// MIKROTIK - PORTAS
// ============================================================
// ============================================================


// ============================================================
// FUNCOES AUXILIARES DA MIKROTIK
// ============================================================

function getRouterById(routerId) {

  return db.prepare(`

    SELECT *

    FROM routers

    WHERE id=?

    LIMIT 1

  `).get(
    routerId
  );

}


function getRouterPorts(routerId) {

  return db.prepare(`

    SELECT *

    FROM router_ports

    WHERE router_id=?

    ORDER BY
      port_number ASC,
      id ASC

  `).all(
    routerId
  );

}



function validPortFunction(value) {

  return [
    "wan_primary",
    "wan_secondary",
    "hotspot",
    "free"
  ].includes(
    String(
      value || ""
    ).trim()
  );

}


// ============================================================
// LISTAR MIKROTIKS DE UM EVENTO
//
// Retorna a MikroTik Ãºnica do evento com suas portas.
// ============================================================

app.get(
  "/admin/api/events/:eventId/routers",
  adminAuth,
  (req, res) => {

    try{

      const eventId =
        positiveId(
          req.params.eventId
        );


      if(
        !eventId
        ||
        !getEventById(
          eventId
        )
      ){

        return res
          .status(
            404
          )
          .json({

            ok:false,

            error:
              "Evento nÃ£o encontrado"

          });

      }


      const routers =
        db.prepare(`

          SELECT *

          FROM routers

          WHERE
            event_id=?
            AND status='active'

          ORDER BY id ASC

        `).all(
          eventId
        );


      const enrichedRouters =
        routers.map(
          router => {

            ensureRouterPorts(
              router
            );

            return {
              ...router,
              role: "primary",
              ports: getRouterPorts(router.id)
            };

          }
        );


      return res.json({

        ok:true,

        count:
          enrichedRouters.length,

        routers:
          enrichedRouters

      });

    }


    catch(error){

      console.error(
        "Erro ao listar MikroTiks:",
        error
      );


      return res
        .status(
          500
        )
        .json({

          ok:false,

          error:
            "Erro ao listar MikroTiks"

        });

    }

  }
);


// ============================================================
// V16.3 - IPS RESERVADOS / FORA DO DHCP
// ============================================================

(function ensureRouterReservedIpsColumn(){

  const columns =
    db.prepare(
      "PRAGMA table_info(routers)"
    ).all();

  if(
    !columns.some(
      column =>
        column.name ===
        "reserved_ips"
    )
  ){
    db.exec(
      "ALTER TABLE routers ADD COLUMN reserved_ips TEXT DEFAULT ''"
    );
  }

})();


(function ensureRouterHotspotTlsColumns(){

  const columns = db.prepare("PRAGMA table_info(routers)").all();

  if(!columns.some(column => column.name === "hotspot_dns_name")){
    db.exec("ALTER TABLE routers ADD COLUMN hotspot_dns_name TEXT DEFAULT ''");
  }

  if(!columns.some(column => column.name === "hotspot_ssl_certificate")){
    db.exec("ALTER TABLE routers ADD COLUMN hotspot_ssl_certificate TEXT DEFAULT ''");
  }

})();


function normalizeReservedIps(
  value,
  clientNetwork
){

  const match =
    String(
      clientNetwork || ""
    ).match(
      /^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/
    );

  if(
    !match
  ){
    return "";
  }

  const base =
    ipv4ToUint32(
      match[1]
    );

  const prefix =
    Number(
      match[2]
    );

  if(
    base === null
    ||
    !Number.isInteger(prefix)
    ||
    prefix < 0
    ||
    prefix > 32
  ){
    return "";
  }

  const hostBits =
    32 - prefix;

  const total =
    Math.pow(
      2,
      hostBits
    );

  const mask =
    (
      0xFFFFFFFF
      <<
      hostBits
    ) >>> 0;

  const network =
    (
      base
      &
      mask
    ) >>> 0;

  const broadcast =
    (
      network
      +
      total
      -
      1
    ) >>> 0;

  return Array.from(
    new Set(
      String(
        value || ""
      )
        .split(
          /[\s,;]+/
        )
        .map(
          item =>
            normalizeIp(
              item
            )
        )
        .filter(Boolean)
        .filter(
          ip => {

            const number =
              ipv4ToUint32(
                ip
              );

            return (
              number !== null
              &&
              number >
                network
              &&
              number <
                broadcast
            );

          }
        )
    )
  )
    .slice(
      0,
      100
    )
    .join(",");

}


// ============================================================
// V16 - REDE DE CLIENTES /22 OU /24
//
// O painel passa a poder trabalhar com duas capacidades:
//
// /24 -> ate 254 enderecos utilizaveis
// /22 -> ate 1022 enderecos utilizaveis
//
// O backend nao confia apenas nos campos calculados pelo navegador.
// Ele valida a rede e recalcula:
// - endereco real da rede
// - gateway padrao
// - inicio do pool
// - final do pool
//
// Os campos dhcp_pool_start/end continuam no banco para manter
// compatibilidade com o Admin e com o gerador de script atual.
// ============================================================

function ipv4ToUint32(
  value
){

  const ip =
    normalizeIp(
      value
    );

  if(
    !ip
  ){
    return null;
  }


  const parts =
    ip
      .split(".")
      .map(Number);


  return (
    (
      (
        (
          parts[0] * 256
          +
          parts[1]
        ) * 256
        +
        parts[2]
      ) * 256
      +
      parts[3]
    )
    >>>
    0
  );

}


function uint32ToIpv4(
  value
){

  const number =
    Number(value) >>> 0;


  return [
    (number >>> 24) & 255,
    (number >>> 16) & 255,
    (number >>> 8) & 255,
    number & 255
  ].join(".");

}


function normalizeClientNetworkConfig(
  input = {},
  fallback = {}
){

  const rawNetwork =
    String(
      input.client_network
      ??
      fallback.client_network
      ??
      "10.50.0.0/24"
    )
      .trim();


  const match =
    rawNetwork.match(
      /^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/
    );


  if(
    !match
  ){

    return {
      ok:false,
      error:
        "Rede de clientes invÃ¡lida. Use, por exemplo, 10.50.0.0/24."
    };

  }


  const baseIp =
    normalizeIp(
      match[1]
    );

  const prefix =
    Number(
      match[2]
    );


  // ==========================================================
  // V16.2 - MASCARA LIVRE ENTRE /32 E /21
  //
  // O painel permite visualizar /32 ate /21.
  //
  // Para HotSpot + gateway + DHCP:
  // /31 e /32 nao possuem espaco para gateway e cliente DHCP.
  // Por isso aparecem no seletor, mas nao podem ser salvos como
  // rede de clientes do HotSpot.
  // ==========================================================

  if(
    !baseIp
    ||
    !Number.isInteger(
      prefix
    )
    ||
    prefix < 21
    ||
    prefix > 32
  ){

    return {
      ok:false,
      error:
        "MÃ¡scara invÃ¡lida. Escolha entre /32 e /21."
    };

  }


  if(
    prefix >= 31
  ){

    return {
      ok:false,
      error:
        `A rede /${prefix} nÃ£o comporta gateway + DHCP para o HotSpot. Use /30 atÃ© /21.`
    };

  }


  const baseNumber =
    ipv4ToUint32(
      baseIp
    );


  const hostBits =
    32 - prefix;

  const totalAddresses =
    Math.pow(
      2,
      hostBits
    );

  const mask =
    (
      0xFFFFFFFF
      <<
      hostBits
    )
    >>>
    0;


  const networkNumber =
    (
      baseNumber
      &
      mask
    )
    >>>
    0;


  const broadcastNumber =
    (
      networkNumber
      +
      totalAddresses
      -
      1
    )
    >>>
    0;


  const firstHostNumber =
    (
      networkNumber + 1
    )
    >>>
    0;


  const lastHostNumber =
    (
      broadcastNumber - 1
    )
    >>>
    0;


  const firstDhcpNumber =
    (
      firstHostNumber + 1
    )
    >>>
    0;


  const isUsableHost =
    value => {

      const normalized =
        normalizeIp(
          value
        );

      const number =
        ipv4ToUint32(
          normalized
        );

      return (
        normalized
        &&
        number !== null
        &&
        number >=
          firstHostNumber
        &&
        number <=
          lastHostNumber
      );

    };


  const requestedGateway =
    String(
      input.client_gateway
      ??
      fallback.client_gateway
      ??
      ""
    )
      .trim();


  const gateway =
    isUsableHost(
      requestedGateway
    )
      ? normalizeIp(
          requestedGateway
        )
      : uint32ToIpv4(
          firstHostNumber
        );


  // ==========================================================
  // POOL PADRAO
  //
  // Redes com espaco suficiente:
  // inicia no host .10 relativo ao inicio da rede.
  //
  // Redes pequenas (/30, /29 etc):
  // inicia no primeiro host depois do gateway.
  // ==========================================================

  const preferredPoolStartNumber =
    (
      networkNumber + 10
    )
    <=
    lastHostNumber
      ? (
          networkNumber + 10
        )
      : firstDhcpNumber;


  const defaultPoolStart =
    uint32ToIpv4(
      preferredPoolStartNumber
    );


  const defaultPoolEnd =
    uint32ToIpv4(
      lastHostNumber
    );


  const requestedPoolStart =
    String(
      input.dhcp_pool_start
      ??
      fallback.dhcp_pool_start
      ??
      ""
    )
      .trim();


  const requestedPoolEnd =
    String(
      input.dhcp_pool_end
      ??
      fallback.dhcp_pool_end
      ??
      ""
    )
      .trim();


  const requestedPoolStartNumber =
    ipv4ToUint32(
      requestedPoolStart
    );

  const requestedPoolEndNumber =
    ipv4ToUint32(
      requestedPoolEnd
    );


  const poolStart =
    (
      isUsableHost(
        requestedPoolStart
      )
      &&
      requestedPoolStartNumber >
        ipv4ToUint32(
          gateway
        )
    )
      ? normalizeIp(
          requestedPoolStart
        )
      : defaultPoolStart;


  const poolEnd =
    (
      isUsableHost(
        requestedPoolEnd
      )
      &&
      requestedPoolEndNumber >
        ipv4ToUint32(
          gateway
        )
    )
      ? normalizeIp(
          requestedPoolEnd
        )
      : defaultPoolEnd;


  const poolStartNumber =
    ipv4ToUint32(
      poolStart
    );


  const poolEndNumber =
    ipv4ToUint32(
      poolEnd
    );


  if(
    poolStartNumber >
    poolEndNumber
  ){

    return {
      ok:false,
      error:
        "Faixa DHCP invÃ¡lida: o inÃ­cio do pool Ã© maior que o final."
    };

  }


  if(
    ipv4ToUint32(
      gateway
    )
    >=
    poolStartNumber
    &&
    ipv4ToUint32(
      gateway
    )
    <=
    poolEndNumber
  ){

    return {
      ok:false,
      error:
        "Faixa DHCP invÃ¡lida: o gateway nÃ£o pode ficar dentro do pool dinÃ¢mico."
    };

  }


  const usableHosts =
    Math.max(
      0,
      totalAddresses - 2
    );


  const dhcpCapacity =
    Math.max(
      0,
      lastHostNumber
      -
      poolStartNumber
      +
      1
    );


  return {
    ok:true,
    prefix,
    client_network:
      uint32ToIpv4(
        networkNumber
      )
      +
      "/"
      +
      prefix,
    client_gateway:
      gateway,
    dhcp_pool_start:
      poolStart,
    dhcp_pool_end:
      poolEnd,
    usable_hosts:
      usableHosts,
    dhcp_capacity:
      dhcpCapacity
  };

}


// ============================================================
// ADICIONAR MIKROTIK
//
// REGRA: cada evento pode possuir somente UMA MikroTik ativa.
// ============================================================


app.post(
  "/admin/api/events/:eventId/routers",
  adminAuth,
  (req, res) => {

    try{

      const eventId =
        positiveId(req.params.eventId);

      const event =
        eventId
          ? getEventById(eventId)
          : null;

      if(!event){
        return res.status(404).json({
          ok:false,
          error:"Evento nÃ£o encontrado"
        });
      }

      const existingRouter =
        db.prepare(`
          SELECT *
          FROM routers
          WHERE event_id=? AND status='active'
          ORDER BY id ASC
          LIMIT 1
        `).get(eventId);

      if(existingRouter){
        return res.status(409).json({
          ok:false,
          error:"Este evento jÃ¡ possui uma MikroTik cadastrada. Cada evento pode possuir somente uma MikroTik."
        });
      }

      const name =
        String(req.body?.name || "MikroTik do Evento")
          .trim().slice(0,150);

      const identity =
        String(req.body?.identity || name || "WIFI-PAGO")
          .trim().slice(0,150);

      const model =
        String(req.body?.model || "RB750Gr3")
          .trim().slice(0,100);

      const routerosVersion =
        String(req.body?.routeros_version || "7")
          .trim().slice(0,50);

      const wanType =
        String(req.body?.wan_type || "pppoe")
          .trim().toLowerCase().slice(0,50);

      const failoverEnabled =
        Number(req.body?.failover_enabled) === 1
          ? 1
          : 0;

      const baseKey =
        makeKey(
          req.body?.router_key ||
          `${event.event_key}-${name}` ||
          `mikrotik-${eventId}`
        ) || `mikrotik-${eventId}`;

      let routerKey = baseKey;
      let suffix = 2;

      while(
        db.prepare(
          "SELECT id FROM routers WHERE router_key=? LIMIT 1"
        ).get(routerKey)
      ){
        routerKey = `${baseKey}-${suffix++}`;
      }

      const token =
        String(req.body?.token || "").trim()
        ||
        crypto.randomBytes(24).toString("hex");

      const networkConfig =
        normalizeClientNetworkConfig(
          req.body || {}
        );

      if(
        !networkConfig.ok
      ){
        return res
          .status(400)
          .json({
            ok:false,
            error:
              networkConfig.error
          });
      }


      const now = nowIso();

      const result =
        db.prepare(`
          INSERT INTO routers (
            event_id, router_key, name, identity, model, routeros_version,
            role, wan_interface, client_interface, wan_type,
            failover_enabled, secondary_wan_interface, secondary_wan_type,
            wan_pppoe_user, wan_pppoe_password, wan_static_address, wan_static_gateway,
            secondary_wan_pppoe_user, secondary_wan_pppoe_password,
            secondary_wan_static_address, secondary_wan_static_gateway,
            client_network, client_gateway, dhcp_pool_start, dhcp_pool_end,
            reserved_ips,
            token, status, created_at, updated_at
          )
          VALUES (
            ?, ?, ?, ?, ?, ?, 'primary', ?, ?, ?, ?, ?, ?,
            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
            ?, 'active', ?, ?
          )
        `).run(
          eventId,
          routerKey,
          name || "MikroTik do Evento",
          identity,
          model,
          routerosVersion,

          String(req.body?.wan_interface || "ether1").trim().slice(0,50),
          String(req.body?.client_interface || "ether2").trim().slice(0,50),
          wanType,

          failoverEnabled,

          failoverEnabled
            ? String(req.body?.secondary_wan_interface || "").trim().slice(0,50)
            : "",

          failoverEnabled
            ? String(req.body?.secondary_wan_type || "dhcp").trim().toLowerCase().slice(0,50)
            : "",

          String(req.body?.wan_pppoe_user || "").trim().slice(0,200),
          String(req.body?.wan_pppoe_password || "").slice(0,300),
          String(req.body?.wan_static_address || "").trim().slice(0,80),
          String(req.body?.wan_static_gateway || "").trim().slice(0,80),

          failoverEnabled
            ? String(req.body?.secondary_wan_pppoe_user || "").trim().slice(0,200)
            : "",

          failoverEnabled
            ? String(req.body?.secondary_wan_pppoe_password || "").slice(0,300)
            : "",

          failoverEnabled
            ? String(req.body?.secondary_wan_static_address || "").trim().slice(0,80)
            : "",

          failoverEnabled
            ? String(req.body?.secondary_wan_static_gateway || "").trim().slice(0,80)
            : "",

          networkConfig.client_network,
          networkConfig.client_gateway,
          networkConfig.dhcp_pool_start,
          networkConfig.dhcp_pool_end,

          normalizeReservedIps(
            req.body?.reserved_ips || "",
            networkConfig.client_network
          ),

          token,
          now,
          now
        );

      db.prepare(`
        UPDATE routers
        SET hotspot_dns_name=?, hotspot_ssl_certificate=?
        WHERE id=?
      `).run(
        String(req.body?.hotspot_dns_name || "").trim().toLowerCase().slice(0,253),
        String(req.body?.hotspot_ssl_certificate || "").trim().slice(0,200),
        Number(result.lastInsertRowid)
      );

      const router =
        getRouterById(
          Number(result.lastInsertRowid)
        );

      ensureRouterPorts(router);

      return res.status(201).json({
        ok:true,
        router:{
          ...router,
          role:"primary"
        },
        ports:getRouterPorts(router.id)
      });

    }catch(error){

      console.error(
        "Erro ao adicionar MikroTik:",
        error
      );

      return res.status(500).json({
        ok:false,
        error:"Erro ao adicionar MikroTik"
      });

    }

  }
);

// ============================================================
// EDITAR MIKROTIK
// ============================================================


app.put(
  "/admin/api/routers/:routerId",
  adminAuth,
  (req, res) => {

    try{

      const routerId =
        positiveId(req.params.routerId);

      const router =
        routerId
          ? getRouterById(routerId)
          : null;

      if(!router){
        return res.status(404).json({
          ok:false,
          error:"MikroTik nÃ£o encontrada"
        });
      }

      const status =
        req.body?.status === "inactive"
          ? "inactive"
          : (
              req.body?.status === "active"
                ? "active"
                : router.status
            );

      const failoverEnabled =
        req.body?.failover_enabled !== undefined
          ? (
              Number(req.body.failover_enabled) === 1
                ? 1
                : 0
            )
          : Number(router.failover_enabled || 0);


      const networkConfig =
        normalizeClientNetworkConfig(
          req.body || {},
          router
        );

      if(
        !networkConfig.ok
      ){
        return res
          .status(400)
          .json({
            ok:false,
            error:
              networkConfig.error
          });
      }


      db.prepare(`
        UPDATE routers
        SET
          name=?,
          identity=?,
          model=?,
          routeros_version=?,
          role='primary',

          wan_interface=?,
          client_interface=?,
          wan_type=?,
          failover_enabled=?,
          secondary_wan_interface=?,
          secondary_wan_type=?,

          wan_pppoe_user=?,
          wan_pppoe_password=?,
          wan_static_address=?,
          wan_static_gateway=?,

          secondary_wan_pppoe_user=?,
          secondary_wan_pppoe_password=?,
          secondary_wan_static_address=?,
          secondary_wan_static_gateway=?,

          client_network=?,
          client_gateway=?,
          hotspot_dns_name=?,
          hotspot_ssl_certificate=?,
          dhcp_pool_start=?,
          dhcp_pool_end=?,
          reserved_ips=?,
          status=?,
          updated_at=?
        WHERE id=?
      `).run(
        String(req.body?.name ?? router.name).trim().slice(0,100),
        String(req.body?.identity ?? router.identity ?? "").trim().slice(0,100),
        String(req.body?.model ?? router.model ?? "").trim().slice(0,80),
        String(req.body?.routeros_version ?? router.routeros_version ?? "").trim().slice(0,30),

        String(req.body?.wan_interface ?? router.wan_interface ?? "").trim().slice(0,50),
        String(req.body?.client_interface ?? router.client_interface ?? "").trim().slice(0,50),
        String(req.body?.wan_type ?? router.wan_type ?? "pppoe").trim().toLowerCase().slice(0,30),

        failoverEnabled,

        failoverEnabled
          ? String(req.body?.secondary_wan_interface ?? router.secondary_wan_interface ?? "").trim().slice(0,50)
          : "",

        failoverEnabled
          ? String(req.body?.secondary_wan_type ?? router.secondary_wan_type ?? "dhcp").trim().toLowerCase().slice(0,30)
          : "",

        String(req.body?.wan_pppoe_user ?? router.wan_pppoe_user ?? "").trim().slice(0,200),
        String(req.body?.wan_pppoe_password ?? router.wan_pppoe_password ?? "").slice(0,300),
        String(req.body?.wan_static_address ?? router.wan_static_address ?? "").trim().slice(0,80),
        String(req.body?.wan_static_gateway ?? router.wan_static_gateway ?? "").trim().slice(0,80),

        failoverEnabled
          ? String(req.body?.secondary_wan_pppoe_user ?? router.secondary_wan_pppoe_user ?? "").trim().slice(0,200)
          : "",

        failoverEnabled
          ? String(req.body?.secondary_wan_pppoe_password ?? router.secondary_wan_pppoe_password ?? "").slice(0,300)
          : "",

        failoverEnabled
          ? String(req.body?.secondary_wan_static_address ?? router.secondary_wan_static_address ?? "").trim().slice(0,80)
          : "",

        failoverEnabled
          ? String(req.body?.secondary_wan_static_gateway ?? router.secondary_wan_static_gateway ?? "").trim().slice(0,80)
          : "",

        networkConfig.client_network,
        networkConfig.client_gateway,
        String(req.body?.hotspot_dns_name ?? router.hotspot_dns_name ?? "").trim().toLowerCase().slice(0,253),
        String(req.body?.hotspot_ssl_certificate ?? router.hotspot_ssl_certificate ?? "").trim().slice(0,200),
        networkConfig.dhcp_pool_start,
        networkConfig.dhcp_pool_end,

        normalizeReservedIps(
          req.body?.reserved_ips
          ??
          router.reserved_ips
          ??
          "",
          networkConfig.client_network
        ),

        status,
        nowIso(),
        routerId
      );

      const updatedRouter =
        getRouterById(routerId);

      ensureRouterPorts(updatedRouter);

      return res.json({
        ok:true,
        router:{
          ...updatedRouter,
          ports:getRouterPorts(routerId)
        }
      });

    }catch(error){

      console.error(
        "Erro ao editar MikroTik:",
        error
      );

      return res.status(500).json({
        ok:false,
        error:"Erro ao editar MikroTik"
      });

    }

  }
);

// ============================================================
// LISTAR PORTAS DE UMA MIKROTIK
//
// GET /admin/api/routers/:routerId/ports
// ============================================================

app.get(
  "/admin/api/routers/:routerId/ports",
  adminAuth,
  (req, res) => {

    try{

      const routerId =
        positiveId(
          req.params.routerId
        );


      const router =
        routerId
          ? getRouterById(
              routerId
            )
          : null;


      if(
        !router
      ){

        return res
          .status(
            404
          )
          .json({

            ok:false,

            error:
              "MikroTik nÃ£o encontrada"

          });

      }


      ensureRouterPorts(
        router
      );


      const ports =
        getRouterPorts(
          routerId
        );


      return res.json({

        ok:true,

        router_id:
          routerId,

        count:
          ports.length,

        ports

      });

    }


    catch(error){

      console.error(
        "Erro ao listar portas da MikroTik:",
        error
      );


      return res
        .status(
          500
        )
        .json({

          ok:false,

          error:
            "Erro ao listar portas da MikroTik"

        });

    }

  }
);


// ============================================================
// SALVAR CONFIGURACAO DAS PORTAS
//
// PUT /admin/api/routers/:routerId/ports
//
// Body:
//
// {
//   "ports":[
//     {"interface_name":"ether1","function":"wan"},
//     {"interface_name":"ether2","function":"hotspot"},
//     {"interface_name":"ether3","function":"free"}
//   ]
// }
//
// FunÃ§Ãµes permitidas: wan, hotspot e free.
// ============================================================


app.put(
  "/admin/api/routers/:routerId/ports",
  adminAuth,
  (req, res) => {

    try{

      const routerId =
        positiveId(
          req.params.routerId
        );

      const router =
        routerId
          ? getRouterById(routerId)
          : null;

      if(!router){
        return res.status(404).json({
          ok:false,
          error:"MikroTik nÃ£o encontrada"
        });
      }

      const requestedPorts =
        Array.isArray(req.body?.ports)
          ? req.body.ports
          : [];

      if(requestedPorts.length === 0){
        return res.status(400).json({
          ok:false,
          error:"Envie ao menos uma porta"
        });
      }

      const existingPorts =
        getRouterPorts(routerId);

      const existingNames =
        new Set(
          existingPorts.map(
            port =>
              String(port.interface_name)
          )
        );

      const seen =
        new Set();

      let primaryCount = 0;
      let secondaryCount = 0;
      let hotspotCount = 0;

      for(const requestedPort of requestedPorts){

        const interfaceName =
          String(
            requestedPort?.interface_name || ""
          ).trim();

        let portFunction =
          String(
            requestedPort?.function || "free"
          ).trim();

        if(portFunction === "wan"){
          portFunction = "wan_primary";
        }

        if(
          !interfaceName
          ||
          !existingNames.has(interfaceName)
        ){
          return res.status(400).json({
            ok:false,
            error:`Porta invÃ¡lida: ${interfaceName || "(vazia)"}`
          });
        }

        if(seen.has(interfaceName)){
          return res.status(400).json({
            ok:false,
            error:`Porta repetida: ${interfaceName}`
          });
        }

        seen.add(interfaceName);

        if(!validPortFunction(portFunction)){
          return res.status(400).json({
            ok:false,
            error:`FunÃ§Ã£o invÃ¡lida para ${interfaceName}`
          });
        }

        if(portFunction === "wan_primary"){
          primaryCount++;
        }

        if(portFunction === "wan_secondary"){
          secondaryCount++;
        }

        if(portFunction === "hotspot"){
          hotspotCount++;
        }

      }

      if(primaryCount !== 1){
        return res.status(400).json({
          ok:false,
          error:"A MikroTik precisa ter exatamente uma porta de LINK PRINCIPAL"
        });
      }

      if(secondaryCount > 1){
        return res.status(400).json({
          ok:false,
          error:"A MikroTik pode possuir no mÃ¡ximo uma porta de LINK SECUNDÃRIO"
        });
      }

      if(hotspotCount < 1){
        return res.status(400).json({
          ok:false,
          error:"Selecione ao menos uma porta CLIENTES / HOTSPOT"
        });
      }

      if(
        Number(router.failover_enabled || 0) === 1
        &&
        secondaryCount !== 1
      ){
        return res.status(400).json({
          ok:false,
          error:"O failover estÃ¡ ativo. Selecione exatamente uma porta de LINK SECUNDÃRIO."
        });
      }

      const updatePort =
        db.prepare(`
          UPDATE router_ports

          SET
            function=?,
            bridge_name=?,
            enabled=?,
            notes=?,
            updated_at=?

          WHERE
            router_id=?
            AND interface_name=?
        `);

      const saveTransaction =
        db.transaction(
          () => {

            for(const requestedPort of requestedPorts){

              const interfaceName =
                String(
                  requestedPort.interface_name
                ).trim();

              let portFunction =
                String(
                  requestedPort.function || "free"
                ).trim();

              if(portFunction === "wan"){
                portFunction = "wan_primary";
              }

              const bridgeName =
                portFunction === "hotspot"
                  ? "bridge-clientes"
                  : null;

              updatePort.run(
                portFunction,
                bridgeName,
                requestedPort?.enabled === false
                  ? 0
                  : 1,
                String(requestedPort?.notes || "")
                  .trim()
                  .slice(0,200),
                nowIso(),
                routerId,
                interfaceName
              );

            }

            const savedPorts =
              getRouterPorts(routerId);

            const primaryWanPort =
              savedPorts.find(
                port =>
                  port.function === "wan_primary"
              );

            const secondaryWanPort =
              savedPorts.find(
                port =>
                  port.function === "wan_secondary"
              );

            const hotspotPort =
              savedPorts.find(
                port =>
                  port.function === "hotspot"
              );

            db.prepare(`
              UPDATE routers

              SET
                wan_interface=?,
                secondary_wan_interface=?,
                failover_enabled=?,
                client_interface=?,
                updated_at=?

              WHERE id=?
            `).run(
              primaryWanPort
                ? primaryWanPort.interface_name
                : "",
              secondaryWanPort
                ? secondaryWanPort.interface_name
                : "",
              secondaryWanPort
                ? 1
                : 0,
              hotspotPort
                ? hotspotPort.interface_name
                : "",
              nowIso(),
              routerId
            );

          }
        );

      saveTransaction();

      return res.json({
        ok:true,
        router:getRouterById(routerId),
        ports:getRouterPorts(routerId)
      });

    }catch(error){

      console.error(
        "Erro ao salvar portas da MikroTik:",
        error
      );

      return res.status(500).json({
        ok:false,
        error:"Erro ao salvar portas da MikroTik"
      });

    }

  }
);


// ============================================================
// PLANOS
// ============================================================
// ============================================================

app.get("/admin/api/events/:eventId/voucher-batches", adminAuth, (req,res) => {
  const eventId = positiveId(req.params.eventId);
  if(!eventId || !getEventById(eventId)) return res.status(404).json({ok:false,error:"Evento nÃ£o encontrado"});
  const batches = db.prepare(`SELECT b.id,b.event_id,b.first_number,b.last_number,b.plan_id,b.plan_name,b.minutes,b.rate_limit,
    b.mikrotik_profile,b.amount,b.active,b.created_at,b.deleted_at,
    CASE WHEN b.print_data_encrypted IS NULL THEN 0 ELSE 1 END AS has_print_data,
    COUNT(v.id) AS quantity,
    SUM(CASE WHEN v.status='unused' THEN 1 ELSE 0 END) AS unused,
    SUM(CASE WHEN v.status='redeemed' THEN 1 ELSE 0 END) AS redeemed
    FROM voucher_batches b LEFT JOIN vouchers v ON v.batch_id=b.id
    WHERE b.event_id=? AND b.deleted_at IS NULL GROUP BY b.id ORDER BY b.id DESC`).all(eventId);
  res.json({ok:true,batches});
});

app.get("/admin/api/voucher-batches/:batchId/vouchers", adminAuth, (req,res) => {
  const batchId = positiveId(req.params.batchId);
  const batch = db.prepare("SELECT id,print_data_encrypted FROM voucher_batches WHERE id=? AND deleted_at IS NULL").get(batchId);
  if(!batch) return res.status(404).json({ok:false,error:"Lote nÃ£o encontrado"});
  let codesByNumber = Object.create(null);
  if(batch.print_data_encrypted){
    try {
      const saved = decryptVoucherPrintData(batch.print_data_encrypted);
      codesByNumber = Object.fromEntries((saved.codes || []).map(item => [Number(item.number),item.code]));
    } catch(error) {
      console.error("Erro ao recuperar codigos do lote para auditoria:",error);
    }
  }
  const vouchers = db.prepare(`SELECT v.serial_number,v.status,v.created_at,v.redeemed_at,
      v.redeemed_mac,v.redeemed_ip,c.name AS customer_name,c.phone AS customer_phone
    FROM vouchers v LEFT JOIN customers c ON c.client_id=v.redeemed_client_id
    WHERE v.batch_id=? ORDER BY v.serial_number ASC`).all(batchId);
  res.set("Cache-Control", "no-store");
  res.json({ok:true,vouchers:vouchers.map(voucher => ({...voucher,code:codesByNumber[voucher.serial_number] || null}))});
});

function escapeWifiQrField(value){
  return String(value || "").replace(/([\\;,:\"])/g, "\\$1");
}

app.post("/admin/api/events/:eventId/voucher-batches", adminAuth, async (req,res) => {
  try{
    const eventId = positiveId(req.params.eventId);
    const quantity = Number(req.body?.quantity);
    const ssid = String(req.body?.ssid || "");
    const wifiPassword = String(req.body?.wifi_password || "");
    if(!eventId || !getEventById(eventId)) return res.status(404).json({ok:false,error:"Evento nÃ£o encontrado"});
    if(!ssid.trim() || Buffer.byteLength(ssid,"utf8") > 32) return res.status(400).json({ok:false,error:"Informe o nome exato do Wi-Fi (atÃ© 32 bytes)."});
    if(wifiPassword && (Buffer.byteLength(wifiPassword,"utf8") < 8 || Buffer.byteLength(wifiPassword,"utf8") > 63)) return res.status(400).json({ok:false,error:"A senha do Wi-Fi deve ter entre 8 e 63 bytes."});
    const plan = db.prepare(`SELECT * FROM event_plans WHERE event_id=? AND plan_key=? AND active=1 AND deleted_at IS NULL`).get(eventId, String(req.body?.plan_id || ""));
    if(!plan) return res.status(400).json({ok:false,error:"Selecione um plano ativo do evento."});
    if(!Number.isInteger(quantity) || quantity<1 || quantity>1000) return res.status(400).json({ok:false,error:"A quantidade deve estar entre 1 e 1.000 vouchers por lote."});
    const wifiPayload = wifiPassword
      ? `WIFI:T:WPA;S:${escapeWifiQrField(ssid)};P:${escapeWifiQrField(wifiPassword)};;`
      : `WIFI:T:nopass;S:${escapeWifiQrField(ssid)};;`;
    const wifiQrDataUrl = await QRCode.toDataURL(wifiPayload,{errorCorrectionLevel:"M",margin:1,width:240});

    const codes = [];
    const createBatch = db.transaction(() => {
      const last = db.prepare("SELECT MAX(last_number) AS value FROM voucher_batches WHERE event_id=?").get(eventId)?.value || 0;
      const first = Number(last)+1, end = first+quantity-1, now = nowIso();
      const result = db.prepare(`INSERT INTO voucher_batches
        (event_id,first_number,last_number,plan_id,plan_name,minutes,rate_limit,mikrotik_profile,amount,created_at)
        VALUES (?,?,?,?,?,?,?,?,?,?)`).run(eventId,first,end,plan.plan_key,plan.name,plan.minutes,plan.rate_limit,plan.mikrotik_profile,plan.amount,now);
      const batchId = Number(result.lastInsertRowid);
      const insert = db.prepare("INSERT INTO vouchers (batch_id,event_id,serial_number,code_hash,code_last4,created_at) VALUES (?,?,?,?,?,?)");
      for(let number=first;number<=end;number++){
        let raw, hash;
        do {
          raw = String(crypto.randomInt(0, 1000000)).padStart(6,"0");
          hash = crypto.createHash("sha256").update(raw).digest("hex");
          if(!db.prepare("SELECT 1 FROM vouchers WHERE code_hash=?").get(hash)) break;
          raw = null;
        } while(raw === null);
        insert.run(batchId,eventId,number,hash,raw.slice(-4),now);
        codes.push({number,code:`${raw.slice(0,3)}-${raw.slice(3)}`});
      }
      return {batchId,first,end,now};
    });
    const created = createBatch();
    db.prepare("UPDATE voucher_batches SET print_data_encrypted=? WHERE id=?").run(
      encryptVoucherPrintData({codes,ssid,wifiPassword}), created.batchId
    );
    res.status(201).json({ok:true,batch:{id:created.batchId,first_number:created.first,last_number:created.end,
      plan_name:plan.name,amount:plan.amount,minutes:plan.minutes,rate_limit:plan.rate_limit,quantity},codes,
      wifi:{ssid,has_password:Boolean(wifiPassword),qr_data_url:wifiQrDataUrl}});
  }catch(error){
    console.error("Erro ao gerar lote de vouchers:",error);
    res.status(500).json({ok:false,error:"NÃ£o foi possÃ­vel gerar o lote de vouchers."});
  }
});

app.get("/admin/api/voucher-batches/:batchId/print-data", adminAuth, async (req,res) => {
  try {
    const batchId = positiveId(req.params.batchId);
    const batch = db.prepare(`SELECT id,first_number,last_number,plan_name,amount,minutes,rate_limit,print_data_encrypted
      FROM voucher_batches WHERE id=? AND deleted_at IS NULL`).get(batchId);
    if(!batch) return res.status(404).json({ok:false,error:"Lote nÃ£o encontrado"});
    if(!batch.print_data_encrypted) return res.status(410).json({ok:false,error:"Este lote foi criado antes do salvamento seguro dos cÃ³digos e nÃ£o pode ser reimpresso."});
    const saved = decryptVoucherPrintData(batch.print_data_encrypted);
    const wifiPayload = saved.wifiPassword
      ? `WIFI:T:WPA;S:${escapeWifiQrField(saved.ssid)};P:${escapeWifiQrField(saved.wifiPassword)};;`
      : `WIFI:T:nopass;S:${escapeWifiQrField(saved.ssid)};;`;
    const qr_data_url = await QRCode.toDataURL(wifiPayload,{errorCorrectionLevel:"M",margin:1,width:240});
    res.set("Cache-Control", "no-store");
    res.json({ok:true,batch:{id:batch.id,first_number:batch.first_number,last_number:batch.last_number,
      plan_name:batch.plan_name,amount:batch.amount,minutes:batch.minutes,rate_limit:batch.rate_limit},
      codes:saved.codes,wifi:{ssid:saved.ssid,has_password:Boolean(saved.wifiPassword),qr_data_url}});
  } catch(error) {
    console.error("Erro ao recuperar dados de impressao do voucher:",error);
    res.status(500).json({ok:false,error:"NÃ£o foi possÃ­vel recuperar os dados para impressÃ£o."});
  }
});

app.patch("/admin/api/voucher-batches/:batchId", adminAuth, (req,res) => {
  const batchId = positiveId(req.params.batchId);
  const active = req.body?.active === false || Number(req.body?.active) === 0 ? 0 : 1;
  const result = db.prepare("UPDATE voucher_batches SET active=? WHERE id=? AND deleted_at IS NULL").run(active,batchId);
  if(!result.changes) return res.status(404).json({ok:false,error:"Lote nÃ£o encontrado"});
  res.json({ok:true,active});
});

app.delete("/admin/api/voucher-batches/:batchId", adminAuth, (req,res) => {
  const batchId = positiveId(req.params.batchId);
  const batch = db.prepare("SELECT id FROM voucher_batches WHERE id=? AND deleted_at IS NULL").get(batchId);
  if(!batch) return res.status(404).json({ok:false,error:"Lote nÃ£o encontrado"});
  const archive = db.transaction(() => {
    const removed = db.prepare("DELETE FROM vouchers WHERE batch_id=? AND status='unused'").run(batchId);
    const redeemed = db.prepare("SELECT COUNT(*) AS count FROM vouchers WHERE batch_id=? AND status='redeemed'").get(batchId).count;
    db.prepare("UPDATE voucher_batches SET active=0,deleted_at=?,print_data_encrypted=NULL WHERE id=?").run(nowIso(),batchId);
    return {removed:Number(removed.changes || 0),preserved:Number(redeemed || 0)};
  });
  const result = archive();
  res.json({ok:true,...result});
});


// ============================================================
// LISTAR PLANOS DO EVENTO
//
// GET
// /admin/api/events/:eventId/plans
// ============================================================

app.get(
  "/admin/api/events/:eventId/plans",
  adminAuth,
  (req, res) => {

    try{

      const eventId =
        positiveId(
          req.params.eventId
        );


      if(
        !eventId
        ||
        !getEventById(
          eventId
        )
      ){

        return res
          .status(
            404
          )
          .json({

            ok:false,

            error:
              "Evento nÃ£o encontrado"

          });

      }


      const plans =
        db.prepare(`

          SELECT *

          FROM event_plans

          WHERE
            event_id=?
            AND deleted_at IS NULL

          ORDER BY
            sort_order ASC,
            id ASC

        `).all(
          eventId
        );


      return res.json({

        ok:
          true,

        count:
          plans.length,

        plans:
          plans

      });

    }


    catch(error){

      console.error(
        "Erro ao listar planos:",
        error
      );


      return res
        .status(
          500
        )
        .json({

          ok:false,

          error:
            "Erro ao listar planos"

        });

    }

  }
);


// ============================================================
// CRIAR PLANO
//
// POST
// /admin/api/events/:eventId/plans
// ============================================================

app.post(
  "/admin/api/events/:eventId/plans",
  adminAuth,
  (req, res) => {

    try{

      const eventId =
        positiveId(
          req.params.eventId
        );


      if(
        !eventId
        ||
        !getEventById(
          eventId
        )
      ){

        return res
          .status(
            404
          )
          .json({

            ok:false,

            error:
              "Evento nÃ£o encontrado"

          });

      }


      const name =
        String(
          req.body?.name || ""
        )
          .trim()
          .slice(
            0,
            100
          );


      const amount =
        Number(
          req.body?.amount
        );


      const minutes =
        Number(
          req.body?.minutes
        );


      if(
        !name
        ||
        !Number.isFinite(
          amount
        )
        ||
        amount < 0
        ||
        !Number.isInteger(
          minutes
        )
        ||
        minutes <= 0
      ){

        return res
          .status(
            400
          )
          .json({

            ok:false,

            error:
              "Dados do plano invÃ¡lidos"

          });

      }


      let planKey =
        makeKey(
          req.body?.plan_key ||
          name
        );


      const existing =
        db.prepare(`

          SELECT id

          FROM event_plans

          WHERE
            event_id=?
            AND
            plan_key=?

          LIMIT 1

        `).get(
          eventId,
          planKey
        );


      if(
        existing
      ){

        planKey =
          planKey

          +

          "-"

          +

          crypto
            .randomBytes(
              2
            )
            .toString(
              "hex"
            );

      }


      const rateLimit =
        String(
          req.body?.rate_limit ||
          "10M/10M"
        )
          .trim()
          .slice(
            0,
            50
          );


      const profile =
        String(
          req.body?.mikrotik_profile ||
          (
            "PLANO-"

            +

            planKey
              .toUpperCase()
          )
        )
          .trim()
          .slice(
            0,
            80
          );


      const now =
        nowIso();

      const subtitle =
        String(req.body?.subtitle || "")
          .trim()
          .slice(0, 120);

      const highlight =
        ["popular", "fastest"].includes(String(req.body?.highlight || ""))
          ? String(req.body.highlight)
          : "";

      const createdPlan = db.transaction(() => {
        const result = db.prepare(`
          INSERT INTO event_plans (
            event_id, plan_key, name, amount, minutes, rate_limit,
            mikrotik_profile, description, subtitle, highlight,
            sort_order, active, created_at, updated_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).run(
          eventId,
          planKey,
          name,
          amount,
          minutes,
          rateLimit,
          profile,
          String(req.body?.description || "").trim().slice(0, 300),
          subtitle,
          highlight,
          Number.isInteger(Number(req.body?.sort_order)) ? Number(req.body.sort_order) : 0,
          1,
          now,
          now
        );

        if(highlight){
          db.prepare(`
            UPDATE event_plans SET highlight=''
            WHERE event_id=? AND id<>? AND highlight=?
          `).run(eventId, result.lastInsertRowid, highlight);
        }

        return result;
      });

      const result = createdPlan();


      queuePlanSync(
        eventId,
        "UPSERT",
        profile,
        rateLimit
      );


      return res
        .status(
          201
        )
        .json({

          ok:
            true,

          plan:
            db.prepare(`

              SELECT *

              FROM event_plans

              WHERE id=?

            `).get(
              result.lastInsertRowid
            )

        });

    }


    catch(error){

      console.error(
        "Erro ao criar plano:",
        error
      );


      return res
        .status(
          500
        )
        .json({

          ok:false,

          error:
            "Erro ao criar plano"

        });

    }

  }
);


// ============================================================
// EDITAR PLANO
//
// PUT
// /admin/api/plans/:planId
// ============================================================

app.put(
  "/admin/api/plans/:planId",
  adminAuth,
  (req, res) => {

    try{

      const planId =
        positiveId(
          req.params.planId
        );


      const plan =
        planId
          ? db.prepare(`

              SELECT *

              FROM event_plans

              WHERE id=?

            `).get(
              planId
            )
          : null;


      if(
        !plan
      ){

        return res
          .status(
            404
          )
          .json({

            ok:false,

            error:
              "Plano nÃ£o encontrado"

          });

      }


      const amount =
        req.body?.amount ===
        undefined
          ? Number(
              plan.amount
            )
          : Number(
              req.body.amount
            );


      const minutes =
        req.body?.minutes ===
        undefined
          ? Number(
              plan.minutes
            )
          : Number(
              req.body.minutes
            );


      if(
        !Number.isFinite(
          amount
        )
        ||
        amount < 0
        ||
        !Number.isInteger(
          minutes
        )
        ||
        minutes <= 0
      ){

        return res
          .status(
            400
          )
          .json({

            ok:false,

            error:
              "Valor ou tempo invÃ¡lido"

          });

      }


      const active =
        req.body?.active ===
        false
        ||
        req.body?.active ===
        0
        ||
        req.body?.active ===
        "0"
          ? 0
          : 1;

      const subtitle =
        req.body?.subtitle === undefined
          ? String(plan.subtitle || "")
          : String(req.body.subtitle || "").trim().slice(0, 120);

      const highlight =
        req.body?.highlight === undefined
          ? String(plan.highlight || "")
          : ["popular", "fastest"].includes(String(req.body.highlight || ""))
            ? String(req.body.highlight)
            : "";


      db.prepare(`

        UPDATE event_plans

        SET

          name=?,

          amount=?,

          minutes=?,

          rate_limit=?,

          mikrotik_profile=?,

          description=?,

          subtitle=?,

          highlight=?,

          sort_order=?,

          active=?,

          updated_at=?

        WHERE id=?

      `).run(

        String(
          req.body?.name ??
          plan.name
        )
          .trim()
          .slice(
            0,
            100
          ),

        amount,

        minutes,

        String(
          req.body?.rate_limit ??
          plan.rate_limit
        )
          .trim()
          .slice(
            0,
            50
          ),

        String(
          req.body?.mikrotik_profile ??
          plan.mikrotik_profile
        )
          .trim()
          .slice(
            0,
            80
          ),

        String(
          req.body?.description ??
          plan.description ??
          ""
        )
          .trim()
          .slice(
            0,
            300
          ),

        subtitle,

        highlight,

        Number.isInteger(
          Number(
            req.body?.sort_order
          )
        )
          ? Number(
              req.body.sort_order
            )
          : Number(
              plan.sort_order || 0
            ),

        active,

        nowIso(),

        planId

      );

      if(highlight){
        db.prepare(`
          UPDATE event_plans SET highlight=''
          WHERE event_id=? AND id<>? AND highlight=?
        `).run(plan.event_id, planId, highlight);
      }


      const updatedPlan =
        db.prepare(`

          SELECT *

          FROM event_plans

          WHERE id=?

        `).get(
          planId
        );


      if(
        Number(updatedPlan.active) === 1
      ){

        queuePlanSync(
          updatedPlan.event_id,
          "UPSERT",
          updatedPlan.mikrotik_profile,
          updatedPlan.rate_limit
        );

      }


      return res.json({
        ok:true,
        plan:updatedPlan
      });

    }


    catch(error){

      console.error(
        "Erro ao editar plano:",
        error
      );


      return res
        .status(
          500
        )
        .json({

          ok:false,

          error:
            "Erro ao editar plano"

        });

    }

  }
);
// ============================================================
// EXCLUIR PLANO
//
// DELETE
// /admin/api/plans/:planId
//
// A exclusao e logica para preservar historico financeiro.
// O perfil e removido da MikroTik somente quando nao existe
// cliente PIX ativo usando o plano.
// ============================================================

app.delete(
  "/admin/api/plans/:planId",
  adminAuth,
  (req, res) => {

    try{

      const planId =
        positiveId(
          req.params.planId
        );


      const plan =
        planId
          ? db.prepare(`

              SELECT *

              FROM event_plans

              WHERE
                id=?
                AND deleted_at IS NULL

              LIMIT 1

            `).get(
              planId
            )
          : null;


      if(
        !plan
      ){

        return res
          .status(404)
          .json({
            ok:false,
            error:"Plano nÃ£o encontrado"
          });

      }


      const now =
        nowIso();


      const activePaid =
        db.prepare(`

          SELECT COUNT(*) AS total

          FROM orders

          WHERE
            event_id=?
            AND plan_id=?
            AND (
              status='approved_pending_router'
              OR (
                status='approved'
                AND access_expires_at IS NOT NULL
                AND access_expired_at IS NULL
                AND access_expires_at > ?
              )
            )

        `).get(
          plan.event_id,
          plan.plan_key,
          now
        );


      if(
        Number(
          activePaid?.total || 0
        ) > 0
      ){

        return res
          .status(409)
          .json({
            ok:false,
            error:
              "Este plano possui cliente PIX ainda ativo. Aguarde o acesso terminar ou encerre o acesso antes de excluir o plano."
          });

      }


      db.prepare(`

        UPDATE event_plans

        SET
          active=0,
          deleted_at=?,
          updated_at=?

        WHERE id=?

      `).run(
        now,
        now,
        planId
      );


      const profileStillUsed = db.prepare(`
        SELECT 1 FROM event_plans
        WHERE event_id=? AND mikrotik_profile=? AND active=1 AND deleted_at IS NULL
        LIMIT 1
      `).get(plan.event_id, plan.mikrotik_profile);

      if(!profileStillUsed){
        queuePlanSync(
          plan.event_id,
          "DELETE",
          plan.mikrotik_profile,
          ""
        );
      }


      return res.json({
        ok:true,
        deleted:true,
        plan_id:planId,
        profile:plan.mikrotik_profile,
        profile_still_used:Boolean(profileStillUsed)
      });

    }

    catch(error){

      console.error(
        "Erro ao excluir plano:",
        error
      );


      return res
        .status(500)
        .json({
          ok:false,
          error:"Erro ao excluir plano"
        });

    }

  }
);

app.post("/admin/api/events/:eventId/plans/reconcile-deleted", adminAuth, (req,res) => {
  const eventId = positiveId(req.params.eventId);
  if(!eventId || !getEventById(eventId)){
    return res.status(404).json({ok:false,error:"Evento nÃ£o encontrado"});
  }

  const deletedProfiles = db.prepare(`
    SELECT DISTINCT old_plan.mikrotik_profile AS profile
    FROM event_plans old_plan
    WHERE old_plan.event_id=?
      AND old_plan.deleted_at IS NOT NULL
      AND old_plan.mikrotik_profile<>''
      AND NOT EXISTS (
        SELECT 1 FROM event_plans active_plan
        WHERE active_plan.event_id=old_plan.event_id
          AND active_plan.mikrotik_profile=old_plan.mikrotik_profile
          AND active_plan.active=1
          AND active_plan.deleted_at IS NULL
      )
      AND NOT EXISTS (
        SELECT 1 FROM orders o
        JOIN event_plans used_plan ON used_plan.event_id=o.event_id AND used_plan.plan_key=o.plan_id
        WHERE o.event_id=old_plan.event_id
          AND used_plan.mikrotik_profile=old_plan.mikrotik_profile
          AND used_plan.deleted_at IS NOT NULL
          AND (
            o.status='approved_pending_router'
            OR (o.status='approved' AND o.access_expires_at IS NOT NULL
              AND o.access_expired_at IS NULL AND o.access_expires_at>?)
          )
      )
  `).all(eventId, nowIso());

  let queued = 0;
  for(const row of deletedProfiles){
    if(queuePlanSync(eventId,"DELETE",row.profile,"")) queued++;
  }

  res.json({ok:true,profiles:deletedProfiles.length,queued});
});


// ============================================================
// APAGAR EVENTO COMPLETO
//
// DELETE
// /admin/api/events/:eventId
//
// Remove de forma transacional:
// - liberaÃ§Ãµes da MikroTik
// - pedidos
// - planos
// - portas
// - MikroTik
// - evento
//
// O evento padrÃ£o/principal fica protegido.
// ============================================================

app.delete(
  "/admin/api/events/:eventId",
  adminAuth,
  (req, res) => {

    try {

      const eventId =
        positiveId(
          req.params.eventId
        );


      if(
        !eventId
      ){

        return res
          .status(400)
          .json({
            ok:false,
            error:"ID do evento invÃ¡lido"
          });

      }


      const event =
        db.prepare(`

          SELECT *

          FROM events

          WHERE id=?

          LIMIT 1

        `).get(
          eventId
        );


      if(
        !event
      ){

        return res
          .status(404)
          .json({
            ok:false,
            error:"Evento nÃ£o encontrado"
          });

      }


      // ========================================================
      // PROTEGER O EVENTO PRINCIPAL
      // ========================================================

      if(
        Number(eventId) ===
        Number(DEFAULT_EVENT.id)
      ){

        return res
          .status(409)
          .json({
            ok:false,
            error:
              "O evento principal do sistema nÃ£o pode ser apagado. Desative-o se necessÃ¡rio."
          });

      }


      // ========================================================
      // EXCLUSÃƒO ATÃ”MICA
      // ========================================================

      const removeEvent =
        db.transaction(
          () => {

            // Grants dependem de orders/routers/event.
            db.prepare(
              "DELETE FROM router_access_grants WHERE event_id=?"
            ).run(
              eventId
            );


            // Pedidos sÃ£o histÃ³rico financeiro do evento.
            // Como o usuÃ¡rio confirmou APAGAR, removemos tambÃ©m
            // estes registros para nÃ£o deixar dados Ã³rfÃ£os.
            db.prepare(
              "DELETE FROM orders WHERE event_id=?"
            ).run(
              eventId
            );


            db.prepare(
              "DELETE FROM event_plans WHERE event_id=?"
            ).run(
              eventId
            );


            const routers =
              db.prepare(`

                SELECT id

                FROM routers

                WHERE event_id=?

              `).all(
                eventId
              );


            for(
              const router
              of routers
            ){

              db.prepare(
                "DELETE FROM router_ports WHERE router_id=?"
              ).run(
                router.id
              );


              // Monitoramento V2, se jÃ¡ estiver instalado.
              try{
                db.prepare(
                  "DELETE FROM router_monitor_events WHERE router_id=?"
                ).run(
                  router.id
                );
              }
              catch(error){
              }


              try{
                db.prepare(
                  "DELETE FROM router_monitor_status WHERE router_id=?"
                ).run(
                  router.id
                );
              }
              catch(error){
              }

            }


            db.prepare(
              "DELETE FROM routers WHERE event_id=?"
            ).run(
              eventId
            );


            db.prepare(
              "DELETE FROM events WHERE id=?"
            ).run(
              eventId
            );

          }
        );


      removeEvent();


      console.log(
        "EVENTO APAGADO:",
        eventId,
        event.event_key,
        event.name
      );


      return res.json({
        ok:true,
        deleted:true,
        event_id:eventId,
        event_key:event.event_key,
        name:event.name
      });

    }
    catch(error){

      console.error(
        "Erro ao apagar evento:",
        error
      );


      return res
        .status(500)
        .json({
          ok:false,
          error:"Erro ao apagar evento"
        });

    }

  }
);
// ============================================================
// MONITORAMENTO V2 - MIKROTIK POR EVENTO
//
// IMPORTANTE:
// O estado da MIKROTIK Ã© separado do estado dos LINKS.
//
// router_online:
//   true  = a MikroTik enviou heartbeat recentemente.
//   false = o backend nÃ£o recebe heartbeat recente.
//
// primary_status:
//   estado do link principal.
//
// secondary_status:
//   estado do link secundÃ¡rio.
//
// Cada MikroTik usa seu prÃ³prio:
// - router_key
// - token
// - event_id
//
// Isso elimina o status global antigo id=1.
// ============================================================


// ============================================================
// TABELA - ESTADO ATUAL POR MIKROTIK
// ============================================================

db.exec(`

  CREATE TABLE IF NOT EXISTS router_monitor_status (

    router_id INTEGER PRIMARY KEY,

    event_id INTEGER NOT NULL,

    primary_status TEXT NOT NULL DEFAULT 'unknown',

    secondary_status TEXT NOT NULL DEFAULT 'unknown',

    active_link TEXT NOT NULL DEFAULT 'unknown',

    failover_status TEXT NOT NULL DEFAULT 'unknown',

    primary_ping TEXT,

    secondary_ping TEXT,

    active_clients INTEGER NOT NULL DEFAULT 0,

    active_macs TEXT,

    hotspot_macs TEXT,

    last_report_at TEXT,

    updated_at TEXT NOT NULL,

    FOREIGN KEY(router_id)
      REFERENCES routers(id)
      ON DELETE CASCADE,

    FOREIGN KEY(event_id)
      REFERENCES events(id)
      ON DELETE CASCADE

  );

`);


// ============================================================
// MIGRAÃ‡ÃƒO - CLIENTES HOTSPOT ATIVOS
// ============================================================

try{

  const monitorColumns =
    db.prepare(
      "PRAGMA table_info(router_monitor_status)"
    ).all();

  const hasActiveClients =
    monitorColumns.some(
      column =>
        column.name === "active_clients"
    );

  if(!hasActiveClients){

    db.exec(`
      ALTER TABLE router_monitor_status
      ADD COLUMN active_clients INTEGER NOT NULL DEFAULT 0;
    `);

    console.log(
      "Banco atualizado: router_monitor_status.active_clients"
    );

  }

}catch(error){

  console.error(
    "Erro ao migrar active_clients:",
    error
  );

}


// ============================================================
// MIGRAÃ‡ÃƒO - MACS ONLINE
// ============================================================

try{

  const monitorColumnsMacs =
    db.prepare(
      "PRAGMA table_info(router_monitor_status)"
    ).all();

  const hasActiveMacs =
    monitorColumnsMacs.some(
      column =>
        column.name === "active_macs"
    );

  if(!hasActiveMacs){

    db.exec(`
      ALTER TABLE router_monitor_status
      ADD COLUMN active_macs TEXT;
    `);

    console.log(
      "Banco atualizado: router_monitor_status.active_macs"
    );

  }

}catch(error){

  console.error(
    "Erro ao migrar active_macs:",
    error
  );

}



// ============================================================
// V15 - MIGRACAO - MACS DETECTADOS EM /IP HOTSPOT HOST
// ============================================================

try{
  const columns =
    db.prepare(
      "PRAGMA table_info(router_monitor_status)"
    ).all();

  const exists =
    columns.some(
      column =>
        column.name === "hotspot_macs"
    );

  if(!exists){
    db.exec(`
      ALTER TABLE router_monitor_status
      ADD COLUMN hotspot_macs TEXT;
    `);
    console.log(
      "Banco atualizado: router_monitor_status.hotspot_macs"
    );
  }
}
catch(error){
  console.error(
    "Erro ao migrar hotspot_macs:",
    error
  );
}


// ============================================================
// TABELA - HISTÃ“RICO DO MONITOR POR MIKROTIK
// ============================================================

db.exec(`

  CREATE TABLE IF NOT EXISTS router_monitor_events (

    id INTEGER PRIMARY KEY AUTOINCREMENT,

    router_id INTEGER NOT NULL,

    event_id INTEGER NOT NULL,

    event_type TEXT NOT NULL,

    previous_active_link TEXT,

    new_active_link TEXT,

    previous_primary_status TEXT,

    new_primary_status TEXT,

    previous_secondary_status TEXT,

    new_secondary_status TEXT,

    created_at TEXT NOT NULL,

    FOREIGN KEY(router_id)
      REFERENCES routers(id)
      ON DELETE CASCADE,

    FOREIGN KEY(event_id)
      REFERENCES events(id)
      ON DELETE CASCADE

  );

`);


db.exec(`

  CREATE INDEX IF NOT EXISTS idx_router_monitor_event
  ON router_monitor_status(event_id);

  CREATE INDEX IF NOT EXISTS idx_router_monitor_events_router
  ON router_monitor_events(router_id, created_at);

`);


// ============================================================
// NORMALIZAR STATUS DOS LINKS DO MONITOR V2
// ============================================================

function normalizeMonitorLinkStatus(
  value
){

  const status =
    String(
      value || ""
    )
      .trim()
      .toLowerCase();


  if(
    [
      "online",
      "offline",
      "standby",
      "unknown"
    ].includes(
      status
    )
  ){

    return status;

  }


  return "unknown";

}


// ============================================================
// NORMALIZAR LINK ATIVO DO MONITOR V2
//
// PADRÃƒO INTERNO:
// primary / secondary / none / unknown
//
// COMPATIBILIDADE COM O PAINEL:
// provider -> primary
// starlink -> secondary
// ============================================================

function normalizeMonitorActiveLink(
  value
){

  const active =
    String(
      value || ""
    )
      .trim()
      .toLowerCase();


  // Aceita tambÃ©m os nomes usados pelo painel antigo,
  // mas grava internamente no padrÃ£o V2.
  if(
    active ===
    "provider"
  ){

    return "primary";

  }


  if(
    active ===
    "starlink"
  ){

    return "secondary";

  }


  if(
    [
      "primary",
      "secondary",
      "none",
      "unknown"
    ].includes(
      active
    )
  ){

    return active;

  }


  return "unknown";

}


// ============================================================
// REGISTRAR MUDANÃ‡AS IMPORTANTES
// ============================================================

function insertRouterMonitorEvent(
  router,
  previous,
  current,
  eventType,
  createdAt
){

  db.prepare(`

    INSERT INTO router_monitor_events (

      router_id,
      event_id,
      event_type,
      previous_active_link,
      new_active_link,
      previous_primary_status,
      new_primary_status,
      previous_secondary_status,
      new_secondary_status,
      created_at

    )

    VALUES (
      ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
    )

  `).run(

    router.id,
    router.event_id,
    eventType,

    previous.active_link ||
      "unknown",

    current.active_link ||
      "unknown",

    previous.primary_status ||
      "unknown",

    current.primary_status ||
      "unknown",

    previous.secondary_status ||
      "unknown",

    current.secondary_status ||
      "unknown",

    createdAt

  );

}


function registerRouterMonitorChange(
  router,
  previous,
  current,
  createdAt
){

  if(
    !previous
  ){

    return;

  }


  const eventTypes =
    [];


  // ==========================================================
  // MUDANÃ‡A DO PROVEDOR PRINCIPAL
  // ==========================================================

  if(
    previous.primary_status !==
    current.primary_status
  ){

    eventTypes.push(

      current.primary_status ===
      "online"
        ? "primary_up"
        : "primary_down"

    );

  }


  // ==========================================================
  // MUDANÃ‡A DO LINK SECUNDÃRIO
  // ==========================================================

  if(
    previous.secondary_status !==
    current.secondary_status
  ){

    if(
      current.secondary_status ===
      "online"
    ){

      eventTypes.push(
        "secondary_up"
      );

    }
    else if(
      current.secondary_status ===
      "offline"
    ){

      eventTypes.push(
        "secondary_down"
      );

    }

  }


  // ==========================================================
  // TROCA DO LINK ATIVO
  // ==========================================================

  if(
    previous.active_link !==
    current.active_link
  ){

    if(
      current.active_link ===
      "secondary"
    ){

      eventTypes.push(
        "failover_to_secondary"
      );

    }
    else if(
      current.active_link ===
      "primary"
    ){

      eventTypes.push(
        "failback_to_primary"
      );

    }
    else if(
      current.active_link ===
      "none"
    ){

      eventTypes.push(
        "internet_down"
      );

    }

  }


  for(
    const eventType
    of eventTypes
  ){

    insertRouterMonitorEvent(

      router,
      previous,
      current,
      eventType,
      createdAt

    );

  }

}


// ============================================================
// V16 - HEARTBEAT LEVE + PRESENCA SEPARADA
//
// Objetivo:
// - manter monitor de WAN/MikroTik rapido (5s)
// - reduzir varredura pesada dos clientes (20s)
// - nao apagar listas de MAC quando o heartbeat leve chegar
//
// ENDPOINT 1:
// /api/mikrotik/heartbeat
//   Status WAN/MK + quantidade de ativos.
//   Nao precisa enviar listas de MAC.
//
// ENDPOINT 2:
// /api/mikrotik/presence
//   active_macs + hotspot_macs.
//   Alimenta o funil e a presenca real dos clientes.
// ============================================================


function parseHeartbeatActiveClients(
  req,
  fallback = 0
){

  const raw =
    req.query.active_clients
    ??
    req.body?.active_clients;

  if(
    raw === undefined
    ||
    raw === null
    ||
    raw === ""
  ){
    return Math.max(
      0,
      Number(
        fallback || 0
      )
    );
  }


  return Math.max(
    0,
    Math.min(
      100000,
      Math.floor(
        Number(raw)
        ||
        0
      )
    )
  );

}


function parseHeartbeatMacList(
  value
){

  return Array.from(
    new Set(
      String(
        value || ""
      )
        .split(",")
        .map(
          item =>
            normalizeMac(
              item
            )
        )
        .filter(Boolean)
    )
  )
    .slice(
      0,
      500
    );

}


// ============================================================
// HEARTBEAT LEVE - WAN / MIKROTIK
// ============================================================

function updateRouterHeartbeat(
  req,
  res
){

  const auth =
    authenticateMikrotik(
      req
    );


  if(
    !auth?.ok
    ||
    auth.mode !==
      "router"
    ||
    !auth.router
  ){

    return res
      .status(401)
      .type("text/plain")
      .send("UNAUTHORIZED");

  }


  try{

    const router =
      auth.router;


    const previous =
      db.prepare(`

        SELECT *

        FROM router_monitor_status

        WHERE router_id=?

        LIMIT 1

      `).get(
        router.id
      ) || null;


    const primaryStatus =
      normalizeMonitorLinkStatus(

        req.query.primary
        ||
        req.body?.primary
        ||
        "unknown"

      );


    const secondaryStatus =
      normalizeMonitorLinkStatus(

        req.query.secondary
        ||
        req.body?.secondary
        ||
        "unknown"

      );


    const activeLink =
      normalizeMonitorActiveLink(

        req.query.active
        ||
        req.body?.active
        ||
        "unknown"

      );


    const failoverStatus =
      String(
        req.query.failover
        ||
        req.body?.failover
        ||
        "automatic"
      )
        .trim()
        .slice(
          0,
          50
        );


    const primaryPing =
      safeText(
        req.query.primary_ping
        ||
        req.body?.primary_ping
        ||
        ""
      );


    const secondaryPing =
      safeText(
        req.query.secondary_ping
        ||
        req.body?.secondary_ping
        ||
        ""
      );


    const activeClients =
      parseHeartbeatActiveClients(
        req,
        previous?.active_clients || 0
      );


    // V16:
    // o heartbeat leve NAO substitui as listas de presenca.
    // Ele conserva a ultima leitura enviada pelo endpoint /presence.
    const previousActiveMacs =
      String(
        previous?.active_macs || ""
      );

    const previousHotspotMacs =
      String(
        previous?.hotspot_macs || ""
      );


    const now =
      nowIso();


    const current = {

      primary_status:
        primaryStatus,

      secondary_status:
        secondaryStatus,

      active_link:
        activeLink,

      failover_status:
        failoverStatus,

      primary_ping:
        primaryPing || null,

      secondary_ping:
        secondaryPing || null,

      active_clients:
        activeClients,

      active_macs:
        previousActiveMacs,

      hotspot_macs:
        previousHotspotMacs,

      last_report_at:
        now,

      updated_at:
        now

    };


    registerRouterMonitorChange(
      router,
      previous,
      current,
      now
    );


    db.prepare(`

      INSERT INTO router_monitor_status (

        router_id,
        event_id,
        primary_status,
        secondary_status,
        active_link,
        failover_status,
        primary_ping,
        secondary_ping,
        active_clients,
        active_macs,
        hotspot_macs,
        last_report_at,
        updated_at

      )

      VALUES (
        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
      )

      ON CONFLICT(router_id)
      DO UPDATE SET

        event_id=excluded.event_id,
        primary_status=excluded.primary_status,
        secondary_status=excluded.secondary_status,
        active_link=excluded.active_link,
        failover_status=excluded.failover_status,
        primary_ping=excluded.primary_ping,
        secondary_ping=excluded.secondary_ping,
        active_clients=excluded.active_clients,
        last_report_at=excluded.last_report_at,
        updated_at=excluded.updated_at

    `).run(

      router.id,
      router.event_id,
      primaryStatus,
      secondaryStatus,
      activeLink,
      failoverStatus,
      primaryPing || null,
      secondaryPing || null,
      activeClients,
      previousActiveMacs,
      previousHotspotMacs,
      now,
      now

    );


    return res
      .type("text/plain")
      .send("OK");

  }
  catch(error){

    console.error(
      "Erro heartbeat MikroTik V16:",
      error
    );


    return res
      .status(500)
      .type("text/plain")
      .send("ERROR");

  }

}


app.get(
  "/api/mikrotik/heartbeat",
  updateRouterHeartbeat
);


app.post(
  "/api/mikrotik/heartbeat",
  updateRouterHeartbeat
);


// ============================================================
// PRESENCA V16 - CLIENTES / FUNIL
//
// Recomendacao do script MikroTik:
// intervalo=20s
//
// IMPORTANTE:
// este endpoint NAO atualiza last_report_at.
// Assim a saude da MikroTik continua dependendo do heartbeat leve.
// ============================================================

function updateRouterPresence(
  req,
  res
){

  const auth =
    authenticateMikrotik(
      req
    );


  if(
    !auth?.ok
    ||
    auth.mode !==
      "router"
    ||
    !auth.router
  ){

    return res
      .status(401)
      .type("text/plain")
      .send("UNAUTHORIZED");

  }


  try{

    const router =
      auth.router;


    const activeMacs =
      parseHeartbeatMacList(
        req.query.active_macs
        ??
        req.body?.active_macs
        ??
        ""
      );


    const hotspotMacs =
      parseHeartbeatMacList(
        req.query.hotspot_macs
        ??
        req.body?.hotspot_macs
        ??
        ""
      );


    const activeClients =
      Math.max(
        parseHeartbeatActiveClients(
          req,
          activeMacs.length
        ),
        activeMacs.length
      );


    const now =
      nowIso();


    db.prepare(`

      INSERT INTO router_monitor_status (

        router_id,
        event_id,
        primary_status,
        secondary_status,
        active_link,
        failover_status,
        primary_ping,
        secondary_ping,
        active_clients,
        active_macs,
        hotspot_macs,
        last_report_at,
        updated_at

      )

      VALUES (
        ?, ?, 'unknown', 'unknown', 'unknown', 'automatic',
        NULL, NULL, ?, ?, ?, NULL, ?
      )

      ON CONFLICT(router_id)
      DO UPDATE SET

        event_id=excluded.event_id,
        active_clients=excluded.active_clients,
        active_macs=excluded.active_macs,
        hotspot_macs=excluded.hotspot_macs,
        updated_at=excluded.updated_at

    `).run(

      router.id,
      router.event_id,
      activeClients,
      activeMacs.join(","),
      hotspotMacs.join(","),
      now

    );


    processFunnelPresenceForRouter(
      router,
      hotspotMacs,
      activeMacs,
      now
    );


    return res
      .type("text/plain")
      .send("OK");

  }
  catch(error){

    console.error(
      "Erro presenca MikroTik V16:",
      error
    );


    return res
      .status(500)
      .type("text/plain")
      .send("ERROR");

  }

}


app.get(
  "/api/mikrotik/presence",
  updateRouterPresence
);


app.post(
  "/api/mikrotik/presence",
  updateRouterPresence
);


// ============================================================
// ============================================================
// MONTAR RESPOSTA DO MONITOR DE UMA MIKROTIK
//
// A MikroTik Ã© considerada comunicando/online se recebeu
// heartbeat nos Ãºltimos 20 segundos.
//
// OBSERVAÃ‡ÃƒO:
// Se todos os links de Internet da MikroTik caÃ­rem, ela tambÃ©m
// deixa de conseguir alcanÃ§ar o Railway. Portanto "offline"
// significa "sem comunicaÃ§Ã£o com o backend". Isso nÃ£o permite
// distinguir energia desligada de ausÃªncia total de Internet.
// ============================================================

function getRouterMonitorSnapshot(
  router
){

  const monitor =
    db.prepare(`

      SELECT *

      FROM router_monitor_status

      WHERE router_id=?

      LIMIT 1

    `).get(
      router.id
    ) || null;


  let ageSeconds =
    null;


  if(
    monitor?.last_report_at
  ){

    const lastMs =
      Date.parse(
        monitor.last_report_at
      );


    if(
      Number.isFinite(
        lastMs
      )
    ){

      ageSeconds =
        Math.max(
          0,
          Math.floor(
            (
              Date.now() -
              lastMs
            )
            /
            1000
          )
        );

    }

  }


  const routerOnline =
    ageSeconds !== null
    &&
    ageSeconds <= 20;


  const failoverEnabled =
    Number(
      router.failover_enabled || 0
    ) === 1;


  return {

    router_id:
      router.id,

    event_id:
      router.event_id,

    router_key:
      router.router_key,

    router_name:
      router.name,

    router_identity:
      router.identity,

    router_online:
      routerOnline,

    communication_status:
      routerOnline
        ? "online"
        : "offline",

    age_seconds:
      ageSeconds,

    stale:
      !routerOnline,

    last_report_at:
      monitor?.last_report_at || null,

    active_clients:
      routerOnline
        ? Math.max(
            0,
            Number(
              monitor?.active_clients || 0
            )
          )
        : 0,

    active_macs:
      routerOnline
        ? Array.from(
            new Set(
              String(
                monitor?.active_macs || ""
              )
                .split(",")
                .map(
                  value =>
                    normalizeMac(
                      value
                    )
                )
                .filter(
                  Boolean
                )
            )
          )
        : [],

    hotspot_macs:
      routerOnline
        ? Array.from(
            new Set(
              String(
                monitor?.hotspot_macs || ""
              )
                .split(",")
                .map(
                  value =>
                    normalizeMac(value)
                )
                .filter(Boolean)
            )
          )
        : [],

    failover_enabled:
      failoverEnabled,

    primary_status:
      routerOnline
        ? (
            monitor?.primary_status ||
            "unknown"
          )
        : "unknown",

    secondary_status:
      routerOnline
        ? (
            monitor?.secondary_status ||
            (
              failoverEnabled
                ? "unknown"
                : "disabled"
            )
          )
        : (
            failoverEnabled
              ? "unknown"
              : "disabled"
          ),

    // O banco V2 usa primary/secondary.
    // A resposta administrativa usa provider/starlink,
    // que Ã© o formato esperado pelo painel atual.
    active_link:
      !routerOnline
        ? "unknown"
        : (
            monitor?.active_link ===
            "primary"
              ? "provider"
              : (
                  monitor?.active_link ===
                  "secondary"
                    ? "starlink"
                    : (
                        monitor?.active_link ||
                        "unknown"
                      )
                )
          ),

    failover_status:
      routerOnline
        ? (
            monitor?.failover_status ||
            "unknown"
          )
        : "unknown",

    primary_ping:
      routerOnline
        ? (
            monitor?.primary_ping ||
            null
          )
        : null,

    secondary_ping:
      routerOnline
        ? (
            monitor?.secondary_ping ||
            null
          )
        : null,

    // ========================================================
    // ALIASES PARA O ADMIN.HTML ATUAL
    //
    // MantÃªm o renderizador existente funcionando:
    // provider  = link principal
    // starlink  = link secundÃ¡rio
    // ========================================================

    provider_status:
      routerOnline
        ? (
            monitor?.primary_status ||
            "unknown"
          )
        : "unknown",

    starlink_status:
      routerOnline
        ? (
            monitor?.secondary_status ||
            (
              failoverEnabled
                ? "unknown"
                : "standby"
            )
          )
        : "unknown",

    provider_ping:
      routerOnline
        ? (
            monitor?.primary_ping ||
            null
          )
        : null,

    starlink_ping:
      routerOnline
        ? (
            monitor?.secondary_ping ||
            null
          )
        : null,

    // aliases de link ativo para o layout antigo
    active_link_legacy:
      !routerOnline
        ? "unknown"
        : (
            monitor?.active_link ===
            "primary"
              ? "provider"
              : (
                  monitor?.active_link ===
                  "secondary"
                    ? "starlink"
                    : (
                        monitor?.active_link ||
                        "unknown"
                      )
                )
          )

  };

}


// ============================================================
// LIMITE DO HISTÃ“RICO V2
// ============================================================

function routerMonitorHistoryLimit(
  value
){

  const limit =
    Number(
      value
    );


  if(
    !Number.isInteger(
      limit
    )
  ){

    return 50;

  }


  return Math.max(

    1,

    Math.min(
      limit,
      200
    )

  );

}


// ============================================================
// TEMPO NO LINK SECUNDÃRIO HOJE
// ============================================================

function calculateRouterSecondarySecondsToday(
  routerId
){

  const dayStart =
    startOfTodayIso();


  const dayStartMs =
    Date.parse(
      dayStart
    );


  const nowMs =
    Date.now();


  const previousSwitch =
    db.prepare(`

      SELECT *

      FROM router_monitor_events

      WHERE
        router_id=?

        AND event_type IN (
          'failover_to_secondary',
          'failback_to_primary'
        )

        AND created_at < ?

      ORDER BY
        created_at DESC,
        id DESC

      LIMIT 1

    `).get(
      routerId,
      dayStart
    );


  let secondaryActive =
    Boolean(

      previousSwitch

      &&

      previousSwitch.event_type ===
      "failover_to_secondary"

    );


  let activeSinceMs =
    secondaryActive
      ? dayStartMs
      : null;


  let totalMs =
    0;


  const switches =
    db.prepare(`

      SELECT *

      FROM router_monitor_events

      WHERE
        router_id=?

        AND event_type IN (
          'failover_to_secondary',
          'failback_to_primary'
        )

        AND created_at >= ?

      ORDER BY
        created_at ASC,
        id ASC

    `).all(
      routerId,
      dayStart
    );


  for(
    const event
    of switches
  ){

    const eventMs =
      Date.parse(
        event.created_at
      );


    if(
      !Number.isFinite(
        eventMs
      )
    ){

      continue;

    }


    if(
      event.event_type ===
      "failover_to_secondary"

      &&

      !secondaryActive
    ){

      secondaryActive =
        true;


      activeSinceMs =
        Math.max(
          eventMs,
          dayStartMs
        );

    }


    if(
      event.event_type ===
      "failback_to_primary"

      &&

      secondaryActive

      &&

      activeSinceMs !== null
    ){

      totalMs +=
        Math.max(
          0,
          eventMs -
          activeSinceMs
        );


      secondaryActive =
        false;


      activeSinceMs =
        null;

    }

  }


  if(
    secondaryActive

    &&

    activeSinceMs !== null
  ){

    totalMs +=
      Math.max(
        0,
        nowMs -
        activeSinceMs
      );

  }


  return Math.floor(
    totalMs / 1000
  );

}


// ============================================================
// RESUMO DO FAILOVER V2 POR MIKROTIK
// ============================================================

function getRouterMonitorSummary(
  routerId
){

  const dayStart =
    startOfTodayIso();


  const dropsToday =
    db.prepare(`

      SELECT COUNT(*) AS total

      FROM router_monitor_events

      WHERE
        router_id=?
        AND event_type='primary_down'
        AND created_at >= ?

    `).get(
      routerId,
      dayStart
    );


  const lastSwitch =
    db.prepare(`

      SELECT *

      FROM router_monitor_events

      WHERE
        router_id=?

        AND event_type IN (
          'failover_to_secondary',
          'failback_to_primary'
        )

      ORDER BY
        created_at DESC,
        id DESC

      LIMIT 1

    `).get(
      routerId
    );


  return {

    provider_drops_today:
      Number(
        dropsToday?.total || 0
      ),

    last_switch_at:
      lastSwitch?.created_at ||
      null,

    last_switch_type:
      lastSwitch?.event_type ||
      null,

    starlink_seconds_today:
      calculateRouterSecondarySecondsToday(
        routerId
      )

  };

}


// ============================================================
// MONTAR HISTÃ“RICO V2 DE UMA MIKROTIK
// ============================================================

function getRouterMonitorHistory(
  router,
  limit
){

  const events =
    db.prepare(`

      SELECT
        id,
        router_id,
        event_id,
        event_type,
        previous_active_link,
        new_active_link,
        previous_primary_status,
        new_primary_status,
        previous_secondary_status,
        new_secondary_status,
        created_at

      FROM router_monitor_events

      WHERE router_id=?

      ORDER BY
        created_at DESC,
        id DESC

      LIMIT ?

    `).all(
      router.id,
      limit
    );


  return {

    count:
      events.length,

    events,

    summary:
      getRouterMonitorSummary(
        router.id
      )

  };

}


// ============================================================
// ADMIN - HISTÃ“RICO V2 DE UM EVENTO
// ============================================================

app.get(
  "/admin/api/events/:eventId/internet/history",
  adminAuth,
  (req, res) => {

    try{

      const eventId =
        positiveId(
          req.params.eventId
        );


      if(
        !eventId
      ){

        return res
          .status(400)
          .json({
            ok:false,
            error:"Evento invÃ¡lido"
          });

      }


      const event =
        db.prepare(`

          SELECT *

          FROM events

          WHERE id=?

          LIMIT 1

        `).get(
          eventId
        );


      if(
        !event
      ){

        return res
          .status(404)
          .json({
            ok:false,
            error:"Evento nÃ£o encontrado"
          });

      }


      const router =
        db.prepare(`

          SELECT *

          FROM routers

          WHERE
            event_id=?
            AND status='active'

          ORDER BY id ASC

          LIMIT 1

        `).get(
          eventId
        );


      if(
        !router
      ){

        return res.json({

          ok:true,

          event:{
            id:event.id,
            event_key:event.event_key,
            name:event.name
          },

          router:null,

          count:0,

          events:[],

          summary:{
            provider_drops_today:0,
            last_switch_at:null,
            last_switch_type:null,
            starlink_seconds_today:0
          }

        });

      }


      const data =
        getRouterMonitorHistory(

          router,

          routerMonitorHistoryLimit(
            req.query.limit
          )

        );


      return res.json({

        ok:true,

        event:{
          id:event.id,
          event_key:event.event_key,
          name:event.name
        },

        router_id:
          router.id,

        ...data

      });

    }
    catch(error){

      console.error(
        "Erro histÃ³rico V2 do evento:",
        error
      );


      return res
        .status(500)
        .json({
          ok:false,
          error:"Erro ao consultar histÃ³rico do evento"
        });

    }

  }
);


// ============================================================
// ADMIN - LIMPAR HISTÃ“RICO V2 DE UM EVENTO
// ============================================================

app.delete(
  "/admin/api/events/:eventId/internet/history",
  adminAuth,
  (req, res) => {

    try{

      const eventId =
        positiveId(
          req.params.eventId
        );

      if(!eventId){
        return res.status(400).json({
          ok:false,
          error:"Evento invÃ¡lido"
        });
      }

      const router =
        db.prepare(`
          SELECT *
          FROM routers
          WHERE
            event_id=?
            AND status='active'
          ORDER BY id ASC
          LIMIT 1
        `).get(
          eventId
        );

      if(!router){
        return res.json({
          ok:true,
          deleted:0
        });
      }

      const result =
        db.prepare(`
          DELETE FROM router_monitor_events
          WHERE router_id=?
        `).run(
          router.id
        );

      console.log(
        "HISTÃ“RICO FAILOVER LIMPO:",
        "event_id=",
        eventId,
        "router_id=",
        router.id,
        "deleted=",
        result.changes
      );

      return res.json({
        ok:true,
        event_id:eventId,
        router_id:router.id,
        deleted:Number(
          result.changes || 0
        )
      });

    }catch(error){

      console.error(
        "Erro ao limpar histÃ³rico V2 do evento:",
        error
      );

      return res.status(500).json({
        ok:false,
        error:"Erro ao limpar histÃ³rico do evento"
      });

    }

  }
);


// ============================================================
// ADMIN - HISTÃ“RICO V2 GLOBAL
//
// Quando nenhum evento estÃ¡ aberto, usa a primeira MikroTik
// ativa para manter o comportamento atual do painel.
// ============================================================

app.get(
  "/admin/api/internet-v2/history",
  adminAuth,
  (req, res) => {

    try{

      const router =
        db.prepare(`

          SELECT
            r.*,
            e.event_key,
            e.name AS event_name

          FROM routers r

          JOIN events e
            ON e.id=r.event_id

          WHERE
            r.status='active'
            AND e.status='active'

          ORDER BY
            e.id ASC,
            r.id ASC

          LIMIT 1

        `).get();


      if(
        !router
      ){

        return res.json({

          ok:true,

          router:null,

          count:0,

          events:[],

          summary:{
            provider_drops_today:0,
            last_switch_at:null,
            last_switch_type:null,
            starlink_seconds_today:0
          }

        });

      }


      const data =
        getRouterMonitorHistory(

          router,

          routerMonitorHistoryLimit(
            req.query.limit
          )

        );


      return res.json({

        ok:true,

        event:{
          id:router.event_id,
          event_key:router.event_key,
          name:router.event_name
        },

        router_id:
          router.id,

        ...data

      });

    }
    catch(error){

      console.error(
        "Erro histÃ³rico V2 global:",
        error
      );


      return res
        .status(500)
        .json({
          ok:false,
          error:"Erro ao consultar histÃ³rico V2"
        });

    }

  }
);


// ============================================================
// ADMIN - MONITOR DE UM EVENTO
// ============================================================

app.get(
  "/admin/api/events/:eventId/internet",
  adminAuth,
  (req, res) => {

    try{

      const eventId =
        positiveId(
          req.params.eventId
        );


      if(
        !eventId
      ){

        return res
          .status(400)
          .json({
            ok:false,
            error:"Evento invÃ¡lido"
          });

      }


      const event =
        db.prepare(`

          SELECT *

          FROM events

          WHERE id=?

          LIMIT 1

        `).get(
          eventId
        );


      if(
        !event
      ){

        return res
          .status(404)
          .json({
            ok:false,
            error:"Evento nÃ£o encontrado"
          });

      }


      const router =
        db.prepare(`

          SELECT *

          FROM routers

          WHERE
            event_id=?
            AND status='active'

          ORDER BY id ASC

          LIMIT 1

        `).get(
          eventId
        );


      if(
        !router
      ){

        return res.json({

          ok:true,

          event:{
            id:event.id,
            event_key:event.event_key,
            name:event.name
          },

          router:null,

          router_online:false,

          communication_status:
            "not_configured",

          stale:true,

          age_seconds:null,

          provider_status:"unknown",
          starlink_status:"unknown",
          active_link:"unknown",
          failover_status:"unknown",

          primary_status:"unknown",
          secondary_status:"unknown"

        });

      }


      const snapshot =
        getRouterMonitorSnapshot(
          router
        );


      return res.json({

        ok:true,

        event:{
          id:event.id,
          event_key:event.event_key,
          name:event.name
        },

        ...snapshot,

        // O renderizador antigo espera provider/starlink.
        active_link:
          snapshot.active_link_legacy

      });

    }
    catch(error){

      console.error(
        "Erro monitor evento:",
        error
      );


      return res
        .status(500)
        .json({
          ok:false,
          error:"Erro ao consultar monitor do evento"
        });

    }

  }
);


// ============================================================
// ADMIN - MONITOR DE TODAS AS MIKROTIKS
// ============================================================

app.get(
  "/admin/api/internet-v2",
  adminAuth,
  (req, res) => {

    try{

      const routers =
        db.prepare(`

          SELECT
            r.*,
            e.event_key,
            e.name AS event_name

          FROM routers r

          JOIN events e
            ON e.id=r.event_id

          WHERE
            r.status='active'
            AND e.status='active'

          ORDER BY
            e.id ASC,
            r.id ASC

        `).all();


      const items =
        routers.map(
          router => ({
            event_name:
              router.event_name,
            event_key:
              router.event_key,
            ...getRouterMonitorSnapshot(
              router
            )
          })
        );


      return res.json({
        ok:true,
        count:items.length,
        routers:items
      });

    }
    catch(error){

      console.error(
        "Erro monitor global:",
        error
      );


      return res
        .status(500)
        .json({
          ok:false,
          error:"Erro ao consultar monitor das MikroTiks"
        });

    }

  }
);


// ============================================================
// FIM DO BLOCO 8.5/10
// ============================================================

// ============================================================
// BLOCO 8.6/10 - BACKUP ADMINISTRATIVO DO BANCO SQLITE
// ============================================================


// ============================================================
// CONTROLE DE EXECUCAO
//
// Impede dois backups simultaneos e evita consumo desnecessario
// de memoria, CPU e espaco temporario no Railway.
// ============================================================

let databaseBackupInProgress = false;


// ============================================================
// DOWNLOAD SEGURO DO BANCO
//
// Protecao:
// - exige o mesmo adminAuth das demais rotas administrativas
// - cria uma copia consistente com db.backup()
// - funciona com o banco online e em modo WAL
// - grava somente um arquivo temporario em /tmp
// - remove o arquivo assim que o download termina
// - nunca envia tokens ou variaveis do Railway
// ============================================================

app.get(
  "/api/admin/backup/database",
  adminAuth,
  async (req, res) => {

    if(databaseBackupInProgress){

      return res
        .status(409)
        .json({
          ok: false,
          error: "BACKUP_IN_PROGRESS",
          message: "Ja existe um backup do banco em andamento."
        });

    }

    databaseBackupInProgress = true;

    const backupStamp =
      new Date()
        .toISOString()
        .replace(/[:.]/g, "-");

    const backupId =
      crypto
        .randomBytes(6)
        .toString("hex");

    const downloadName =
      `wifi-pago-backup-${backupStamp}.db`;

    const temporaryPath =
      path.join(
        "/tmp",
        `wifi-pago-backup-${backupId}.db`
      );

    const removeTemporaryBackup = () => {

      try{

        if(fs.existsSync(temporaryPath)){
          fs.unlinkSync(temporaryPath);
        }

      }catch(error){

        console.error(
          "Falha ao remover backup temporario:",
          error.message
        );

      }

    };

    try{

      await db.backup(temporaryPath);

      res.setHeader(
        "Cache-Control",
        "no-store, no-cache, must-revalidate, private"
      );

      res.setHeader(
        "Pragma",
        "no-cache"
      );

      res.setHeader(
        "X-Content-Type-Options",
        "nosniff"
      );

      return res.download(
        temporaryPath,
        downloadName,
        error => {

          removeTemporaryBackup();
          databaseBackupInProgress = false;

          if(error){

            console.error(
              "Falha no download do backup:",
              error.message
            );

            if(!res.headersSent){

              res
                .status(500)
                .json({
                  ok: false,
                  error: "BACKUP_DOWNLOAD_FAILED"
                });

            }

          }

        }
      );

    }catch(error){

      removeTemporaryBackup();
      databaseBackupInProgress = false;

      console.error(
        "Falha ao gerar backup do banco:",
        error.message
      );

      return res
        .status(500)
        .json({
          ok: false,
          error: "DATABASE_BACKUP_FAILED"
        });

    }

  }
);


// ============================================================
// FIM DO BLOCO 8.6/10

// BLOCO 9/10 - ROTAS INVÃLIDAS E TRATAMENTO DE ERROS
// ============================================================


// ============================================================
// API 404
//
// Qualquer rota iniciada por /api que nÃ£o exista
// cai aqui.
// ============================================================

app.use(
  "/api",
  (req, res) => {

    return res
      .status(
        404
      )
      .json({

        error:
          "Endpoint nÃ£o encontrado"

      });

  }
);


// ============================================================
// ADMIN 404
//
// Evita resposta HTML genÃ©rica em rotas administrativas
// inexistentes.
// ============================================================

app.use(
  "/admin/api",
  (req, res) => {

    return res
      .status(
        404
      )
      .json({

        error:
          "Endpoint administrativo nÃ£o encontrado"

      });

  }
);


// ============================================================
// TRATAMENTO GLOBAL DE ERROS
//
// Este middleware fica depois das rotas.
// ============================================================

app.use(
  (
    error,
    req,
    res,
    next
  ) => {

    console.error(
      "ERRO NÃƒO TRATADO:",
      error
    );


    if (
      res.headersSent
    ) {

      return next(
        error
      );

    }


    return res
      .status(
        500
      )
      .json({

        error:
          "Erro interno do servidor"

      });

  }
);


// ============================================================
// FIM DO BLOCO 9/10

// BLOCO 10/10 - INICIALIZAÃ‡ÃƒO DO SERVIDOR
// ============================================================


// ============================================================
// PORTA
// ============================================================

const PORT =
  Number(
    process.env.PORT
  ) || 8080;


// ============================================================
// INICIAR SERVIDOR
// ============================================================

app.listen(
  PORT,
  "0.0.0.0",
  () => {

    console.log(
      `WiFi Pago ativo na porta ${PORT}`
    );


    console.log(
      "Banco:",
      path.join(
        dataDir,
        "wifi.db"
      )
    );


    console.log(
      "Identidade de cortesia: CLIENT_ID"
    );


    console.log(
      "Comandos administrativos ativos:"
    );


    console.log(
      "- BYPASS"
    );


    console.log(
      "- UNBYPASS"
    );


    console.log(
      "- BLOCK_NOW"
    );

  }
);


// ============================================================
// FIM DO BLOCO 10/10



