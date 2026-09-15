Wi-Fi Pago — uma MikroTik por evento
Portal de Wi-Fi pago com Mercado Pago PIX, Hotspot MikroTik e painel administrativo.
Estrutura desta versão
cada evento possui somente uma MikroTik;
a MikroTik é criada automaticamente junto com o evento;
não existem MK principal, MK adicional, UPLINK ou interligações;
o painel permite editar o equipamento, as portas e a rede do evento;
o botão GERAR SCRIPT MIKROTIK monta o script completo daquele evento;
eventos antigos com várias MKs mantêm a primeira ativa e deixam as adicionais inativas.
Script gerado
O script inclui identidade, bridge dos clientes, gateway, DHCP, DNS, NAT, Hotspot, perfis dos planos, Walled Garden, WIFI-PAGO-PULL, ACK e EXPIRE.
O script não executa reset de fábrica. Quando a WAN for PPPoE ou IP estático, ele preserva a configuração e as credenciais de Internet existentes.
Estrutura para implantação
```text
server.js
package.json
Dockerfile
public/
  index.html
  admin.html
```
Uso
Entre no painel administrativo.
Crie um evento.
Abra o evento; a MikroTik já estará criada.
Edite modelo, RouterOS, WAN, portas Hotspot e rede, se necessário.
Cadastre ou revise os planos.
Clique em GERAR SCRIPT MIKROTIK.
Copie o script e o `login.html` mostrados pelo painel.

Variaveis obrigatorias em producao
Configure no Railway (ou no ambiente de execucao) antes de publicar:

```text
ADMIN_USER
ADMIN_PASSWORD
MP_ACCESS_TOKEN
MP_WEBHOOK_SECRET
```

Os códigos dos vouchers são guardados criptografados para permitir consulta e reimpressão pelo painel. A chave `voucher-print.key` é criada dentro de `DATA_DIR`; mantenha esse arquivo junto com `wifi.db` no volume persistente e nas cópias de segurança. Lotes criados antes dessa mudança não podem ser recuperados, pois o banco guardava somente o hash do código.

Use uma senha administrativa forte; senhas padrao conhecidas fazem o servidor recusar a inicializacao. `TRUST_PROXY_HOPS` define quantos proxies confiaveis existem antes da aplicacao e assume `1` no Railway. Em acesso direto sem proxy reverso, configure `TRUST_PROXY_HOPS=0`.

Os limites de protecao atuais sao mantidos em memoria por processo: ate 30 requisicoes de PIX por IP por minuto e 5 por aparelho por minuto; recuperacao de acesso permite 30 por IP e 5 por aparelho a cada 15 minutos. Se o servico rodar com varias replicas, cada replica aplica seus proprios limites.
