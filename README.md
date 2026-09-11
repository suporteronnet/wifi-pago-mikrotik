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
