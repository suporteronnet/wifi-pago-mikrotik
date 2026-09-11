# MikroTik RouterOS 7 - complemento para integração REST
# IMPORTANTE: use somente após definir uma senha forte.
# A REST API exige www-ssl (recomendado) ou www.
#
# 1) Crie usuário restrito para a aplicação:
# /user group add name=wifi-api policy=read,write,rest-api,!local,!telnet,!ssh,!ftp,!reboot,!policy,!test,!winbox,!password,!web,!sniff,!sensitive,!api,!romon
# /user add name=wifi-api group=wifi-api password="TROQUE_POR_SENHA_FORTE"
#
# 2) Habilite HTTPS do RouterOS (www-ssl) depois de configurar certificado.
# Não exponha a porta diretamente à Internet; prefira VPN.
#
# 3) Perfis esperados:
# PLANO-1H, PLANO-4H, PLANO-12H, PLANO-24H
