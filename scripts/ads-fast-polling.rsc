# Apply only to an advertising HotSpot with the existing WIFI-PAGO scripts.
# Keeps commands, tokens, HotSpot configuration and active clients unchanged.
:local pull [/system scheduler find where name="WIFI-PAGO-ADMIN-PULL"];
:local presence [/system scheduler find where name="WIFI-PAGO-PRESENCE"];
:if ([:len $pull] != 1) do={ :error "Expected one WIFI-PAGO-ADMIN-PULL scheduler" };
:if ([:len $presence] != 1) do={ :error "Expected one WIFI-PAGO-PRESENCE scheduler" };
/system scheduler set $pull interval=2s on-event={ :if ([/system script job print count-only where script="WIFI-PAGO-ADMIN-PULL"] = 0) do={ /system script run WIFI-PAGO-ADMIN-PULL } };
/system scheduler set $presence interval=5s on-event={ :if ([/system script job print count-only where script="WIFI-PAGO-PRESENCE"] = 0) do={ /system script run WIFI-PAGO-PRESENCE } };
