jq . oui_extra.json >/dev/null && echo "OK" || echo "Syntax error"
jq . mac_overrides.json >/dev/null && echo "OK" || echo "Syntax error"
