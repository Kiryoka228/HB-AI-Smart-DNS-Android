# Восстановление сетевых правил root-режима

При нормальном выключении приложение удаляет только цепочки `HB_AI_DNS4`, `HB_AI_DNS6` и восстанавливает сохранённое значение Android `private_dns_mode`. Если приложение аварийно закрывается, watchdog пытается сделать это самостоятельно.

Если DNS перестал работать после сбоя, в любом root-терминале, где есть `su`, выполните:

```sh
su -c 'iptables -t nat -D OUTPUT -j HB_AI_DNS4 2>/dev/null || true; iptables -t nat -F HB_AI_DNS4 2>/dev/null || true; iptables -t nat -X HB_AI_DNS4 2>/dev/null || true'
su -c 'ip6tables -t nat -D OUTPUT -j HB_AI_DNS6 2>/dev/null || true; ip6tables -t nat -F HB_AI_DNS6 2>/dev/null || true; ip6tables -t nat -X HB_AI_DNS6 2>/dev/null || true'
```

Затем вручную верните желаемый режим **Настройки → Сеть → Частный DNS**. Не выполняйте `iptables -F` без имени цепочки: это удалит чужие правила и может нарушить сетевую работу устройства.
