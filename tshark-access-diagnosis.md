# Причина за отказа на TShark

Проверка: 29.10.2026. Примерният потребител е с UID 1000. Файловете могат да бъдат прочетени от Python под този потребител.

Системният журнал потвърждава AppArmor отказ за отваряне на запис от captures:

```text
apparmor="DENIED" operation="open" profile="tshark"
comm="tshark" requested_mask="r" denied_mask="r" fsuid=1000 ouid=1000
```

В `/etc/apparmor.d/tshark` основният профил няма разрешение за четене на PCAP файлове от работната папка. Включената `abstractions/user-tmp` позволява собствени файлове в `/tmp`, което обяснява успешния анализ на временните копия. Разрешенията за PCAP в подчинения профил `dumpcap` не се отнасят за основния `tshark` профил.

Промяна на собствеността или chmod 777 не премахва AppArmor ограничението.

Тясно разрешение, което може да бъде добавено в `/etc/apparmor.d/local/tshark` (основният профил вече включва този локален файл):

```text
owner "/path/to/wifi-bee/captures/**.pcapng" r,
owner "/path/to/wifi-bee/captures/**.pcap" r,
owner "/path/to/wifi-bee/captures/**.cap" r,
```

След редакция профилът се презарежда с:

```bash
sudo apparmor_parser -r /etc/apparmor.d/tshark
```

Правилата разрешават само четене на собствените capture файлове в тази папка и не изключват AppArmor. Системни настройки не са променяни в рамките на диагностиката. Първоначалният отказ на директно стартирания dumpcap не е доказан от тези логове; потвърденият тук проблем е четенето с TShark.
