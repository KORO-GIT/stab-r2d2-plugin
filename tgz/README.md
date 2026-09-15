# R2D2 `.tgz` fallback

`start.sh` запускает тот же прокси непосредственно на Raspberry Pi R2D2, без
Podman. Этот вариант нужен для старых загрузчиков R2D2, которые перед публичным
Docker pull ошибочно требуют `/storage/podman/auth.json`.

Релизный архив содержит ARM64-зависимости `aiohttp` для Python 3.9–3.12.
В корне архива обязательно находятся `start.sh` и `plugin.py`.

