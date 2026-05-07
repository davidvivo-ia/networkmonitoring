# 🛰 ipmonitor — Monitor profesional de paquetes IP

`ipmonitor` es un controlador de paquetes IP en tiempo real, escrito en Python,
que muestra qué paquetes pasan por tu equipo y a qué países van o de dónde
vienen. Pensado para uso de administrador / analista de red / curiosidad
saludable sobre tu propia máquina.

```
┌──────────────────────────────────────────────────────────────────────────┐
│                          🛰  IP PACKET MONITOR                          │
│           iface: eth0   filter: tcp or udp   2026-05-07 18:45:11        │
├──────────────┬──────────────────────────────────┬────────────────────────┤
│  📊 Resumen   │   🌍 Países (origen / destino)  │  🎯 Top destinos      │
│  Uptime  …    │  🇺🇸 United States  IN  OUT  …  │  🇮🇪 Dublin / 17.x.x  │
│  Packets …    │  🇪🇸 Spain                      │  🇺🇸 1.1.1.1         │
│  Bytes   …    │  🇩🇪 Germany                    │  🏠 LAN              │
│  Rate    …    │  …                              │  …                    │
├──────────────┴──────────────────────────────────┴────────────────────────┤
│   📡 Paquetes en vivo (últimos 10) — IP, puerto, servicio, país, len   │
└──────────────────────────────────────────────────────────────────────────┘
```

## Características

- **Captura en vivo** sobre cualquier interfaz, basada en Scapy (libpcap).
- **Soporte BPF** completo (`-f "tcp or udp"`, `-f "host 8.8.8.8"`, etc.).
- **Geolocalización por país** con tres caminos:
  1. Caché en memoria + persistente (`~/.cache/ipmonitor/geoip.json`).
  2. Base de datos offline **MaxMind GeoLite2** (`--mmdb …`).
  3. **`ip-api.com`** en lotes (gratis, sin API key) como fallback online.
- **Dashboard TUI** con [Rich](https://rich.readthedocs.io): resumen, país,
  protocolos, top destinos, top puertos, paquetes en vivo, banderas Unicode.
- **Estadísticas**: paquetes y bytes por país, por protocolo, por IP origen,
  IP destino, puerto destino y *flow* (5-tupla colapsada).
- **Tasa instantánea** (bytes/s, pkt/s) con ventana móvil configurable.
- **Modo headless** (`--no-ui`) para logs por línea.
- **Exportación** JSON y CSV al cerrar la sesión.
- **Filtrado** automático de tráfico privado/LAN para no saturar el panel
  de geolocalización.
- Tolerante a fallos: si `ip-api.com` está caído o `geoip2` no está
  instalado, sigue funcionando offline.

## Instalación

Requiere Python 3.9+ y permisos de captura (`CAP_NET_RAW` o root).

```bash
git clone https://github.com/davidvivo-ia/networkmonitoring.git
cd networkmonitoring
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Atajo: `./run.sh` crea el venv y lanza con `sudo` automáticamente.

## Uso

```bash
# Lo más simple (todas las interfaces, sin filtro):
sudo -E python -m ipmonitor

# Interfaz específica + filtro BPF:
sudo -E python -m ipmonitor -i eth0 -f "tcp or udp"

# Solo tráfico hacia/desde 8.8.8.8:
sudo -E python -m ipmonitor -f "host 8.8.8.8"

# 30 segundos en modo headless con informe JSON:
sudo -E python -m ipmonitor --no-ui --duration 30 --export-json sesion.json

# Modo offline puro (requiere --mmdb GeoLite2):
sudo -E python -m ipmonitor --offline --mmdb /var/lib/GeoLite2-City.mmdb

# Listar interfaces disponibles:
python -m ipmonitor --list-interfaces
```

### Argumentos

| Flag | Descripción |
|------|-------------|
| `-i, --interface` | Interfaz a capturar (por defecto la elegida por scapy). |
| `-f, --filter`   | Filtro BPF estilo tcpdump. |
| `--mmdb PATH`    | MaxMind GeoLite2-City.mmdb para resolución offline. |
| `--cache PATH`   | Caché GeoIP persistente (def `~/.cache/ipmonitor/geoip.json`). |
| `--offline`      | Desactiva el fallback online ip-api.com. |
| `--no-ui`        | Sin TUI, una línea por paquete. |
| `--duration N`   | Para tras N segundos (0 = hasta Ctrl+C). |
| `--refresh HZ`   | Refrescos por segundo del dashboard (def 4). |
| `--export-json`  | Vuelca el snapshot final en JSON. |
| `--export-csv`   | Resumen por país en CSV. |
| `--list-interfaces` | Lista interfaces y sale. |

### Permisos

La captura de paquetes requiere privilegios:

- `sudo` (más simple, ojo con la variable `PATH`: usa `sudo -E`).
- O concede capacidad sin root al binario de Python:
  ```bash
  sudo setcap cap_net_raw,cap_net_admin=eip "$(readlink -f $(which python3))"
  ```

## Arquitectura

```
ipmonitor/
├── capture.py    # AsyncSniffer de Scapy → PacketRecord
├── geoip.py      # Resolver thread-safe (cache + mmdb + ip-api batch)
├── stats.py      # Aggregator (counters, ventanas móviles, flows)
├── ui.py         # Dashboard rich.Live con layout 3-columnas
├── exporter.py   # JSON / CSV / resumen final
├── utils.py      # IP privada, formato bytes/rate, banderas, puertos
└── cli.py        # argparse + bucle principal + manejo de señales
```

Flujo:

```
 NIC → scapy.AsyncSniffer
        └── prn callback (capture.py)
              └── PacketRecord
                   ├── geoip.lookup(src), lookup(dst)   (no bloqueante)
                   └── stats.record(pkt, src_geo, dst_geo)
                                  ↑
                          ui.Dashboard cada 250 ms hace stats.snapshot()
```

El resolver GeoIP nunca bloquea el hilo de captura: para IPs sin caché
encola la consulta y un *worker* en segundo plano la resuelve en lotes
de hasta 100 (límite gratuito de `ip-api.com`).

## Tests

```bash
pip install pytest
pytest -q
```

Los tests cubren `utils` y `stats` (no requieren root ni red).

## Privacidad y uso responsable

- Sólo monitoriza el tráfico que pasa por **tu propia máquina**.
- Las consultas a `ip-api.com` envían IPs públicas a un tercero;
  desactívalas con `--offline` si te preocupa.
- No descifra payloads ni guarda contenido — sólo metadatos (IP, puerto,
  protocolo, longitud, timestamp).

## Licencia

MIT.
