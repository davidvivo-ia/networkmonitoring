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

## Instalación (Windows)

Requisitos:

1. **Python 3.9+** (https://www.python.org/downloads/windows — marca *Add
   Python to PATH* en el instalador).
2. **Npcap** (https://npcap.com), driver de captura. Durante la instalación
   marca **“Install Npcap in WinPcap API-compatible mode”**.
3. Una **terminal con privilegios de Administrador** (PowerShell o cmd
   abiertos con *Run as administrator*). La captura de paquetes requiere
   privilegios elevados.

Pasos:

```powershell
git clone https://github.com/davidvivo-ia/networkmonitoring.git
cd networkmonitoring
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### Atajo: `run.ps1` (auto-eleva por UAC)

```powershell
# En la carpeta del proyecto, desde una PowerShell normal:
.\run.ps1
```

`run.ps1` crea el venv si no existe, instala dependencias, y abre una
ventana elevada por UAC con el dashboard. También puedes invocar
`run.bat` (que delega en `run.ps1`).

> Si PowerShell bloquea el script con un error de política de ejecución,
> ejecuta una vez:
> `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`

### Linux / macOS

También funciona en Linux/macOS (con `libpcap`):

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
sudo -E python -m ipmonitor          # o usa ./run.sh
```

## Uso (Windows, PowerShell elevada)

```powershell
# 1) Listar interfaces para saber el nombre amigable que tienes que pasar:
python -m ipmonitor --list-interfaces

# 2) Captura completa con dashboard:
python -m ipmonitor

# 3) Interfaz concreta + filtro BPF (igual que tcpdump):
python -m ipmonitor -i "Wi-Fi" -f "tcp or udp"

# 4) Solo tráfico hacia/desde 8.8.8.8:
python -m ipmonitor -f "host 8.8.8.8"

# 5) 30 segundos en modo headless con informe JSON:
python -m ipmonitor --no-ui --duration 30 --export-json sesion.json

# 6) Modo offline puro con GeoLite2 (sin llamadas a Internet):
python -m ipmonitor --offline --mmdb C:\datos\GeoLite2-City.mmdb
```

En Windows el flag `-i` espera el **nombre amigable** que ves en
*“Conexiones de red”* (`Wi-Fi`, `Ethernet`, `vEthernet (Default Switch)`…).
Si `--list-interfaces` te muestra rutas con GUID (`\Device\NPF_{...}`),
también las acepta — ese GUID es lo que entiende Npcap por debajo.

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

La captura requiere privilegios elevados:

- **Windows**: PowerShell o cmd como *Administrador*. `run.ps1` lo gestiona
  por ti (UAC). Necesitas además **Npcap** instalado.
- **Linux**: `sudo -E python -m ipmonitor` o concede capacidades sin root:
  `sudo setcap cap_net_raw,cap_net_admin=eip "$(readlink -f $(which python3))"`.

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
