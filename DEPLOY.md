# SENTINEL — installazione neutra e adattamento per sito

Questo repository contiene **il codice** di Sentinel e la **configurazione neutra**.
Non contiene i segreti, i database GeoIP e i modelli ONNX: quelli si provisionano
sul server di destinazione, perché sono propri di ogni installazione o soggetti a
licenza di terzi. È così che si copia su un server nuovo e lo si adatta.

Sentinel è un WAF: sta **davanti** alla piattaforma, tra il reverse proxy
(nginx/Traefik) e l'applicazione. Non è legato al linguaggio del backend.

---

## Cosa NON è nel repo (e va messo sul server)

| Elemento | Dove si prende | Percorso atteso |
|---|---|---|
| 4 modelli ONNX | dal proprio archivio modelli (vedi sotto) | `models/` |
| GeoLite2 City + ASN | `scripts/scarica-geoip.sh` (account MaxMind gratuito) | `geoip/` |
| Segreti e URL | generati e scritti in `.env` | `.env` |

Sono esclusi da git in `.gitignore`: `*.onnx`, `*.mmdb`, `.env`.

### I 4 modelli ONNX

Il neural layer non parte senza questi quattro file in `models/`:

- `prompt-injection.onnx`
- `toxicity.onnx`
- `llm-output-safety.onnx`
- `threat-classifier-v2.onnx`

I primi tre sono nell'archivio modelli interno; **`threat-classifier-v2.onnx`
va recuperato dal server zeliAI** (non era tra i modelli locali). Finché manca,
avviare con `SENTINEL_SAFE_MODE=true` e il prompt-injection su soglia, così il
layer degrada senza bloccare.

---

## Installazione su un server nuovo

```bash
# 1. Codice
git clone <questo-repo> sentinel && cd sentinel

# 2. Configurazione — copiare e riempire
cp .env.example .env
#    generare i segreti:
openssl rand -hex 32     # → SENTINEL_CHALLENGE_SECRET
openssl rand -hex 32     # → SENTINEL_INTERNAL_SECRET
#    puntare PORTAL_INTERNAL_URL / PORTAL_PUBLIC_URL alla piattaforma da proteggere

# 3. GeoIP
MAXMIND_LICENSE_KEY=xxxxx ./scripts/scarica-geoip.sh

# 4. Modelli — copiare i 4 .onnx in models/
mkdir -p models && cp /percorso/ai/modelli/*.onnx models/

# 5. Avvio
docker compose up -d --build
curl -f http://127.0.0.1:8080/health
```

---

## Adattare Sentinel a una piattaforma specifica

L'adattamento è **configurazione, non modifica del codice**:

- `PORTAL_INTERNAL_URL` / `PORTAL_PUBLIC_URL` → la piattaforma da proteggere.
- `SENTINEL_TRUSTED_IPS` → gli IP dello studio, che non vanno mai sfidati.
- `SENTINEL_SAFE_MODE=true` per le prime settimane: Sentinel osserva e registra
  senza bloccare, così si vedono i falsi positivi prima di attivare i blocchi.
- Le soglie neural (`*_THRESHOLD`) si tarano sui falsi positivi reali del sito.

Se servisse una capacità che Sentinel non ha ancora, si aggiunge **al codice di
Sentinel** (ne beneficiano tutte le installazioni), mai a una copia del sito.

---

## Nota sul build

Il sorgente è la versione ufficiale in esercizio (workspace Cargo a 7 crate).
Il build completo compila Rust + ONNX runtime: è pesante e va eseguito sulla
macchina di deploy, non serve rifarlo a ogni copia. Verificare che l'immagine
includa la runtime ONNX richiesta dal neural layer.
