#!/usr/bin/env bash
# Scarica i database GeoIP MaxMind (GeoLite2 City + ASN) nella cartella geoip/.
#
# PERCHE' NON SONO NEL REPO: la licenza MaxMind vieta la redistribuzione, e ogni
# installazione deve tenere dati aggiornati. Serve un account MaxMind gratuito e
# una License Key: https://www.maxmind.com/en/geolite2/signup
#
# USO:  MAXMIND_LICENSE_KEY=xxxxx ./scripts/scarica-geoip.sh
set -euo pipefail

CHIAVE="${MAXMIND_LICENSE_KEY:-}"
if [[ -z "$CHIAVE" ]]; then
  echo "Manca MAXMIND_LICENSE_KEY." >&2
  echo "Registrati gratis su maxmind.com, genera una License Key e rilancia:" >&2
  echo "  MAXMIND_LICENSE_KEY=xxxxx $0" >&2
  exit 1
fi

DEST="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/geoip"
mkdir -p "$DEST"
BASE="https://download.maxmind.com/app/geoip_download"

scarica() {
  local edizione="$1" out="$2"
  echo "→ ${edizione}"
  local tmp; tmp="$(mktemp -d)"
  curl -fsSL "${BASE}?edition_id=${edizione}&license_key=${CHIAVE}&suffix=tar.gz" -o "$tmp/db.tar.gz"
  tar -xzf "$tmp/db.tar.gz" -C "$tmp"
  find "$tmp" -name '*.mmdb' -exec cp {} "$DEST/$out" \;
  rm -rf "$tmp"
  echo "  salvato in geoip/$out"
}

scarica "GeoLite2-City" "GeoLite2-City.mmdb"
scarica "GeoLite2-ASN" "GeoLite2-ASN.mmdb"
echo "Fatto. I percorsi corrispondono a GEOIP_DB_PATH / GEOIP_ASN_PATH nel .env."
