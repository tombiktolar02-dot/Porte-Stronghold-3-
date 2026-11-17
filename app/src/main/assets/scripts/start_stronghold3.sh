#!/system/bin/sh
# start_stronghold3.sh — Stronghold 3 Android Wrapper (auto-generated)
# Launches Stronghold3.exe through Wine inside the extracted rootfs.

set -e

APP_ROOT="${APP_ROOT:-/data/data/com.bolt.stronghold3wrapper}"
ROOTFS_DIR="${APP_ROOT}/rootfs"
WINEPREFIX="${ROOTFS_DIR}/wineprefix"
GAME_DIR="${GAME_DIR:-/sdcard/Stronghold3}"
EXE="Stronghold3.exe"

log() { echo "[start] $*"; }

# Verify required files exist before launching.
if [ ! -f "${GAME_DIR}/${EXE}" ]; then
  log "ERROR: ${EXE} not found in ${GAME_DIR}"
  exit 1
fi
for dll in d3d9.dll d3dx9_43.dll vcruntime140.dll; do
  if [ ! -f "${WINEPREFIX}/drive_c/windows/system32/${dll}" ]; then
    log "ERROR: missing ${dll} in Wine prefix (DirectX 9 / VC++ 2008 runtime)"
    exit 1
  fi
done

export BOX86_DYNAREC="1"
export BOX64_DYNAREC="1"
export DXVK_HUD="fps"
export DXVK_ASYNC="1"
export WINEARCH="win32"
export WINEDLLOVERRIDES="d3d9=n,b;d3dx9_43=n,b;vcruntime140=n,b"
export WINEPREFIX="$ROOTFS/wineprefix"
export BOX86_DYNAREC_FASTNAN="1"
export BOX64_DYNAREC_SAFEFLAGS="2"
export DXVK_STATE_CACHE_PATH="$ROOTFS/cache/xclipse"

log "Generating Vision Engine options.xml (resolution ${RES}, shadows/${SHADOWS}, ssao/${SSAO}, shader ${QUALITY})…"
RES="1280x720"
SHADOWS="off"
SSAO="off"
QUALITY="low"

mkdir -p "${GAME_DIR}"
cat > "${GAME_DIR}/options.xml" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<options>
  <render>
    <width>${RES%%x*}</width>
    <height>${RES##*x}</height>
    <fullscreen>0</fullscreen>
    <shadows>${SHADOWS}</shadows>
    <ssao>${SSAO}</ssao>
    <shader_quality>${QUALITY}</shader_quality>
  </render>
</options>
EOF

cd "${GAME_DIR}"
log "Launching Stronghold3.exe via Wine + Box86…"
exec "${ROOTFS_DIR}/usr/local/bin/box86" \
  "${ROOTFS_DIR}/usr/local/bin/wine" "${EXE}"
