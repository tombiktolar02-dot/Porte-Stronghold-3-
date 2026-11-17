#!/system/bin/sh
# extract_rootfs_from_port.sh — Stronghold 3 Android Wrapper (auto-generated)
# Helper: pull a prebuilt Linux rootfs (Box86/Box64 + Wine + DXVK 1.10.3) out of an
# existing Generals Zero Hour or Stronghold Crusader port APK and inject it into
# this wrapper's private data folder. Run from a rooted shell or "adb shell su".

set -e

SRC_APK="${SRC_APK:-/sdcard/Download/port.apk}"
APP_ID="com.bolt.stronghold3wrapper"
APP_ROOT="${APP_ROOT:-/data/data/com.bolt.stronghold3wrapper}"
TMP_DIR="${APP_ROOT}/rootfs_tmp"
OUT_TAR="${APP_ROOT}/rootfs.tar.xz"

log() { echo "[extract_rootfs] $*"; }

if [ ! -f "${SRC_APK}" ]; then
  log "ERROR: ${SRC_APK} not found. Copy the port APK to /sdcard/Download/port.apk first."
  exit 1
fi

mkdir -p "${TMP_DIR}"

# 1. Unzip the APK contents (an APK is just a zip archive).
log "Unpacking ${SRC_APK}…"
cd "${TMP_DIR}"
unzip -o "${SRC_APK}" "assets/*" -d . 2>/dev/null || true

# 2. Locate the rootfs archive inside the port APK. Known layouts:
#    - assets/rootfs.tar.xz        (Zero Hour / Crusader ports)
#    - assets/data/rootfs.tar.xz   (some Winlator-derived ports)
#    - assets/obb/rootfs.tar.xz
ROOTFS_SRC=""
for candidate in \
  assets/rootfs.tar.xz \
  assets/data/rootfs.tar.xz \
  assets/obb/rootfs.tar.xz; do
  if [ -f "${candidate}" ]; then
    ROOTFS_SRC="${candidate}"
    break
  fi
done

if [ -z "${ROOTFS_SRC}" ]; then
  log "ERROR: no rootfs.tar.xz found in the port APK. Looked in assets/, assets/data/, assets/obb/."
  ls -R assets | head -50
  exit 1
fi

log "Found rootfs at ${ROOTFS_SRC}. Copying into wrapper data folder…"
cp "${ROOTFS_SRC}" "${OUT_TAR}"

# 3. Reset extraction marker so init_env.sh re-extracts on next launch.
rm -f "${APP_ROOT}/rootfs/.extracted"

# 4. Fix permissions so the wrapper app owns the file.
if command -v chown >/dev/null 2>&1; then
  OWNER="$(stat -c '%u:%g' "${APP_ROOT}")"
  chown -R "${OWNER}" "${APP_ROOT}/rootfs_tmp" "${OUT_TAR}" 2>/dev/null || true
fi

# 5. Clean up temp files.
rm -rf "${TMP_DIR}"

log "Done. Rootfs injected at ${OUT_TAR}."
log "Launch the wrapper once — init_env.sh will extract it and build the Wine prefix."
