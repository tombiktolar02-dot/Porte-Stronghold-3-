# Stronghold 3 — Android Wrapper APK

porte Android. Runs the PC game "Stronghold 3"
(x86 32-bit, Vision Engine, DirectX 9.0c) on ARM64 Android via Box86/Box64 +
Wine (win32 prefix) + DXVK 1.10.3 (DirectX 9 -> Vulkan).

## Quick start (GitHub Actions — no local Android Studio needed)

1. Create a new (private) GitHub repository and upload every file in this ZIP,
   keeping the folder layout as-is.
2. GitHub Actions will run `.github/workflows/build-apk.yml` on push and produce
   a debug-signed `Stronghold3-Wrapper.apk` as a build artifact.
3. Download the APK from the Actions run page and sideload it onto your device
   (Settings → Security → Install unknown apps).

## Manual build (Android Studio)

1. Open this folder in Android Studio (Ladybug or newer).
2. Let Gradle sync, then Build → Build Bundle(s)/APK(s) → Build APK(s).
3. The debug APK lands in `app/build/outputs/apk/debug/`.

## Preparing the game and rootfs

- Put the PC copy of Stronghold 3 in `/sdcard/Stronghold3` on the device
  (must contain `Stronghold3.exe`, `data/`, `bin/`).
- Provide a minimal Linux rootfs with Box86/Box64, Wine 32-bit and DXVK 1.10.3
  as `app/src/main/assets/rootfs.tar.xz`. If you already own the Generals Zero
  Hour or Stronghold Crusader Android port, run the
  `extract_rootfs_from_port.sh` helper (see the Setup tab) to pull the rootfs
  out of that APK and inject it here.
- DirectX 9 / Visual C++ 2008 redistributables are provisioned into the Wine
  prefix automatically on first launch.

## Current config (from the builder)

- Game path: `/sdcard/Stronghold3`
- Resolution: 1280x720 · shadows off · SSAO off · shaders low
- GPU profile: xclipse
- Overlay: marquee select on · pinch-zoom on · hotkey bar on

 
# Stronghold 3 — Android Wrapper APK# Stronghold 3 — Android Wrapper APK

porte Android. Runs the PC game "Stronghold 3"
(x86 32-bit, Vision Engine, DirectX 9.0c) on ARM64 Android via Box86/Box64 +
Wine (win32 prefix) + DXVK 1.10.3 (DirectX 9 -> Vulkan).

## Quick start (GitHub Actions — no local Android Studio needed)

1. Create a new (private) GitHub repository and upload every file in this ZIP,
   keeping the folder layout as-is.
2. GitHub Actions will run `.github/workflows/build-apk.yml` on push and produce
   a debug-signed `Stronghold3-Wrapper.apk` as a build artifact.
3. Download the APK from the Actions run page and sideload it onto your device
   (Settings → Security → Install unknown apps).

## Manual build (Android Studio)

1. Open this folder in Android Studio (Ladybug or newer).
2. Let Gradle sync, then Build → Build Bundle(s)/APK(s) → Build APK(s).
3. The debug APK lands in `app/build/outputs/apk/debug/`.

## Preparing the game and rootfs

- Put the PC copy of Stronghold 3 in `/sdcard/Stronghold3` on the device
  (must contain `Stronghold3.exe`, `data/`, `bin/`).
- Provide a minimal Linux rootfs with Box86/Box64, Wine 32-bit and DXVK 1.10.3
  as `app/src/main/assets/rootfs.tar.xz`. If you already own the Generals Zero
  Hour or Stronghold Crusader Android port, run the
  `extract_rootfs_from_port.sh` helper (see the Setup tab) to pull the rootfs
  out of that APK and inject it here.
- DirectX 9 / Visual C++ 2008 redistributables are provisioned into the Wine
  prefix automatically on first launch.

## Current config (from the builder)

- Game path: `/sdcard/Stronghold3`
- Resolution: 1280x720 · shadows off · SSAO off · shaders low
- GPU profile: xclipse
- Overlay: marquee select on · pinch-zoom on · hotkey bar on
 
