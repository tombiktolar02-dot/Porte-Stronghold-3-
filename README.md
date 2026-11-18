# Stronghold 3 --- Native Android ARM64 Port

An experimental project to bring Stronghold 3 to native ARM64 Android.

> **Current status:** Stage 4 completed --- diagnostic prototype
> verified on a physical Android device.
>
> **Important:** The game is not playable yet. Actual x86 game-code
> execution has not been implemented.

## Project Overview

Stronghold 3 is a 32-bit x86 Windows game built around the Vision Engine
and DirectX 9.

The goal is to develop a native ARM64 Android compatibility layer that
can eventually load and run the original game without relying on:

-   Winlator
-   Wine
-   Box86 / Box64
-   Linux RootFS or PRoot

The long-term objective is a standalone Android application.

## Development Progress

### Stage 1 --- PE Inspection

-   Implemented an initial JNI-based PE inspection component.
-   Scanned 8 game modules.
-   Extracted basic PE information.

### Stage 2 --- Experimental PE Mapping

-   Implemented experimental PE32 memory mapping.
-   Processed PE headers and sections.
-   Inspected relocation entries, exports, and imports.

This is not yet a complete Windows PE loader.

### Stage 3 --- Experimental Linking and Thunk Analysis

-   Added experimental import/export processing.
-   Added module-level diagnostics.
-   Implemented Windows-to-Android path redirection.
-   Identified 668 unique imported-function thunk entries.

The current thunk addresses are diagnostic placeholders, not executable
ARM64 Windows API implementations.

### Stage 4 --- Runtime Diagnostics

Verified on a physical Samsung Galaxy S22:

-   8 game modules detected by the prototype.
-   Executable EntryPoint address and initial bytes inspected.
-   External DLL thunk breakdown displayed.
-   `config.xml` located and measured at 764 bytes.
-   `core.v` opened and its first 8 bytes read.
-   JNI diagnostic output displayed successfully on Android.

Reading EntryPoint bytes does not mean that the game code has been
executed.

## Current Limitations

The following major components are not implemented yet:

-   x86-to-ARM64 instruction translation or execution.
-   Real, callable Windows API implementations.
-   Complete PE loading and runtime import resolution.
-   Compatible CRT and process initialization.
-   DirectX 9 graphics compatibility.
-   Audio and input compatibility.
-   Complete game resource archive integration.
-   Actual execution of the game EntryPoint.
-   Reaching the Stronghold 3 main menu.

**No successful game-engine launch has been demonstrated yet.**

## Development Environment

  Component                 Details
  ------------------------- -----------------------------
  Test device               Samsung Galaxy S22 SM-S906B
  SoC                       Exynos 2200
  GPU                       Xclipse 920
  Target ABI                arm64-v8a
  Platform                  Android
  Development environment   Termux
  Build system              GitHub Actions
  Native language           C++
  Android interface         JNI

The project is developed and tested using an Android phone.

## Repository Status

-   Branch: `main`
-   Latest validated commit: `73dd89b`
-   Stage 4 GitHub Actions build: successful
-   Stage 4 APK artifact: generated successfully
-   Stage 4 diagnostic runtime: verified on the target phone

The current APK is an experimental diagnostic build, not a playable game
release.

## Roadmap

1.  Improve PE loading and memory management.
2.  Implement essential CRT initialization.
3.  Develop real Windows API compatibility components.
4.  Investigate x86 instruction translation or execution.
5.  Establish a valid game execution environment.
6.  Investigate graphics, audio, input, and resource compatibility.
7.  Attempt the first real game-engine launch.
8.  Work toward reaching the main menu and playable gameplay.

## Game Files and Copyright

This project does not intend to distribute copyrighted Stronghold 3 game
files.

Users must independently obtain their own lawful copy of the game and
provide the required files themselves.

Do not upload or redistribute original game executables, proprietary
DLLs, archives, or copyrighted game assets.

This is an unofficial community development project and is not
affiliated with or endorsed by Firefly Studios or its publishers.

## Project Leadership

**Founder & Project Lead:** Lamine Sehil

Technical contributions will be credited transparently as the project
progresses.

## Disclaimer

This is experimental software. Compatibility, performance, stability,
and successful game execution are not guaranteed.

The project is intended for research, development, and compatibility
experimentation.
