#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
command -v gradle >/dev/null || { echo 'Gradle 8.11.1+ required. Use .github/workflows/android-apk.yml for a no-local-SDK cloud build.' >&2; exit 2; }
: "${ANDROID_HOME:?Android SDK required for building only. Use the GitHub Actions build to avoid installing it.}"
bash tests/run-offline.sh
gradle :app:assembleDebug --no-daemon
printf '\nAPK: %s\n' "$PWD/app/build/outputs/apk/debug/app-debug.apk"
