#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p build/offline-tests
javac -d build/offline-tests app/src/main/java/ai/hb/smartdns/{DnsEngine,SmartRoute,PacketCodec,DnsProxy}.java tests/OfflineTest.java
java -cp build/offline-tests OfflineTest
node --check app/src/main/assets/web/app.js
