# TrustGuard Security Lab

A standalone Android application for local, offline inspection of APK files.

## Features
- Select an APK through Android's document picker.
- Display package name, version, and debuggable flag.
- List declared permissions.
- List exported activities, services, receivers, and providers.
- Calculate the selected APK's SHA-256 hash.
- No INTERNET permission; no upload or remote analysis.

## Build
Requires JDK 17, Android SDK 35, and Gradle 8.9.

```bash
gradle --no-daemon :app:assembleDebug
```

APK output: `app/build/outputs/apk/debug/app-debug.apk`.

## Privacy and limitations
Analysis runs on-device. Exported components and permissions are review indicators, not a verdict that an app is malicious. The app does not verify every signature scheme or perform full malware detection.
