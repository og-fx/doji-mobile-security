# Doji Mobile Security

### Mobile Threat Detection, Security Assessment and Digital Forensics

Doji Mobile Security is a desktop-based cybersecurity
application designed to help individuals, security
professionals and investigators identify potential mobile
security threats and investigate device compromise.

## Core Features

- Automatic mobile device discovery
- Android Quick Security Scan
- Android Full Security Scan
- Standalone APK malware analysis
- YARA-based threat detection
- Quark Engine behavioral analysis
- VirusTotal hash reputation checks
- Application permission analysis
- APK digital signature verification
- Accessibility and device administrator checks
- Sampled live security monitoring
- MVT-powered forensic investigations
- SHA-256 evidence integrity verification
- Professional PDF and JSON security reports
- Scan history and report management
- Secure device disconnection guidance

## Scan Modes

| Capability | Quick Scan | Full Scan |
|---|---|---|
| YARA analysis | Yes | Yes |
| VirusTotal hash lookup | Yes | Yes |
| Permission analysis | Yes | Yes |
| APK signature verification | Yes | Yes |
| Quark behavioral analysis | No | Yes |
| Security configuration | Yes | Yes |
| Live monitoring | Yes | Yes |

Quick Scan prioritizes speed and excludes Quark.
Full Scan provides extended behavioral analysis,
subject to engine timeouts and evidence availability.

A Quick Scan completed in approximately four minutes
during development testing. Actual duration depends
on device specifications, installed applications,
USB transfer speed and network availability.

## Threat Detection

Doji examines available evidence for indicators of:

- Android malware
- Remote Access Trojans (RATs)
- Spyware and stalkerware
- Suspicious application capabilities
- Unauthorized security configuration changes
- Known surveillance-related indicators

Detection depends on available evidence, detection
rules and supported analysis methods.

## Supported Platforms

- Host operating system: Kali Linux
- Android: Primary tested mobile platform
- iOS: Experimental forensic capabilities

iOS assessment capabilities have not undergone
equivalent end-to-end release validation.

## Installation

Open a terminal inside the project directory:

```bash
chmod +x INSTALL.sh DOJI-START
./INSTALL.sh
```

The installer prepares system dependencies,
Quark Engine, MVT and local storage directories.

A fresh installation has not yet been independently
validated across different Kali Linux environments.

## Launch Doji

```bash
./DOJI-START
```

## Android Device Scanning

1. Enable Developer Options on your Android phone.
2. Enable USB debugging.
3. Connect the phone using a USB data cable.
4. Authorize the computer when prompted.
5. Open Doji Mobile Security.
6. Select the security scan option.
7. Choose Quick Scan or Full Scan.
8. Wait for the assessment to finish.
9. Review the generated security report.
10. Disconnect securely and disable USB debugging
    when it is no longer required.

## Standalone APK Analysis

Doji can analyze a saved Android APK without
installing or executing the application.

1. Open the APK malware analysis workflow.
2. Select the APK file.
3. Start the assessment.
4. Review the findings and coverage limitations.

## Advanced Forensics

Doji integrates Mobile Verification Toolkit (MVT)
to investigate supported mobile forensic evidence.

Supported evidence workflows include:

- Android bug reports
- AndroidQF evidence
- Android backup evidence
- iOS backups
- iOS filesystem evidence
- iOS sysdiagnose evidence

Availability depends on the installed MVT version,
evidence format and device restrictions.

Current public indicators must be configured before
indicator-based forensic investigations.

## Security Reports

Doji records available findings, analysis results,
coverage limitations and supporting evidence.

Reports may be exported in JSON and PDF formats.

Generated reports are stored locally in:

    reports/

Forensic investigation results are stored in:

    forensic/results/

## Understanding Results

- SUSPICIOUS: Significant threat indicators detected.
- REVIEW REQUIRED: Evidence requires further review.
- NO KNOWN THREAT DETECTED: No known indicators
  were identified by the applicable checks.
- SCAN INCOMPLETE: Required analysis did not finish.

Always review scan completeness independently
of the threat verdict.

A skipped, unavailable or timed-out check must
not be interpreted as a clean result.

## Privacy and Evidence Handling

- APK analysis is performed locally.
- VirusTotal reputation checks use file hashes.
- Routine device scans remove collected APK copies.
- Evidence retention is optional.
- Forensic workflows support integrity verification.
- Private reports and evidence must never be
  committed to public repositories.

## Integrated Technologies

- Android Debug Bridge (ADB)
- YARA
- Quark Engine
- Mobile Verification Toolkit (MVT)
- VirusTotal
- AAPT
- APKSigner
- Python
- Tkinter
- ReportLab

## Limitations

Doji is a security assessment and investigation
platform, not a guarantee of device safety.

Android security restrictions limit access to
protected application data and system components.

Quick Scan does not perform Quark analysis.
Full Scan may encounter analysis timeouts.

Live monitoring observes sampled security changes
and does not provide continuous network inspection.

Known indicators may not identify previously
unknown malware or advanced surveillance tools.

Doji does not automatically remove malware.

## Responsible Use

Only examine devices, applications and forensic
evidence that you own or have explicit permission
to investigate.

## Development Status

Android-focused beta release candidate.

Developed for mobile security assessment,
cybersecurity research and digital forensics.

## Project

Doji Mobile Security

Mobile Security | Threat Detection | Digital Forensics

## License

Doji Mobile Security's original source code is licensed
under the GNU General Public License version 3
(GPL-3.0-only).

See the LICENSE file for the complete license terms.

### Third-Party Software

External dependencies retain their respective licenses.

- Quark Engine: GNU GPL v3
- Mobile Verification Toolkit: MVT License 1.1

These engines are installed separately and are not
bundled or relicensed as part of Doji Mobile Security.

Users must comply with applicable third-party
license terms and usage restrictions.
