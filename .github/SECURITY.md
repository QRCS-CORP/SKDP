# Security Policy

## Supported Versions

We support the latest release of SKDP. Older versions are not maintained and may be vulnerable.

| Version | Supported |
|---------|-----------|
| 1.x     | ✅ Yes     |
| < 1.0   | ❌ No      |

## Reporting a Vulnerability

If you discover a security vulnerability in SKDP, **please report it privately** and responsibly.

- **Do not** file public GitHub issues.
- Contact us at: [security@qrcs.ca](mailto:security@qrcs.ca)
- Include:
  - A clear description of the issue
  - Steps to reproduce
  - A proposed fix if available

We will respond within 72 hours and aim to provide a patch within 7 days, depending on severity.

## Disclosure Policy

We follow a coordinated disclosure approach:

1. The reporter contacts us privately.
2. We assess, fix, and test internally.
3. We release an update and optionally credit the reporter.
4. You may publicly disclose the issue after the fix is released.

## Our Commitments

- All code is reviewed for **MISRA C 2023**, **CERT C**, and **FIPS 140-3** compliance.
- All cryptographic operations are designed to be **constant-time** and **side-channel resistant**.
- Static and dynamic analysis tools such as **CodeQL** and **Cppcheck** are used regularly.
- Dependencies are scanned and updated proactively.

## Hall of Fame

If you responsibly disclose a severe issue, we’d be happy to include your name here with your permission.

---

Thank you for helping us keep SKDP secure.
