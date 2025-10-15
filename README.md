# 🔐 PassSec 0.1

**Two-second password audits. Zero compromises.**

<div align="center">

[![Run Quick Check](https://img.shields.io/badge/🚀_Quick_Check-Offline-brightgreen?style=for-the-badge)](https://github.com)
[![Deep Analysis](https://img.shields.io/badge/🔬_Deep_Analysis-Online-blue?style=for-the-badge)](https://github.com)
[![Python 3.6+](https://img.shields.io/badge/Python-3.6+-yellow?style=for-the-badge&logo=python)](https://python.org)

[![MIT License](https://img.shields.io/badge/📜_License-MIT-lightgrey?style=for-the-badge)](LICENSE)
[![HIBP API](https://img.shields.io/badge/🌐_Powered_by-HIBP-orange?style=for-the-badge)](https://haveibeenpwned.com)

</div>

---

## Why This Exists

Your password got pwned? You'd want to know. This checks 600M+ breached passwords in real-time while calculating entropy and crack times. Works offline too.

## 🎯 Quick Start

<table>
<tr>
<td width="50%">

### Installation
```bash
pip install requests
python passec 0.1.py
```

</td>
<td width="50%">

### Run Modes
**1** → Quick Check (Instant)  
**2** → Deep Analysis (Comprehensive)  
**q** → Quit

</td>
</tr>
</table>

## ⚡ Features

<div align="center">

| Mode | Speed | Internet | Score | Special Features |
|:----:|:-----:|:--------:|:-----:|:----------------|
| **Quick** | <1ms | ❌ | 0-5 | Pattern detection |
| **Deep** | ~200ms | ✅ | 0-100 | Breach check, Entropy, Crack time |

</div>

## 📊 Sample Output

```
Strength: Strong
Score: 78/100
Visual: ████████████████████████░░░░░░░
Entropy: 96.72 bits
Crack Time: 2,500,000 years
✓ Not found in breaches
```

## 🔧 Use Programmatically

```python
from password_checker import AdvancedPasswordChecker

result = AdvancedPasswordChecker.deep_analysis("Tr0ub4dor&3")
print(f"Breached: {result['is_breached']}")
```

## 🎨 Score Guide

<div align="center">

![Very Strong](https://img.shields.io/badge/85--100-Very_Strong-success?style=flat-square)
![Strong](https://img.shields.io/badge/70--84-Strong-informational?style=flat-square)
![Moderate](https://img.shields.io/badge/50--69-Moderate-yellow?style=flat-square)
![Weak](https://img.shields.io/badge/30--49-Weak-orange?style=flat-square)
![Critical](https://img.shields.io/badge/0--29-Critical-critical?style=flat-square)

</div>

## 🔒 Privacy

- **k-Anonymity**: Only 5 chars of SHA-1 hash sent
- **Zero Storage**: Nothing logged or saved
- **Local First**: Full password never leaves your machine

## 🙏 Credits

Built on Troy Hunt's [Have I Been Pwned](https://haveibeenpwned.com) API.

