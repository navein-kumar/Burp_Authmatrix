# Burp AuthMatrix - Patched Version

[![GitHub](https://img.shields.io/badge/GitHub-navein--kumar-blue)](https://github.com/navein-kumar/Burp_Authmatrix)
[![Burp Suite](https://img.shields.io/badge/Burp%20Suite-2023%2B-orange)](https://portswigger.net/burp)

A patched version of the [AuthMatrix](https://github.com/SecurityInnovation/AuthMatrix) Burp Suite extension with fixes for modern Burp Suite versions.

## 🐛 Issues Fixed

| Issue | Description | Status |
|-------|-------------|--------|
| [#90](https://github.com/SecurityInnovation/AuthMatrix/issues/90) | Duplicate requests when sending to AuthMatrix | ✅ Fixed |
| FlatLaf UI | `setSelected()` error on Burp 2023+ | ✅ Fixed |
| Color Indicators | Hard to distinguish colors | ✅ Changed to V/S/FP |

## 📊 New Result Indicators

Instead of confusing color-only indicators, this version uses clear text labels:

| Indicator | Color | Meaning |
|-----------|-------|---------|
| **S** | 🟢 Green | **Secure** - Access control working correctly |
| **V** | 🔴 Red | **VULNERABLE** - Unauthorized access detected! |
| **FP** | 🔵 Blue | **False Positive** - Check manually (config issue) |
| **-** | ⚪ White | Not tested yet |

## 🔧 Installation

### Option 1: Replace Existing Extension

1. Close Burp Suite completely
2. Navigate to AuthMatrix extension folder:
   ```
   Windows: %APPDATA%\BurpSuite\bapps\30d8ee9f40c041b0bfec67441aad158e\
   macOS:   ~/Library/Application Support/BurpSuite/bapps/30d8ee9f40c041b0bfec67441aad158e/
   Linux:   ~/.BurpSuite/bapps/30d8ee9f40c041b0bfec67441aad158e/
   ```
3. Backup original `AuthMatrix.py`
4. Replace with patched version from this repo
5. Restart Burp Suite

### Option 2: Manual Install

1. Download `AuthMatrix.py` from this repository
2. In Burp Suite: **Extender → Extensions → Add**
3. Extension Type: **Python**
4. Select the downloaded `AuthMatrix.py`

## 📋 Requirements

- Burp Suite Professional 2023+ (tested on v2025.12.2)
- Jython 2.7.3+ configured in Burp Suite
- Python environment for running patch scripts (optional)

## 🛠️ Patches Applied

### 1. Duplicate Request Fix

**Problem:** When right-clicking a request and selecting "Send to AuthMatrix", the request appeared twice.

**Solution:** Added URL+Method deduplication check in `addMessage()` method:

```python
def addMessage(self, messageEntry):
    # Check for existing duplicate
    newUrl = str(self._extender._helpers.analyzeRequest(messageEntry._requestResponse).getUrl())
    newMethod = self._extender._helpers.analyzeRequest(messageEntry._requestResponse).getMethod()
    
    for existing in self.arrayOfMessages:
        if not existing._deleted:
            existingUrl = str(self._extender._helpers.analyzeRequest(existing._requestResponse).getUrl())
            existingMethod = self._extender._helpers.analyzeRequest(existing._requestResponse).getMethod()
            if existingUrl == newUrl and existingMethod == newMethod:
                return  # Skip duplicate
    
    self.arrayOfMessages.add(messageEntry)
```

### 2. FlatLaf UI Compatibility

**Problem:** Burp Suite 2023+ uses FlatLaf UI which doesn't support `setSelected()` method, causing:
```
AttributeError: 'com.formdev.flatlaf.ui.FlatTableUI$FlatBooleanRend' object has no attribute 'setSelected'
```

**Solution:** Replace `cell.setSelected(True/False)` with `pass`:
```python
# Old (broken):
cell.setSelected(True)

# New (fixed):
pass  # FlatLaf compatibility
```

### 3. Text-Based Result Indicators

**Problem:** Color-only indicators (green/red/blue) can be difficult to distinguish, especially for colorblind users.

**Solution:** Added text labels (S/V/FP) alongside colors for clarity.

## 📝 Usage

1. **Create Roles:** Admin, User, Anonymous, etc.
2. **Create Users:** Add users with their session cookies/tokens
3. **Send Requests:** Right-click in HTTP History → Send to AuthMatrix
4. **Configure Access:** Check which roles SHOULD have access
5. **Run Tests:** Click "Run" button
6. **Review Results:**
   - **S (Green)** = Working as expected ✓
   - **V (Red)** = **VULNERABILITY FOUND!** ⚠️
   - **FP (Blue)** = Check your configuration

## 🤝 Contributing

Feel free to submit issues and pull requests!

## 📜 License

Same as original AuthMatrix - see [SecurityInnovation/AuthMatrix](https://github.com/SecurityInnovation/AuthMatrix)

## 🙏 Credits

- Original AuthMatrix by [Security Innovation](https://github.com/SecurityInnovation/AuthMatrix)
- Patches by [Naveen Kumar](https://github.com/navein-kumar) - CodeSecure Solutions

## 📧 Contact

- **Author:** Naveen Kumar
- **Company:** CodeSecure Solutions
- **LinkedIn:** [Connect](https://linkedin.com/in/navein-kumar)
- **Website:** [codesecure.in](https://codesecure.in)

---

**⭐ Star this repo if it helped you!**
