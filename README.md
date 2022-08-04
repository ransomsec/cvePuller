# CVE Puller

## A tool for pulling latest Top-10 CVEs from [CVE-TREND](https://cvetrends.com/) to your Black-Terminal. ;)
### AKA Real-Time CVE puller.

- [Usage](#usage)
- [Installation](#installation)
- [About](#about)

![dahBoard](https://github.com/ransomsec/cvePuller/blob/main/images/dash-board.jpg)
![info](https://github.com/ransomsec/cvePuller/blob/main/images/info.jpg)

### Usage:

- **help**
```html
➜ cvePuller --help
Usage of cvePuller:
  -all
    	Detail like CVE-ID, Description, Assigner, Severity (Usage: --cve day/week -all)
  -cve string
    	Only CVE ID. (Usage: --cve day, --cve week)
  -info string
    	All info about specific CVE (Usage: -info CVE-XXXX-XXXX)
  -sa
    	For Severity and Assigner (Usage: --cve day/week -sa)

```

- **Fetch only CVE ID Day/Week**
```html
➜ cvePuller -cve day/week
[1]  ➜  CVE-XXXX-XXXXX
[2]  ➜  CVE-XXXX-XXXXX
[3]  ➜  CVE-XXXX-XXXXX
```

- **All Detail like! CVE-ID, Description, Assigner, Severity. Max(10)**
```html
➜ cvePuller -cve day/week -all

CVE ID 1: CVE-XXXX-XXXXX
DESCRIPTION: Find a critical bug in your mind. ;)
ASSIGNER: ransomsec@ransomsec.org
SEVERITY: CRITICAL

CVE ID 2: CVE-XXXX-XXXXX
```

- **Fetch info about specific CVE ID**
```html
➜  cvePuller -info CVE-2022-30190

CVE ID: CVE-2022-30190
ASSIGNER: secure@microsoft.com
DESCRIPTION: Microsoft Windows Support Diagnostic Tool (MSDT) Remote Code Execution Vulnerability.
SEVERITY: HIGH
PUBLISHED-DATE: 2022-06-01T20:15Z
```

### **Note: Currently cvePuller fetch only top 10 CVEs.**

### Installation:
- **Make sure you installed go verison 1.18 or upper (BOTH)**
- Direct Download from : [Release Page](https://github.com/ransomsec/cvePuller/releases/tag/cvePuller)
  - For Linux (Local Compile)
```html
make linux
```
- Direct Download from: [Release Page](https://github.com/ransomsec/cvePuller/releases/tag/cvePuller)
  - For Windows (Local Compile)
```html
make windows
```

### About:
**This tool is totally written in Golang! Only for fun, practice and my learning so, if you find any Issue or you want to give me any Suggestion please contact me on [ransomsec](https://twitter.com/ransomsec). And last i am not expert so if you find any mistake ping me. Thank You ;)**
