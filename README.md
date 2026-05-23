# gradle-dep-audit

> Python script to scan Gradle dependency trees for outdated or vulnerable packages

---

## Installation

```bash
git clone https://github.com/yourusername/gradle-dep-audit.git
pip install -r requirements.txt
```

---

## Usage

Run the script against your Gradle project directory:

```bash
python audit.py --project /path/to/your/gradle-project
```

**Example output:**

```
[OUTDATED]  com.squareup.okhttp3:okhttp  3.12.0  →  4.11.0
[VULNERABLE] org.apache.logging.log4j:log4j-core  2.14.1  CVE-2021-44228
[OK]        com.google.guava:guava  32.1.2-jre
```

### Options

| Flag | Description |
|------|-------------|
| `--project` | Path to the Gradle project root |
| `--output` | Output format: `text`, `json`, or `csv` |
| `--fail-on` | Exit with error on `outdated`, `vulnerable`, or `both` |

```bash
python audit.py --project ./my-app --output json --fail-on vulnerable
```

---

## Requirements

- Python 3.8+
- Gradle 6.0+ installed and accessible via `PATH`

---

## Contributing

Pull requests are welcome. Please open an issue first to discuss any major changes.

---

## License

This project is licensed under the [MIT License](LICENSE).