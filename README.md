# dep-audit-cli

> CLI tool to surface outdated and vulnerable dependencies across multiple Python projects at once.

---

## Installation

```bash
pip install dep-audit-cli
```

Or install from source:

```bash
git clone https://github.com/yourname/dep-audit-cli.git
cd dep-audit-cli
pip install .
```

---

## Usage

Run an audit against one or more project directories:

```bash
dep-audit ./my-project ./another-project
```

Check for outdated packages only:

```bash
dep-audit ./my-project --outdated-only
```

Output results as JSON:

```bash
dep-audit ./my-project --format json
```

Example output:

```
[my-project]
  ⚠  requests 2.20.0  →  2.31.0  (CVE-2023-32681)
  ↑  numpy 1.21.0     →  1.26.4

[another-project]
  ✓  All dependencies up to date.
```

### Options

| Flag | Description |
|------|-------------|
| `--outdated-only` | Skip vulnerability checks |
| `--format` | Output format: `text` (default) or `json` |
| `--ignore` | Comma-separated list of packages to skip |

---

## License

This project is licensed under the [MIT License](LICENSE).