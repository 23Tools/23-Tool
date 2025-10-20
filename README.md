# 23 Tool
**Intelligent Windows Performance Optimizer — Safe, Modular, and Open Source**

 Detect hardware → Build recommendations → Apply safely with backup and restore.

### Features
- Hardware & OS detection (CPU, GPU, RAM, disks, power plan)
- AI-style recommendation engine with priority/risk
- Interactive or non-interactive CLI
- Backup, restore, dry-run, and manifest logging
- Profiles (Gaming, Laptop Balanced)
- 100% Python standard library (no dependencies)

### Quick start
```bash
python 23.py --dry-run
python 23.py --apply-recommended --yes
python 23.py --profile profiles/gaming.json --yes
