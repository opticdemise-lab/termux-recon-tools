# A Toolkit I'm working on currently Nov 19 26 P.S I will probably forget to update.

A collection of custom reconnaissance and automation scripts. 

> **Disclaimer:** These tools are intended for educational purposes and authorized security testing only. Users are responsible for complying with all applicable laws and program rules.

## Scripts Included

* **`recon.py` (Stable):** General reconnaissance script that routes output directly into an encrypted vault.
* **`h1_recon.py` (Bug Bounty):** Tailored specifically for HackerOne targets. Requires minor configuration before running.
* **`Spyder.py` (In Development):** Currently a work in progress—check back for updates.

---

## Setup & Configuration

### 1. HackerOne Tag (`h1_recon.py`)
Before running `h1_recon.py`, open your config file and set your personal HackerOne identifier so your traffic is properly tagged:
```python
USERNAME = "YOUR_OWN_TAG"
```

### 2. Adjusting FFUF Rate Limits
By default, FFUF is configured with conservative rate limits to avoid getting blocked or violating program rules. If you want to adjust the speed or threads, modify the flags in the script here:
```python
"-ac", "-t", "4", "-rate", "4", "-timeout", "18", "-noninteractive"
```
