# NetTrace Troubleshooting Guide

This guide details common operational scenarios, diagnostic error messages, and corrective steps.

---

## 1. Backend / Python Issues

### Issue: `ModuleNotFoundError: No module named 'app'`
- **Cause:** Running python or pytest from an incorrect directory without the current folder on `PYTHONPATH`.
- **Solution:** Execute commands from the `backend/` directory or run `scripts/verify.ps1` / `scripts/start.ps1`. The `backend/pyproject.toml` file includes `pythonpath = ["."]`.

### Issue: `Port 8000 already in use`
- **Cause:** An existing instance of uvicorn is running.
- **Solution (Windows PowerShell):**
  ```powershell
  Get-NetTCPConnection -LocalPort 8000 | ForEach-Object { Stop-Process -Id $_.OwningProcess -Force }
  ```
- **Solution (Linux):**
  ```bash
  fuser -k 8000/tcp
  ```

### Issue: Scapy warning `No libpcap provider available ! pcap won't be used`
- **Cause:** WinPcap or Npcap is not installed on Windows.
- **Impact:** None for offline PCAP reading! Scapy's native Python `PcapReader` reads offline PCAP and PCAPNG files without requiring WinPcap or Npcap. Live sniffing is intentionally not supported.

---

## 2. Frontend / Node Issues

### Issue: `npm.ps1 cannot be loaded because running scripts is disabled`
- **Cause:** Windows PowerShell script execution policy prevents `.ps1` execution.
- **Solution:** Run `npm.cmd` instead of `npm`, or run PowerShell with `-ExecutionPolicy Bypass`:
  ```powershell
  npm.cmd run dev
  ```

### Issue: `NetworkError when attempting to fetch resource`
- **Cause:** Frontend cannot communicate with the FastAPI backend.
- **Solution:** Verify the backend is active at `http://127.0.0.1:8000/api/v1/health`. Ensure the Vite proxy in `frontend/vite.config.ts` is pointing to `http://127.0.0.1:8000`.

---

## 3. PCAP Ingestion & Parsing

### Issue: `Invalid file content: Missing valid PCAP or PCAPNG header magic bytes`
- **Cause:** The uploaded file has a `.pcap` extension but does not contain valid pcap header bytes (e.g. text file or corrupted container).
- **Solution:** Ensure the capture was created with a standard packet logger (e.g. tcpdump, Wireshark) or generated using `samples/generate_samples.py`.

### Issue: `File exceeds maximum upload size of 100 MB`
- **Cause:** Capture file is larger than the default limit.
- **Solution:** Increase the ceiling in `backend/app/core/config.py` (`MAX_UPLOAD_SIZE_MB = 200`) or in environment variable `NETTRACE_MAX_UPLOAD_SIZE_MB`.
