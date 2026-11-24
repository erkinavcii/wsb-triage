"""Windows Sandbox / VirtualBox helpers: capabilities, hardened .wsb / wsb CLI, start/stop, VM execution & isolation."""
import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
from xml.sax.saxutils import escape

BASE_DIR = Path(__file__).parent.resolve()
WSB_EXE = Path(os.environ.get("WINDIR", r"C:\Windows")) / "System32" / "WindowsSandbox.exe"
VBOX_EXE = Path(r"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe")
NO_WINDOW = 0x08000000
_GUID_RX = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")


def _run(args: List[str], timeout: int = 30) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout, encoding="utf-8",
                          errors="replace", creationflags=NO_WINDOW)


def find_tool(name: str, candidates: List[str]) -> str:
    found = shutil.which(name)
    if found:
        return found
    for c in candidates:
        if c and Path(c).exists():
            return c
    return ""


def seven_zip_path() -> str:
    pf, pf86 = os.environ.get("ProgramFiles", r"C:\Program Files"), os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
    return find_tool("7z.exe", [rf"{pf}\7-Zip\7z.exe", rf"{pf86}\7-Zip\7z.exe"])


def tshark_path() -> str:
    pf = os.environ.get("ProgramFiles", r"C:\Program Files")
    return find_tool("tshark.exe", [rf"{pf}\Wireshark\tshark.exe"])


def innoextract_path() -> str:
    pf, pf86 = os.environ.get("ProgramFiles", r"C:\Program Files"), os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
    return find_tool("innoextract.exe", [
        rf"{pf}\InnoExtract\innoextract.exe",
        rf"{pf86}\InnoExtract\innoextract.exe",
        str(BASE_DIR / "tools" / "innoextract.exe"),
        str(BASE_DIR / "sandbox" / "innoextract.exe"),
    ])


def wsb_cli_path() -> str:
    local_app = os.environ.get("LOCALAPPDATA", "")
    win_dir = os.environ.get("WINDIR", r"C:\Windows")
    cands = [
        rf"{local_app}\Microsoft\WindowsApps\wsb.exe" if local_app else "",
        rf"{win_dir}\System32\wsb.exe",
    ]
    return find_tool("wsb.exe", cands)


def windows_sandbox_available() -> bool:
    return WSB_EXE.exists() or bool(wsb_cli_path())


def vbox_manage_path() -> str:
    if VBOX_EXE.exists():
        return str(VBOX_EXE)
    msi_dir = os.environ.get("VBOX_MSI_INSTALL_PATH", "").rstrip("\\/")
    pf, pf86 = os.environ.get("ProgramFiles", r"C:\Program Files"), os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
    cands = [
        rf"{msi_dir}\VBoxManage.exe" if msi_dir else "",
        rf"{pf}\Oracle\VirtualBox\VBoxManage.exe",
        rf"{pf86}\Oracle\VirtualBox\VBoxManage.exe",
    ]
    return find_tool("VBoxManage.exe", cands)


def windows_version() -> str:
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion") as k:
            build = int(winreg.QueryValueEx(k, "CurrentBuildNumber")[0])
            edition = winreg.QueryValueEx(k, "EditionID")[0]
        name = "Windows 11" if build >= 22000 else "Windows 10"
        return f"{name} {edition} (build {build})"
    except Exception:
        return "Windows"


def list_vbox_vms() -> List[Dict[str, str]]:
    vms: List[Dict[str, str]] = []
    vbox = vbox_manage_path()
    if not vbox:
        return vms
    try:
        proc = _run([vbox, "list", "vms"], timeout=10)
        for line in proc.stdout.strip().splitlines():
            if '"' in line and "{" in line:
                vms.append({"name": line.split('"')[1], "uuid": line.split("{")[1].split("}")[0]})
    except Exception:
        pass
    return vms


def list_vbox_snapshots(vm_name: str) -> List[str]:
    vbox = vbox_manage_path()
    if not vbox or not vm_name:
        return []
    try:
        proc = _run([vbox, "snapshot", vm_name, "list", "--machinereadable"], timeout=15)
        if proc.returncode != 0:
            return []
        snaps: List[str] = []
        for line in proc.stdout.splitlines():
            if line.startswith("SnapshotName"):
                val = line.split("=", 1)[1].strip().strip('"')
                if val and val not in snaps:
                    snaps.append(val)
        return snaps
    except Exception:
        return []


def get_system_capabilities() -> Dict[str, Any]:
    vbox = vbox_manage_path()
    return {
        "os": windows_version(),
        "windows_sandbox_enabled": windows_sandbox_available(),
        "wsb_cli": wsb_cli_path(),
        "seven_zip": seven_zip_path(),
        "tshark": tshark_path(),
        "innoextract": innoextract_path(),
        "vbox_manage": vbox,
        "virtualbox_installed": bool(vbox),
        "virtualbox_vms": list_vbox_vms(),
        "sandbox_running": sandbox_running(),
    }


def enable_windows_sandbox_feature() -> Dict[str, Any]:
    """Opens an elevated (UAC) PowerShell that enables the Windows Sandbox feature."""
    ps_script = (
        "Write-Host 'Windows Sandbox etkinlestiriliyor...' -ForegroundColor Cyan; "
        "Enable-WindowsOptionalFeature -Online -FeatureName 'Containers-DisposableClientVM' -All; "
        "Write-Host ''; Write-Host 'Tamamlandi. Bilgisayari yeniden baslatin.' -ForegroundColor Green; Pause"
    )
    try:
        subprocess.run(["powershell", "-NoProfile", "-Command",
                        f"Start-Process powershell -Verb RunAs -ArgumentList '-NoProfile -Command \"{ps_script}\"'"],
                       timeout=15, creationflags=NO_WINDOW)
        return {"status": "started",
                "message": "Yönetici (UAC) onay penceresi açıldı. Onaydan sonra özellik kurulur; aktif olması için bilgisayarı yeniden başlatın."}
    except Exception as e:
        return {"status": "error", "message": f"Yönetici penceresi açılamadı: {e}"}


# ------------------------------------------------------------------ Windows Sandbox
def build_wsb(case_dir: Path, network: bool, memory_mb: int = 4096, input_dir: Optional[Path] = None) -> str:
    """Hardened config: sample/tools read-only, only output writable, no clipboard/vGPU/printer/audio/camera.
    input_dir lets a user-selected folder be mapped read-only in place instead of being copied."""
    maps = [
        (input_dir or (case_dir / "input"), r"C:\Analysis\input", "true"),
        (case_dir / "tools", r"C:\Analysis\tools", "true"),
        (case_dir / "output", r"C:\Analysis\output", "false"),
    ]
    map_xml = "\n".join(
        f"    <MappedFolder><HostFolder>{escape(str(h))}</HostFolder><SandboxFolder>{b}</SandboxFolder><ReadOnly>{ro}</ReadOnly></MappedFolder>"
        for h, b, ro in maps
    )
    safe_memory = max(1024, min(65536, int(memory_mb or 4096)))
    return f"""<Configuration>
  <VGpu>Disable</VGpu>
  <Networking>{"Enable" if network else "Disable"}</Networking>
  <MemoryInMB>{safe_memory}</MemoryInMB>
  <AudioInput>Disable</AudioInput>
  <VideoInput>Disable</VideoInput>
  <PrinterRedirection>Disable</PrinterRedirection>
  <ClipboardRedirection>Disable</ClipboardRedirection>
  <ProtectedClient>Enable</ProtectedClient>
  <MappedFolders>
{map_xml}
  </MappedFolders>
  <LogonCommand>
    <Command>powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\\Analysis\\tools\\Inside-Sandbox.ps1</Command>
  </LogonCommand>
</Configuration>
"""


_SANDBOX_IDLE_BROKERS = {"windowssandboxserver.exe"}


def _sandbox_processes() -> Optional[List[str]]:
    """Names of running Windows Sandbox session processes (excluding the persistent Win11 24H2+
    WindowsSandboxServer.exe idle broker daemon), or None if the check itself failed."""
    try:
        p = _run(["tasklist", "/fo", "csv", "/nh"], timeout=30)
        if p.returncode != 0 or not p.stdout.strip():
            return None
    except Exception:
        return None
    names = []
    for line in p.stdout.splitlines():
        name = line.split('","')[0].strip('"')
        low = name.lower()
        if low.startswith("windowssandbox") and low not in _SANDBOX_IDLE_BROKERS:
            names.append(name)
    return names


def wsb_list_ids() -> Optional[List[str]]:
    """Lists active Windows Sandbox IDs via `wsb.exe`. Returns None if `wsb.exe` is unavailable or failed."""
    wsb = wsb_cli_path()
    if not wsb:
        return None
    try:
        proc = _run([wsb, "list", "--raw"], timeout=15)
        raw = (proc.stdout or "").strip()
        if proc.returncode == 0 and raw:
            try:
                parsed = json.loads(raw)
                items = parsed if isinstance(parsed, list) else ([parsed] if isinstance(parsed, dict) else [])
                ids: List[str] = []
                for it in items:
                    if not isinstance(it, dict):
                        continue
                    status = str(it.get("Status") or it.get("status") or "").lower()
                    if status == "stopped":
                        continue
                    sid = str(it.get("Id") or it.get("id") or "")
                    if _GUID_RX.fullmatch(sid):
                        ids.append(sid)
                return ids
            except Exception:
                pass
        proc2 = _run([wsb, "list"], timeout=15)
        if proc2.returncode != 0:
            return None
        ids = []
        for line in (proc2.stdout or "").splitlines():
            if "stopped" in line.lower():
                continue
            ids.extend(_GUID_RX.findall(line))
        return ids
    except Exception:
        return None


def sandbox_state() -> Optional[bool]:
    """True = running, False = not running, None = unknown (check failed; do NOT treat as closed)."""
    names = _sandbox_processes()
    wsb_ids = wsb_list_ids()
    if names or wsb_ids:
        return True
    if names is None and wsb_ids is None:
        return None
    return False


def sandbox_running() -> bool:
    return bool(sandbox_state())


def launch_sandbox(wsb_path: Path) -> Optional[str]:
    """Starts Windows Sandbox via `wsb start --config` when available, falling back to `.wsb` shell launch."""
    wsb = wsb_cli_path()
    if wsb and wsb_path.is_file():
        try:
            xml_cfg = wsb_path.read_text(encoding="utf-8")
            proc = _run([wsb, "start", "--config", xml_cfg, "--raw"], timeout=60)
            if proc.returncode != 0:
                proc = _run([wsb, "start", "--config", xml_cfg], timeout=60)
            if proc.returncode == 0:
                out = (proc.stdout or "").strip()
                try:
                    data = json.loads(out)
                    sid = str((data or {}).get("Id") or (data or {}).get("id") or "")
                    if _GUID_RX.fullmatch(sid):
                        return sid
                except Exception:
                    pass
                m = _GUID_RX.search(out)
                return m.group(0) if m else None
        except Exception:
            pass
    os.startfile(str(wsb_path))
    return None


def stop_sandbox(session_id: Optional[str] = None) -> None:
    wsb = wsb_cli_path()
    if wsb:
        try:
            seen: set = set()
            if session_id and _GUID_RX.fullmatch(session_id):
                _run([wsb, "stop", "--id", session_id], timeout=30)
                seen.add(session_id.lower())
            for sid in (wsb_list_ids() or []):
                if sid.lower() not in seen:
                    _run([wsb, "stop", "--id", sid], timeout=30)
                    seen.add(sid.lower())
        except Exception:
            pass
    time.sleep(3)
    for name in set(_sandbox_processes() or []):
        try:
            _run(["taskkill", "/f", "/im", name], timeout=15)
        except Exception:
            pass


# ------------------------------------------------------------------ VirtualBox
def _vm_state(vm_name: str) -> str:
    vbox = vbox_manage_path()
    if not vbox:
        return "unknown"
    proc = _run([vbox, "showvminfo", vm_name, "--machinereadable"], timeout=15)
    for line in proc.stdout.splitlines():
        if line.startswith("VMState="):
            return line.split("=", 1)[1].strip('"')
    return "unknown"


def harden_and_snapshot_virtualbox_vm(vm_name: str) -> Dict[str, Any]:
    """Cuts network/clipboard/drag&drop of a powered-off VM and takes a clean snapshot. Every step is verified."""
    vbox = vbox_manage_path()
    if not vbox:
        return {"status": "error", "message": "VirtualBox (VBoxManage.exe) bulunamadı."}
    try:
        state = _vm_state(vm_name)
        if state not in ("poweroff", "aborted", "saved"):
            return {"status": "error",
                    "message": f"'{vm_name}' şu an '{state}' durumunda. Ayarlar ancak VM kapalıyken değişir; önce VM'i kapatın."}
        steps, failed = [], []
        # Each setting: VirtualBox 7 option names first, older 6.x names as fallback.
        checks = [
            ([["--nic1", "none", "--nic2", "none", "--nic3", "none", "--nic4", "none"]], "Tüm ağ kartları kapatıldı"),
            ([["--clipboard-mode", "disabled"], ["--clipboard", "disabled"]], "Pano paylaşımı kapatıldı"),
            ([["--drag-and-drop", "disabled"], ["--draganddrop", "disabled"]], "Sürükle-bırak kapatıldı"),
            ([["--usb-ohci", "off", "--usb-ehci", "off", "--usb-xhci", "off"], ["--usb", "off", "--usbehci", "off", "--usbxhci", "off"]],
             "USB denetleyicileri kapatıldı (USB bellek / cihaz geçişi yok)"),
            ([["--accelerate-3d", "off"], ["--accelerate3d", "off"]], "3D hızlandırma kapatıldı (grafik sürücüsü saldırı yüzeyi)"),
            ([["--vrde", "off"]], "Uzaktan ekran (VRDE) kapatıldı"),
        ]
        for variants, label in checks:
            err = ""
            for opts in variants:
                p = _run([vbox, "modifyvm", vm_name] + opts, timeout=20)
                if p.returncode == 0:
                    steps.append(label)
                    break
                err = (p.stderr or p.stdout).strip()[:200]
            else:
                failed.append(f"{label} — BAŞARISIZ: {err}")
        shared = _run([vbox, "showvminfo", vm_name, "--machinereadable"], timeout=15).stdout
        if "SharedFolderNameMachineMapping" in shared:
            failed.append("VM'de paylaşılan klasör var — VirtualBox ayarlarından kaldırın (zararlı oradan ana bilgisayara ulaşabilir).")
        snap = f"SafeBox_Temiz_{datetime.now().strftime('%Y%m%d_%H%M')}"
        p = _run([vbox, "snapshot", vm_name, "take", snap, "--description", "SafeBox analiz oncesi temiz yedek"], timeout=120)
        (steps if p.returncode == 0 else failed).append(
            f"Temiz snapshot alındı: '{snap}'" if p.returncode == 0 else f"Snapshot alınamadı: {(p.stderr or p.stdout).strip()[:200]}")
        return {
            "status": "ok" if not failed else "partial",
            "vm_name": vm_name,
            "steps": steps + failed,
            "message": (f"'{vm_name}' izole edildi." if not failed else f"'{vm_name}' için bazı adımlar başarısız oldu, aşağıya bakın.")
                       + " Not: Bu VM'i başka işler için de kullanıyorsanız (hesap oturumları vb.) zararlı testi için ayrı bir VM kullanın.",
        }
    except Exception as e:
        return {"status": "error", "message": f"VirtualBox yapılandırma hatası: {e}"}


def vbox_start_analysis(
    vm_name: str,
    snapshot_name: str,
    input_dir: Path,
    tools_dir: Path,
    output_dir: Path,
    network: bool,
    guest_user: str,
    guest_pass: str,
    log_cb: Optional[Callable[[str], None]] = None,
) -> str:
    """Restores a clean VirtualBox snapshot, isolates peripherals, mounts shared folders and starts Inside-Sandbox.ps1."""
    vbox = vbox_manage_path()
    if not vbox:
        raise RuntimeError("VirtualBox (VBoxManage.exe) bulunamadı.")
    if not vm_name:
        raise RuntimeError("VirtualBox VM adı belirtilmedi.")
    if not guest_user:
        raise RuntimeError("VirtualBox misafir Windows kullanıcı adı belirtilmedi.")

    snaps = list_vbox_snapshots(vm_name)
    snap = (snapshot_name or "").strip()
    if not snap:
        clean_snaps = [s for s in snaps if s.startswith("SafeBox_Temiz_")]
        snap = clean_snaps[-1] if clean_snaps else (snaps[-1] if snaps else "")
    if not snap:
        raise RuntimeError(f"'{vm_name}' için temiz snapshot bulunamadı. Önce 'VM'i izole et + snapshot' butonunu kullanın.")

    if log_cb:
        log_cb(f"VirtualBox VM '{vm_name}' temiz snapshot'a ({snap}) döndürülüyor...")
    state = _vm_state(vm_name)
    if state in ("running", "paused", "stuck"):
        _run([vbox, "controlvm", vm_name, "poweroff"], timeout=30)
        time.sleep(2)

    rp = _run([vbox, "snapshot", vm_name, "restore", snap], timeout=120)
    if rp.returncode != 0:
        raise RuntimeError(f"Snapshot geri yüklenemedi ({snap}): {(rp.stderr or rp.stdout).strip()[:200]}")

    for opts in (
        ["--clipboard-mode", "disabled"],
        ["--drag-and-drop", "disabled"],
        ["--usb-ohci", "off", "--usb-ehci", "off", "--usb-xhci", "off"],
        ["--nic1", "nat" if network else "none", "--nic2", "none", "--nic3", "none", "--nic4", "none"],
    ):
        _run([vbox, "modifyvm", vm_name] + opts, timeout=20)

    sp = _run([vbox, "startvm", vm_name, "--type", "gui"], timeout=60)
    if sp.returncode != 0:
        raise RuntimeError(f"VirtualBox VM başlatılamadı: {(sp.stderr or sp.stdout).strip()[:200]}")

    if log_cb:
        log_cb("VirtualBox Guest Additions bekleniyor...")
    ready = False
    deadline = time.time() + 120
    while time.time() < deadline:
        cmd_stat = [vbox, "guestcontrol", vm_name, "stat", "--username", guest_user]
        if guest_pass:
            cmd_stat += ["--password", guest_pass]
        cmd_stat.append(r"C:\Windows\System32\cmd.exe")
        gp = _run(cmd_stat, timeout=15)
        if gp.returncode == 0:
            ready = True
            break
        time.sleep(3)
    if not ready:
        vbox_stop_and_restore(vm_name, snap)
        raise RuntimeError("VirtualBox Guest Additions yanıt vermedi (oturum bilgisi veya Guest Additions kurulumunu kontrol edin).")

    for name, host_p, ro in (("sb_input", input_dir, True), ("sb_tools", tools_dir, True), ("sb_output", output_dir, False)):
        _run([vbox, "sharedfolder", "remove", vm_name, "--name", name, "--transient"], timeout=10)
        args = [vbox, "sharedfolder", "add", vm_name, "--name", name, "--hostpath", str(host_p), "--transient"]
        if ro:
            args.append("--readonly")
        sf = _run(args, timeout=15)
        if sf.returncode != 0:
            vbox_stop_and_restore(vm_name, snap)
            raise RuntimeError(f"Paylaşılan klasör ({name}) bağlanamadı: {(sf.stderr or sf.stdout).strip()[:200]}")

    gc = [vbox, "guestcontrol", vm_name, "start", "--username", guest_user]
    if guest_pass:
        gc += ["--password", guest_pass]
    gc += [
        "--exe", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "--",
        "-NoProfile", "-ExecutionPolicy", "Bypass",
        "-File", r"\\VBoxSvr\sb_tools\Inside-Sandbox.ps1",
        "-InputDir", r"\\VBoxSvr\sb_input",
        "-ToolsDir", r"\\VBoxSvr\sb_tools",
        "-OutputDir", r"\\VBoxSvr\sb_output",
    ]
    gp_start = _run(gc, timeout=30)
    if gp_start.returncode != 0:
        vbox_stop_and_restore(vm_name, snap)
        raise RuntimeError(f"VM içinde izleyici başlatılamadı: {(gp_start.stderr or gp_start.stdout).strip()[:200]}")
    return snap


def vbox_stop_and_restore(vm_name: str, snapshot_name: str = "") -> None:
    vbox = vbox_manage_path()
    if not vbox or not vm_name:
        return
    try:
        _run([vbox, "controlvm", vm_name, "poweroff"], timeout=30)
        time.sleep(2)
        if snapshot_name:
            _run([vbox, "snapshot", vm_name, "restore", snapshot_name], timeout=120)
    except Exception:
        pass


# ------------------------------------------------------------------ Explorer Right-Click Context Menu (HKCU, no UAC)
_CTX_ROOTS = (
    r"Software\Classes\*\shell\SafeBoxAnalyze",
    r"Software\Classes\Directory\shell\SafeBoxAnalyze",
)


def _context_command() -> str:
    py = Path(sys.executable)
    pyw = py.with_name("pythonw.exe")
    launcher = pyw if pyw.exists() else py
    script = (BASE_DIR / "enqueue.py").resolve()
    return f'"{launcher}" "{script}" "%1"'


def context_menu_status() -> bool:
    if os.name != "nt":
        return False
    import winreg
    try:
        for root in _CTX_ROOTS:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, f"{root}\\command"):
                pass
        return True
    except OSError:
        return False


def set_context_menu(enabled: bool) -> Dict[str, Any]:
    if os.name != "nt":
        return {"status": "error", "enabled": False, "message": "Sağ tık menüsü yalnızca Windows'ta desteklenir."}
    import winreg
    if enabled:
        cmd = _context_command()
        icon = os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "System32", "shell32.dll") + ",48"
        for root in _CTX_ROOTS:
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, root) as k:
                winreg.SetValueEx(k, "", 0, winreg.REG_SZ, "SafeBox ile analiz et")
                winreg.SetValueEx(k, "Icon", 0, winreg.REG_SZ, icon)
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, f"{root}\\command") as kc:
                winreg.SetValueEx(kc, "", 0, winreg.REG_SZ, cmd)
        return {"status": "ok", "enabled": True, "message": "Dosya Gezgini sağ tık menüsü eklendi (HKEY_CURRENT_USER)."}
    for root in _CTX_ROOTS:
        for sub in (f"{root}\\command", root):
            try:
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, sub)
            except FileNotFoundError:
                pass
    return {"status": "ok", "enabled": False, "message": "Dosya Gezgini sağ tık menüsü kaldırıldı."}
