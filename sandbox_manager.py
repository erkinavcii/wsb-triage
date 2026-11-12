"""Windows Sandbox / VirtualBox helpers: capabilities, hardened .wsb, start/stop, VM isolation."""
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from xml.sax.saxutils import escape

BASE_DIR = Path(__file__).parent.resolve()
WSB_EXE = Path(os.environ.get("WINDIR", r"C:\Windows")) / "System32" / "WindowsSandbox.exe"
VBOX_EXE = Path(r"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe")
NO_WINDOW = 0x08000000


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
    if not VBOX_EXE.exists():
        return vms
    try:
        proc = _run([str(VBOX_EXE), "list", "vms"], timeout=10)
        for line in proc.stdout.strip().splitlines():
            if '"' in line and "{" in line:
                vms.append({"name": line.split('"')[1], "uuid": line.split("{")[1].split("}")[0]})
    except Exception:
        pass
    return vms


def get_system_capabilities() -> Dict[str, Any]:
    return {
        "os": windows_version(),
        "windows_sandbox_enabled": WSB_EXE.exists(),
        "seven_zip": seven_zip_path(),
        "tshark": tshark_path(),
        "virtualbox_installed": VBOX_EXE.exists(),
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


def _sandbox_processes() -> Optional[List[str]]:
    """Names of running Windows Sandbox processes, or None if the check itself failed (e.g. tasklist timed out)."""
    try:
        p = _run(["tasklist", "/fo", "csv", "/nh"], timeout=30)
        if p.returncode != 0 or not p.stdout.strip():
            return None
    except Exception:
        return None
    names = []
    for line in p.stdout.splitlines():
        name = line.split('","')[0].strip('"')
        if name.lower().startswith("windowssandbox"):
            names.append(name)
    return names


def sandbox_state() -> Optional[bool]:
    """True = running, False = not running, None = unknown (check failed; do NOT treat as closed)."""
    names = _sandbox_processes()
    return None if names is None else bool(names)


def sandbox_running() -> bool:
    return bool(sandbox_state())


def launch_sandbox(wsb_path: Path) -> None:
    os.startfile(str(wsb_path))


def stop_sandbox() -> None:
    wsb = shutil.which("wsb.exe")
    if wsb:
        try:
            import re
            out = _run([wsb, "list"], timeout=15).stdout
            for sid in re.findall(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", out):
                _run([wsb, "stop", "--id", sid], timeout=30)
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
    proc = _run([str(VBOX_EXE), "showvminfo", vm_name, "--machinereadable"], timeout=15)
    for line in proc.stdout.splitlines():
        if line.startswith("VMState="):
            return line.split("=", 1)[1].strip('"')
    return "unknown"


def harden_and_snapshot_virtualbox_vm(vm_name: str) -> Dict[str, Any]:
    """Cuts network/clipboard/drag&drop of a powered-off VM and takes a clean snapshot. Every step is verified."""
    if not VBOX_EXE.exists():
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
                p = _run([str(VBOX_EXE), "modifyvm", vm_name] + opts, timeout=20)
                if p.returncode == 0:
                    steps.append(label)
                    break
                err = (p.stderr or p.stdout).strip()[:200]
            else:
                failed.append(f"{label} — BAŞARISIZ: {err}")
        shared = _run([str(VBOX_EXE), "showvminfo", vm_name, "--machinereadable"], timeout=15).stdout
        if "SharedFolderNameMachineMapping" in shared:
            failed.append("VM'de paylaşılan klasör var — VirtualBox ayarlarından kaldırın (zararlı oradan ana bilgisayara ulaşabilir).")
        snap = f"SafeBox_Temiz_{datetime.now().strftime('%Y%m%d_%H%M')}"
        p = _run([str(VBOX_EXE), "snapshot", vm_name, "take", snap, "--description", "SafeBox analiz oncesi temiz yedek"], timeout=120)
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
