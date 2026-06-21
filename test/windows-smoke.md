# Windows/WSL hand-smoke validation

Manual checklist to validate sdme under WSL2 on a real Windows machine. Not wired
into CI (parallels how the macOS and Windows setup tutorials are excluded from
`verify-tutorial.sh`, since they cannot run on Linux CI runners).

Run after pulling the `windows-wsl-docs` branch. It walks the
[Windows tutorial](../site/content/tutorial/windows.md) with explicit checkpoints
for the parts not yet verified by the project: systemd enabled in WSL2, whether
systemd-nspawn boots under WSL2, and container port reachability from Windows.

> Note: the tutorial points at `https://sdme.io/install.sh`, which is not live in
> prod yet. Until the domain switch lands, install with the current URL instead:
> `curl -fsSL https://fiorix.github.io/sdme/install.sh | sudo sh`

For each step record `PASS` / `FAIL` and paste actual output where it differs
from expected.

## 1. WSL2 present

```powershell
wsl --version
wsl -l -v
```

Expected: WSL2, a distro listed with `VERSION 2`.

Result: ____

## 2. systemd is PID 1

Inside the distro:

```bash
systemctl is-system-running
ps -p 1 -o comm=
```

Expected: `running` or `degraded`; PID 1 is `systemd`. If `offline`, enable
systemd per the tutorial (`/etc/wsl.conf` `[boot] systemd=true`, then
`wsl --shutdown`).

Result: ____

## 3. Install sdme

```bash
curl -fsSL https://fiorix.github.io/sdme/install.sh | sudo sh
sdme --version
```

Expected: install completes, version prints.

Result: ____

## 4. Container lifecycle (core open question: nspawn under WSL2)

```bash
sudo sdme new
sudo sdme ps
sudo sdme exec <name> uname -a
sudo sdme join <name>     # exit with: exit / Ctrl-D
sudo sdme stop <name>
```

Expected: a host-clone container boots, appears in `ps`, runs a command, joins an
interactive shell, and stops cleanly. This confirms systemd-nspawn works under
WSL2, the main unknown.

Record any nspawn/cgroup/namespace errors verbatim.

Result: ____

## 5. Host wrapper

With the alias/function configured per the tutorial:

PowerShell:

```powershell
sdme ps
```

Git Bash:

```bash
sdme ps
```

Expected: both list containers without entering the distro manually.

Result (PowerShell): ____

Result (Git Bash): ____

## 6. Networking (open question: WSL2 port reachability)

Start an OCI app with a forwarded port (import nginx first if needed, see the
tutorial / `sdme --help`):

```bash
sudo sdme fs import nginx docker.io/nginx --base-fs=ubuntu -v
sudo sdme new web -r nginx --network-veth -p 8080:80
sudo sdme ps             # note the container IP
```

Test reachability in three places:

```bash
# a) inside the distro
curl -fsS http://localhost:8080/ | head -1
```

```powershell
# b) from Windows (default NAT networking)
curl.exe -fsS http://localhost:8080/
```

Then enable mirrored networking (`%UserProfile%\.wslconfig` `[wsl2]
networkingMode=mirrored`, `wsl --shutdown`, relaunch) and repeat (b).

Record which of {inside distro, Windows + NAT, Windows + mirrored} succeed. This
determines what the tutorial's Networking section should state as fact.

Result (inside distro): ____

Result (Windows, NAT): ____

Result (Windows, mirrored): ____

## 7. Feedback

- Overall: which steps passed / failed?
- Surprises or errors (paste output):
- Tutorial corrections needed (wording, missing prereqs, wrong commands):
- Networking verdict (which modes expose container ports to Windows):
- nspawn verdict (does it boot under WSL2 as-is, or need tweaks?):
