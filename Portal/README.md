# Portal

Port **8079** — the main menu for the suite.

```bash
docker compose up --build -d
# http://localhost:8079
```

Or, from the repo root, `./labs.sh up` starts the portal along with every lab.

## What it does

- **Lists all 21 labs**, grouped into the seven phases of the suggested order,
  with a short note on why each phase comes where it does.
- **Shows which labs are actually running.** Liveness is checked server-side in
  parallel with `curl_multi`, so the page loads in well under a second even with
  everything down. A lab that is not up is greyed out.
- **One scoreboard for the whole suite.** Cookies are scoped to the host and not
  to the port, so `localhost:8079` can read the progress cookie every lab wrote
  on its own port. Each card shows `solved/total` and the hero shows the running
  total across all 216 levels.
- **Direct links** to each lab's index, its flag page, and its workbench where
  one exists (JWT, Crypto, Auth Reset).
- **Filter box**, focused with `/` and cleared with `Escape`. Matches on lab
  name, vulnerability class and port. There is also a "only labs that are
  running" toggle.
- **Reset all progress** clears every lab's cookie in one action, behind a
  confirmation.

## Files

```
registry.php   the single source of truth: dir, port, level count, progress
               cookie, phase and tool links for every lab
index.php      the menu itself
css/styles.css shared black-and-white theme plus the kit layer
```

Adding a lab means adding one entry to `portal_labs()` in `registry.php` and one
line to `labs.sh` at the repo root.

## Notes

- The portal runs with `network_mode: bridge` rather than creating its own
  Docker network. With every lab up, Docker's default address pools are already
  fully subnetted and a twenty-second network would fail to create.
- Liveness checks go to `host.docker.internal`, since the labs are published on
  the Docker host rather than inside this container's network. Override with the
  `LAB_HOST` environment variable if your setup differs.
- The portal reads cookies and calls the other labs. It stores nothing.
