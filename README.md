# Data Manager GUI (prototype)

A lightweight Tkinter-based GUI for reviewing raw and processed data, assigning ownership, and marking items for deletion. The app reads existing directory structures and stores state in a shared SQLite DB so multiple users can collaborate.

## Paths and config
- Raw data root: `/data/Remote_Repository`
- Processed data: `/home/<user>/Data/Repository`
- User initials map: `/data/common/configs/data_manager/users.txt` (tab/space delimited)
- Shared DB: `/data/common/configs/data_manager/data_manager.db`

## Usage
```
python main.py
```
- The current user is auto-selected. If you are `adamranson`, you can switch to any `/home/*` user via the dropdown.
- Raw and processed panels list animals and experiment IDs. Size/last-access columns use cached metrics; click **Scan metrics** to compute them in the background and color by size (hot = big).
- Select a node to:
  - Toggle **Mark for deletion** (writes to `kill_list` table; actual deletion is for a separate daemon).
  - Apply or clear an **owner override** (writes to `ownership_overrides`).
- Overrides/marks are stored immediately in the shared DB. Metrics are cached in the DB as they’re scanned.

## Notes
- Ownership is guessed from initials appearing in the animal ID (longest match wins). Overrides take precedence.
- Last access uses file `atime`; if the filesystem doesn’t update atime, values may stay blank.
- The prototype avoids destructive operations; it only writes to SQLite.

