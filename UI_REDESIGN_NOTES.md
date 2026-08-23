# Final UI redesign

The previous fixed split-screen dashboard was replaced with a cleaner file-manager layout.

## Main workspace
- Drive-style left navigation
- Search bar in the top app bar
- New menu for folder, upload, and secure text file
- Nested folders and breadcrumbs
- List / grid file views
- Rename, move, share, download, and delete actions

## Crypto demonstration
The crypto guide is now an on-demand right drawer instead of occupying the dashboard all the time.

- Open with **Crypto demo**
- Auto-opens when a live crypto operation runs
- Simple and Technical modes
- Replay last demo any number of times
- Replay does not encrypt the file again and does not create duplicate database records

## Database
Run `upgrade_drive_ui.sql` once on an existing database to add folder support.
