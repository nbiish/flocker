# MEMORY.md - Token Efficient Memory Storage

```toon
context:
  user: nbiish
  role: developer
  project: flocker (fork of flock-you)

# Git Remote Configuration
remotes[2]{name,url,purpose}:
  origin,https://github.com/nbiish/flocker.git,Push your changes here
  upstream,https://github.com/colonelpanichacks/flock-you.git,Pull updates from source

# Git Workflow Commands
git_workflow[6]{cmd,action,when}:
  git push,Push to nbiish/flocker,After committing your changes
  git pull,Pull from nbiish/flocker,Sync with your remote
  git fetch upstream,Check upstream updates,Before merging source changes
  git log main..upstream/main --oneline,Preview upstream commits,See what's new
  git diff main upstream/main --stat,Preview changed files,See which files differ
  git merge upstream/main,Merge upstream changes,When ready to sync

# Safe Sync Workflow
sync_workflow[4]{step,cmd,note}:
  1,git stash,Stash uncommitted work first
  2,git fetch upstream,Get latest without merging
  3,git merge upstream/main OR git pull --rebase upstream main,Merge or rebase
  4,git stash pop,Restore uncommitted work

# Conflict Resolution
conflicts{scenario,resolution}:
  No conflicts,Auto-merge preserves your work
  Same file changed,Git pauses - manual resolution required (your work safe)
  Rebase preferred,git pull --rebase upstream main for linear history

# Session Facts
facts[4]{topic,detail,timestamp}:
  stack,ESP32/PlatformIO/C++,2026-01-29T00:00:00Z
  fork_setup,Configured dual-remote workflow,2026-01-29T00:00:00Z
  branch,main tracks origin/main (nbiish/flocker),2026-01-29T00:00:00Z
  sweep_fix,Fixed SWEEP profile BLE duty cycle + responsiveness (v3.2.0-secure),2026-01-29T23:40:00Z
```
