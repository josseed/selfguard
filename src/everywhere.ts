/**
 * "Find my projects": discovery across the whole home folder, for people who don't keep
 * their code in one place.
 *
 * It walks the home folder without a depth limit but prunes aggressively:
 * - dependency, build and cache folders by name, anywhere;
 * - hidden folders (dotfiles, tool caches, trash), system and media folders of the home;
 * - cloud drives (~/Library/CloudStorage, iCloud): listing them can download files;
 * - inside a repo, folders its own .gitignore marks as disposable;
 * - other disks (no crossing of filesystems) and symlinks (never followed);
 * - zones that burn through their budget without a single project.
 * Worktrees hidden in tool folders (~/.t3/worktrees, ~/.codex/worktrees…) are found from
 * their main repo's .git/worktrees/<name>/gitdir instead of walking hidden folders.
 *
 * Results are grouped into places (folders to watch) so the user approves a handful of
 * folders, not hundreds of projects. Read-only: nothing is opened besides directory
 * listings and a few small files (.gitignore, .git/worktrees/*\/gitdir).
 */
export { PROTECTED, PRUNE_NAMES, gitignoredNames } from "./everywhere/rules.ts";
export {
  discoverEverywhere,
  type EverywhereOptions,
  type EverywhereProgress,
  type EverywhereResult,
  type FoundProject,
} from "./everywhere/walk.ts";
export { groupPlaces, type Place } from "./everywhere/places.ts";
