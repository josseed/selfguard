import type { Root } from "../config.ts";
import { LOCKFILES } from "../lockfile/detect.ts";
import { clean } from "../sanitize.ts";
import { FETCHABLE, isReader, MAX_ANSWER_BYTES, MAX_FILE_BYTES, READER_COMMAND, READER_PROTOCOL, READER_REVISION, RemoteError, shq, SKIP, type Target } from "./core.ts";

// ---------- the read-only shell code ----------

/** "@{" stands for "${" (JS template literals reserve the latter). */
const sh = (s: string): string => s.replace(/@\{/g, "${");

const COMMON = sh(String.raw`
set -u
LC_ALL=C; export LC_ALL
TAB=$(printf '\t')
NL='
'
if stat -c %Y / >/dev/null 2>&1; then
  sg_stat() { stat -c '%s %Y' -- "$1" 2>/dev/null; }
  sg_mtimes() { stat -c '%Y' -- "$@" 2>/dev/null; }
else
  sg_stat() { stat -f '%z %m' -- "$1" 2>/dev/null; }
  sg_mtimes() { stat -f '%m' -- "$@" 2>/dev/null; }
fi
sg_expand() {
  case $1 in
    "~") printf '%s' "$HOME" ;;
    "~/"*) printf '%s/%s' "$HOME" "@{1#??}" ;;
    *) printf '%s' "$1" ;;
  esac
}
# Header line. A reader adds its revision (READER_REVISION).
sg_header() {
  if [ -n "@{3:-}" ]; then printf 'SG1\t%s\t%s\t%s\t%s\t%s\n' "$HOME" "$(uname -s 2>/dev/null)" "$1" "$2" "$3"
  else printf 'SG1\t%s\t%s\t%s\t%s\n' "$HOME" "$(uname -s 2>/dev/null)" "$1" "$2"; fi
}
# Inside the granted folder (restricted reader only; SG_SCOPE is its physical path).
sg_inside() { case $1 in "$SG_SCOPE"|"$SG_SCOPE"/*) return 0 ;; esac; return 1; }
# Physical path of a folder. Refused if it holds a control character: a newline would split
# the answer's lines (printf . keeps a trailing newline that $(...) would otherwise drop).
sg_phys() {
  ph=$(cd -- "$1" 2>/dev/null && pwd -P && printf .) || return 1
  ph=@{ph%.}; ph=@{ph%"$NL"}
  case $ph in *[[:cntrl:]]*) return 1 ;; esac
  printf '%s' "$ph"
}

# Git facts for a project: walks up to the folder holding .git and reads HEAD, commondir,
# the worktree pointer and the [section]/url lines of the config. Never runs git. Those files
# are never read through a symlink: one could point anywhere, outside the granted folder too.
sg_git() {
  d=$1; g=; wt=0
  while :; do
    if [ -d "$d/.git" ]; then g="$d/.git"; break; fi
    [ -L "$d/.git" ] && break
    if [ -f "$d/.git" ]; then
      l=; IFS= read -r l < "$d/.git" || true
      p=@{l#gitdir:}; p=@{p# }
      case $p in /*) g=$p ;; "") break ;; *) g="$d/$p" ;; esac
      wt=1; break
    fi
    # Never above the granted folder (nor the home).
    if [ "$d" = "@{SG_SCOPE:-}" ] || [ "$d" = "$HOME" ] || [ "$d" = / ] || [ -z "$d" ]; then break; fi
    d=@{d%/*}; [ -n "$d" ] || d=/
  done
  [ -n "$g" ] || return 0
  # Restricted reader: the git dir must be inside the granted folder too.
  if [ -n "@{SG_SCOPE:-}" ]; then
    gr=$(sg_phys "$g") || return 0
    sg_inside "$gr" || return 0
  fi
  if [ -d "$g" ]; then ok=1; else ok=0; fi
  head=; [ -f "$g/HEAD" ] && [ ! -L "$g/HEAD" ] && { IFS= read -r head < "$g/HEAD" || true; }
  cd_=$g
  if [ -f "$g/commondir" ] && [ ! -L "$g/commondir" ]; then
    c=; IFS= read -r c < "$g/commondir" || true
    case $c in /*) cd_=$c ;; "") ;; *) cd_="$g/$c" ;; esac
  fi
  cdr=$(sg_phys "$cd_")
  if [ -n "@{SG_SCOPE:-}" ]; then
    [ -n "$cdr" ] && sg_inside "$cdr" || return 0
  fi
  a=0
  for m in $(sg_mtimes "$g/HEAD" "$g/index" "$g/logs/HEAD"); do
    [ "$m" -gt "$a" ] 2>/dev/null && a=$m
  done
  printf 'G\t%s\t%s\t%s\t%s\t%s\t%s\n' "$d" "$wt" "$ok" "$a" "$cdr" "$head"
  # Through the checked physical path, not the one the pointer named.
  if [ "$ok" = 1 ] && [ -n "$cdr" ] && [ -f "$cdr/config" ] && [ ! -L "$cdr/config" ]; then
    n=0
    while IFS= read -r l && [ $n -lt 400 ]; do
      n=$((n + 1))
      case $l in *"["*|*url*=*) printf 'U\t%s\n' "$l" ;; esac
    done < "$cdr/config"
  fi
}

# Projects under $SG_ROOTS ("depth<TAB>folder" lines): lockfile, size, mtime and git facts.
# Folders whose name holds a control character are skipped: a newline in one would split the
# path in two lines below (and in the answer).
sg_list() {
  printf '%s\n' "$SG_ROOTS" | while IFS="$TAB" read -r depth root; do
    [ -n "$root" ] || continue
    root=$(sg_expand "$root")
    if [ -d "$root" ]; then printf 'R\t1\t%s\n' "$root"; else printf 'R\t0\t%s\n' "$root"; fi
  done
  printf '%s\n' "$SG_ROOTS" | while IFS="$TAB" read -r depth root; do
    [ -n "$root" ] || continue
    root=$(sg_expand "$root")
    [ -d "$root" ] || continue
    find "$root" -maxdepth $((depth + 1)) \( \( ${SKIP.map((d) => `-name ${d}`).join(" -o ")} -o -name '.*' -o -name '*[[:cntrl:]]*' -o -path '*/pkg/mod' \) -type d ! -path "$root" -prune \) -o \( ${LOCKFILES.map(([n]) => `-name ${n}`).join(" -o ")} -o -name package.json \) -type f -print 2>/dev/null
  done | sed -n 's|/[^/]*$||p' | sort -u | while IFS= read -r dir; do
    case $dir in /*) ;; *) continue ;; esac
    if [ -n "@{SG_SCOPE:-}" ]; then sg_inside "$dir" || continue; fi
    lock=
    for n in ${LOCKFILES.map(([n]) => n).join(" ")}; do
      if [ -f "$dir/$n" ] && [ ! -L "$dir/$n" ]; then lock=$n; break; fi
    done
    if [ -z "$lock" ]; then
      [ -f "$dir/package.json" ] && [ -e "$dir/.git" ] || continue
      printf 'P\t%s\t-\t0\t0\n' "$dir"
    else
      st=$(sg_stat "$dir/$lock"); sz=@{st%% *}; mt=@{st#* }
      printf 'P\t%s\t%s\t%s\t%s\n' "$dir" "$lock" "@{sz:-0}" "@{mt:-0}"
    fi
    sg_git "$dir"
  done
}

# Files in $SG_FILES (one per line): "F<TAB>size<TAB>path" + exactly size bytes, gzipped.
# Only lockfiles and manifests (package.json, pyproject.toml), never symlinks, at most
# ${MAX_FILE_BYTES} bytes each and ${MAX_ANSWER_BYTES} in all (the rest is answered as unreadable).
sg_fetch() {
  tot=0
  printf '%s\n' "$SG_FILES" | while IFS= read -r f; do
    [ -n "$f" ] || continue
    case @{f##*/} in ${[...FETCHABLE].join("|")}) ;; *) continue ;; esac
    if [ -f "$f" ] && [ ! -L "$f" ]; then n=$(wc -c < "$f" 2>/dev/null | tr -d ' '); else n=-1; fi
    [ -n "$n" ] || n=-1
    if [ "$n" -lt 0 ] || [ "$n" -gt ${MAX_FILE_BYTES} ] || [ $((tot + n)) -gt ${MAX_ANSWER_BYTES} ]; then printf 'F\t-1\t%s\n' "$f"; continue; fi
    tot=$((tot + n))
    printf 'F\t%s\t%s\n' "$n" "$f"
    { head -c "$n" "$f" 2>/dev/null; cat /dev/zero 2>/dev/null; } | head -c "$n"
  done | if command -v gzip >/dev/null 2>&1; then gzip -c; else cat; fi
}

# Subfolder names of $SG_PATH (no hidden, no dependency folders), for the folder picker.
sg_browse() {
  if ! cd -- "$SG_PATH" 2>/dev/null; then printf 'X\tnot a directory\n'; return 0; fi
  printf 'D\t%s\n' "$(pwd -P)"
  for e in *; do
    [ -d "$e" ] && [ ! -L "$e" ] || continue
    case $e in ${SKIP.join("|")}|*[[:cntrl:]]*) continue ;; esac
    if [ -f "$e/package.json" ]; then j=1; else j=0; fi
    printf 'S\t%s\t%s\n' "$j" "$e"
  done | head -n 2000
}
`);

/** The reader: request on stdin, answers only inside its folder. Installed on the machine. */
export function readerScript(scope: string, installedFor: string): string {
  return `#!/bin/sh
# selfguard reader (${READER_PROTOCOL}) for ${clean(installedFor, 80)}
#
# Run by sshd for the selfguard key only (authorized_keys: restrict,command="${READER_COMMAND}").
# Read-only: lists lockfiles, reads them and a few git files under the folder below,
# never writes, never runs git, package managers or anything from a project.
# Requests come on stdin as data and are never evaluated as shell code.
# Source: https://github.com/josseed/selfguard/blob/main/src/remote.ts
SG_SCOPE_RAW=${shq(scope)}
${COMMON}${sh(String.raw`
SG_SCOPE=$(cd -- "$(sg_expand "$SG_SCOPE_RAW")" 2>/dev/null && pwd -P) || SG_SCOPE=
sg_header "reader ${READER_PROTOCOL}" "$SG_SCOPE" ${READER_REVISION}
[ -n "$SG_SCOPE" ] || { printf 'X\tthe allowed folder does not exist\n'; exit 0; }
sg_in_scope() { case $1 in "$SG_SCOPE"|"$SG_SCOPE"/*) return 0 ;; esac; return 1; }
# Resolve a requested folder (absolute or ~/...) to its physical path, "" if not allowed.
sg_resolve() {
  case $1 in /*|"~"|"~/"*) ;; *) return 0 ;; esac
  case $1 in */../*|*/..) return 0 ;; esac
  r=$(sg_phys "$(sg_expand "$1")") || return 0
  sg_in_scope "$r" && printf '%s' "$r"
}
req=; IFS= read -r req || true
case $req in
  "SGREQ1 ping") ;;
  "SGREQ1 list")
    SG_ROOTS=; n=0
    while IFS="$TAB" read -r depth root && [ $n -lt 64 ]; do
      n=$((n + 1))
      case $depth in [1-9]|10) ;; *) continue ;; esac
      r=$(sg_resolve "$root")
      if [ -z "$r" ]; then printf 'R\t0\t%s\n' "$root"; continue; fi
      # The same folder asked again is walked once, as deep as the deepest ask (in place).
      case "$NL$SG_ROOTS" in
        *"$TAB$r$NL"*)
          pre=@{SG_ROOTS%%"$TAB$r$NL"*}; old=@{pre##*"$NL"}
          [ "$depth" -gt "$old" ] && SG_ROOTS="@{pre%"$old"}$depth$TAB$r$NL@{SG_ROOTS#*"$TAB$r$NL"}" ;;
        *) SG_ROOTS="$SG_ROOTS$depth$TAB$r$NL" ;;
      esac
    done
    sg_list ;;
  "SGREQ1 fetch")
    SG_FILES=; n=0
    while IFS= read -r f && [ $n -lt 1000 ]; do
      n=$((n + 1))
      case $f in /*/*) ;; *) continue ;; esac
      # Each file once: asking for it again would only repeat it in the answer.
      case "$NL$SG_FILES" in *"$NL$f$NL"*) continue ;; esac
      d=$(sg_resolve "@{f%/*}")
      [ -n "$d" ] && [ "$d/@{f##*/}" = "$f" ] && SG_FILES="$SG_FILES$f$NL"
    done
    printf '\n'
    sg_fetch ;;
  "SGREQ1 browse")
    p=; IFS= read -r p || true
    SG_PATH=$(sg_resolve "@{p:-$SG_SCOPE}")
    if [ -z "$SG_PATH" ]; then printf 'X\toutside the allowed folder\n'; else sg_browse; fi ;;
  *) printf 'X\tbad request\n' ;;
esac
`)}`;
}

/** Same functions for the ssh mode: values as literals, then one call. */
export function openScript(vars: Record<string, string>, call: string, tag = "sh"): string {
  const assigns = Object.entries(vars).map(([k, v]) => `${k}=${shq(v)}`).join("\n");
  return `${assigns}\n${COMMON}\nsg_header ${shq(tag)} ''\n${call}\n`;
}

export function listRequest(t: Target, roots: Root[]): string {
  const lines = roots.map((r) => `${r.depth}\t${r.path}`);
  for (const l of lines) if (/[\n\u0000]/.test(l)) throw new RemoteError("protocol", "newline in path");
  return isReader(t) ? `SGREQ1 list\n${lines.join("\n")}\n` : openScript({ SG_ROOTS: lines.join("\n") }, "sg_list");
}

export function fetchRequest(t: Target, files: string[]): string {
  for (const f of files) if (/[\n\u0000]/.test(f)) throw new RemoteError("protocol", "newline in path");
  return isReader(t) ? `SGREQ1 fetch\n${files.join("\n")}\n` : openScript({ SG_FILES: files.join("\n") }, "printf '\\n'\nsg_fetch");
}

export function browseRequest(t: Target, path: string): string {
  if (/[\n\u0000]/.test(path)) throw new RemoteError("protocol", "newline in path");
  return isReader(t) ? `SGREQ1 browse\n${path}\n` : openScript({ SG_PATH: path }, `SG_PATH=$(sg_expand "$SG_PATH")\nsg_browse`);
}
