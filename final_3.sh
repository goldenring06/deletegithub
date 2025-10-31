#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

# single_repo_max_scan_with_forks.sh
# Safe mirror + unpack packs + recover deleted files + dump dangling blobs + TruffleHog + metadata
# Now supports scanning forks automatically.

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

log(){
    local msg="$1"
    local level="${2:-INFO}"
    case "$level" in
        INFO) COLOR="$CYAN" ;;
        SUCCESS) COLOR="$GREEN" ;;
        WARNING) COLOR="$YELLOW" ;;
        ERROR) COLOR="$RED" ;;
        *) COLOR="$NC" ;;
    esac
    echo -e "${COLOR}[$level] $msg${NC}"
}

usage() {
  cat <<EOF
Usage: $0 /path/to/repo-or-git-url /path/to/output [threads]
 - Creates a safe mirror clone, unpacks pack files, extracts deleted files & dangling blobs,
   scans with TruffleHog, and produces structured outputs and metadata.
 - Automatically detects and scans forks for GitHub repos.
EOF
  exit 1
}

if [ "$#" -lt 2 ]; then
  usage
fi

REPO_SRC="$1"
OUTPUT_DIR="${2%/}"
THREADS="${3:-4}"   # informational

# required tools
for cmd in git trufflehog jq gh; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    log "ERROR: required command not found: $cmd" "ERROR"
    exit 1
  fi
done

# ensure realpath exists; if not, provide a small fallback
if ! command -v realpath >/dev/null 2>&1; then
  realpath() { python3 -c "import os,sys; print(os.path.realpath(sys.argv[1]))" "$1"; }
fi

mkdir -p "$OUTPUT_DIR/deleted_instances"
mkdir -p "$OUTPUT_DIR/dangling_blobs"
mkdir -p "$OUTPUT_DIR/trufflehog_results"
mkdir -p "$OUTPUT_DIR/logs"

log "Repo source: $REPO_SRC" "INFO"
log "Output directory: $OUTPUT_DIR" "INFO"
log "Threads (informational): $THREADS" "INFO"


# --- Detect GitHub forks ---
# --- Detect GitHub forks ---
repos_to_scan=("$REPO_SRC")

# If user passed a local repo path, try to get its remote origin
if [ -d "$REPO_SRC/.git" ]; then
  origin_url=$(git -C "$REPO_SRC" config --get remote.origin.url 2>/dev/null || true)
  if [ -n "$origin_url" ]; then
    REPO_SRC="$origin_url"
    repos_to_scan=("$REPO_SRC")
    log "[*] Detected local repo with origin: $REPO_SRC" "INFO"
  fi
fi
 # detect github repo
if [[ "$REPO_SRC" =~ github\.com[:/]+([^/]+/[^/]+)(\.git)?$ ]]; then
  repo_for_gh_api="${BASH_REMATCH[1]}"
  # strip .git if present
  repo_for_gh_api="${repo_for_gh_api%.git}"
  log "[*] Detected GitHub repo: $repo_for_gh_api" "INFO"

  # Get total forks count
  forks_count=$(gh api "repos/$repo_for_gh_api" --jq '.forks_count' 2>/dev/null || echo "0")
  log "[*] Total forks according to GitHub API: $forks_count" "INFO"

  # Fetch forks
  forks_output=$(mktemp)
  if ! gh api "repos/$repo_for_gh_api/forks" --paginate --jq '.[].full_name' > "$forks_output" 2> "$OUTPUT_DIR/logs/gh_forks_errors.log"; then
    log "WARN: Could not fetch forks for $repo_for_gh_api. Check $OUTPUT_DIR/logs/gh_forks_errors.log" "WARNING"
  fi

  mapfile -t forks < "$forks_output"
repos_to_scan=("$REPO_SRC") # main repo first

for f in "${forks[@]}"; do
    url="https://github.com/$f.git"
    if gh repo view "$f" >/dev/null 2>&1; then
        repos_to_scan+=("$url")
    else
        log "Skipping private/inaccessible fork: $url" "INFO"
    fi
done


  if [ "${#forks[@]}" -lt "$forks_count" ]; then
    log "NOTE: Only ${#forks[@]} forks could be fetched out of $forks_count. Some forks may be private or inaccessible." "INFO"
  fi

  log "[*] Forks to scan (public/accessible): ${#forks[@]}" "INFO"
fi


# --- Metadata CSV header ---
METADATA_CSV="$OUTPUT_DIR/metadata_deleted_and_dangling.csv"
echo "repo,type,commit,parent,path,out_file,blob_hash,author,author_date,mode" > "$METADATA_CSV"

# --- Counters ---
current_deleted=0
current_dangling=0


clone_repo() {
    local url="$1"
    local dir="$2"
    local label="$3"

    log "[*] Cloning repo: $label" "INFO"

    # Use GITHUB_TOKEN if set (helps with API rate limits and private forks)
    if [ -n "${GITHUB_TOKEN:-}" ]; then
        auth_url=$(echo "$url" | sed "s#https://#https://$GITHUB_TOKEN@#")
    else
        auth_url="$url"
    fi
    

    # Try mirror clone first
    if git clone --mirror "$auth_url" "$dir"; then
        log "[*] Mirror clone succeeded ($label)" "SUCCESS"
    else
        log "WARN: Mirror clone failed for $label — trying bare clone..." "WARNING"
        if git clone --bare "$auth_url" "$dir"; then
            log "[*] Bare clone succeeded ($label)" "SUCCESS"
        else
            log "could not clone repo $label (mirror/bare both failed)" "ERROR"
            echo "Check logs for details."
            return 1
        fi
    fi
}

#truuflle hog



deep_trufflehog_scan(){
    local repo_dir="$1"
    local repo_name="$2"

    cd "$repo_dir" || { log "Failed to change directory to $repo_dir" "ERROR"; return 1; }

    if ! command -v trufflehog &> /dev/null; then
        log "Step 3: TruffleHog not available, skipping" "WARNING"
        return 1
    fi

    local scan_output="$OUTPUT_DIR/findings/$repo_name/trufflehog"
    mkdir -p "$scan_output" || { log "Failed to create output directory $scan_output" "ERROR"; return 1; }

    echo "=== VERIFIED SECRETS ===" > "$scan_output/detailed_findings.txt"
    echo "=== UNVERIFIED SECRETS ===" >> "$scan_output/detailed_findings.txt"

    log "step 3: Running comprehensive TruffleHog scan for $repo_name..." "INFO"

    # Run: git history scan (works against bare/mirror clones via file://)
    local git_json="$scan_output/git_history.json"
    log "scanning git history - this may take a while..." "INFO"
    if ! timeout 900 trufflehog git --no-update --json "file://$repo_dir" > "$git_json" 2> "$scan_output/trufflehog_git.log"; then
        log "TruffleHog git scan returned non-zero (check $scan_output/trufflehog_git.log)" "WARNING"
    fi

    # If the repo path looks like a working copy (has files outside .git), run filesystem scan too.
    local fs_json="$scan_output/current_files.json"
    if [ -d "$repo_dir/.git" ] && compgen -G "$repo_dir/*" >/dev/null 2>&1; then
        log "scanning current files (filesystem)..." "INFO"
        if ! timeout 600 trufflehog filesystem --no-update --json "$repo_dir" > "$fs_json" 2> "$scan_output/trufflehog_fs.log"; then
            log "TruffleHog filesystem scan returned non-zero (check $scan_output/trufflehog_fs.log)" "WARNING"
        fi
    else
        # no working tree to scan (bare/mirror); leave fs_json empty but create file for consistency
        echo "[]" > "$fs_json"
    fi

    # Helper jq expression to normalize results:
    # If JSON has top-level "DetectedSecrets" return that array, else if file is an array return that.
    local jq_normalize='
      if (type=="object" and has("DetectedSecrets")) then .DetectedSecrets
      elif (type=="array") then .
      else [] end
    '

    # process both files
    for type in "git_history" "current_files"; do
        local jf="$scan_output/${type}.json"
        [ -f "$jf" ] || { echo "[]" > "$jf"; }

        # get counts safely even if file is empty/invalid
        verified_count=$(jq -r --argfile f "$jf" "try ( $jq_normalize | map(select(.verified==true)) | length ) catch 0" 2>/dev/null || echo 0)
        total_count=$(jq -r --argfile f "$jf" "try ( $jq_normalize | length ) catch 0" 2>/dev/null || echo 0)
        # ensure numbers
        verified_count=${verified_count:-0}
        total_count=${total_count:-0}
        unverified_count=$(( total_count - verified_count ))
        [ "$unverified_count" -lt 0 ] && unverified_count=0

        if [ "$total_count" -gt 0 ]; then
            echo -e "\n=== TruffleHog Results for ${repo_name} (${type}) ===" | tee -a "$scan_output/detailed_findings.txt"

            if [ "$verified_count" -gt 0 ]; then
                echo "[VERIFIED] $verified_count" | tee -a "$scan_output/detailed_findings.txt"
                jq -r --argfile f "$jf" '
                  '"$jq_normalize"' |
                  map(select(.verified==true))[] |
                  (
                    "[VERIFIED] " + ( .detectorName // "<unknown-detector>" )
                    + "\nFile: " + ( .sourceMetadata.file // "<no-file>" )
                    + ":" + ( (.sourceMetadata.line // 0) | tostring )
                    + "\nCommit: " + ( (.sourceMetadata.commit // "<no-commit>") | tostring )
                    + "\nValue: " + ( (.raw // "<redacted>") )
                  )
                ' "$jf" 2>/dev/null >> "$scan_output/detailed_findings.txt" || true
            fi

            if [ "$unverified_count" -gt 0 ]; then
                echo "[POTENTIAL] $unverified_count" | tee -a "$scan_output/detailed_findings.txt"
                jq -r --argfile f "$jf" '
                  '"$jq_normalize"' |
                  map(select((.verified != true) and (.raw != null)))[] |
                  (
                    "[POTENTIAL] " + ( .detectorName // "<unknown-detector>" )
                    + "\nFile: " + ( .sourceMetadata.file // "<no-file>" )
                    + ":" + ( (.sourceMetadata.line // 0) | tostring )
                    + "\nCommit: " + ( (.sourceMetadata.commit // "<no-commit>") | tostring )
                    + "\nValue: " + ( (.raw // "<redacted>") )
                  )
                ' "$jf" 2>/dev/null >> "$scan_output/detailed_findings.txt" || true
            fi

            # send notification for verified hits (user's existing send_notification)
            #if [ "$verified_count" -gt 0 ]; then
             #   send_notification "⚠️ TruffleHog found $verified_count verified secrets in $repo_name ($type)!"
            #fi
        else
            log "No secrets found in ${repo_name} (${type})" "SUCCESS"
        fi
    done

    return 0
}

# --- Scan function ---
scan_repo() {
  local repo_path="$1"
  local rrepo_label="$2"

 log "[*] Scanning repo: $repo_label" "INFO"
  TMP_ROOT="$OUTPUT_DIR/tmp_scan"
mkdir -p "$TMP_ROOT"
cd "$TMP_ROOT" || { log "cannot cd into $TMP_ROOT" "ERROR"; return 1; }
MIRROR_DIR="$TMP_ROOT/${repo_label}.git"

  # Ensure we have a valid URL or local path
  clone_target="$repo_path"

  # Determine if local or remote
  if [[ -d "$repo_path/.git" ]]; then
      clone_type="local"
  else
      clone_type="remote"
  fi

  log "[*] Creating mirror clone for $repo_label ($clone_type)" "INFO"

# --- REMOVE OR COMMENT THIS ---
# Check if repo is reachable
# if ! git ls-remote "$clone_target" &>/dev/null; then
#     echo "WARN: Repo not reachable (private or removed): $clone_target — skipping"
#     return 0
# fi

  # Try mirror clone
 clone_repo "$clone_target" "$MIRROR_DIR" "$repo_label"



  # Move into cloned repo before running git commands
  cd "$MIRROR_DIR" || { log "failed to enter repo directory for $repo_label" "ERROR"; rm -rf "$TMP_ROOT"; return 1; }

  
  # Unpack packs
  shopt -s nullglob
  for pack in objects/pack/pack-*.pack; do
    git unpack-objects < "$pack" >/dev/null 2>&1 || true
  done
  shopt -u nullglob

  # git fsck
  fsck_output=$(git fsck --unreachable --no-reflogs 2>/dev/null || true)
  echo "$fsck_output" > "$OUTPUT_DIR/logs/git_fsck_output_$repo_label.txt"

  # Deleted files recovery
  mapfile -t commit_lines < <(git log --diff-filter=D --pretty=format:"%H %P")
  total_deleted_repo=$(git log --diff-filter=D --name-only --pretty=format: | sed '/^$/d' | wc -l || echo 0)

  for commit_line in "${commit_lines[@]}"; do
    commit=$(awk '{print $1}' <<<"$commit_line")
    parents=$(echo "$commit_line" | cut -d' ' -f2-)
    [ -z "$parents" ] && continue
    parent=$(awk '{print $1; exit}' <<<"$parents")

    while IFS= read -r -d '' path; do
      safe_name=$(printf "%s___%s___%s" "$commit" "$parent" "$path" | tr '/' '___' | tr ' ' '_')
      out_file="$OUTPUT_DIR/deleted_instances/${repo_label}___$safe_name"

      mkdir -p "$(dirname "$out_file")"
      if git show "$parent:$path" > "$out_file" 2>/dev/null; then
        current_deleted=$((current_deleted + 1))
        echo "[${current_deleted}/${total_deleted_repo}] Restored: $path -> $(realpath --relative-to="$OUTPUT_DIR" "$out_file")"

        mode=$(git ls-tree -r "$parent" -- "$path" 2>/dev/null | awk '{print $1}' | head -n1 || true)
        [[ "$mode" == "100755" ]] && chmod +x "$out_file" 2>/dev/null || true

        author=$(git show -s --format='%an' "$commit" 2>/dev/null || true)
        author_date=$(git show -s --format='%aI' "$commit" 2>/dev/null || true)
        blob_hash=$(git hash-object "$out_file" 2>/dev/null || true)

        esc_path=$(printf '%s' "$path" | sed 's/"/""/g')
        esc_out=$(printf '%s' "$out_file" | sed 's/"/""/g')
        esc_author=$(printf '%s' "$author" | sed 's/"/""/g')
        echo "${repo_label},deleted,$commit,$parent,\"$esc_path\",\"$esc_out\",$blob_hash,\"$esc_author\",$author_date,$mode" >> "$METADATA_CSV"
      else
        log "could not recover $path from parent $parent (commit $commit)" "WARNING" >> "$OUTPUT_DIR/logs/recover_warnings.txt"
      fi
    done < <(git diff-tree --no-commit-id -r --diff-filter=D -z --name-only "$commit")
  done

  # Dangling blobs extraction
  mapfile -t dangling_hashes < <(printf "%s\n" "$fsck_output" | awk '/unreachable blob/{print $3}' || true)
  total_dangling_repo=${#dangling_hashes[@]}
  for hash in "${dangling_hashes[@]}"; do
    current_dangling=$((current_dangling + 1))
    out_file="$OUTPUT_DIR/dangling_blobs/${repo_label}___dangling_$hash.bin"
    if git cat-file -p "$hash" > "$out_file" 2>/dev/null; then
      echo "[${current_dangling}/${total_dangling_repo}] Dumped dangling blob: $hash -> $(realpath --relative-to="$OUTPUT_DIR" "$out_file")"
      mimetype=$(command -v file >/dev/null 2>&1 && file -b --mime-type "$out_file" 2>/dev/null || echo "")
      echo "${repo_label},dangling, , , ,\"$out_file\",$hash, , ,$mimetype" >> "$METADATA_CSV"
    else
      log "failed to dump dangling blob $hash" "WARNING" >> "$OUTPUT_DIR/logs/recover_warnings.txt"
    fi
  done

    deep_trufflehog_scan "$MIRROR_DIR" "$repo_label" || log "deep_trufflehog_scan failed for $repo_label" "WARNING"

}

# --- Scan all repos (main + forks) ---
for repo in "${repos_to_scan[@]}"; do
  # Ensure full Git URL
  if [[ "$repo" =~ ^https?:// ]]; then
    repo_url="$repo"
  else
    repo_url="https://github.com/$repo.git"
  fi

  # Unique label for each repo/fork
  repo_label=$(echo "$repo_url" | sed 's#https://github.com/##; s#/#_#g; s/\.git$//')

  scan_repo "$repo_url" "$repo_label"
done

# --- TruffleHog scans ---




# --- Robust clone function ---

# --- Combine results ---
#for f in "$DELETED_JSON" "$DANGLING_JSON"; do [ ! -s "$f" ] && echo "[]" > "$f"; done
#COMBINED_JSON="$OUTPUT_DIR/trufflehog_results/combined.json"
#jq -s 'add | unique' "$DELETED_JSON" "$DANGLING_JSON" > "$COMBINED_JSON" || echo "NOTE: jq merge failed"
# --- Skip undefined DELETED_JSON/DANGLING_JSON merge ---
#echo "[*] Skipping DELETED_JSON/DANGLING_JSON merge — variables not defined."
COMBINED_JSON="$OUTPUT_DIR/trufflehog_results/combined.json"
mkdir -p "$(dirname "$COMBINED_JSON")"
mapfile -t th_jsons < <(find "$OUTPUT_DIR/findings" -type f -name "*.json")
if [ "${#th_jsons[@]}" -gt 0 ]; then
    jq -s 'add | unique' "${th_jsons[@]}" > "$COMBINED_JSON" || echo "NOTE: jq merge failed"
else
    echo "[]" > "$COMBINED_JSON"
fi


total_secrets=$(jq length "$COMBINED_JSON" 2>/dev/null || echo 0)

log "Scan Summary:" "INFO"
log "Deleted files recovered -> $current_deleted" "SUCCESS"
log "Dangling blobs extracted -> $current_dangling" "SUCCESS"
log "Total TruffleHog secrets -> $total_secrets" "SUCCESS"

log "Outputs:" "INFO"
log "Deleted instances -> $OUTPUT_DIR/deleted_instances" "INFO"
log "Dangling blobs    -> $OUTPUT_DIR/dangling_blobs" "INFO"
log "TruffleHog results-> $OUTPUT_DIR/trufflehog_results" "INFO"
log "Metadata CSV      -> $METADATA_CSV" "INFO"
log "Logs              -> $OUTPUT_DIR/logs" "INFO"

log "Done." "SUCCESS"