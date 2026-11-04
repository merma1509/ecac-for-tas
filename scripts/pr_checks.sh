#!/usr/bin/env bash
#
# Pull-request hygiene checks, invoked by .github/workflows/pr.yml.
#
# Modes:
#   title     <title>    <pr-number>       conventional title format
#   changelog <base-sha> <head-ref>        package changes must touch CHANGELOG
#   size      <base-sha> <head-ref> <num>  advisory only, never fails
#
# These run under `pull_request_target`, so they must never execute code taken
# from the PR: only git plumbing, grep, and GitHub API calls via gh.
#
set -euo pipefail

die() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

# Comma-separated labels of the current PR, used for opt-outs.
has_label() {
    case ",${PR_LABELS:-}," in
    *",$1,"*) return 0 ;;
    esac
    return 1
}

cmd_title() {
    local title="${1:-}" pr="${2:-}"
    [ -n "$title" ] || die "no PR title provided"

    # type(scope): summary   OR   type: summary
    local re='^(feat|fix|docs|style|refactor|perf|test|build|ci|chore|revert)(\([a-z0-9._/-]+\))?!?: .+'
    if printf '%s' "$title" | grep -Eq "$re"; then
        echo "PR title OK: $title"
        return 0
    fi

    printf 'PR title does not follow <type>(<scope>): <summary>\n' >&2
    printf '  got: %s\n' "$title" >&2
    printf '  allowed types: feat fix docs style refactor perf test build ci chore revert\n' >&2
    printf '  examples:\n' >&2
    printf '    feat(metrics): add per-mechanism breakdown\n' >&2
    printf '    fix(executor): preserve send budget on failure\n' >&2
    exit 1
}

cmd_changelog() {
    local base="${1:-}" head="${2:-}"
    [ -n "$base" ] && [ -n "$head" ] || die "usage: changelog <base-sha> <head-ref>"

    local changed
    changed="$(git diff --name-only "$base" "$head")"

    # Did the PR touch the package, tests, bin, or scripts?
    local needs_entry=0
    if printf '%s\n' "$changed" | grep -Eq '^(effect_broker/|tests/|bin/|scripts/)'; then
        needs_entry=1
    fi

    if [ "$needs_entry" -eq 0 ]; then
        echo "no package changes; changelog not required"
        return 0
    fi

    if has_label "skip-changelog"; then
        echo "label 'skip-changelog' present; skipping changelog gate"
        return 0
    fi

    if printf '%s\n' "$changed" | grep -qx 'CHANGELOG.md'; then
        if git diff "$base" "$head" -- CHANGELOG.md | grep -q '^+'; then
            echo "changelog updated"
            return 0
        fi
        die "CHANGELOG.md changed but without added lines"
    fi

    echo "package files changed but CHANGELOG.md was not updated" >&2
    echo "add an entry under '## [Unreleased]' in CHANGELOG.md," >&2
    echo "or apply the 'skip-changelog' label if this is genuinely internal." >&2
    exit 1
}

cmd_size() {
    local base="${1:-}" head="${2:-}" pr="${3:-}"
    [ -n "$base" ] && [ -n "$head" ] || die "usage: size <base-sha> <head-ref> <pr>"

    local files additions deletions
    files="$(git diff --name-only "$base" "$head" | wc -l | tr -d ' ')"
    additions="$(git diff --numstat "$base" "$head" | awk '{a+=$1} END {print a+0}')"
    deletions="$(git diff --numstat "$base" "$head" | awk '{d+=$2} END {print d+0}')"

    echo "PR size: $files files, +$additions / -$deletions"

    # Advisory only: comment once, never fail the job.
    local big_files=0 big_lines=0
    [ "$files" -gt 20 ] && big_files=1
    [ $((additions + deletions)) -gt 400 ] && big_lines=1

    if [ "$big_files" -eq 0 ] && [ "$big_lines" -eq 0 ]; then
        echo "size within guidance (<=20 files, <=400 lines)"
        return 0
    fi

    local marker="<!-- pr-size-advisory -->"
    if [ -n "$pr" ] && command -v gh >/dev/null 2>&1; then
        if gh pr view "$pr" --json comments --jq '.comments[].body' 2>/dev/null |
            grep -qF "$marker"; then
            echo "advisory comment already present"
            return 0
        fi
        gh pr comment "$pr" --body "$marker
This PR is larger than the guidance (<20 files, <400 changed lines):

- **Files:** $files
- **Lines:** +$additions / -$deletions

Not blocking — but a focused PR is easier to review and to revert." 2>/dev/null ||
            echo "could not post advisory comment (non-fatal)"
    fi
    echo "large PR (advisory only)"
    return 0
}

mode="${1:-}"
shift || true

case "$mode" in
title) cmd_title "$@" ;;
changelog) cmd_changelog "$@" ;;
size) cmd_size "$@" ;;
*) die "unknown mode '$mode' (expected: title|changelog|size)" ;;
esac
