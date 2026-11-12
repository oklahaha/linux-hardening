#!/usr/bin/env bash
# Run a Lynis audit and summarise it.
# Usage: lynis.sh                   full audit -> hardening-reports/<timestamp>-lynis/{report.dat,lynis.log,lynis.out} + summary
#        lynis.sh --test <TEST-ID>  re-run one test (e.g. SSH-7408) after a fix
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
OUT_ROOT=${HARDENING_REPORTS:-$PWD/hardening-reports}

test=
if [ "${1:-}" = --test ]; then
  test=${2:-}
  [[ $test =~ ^[A-Z]+-[0-9]+$ ]] || { echo "bad test id: $test" >&2; exit 64; }
fi
command -v lynis >/dev/null || [ -x /usr/sbin/lynis ] || { echo "lynis missing: see references/distro-mapping.md for the install command" >&2; exit 69; }

mkdir -p "$OUT_ROOT"
out=$OUT_ROOT/$(date +%Y%m%d-%H%M%S)-lynis${test:+-$test}
# New private dir: reports reveal config weaknesses; mkdir fails if the path already exists.
mkdir -m 700 "$out"
# Root writes only into a dir root created; the user's shell copies the reports out, so no privileged write goes through $out.
priv=$(sudo mktemp -d)
trap 'sudo rm -rf "$priv"' EXIT
echo "Running Lynis${test:+ test $test} (a full audit takes a few minutes)..." >&2
# Run from root's empty private dir: Lynis reads custom.prf and ./include from its working directory,
# so the caller's directory must not be able to skip or replace tests.
sudo sh -c 'cd "$1" && shift && exec lynis "$@"' sh "$priv" audit system --quick --no-colors ${test:+--tests "$test"} \
  --report-file "$priv/report.dat" --logfile "$priv/lynis.log" > "$out/lynis.out" 2>&1 && rc=0 || rc=$?
sudo test -s "$priv/report.dat" || { echo "Lynis wrote no report (exit $rc); see $out/lynis.out" >&2; exit 70; }
# Copy whatever exists, even a partial report, so a failure can be diagnosed.
sudo cat "$priv/report.dat" > "$out/report.dat"
sudo cat "$priv/lynis.log" > "$out/lynis.log" 2>/dev/null || true
# Lynis writes the report header before its checks and appends finish=true only at the end.
if [ "$rc" -ne 0 ] || ! grep -qx 'finish=true' "$out/report.dat"; then
  echo "Lynis did not complete (exit $rc$(grep -qx 'finish=true' "$out/report.dat" || echo ', no finish=true in the report')); the findings are partial and must not be reported as a result. See $out/lynis.out and $out/lynis.log" >&2
  exit 70
fi
# A skipped or unknown test leaves no findings, which must not read as a pass.
if [ -n "$test" ] && ! grep -qE "^tests_executed=(.*\|)?$test(\||$)" "$out/report.dat"; then
  echo "Lynis did not run $test (skipped by a profile, not applicable here, or unknown id); this is not a pass. See $out/lynis.log" >&2
  exit 70
fi

echo "Report dir: $out"
python3 -I "$HERE/summary.py" --lynis "$out/report.dat"
