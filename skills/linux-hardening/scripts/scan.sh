#!/usr/bin/env bash
# Scan this machine against a SCAP Security Guide profile with OpenSCAP.
# Usage: scan.sh                          list the standards (profiles) available for this distro
#        scan.sh <profile>                full scan -> hardening-reports/<timestamp>-<profile>/{results.xml,report.html,fixes.sh} + summary
#        scan.sh <profile> --rule <id>    re-check one rule
set -euo pipefail

SSG_VERSION=0.1.82
SSG_SHA512=1caea418f0a5aaef7025e1655ca45a80942ea87ee832b943644ba6f9991b14a6ac5b35dddcd04b754e1fc8fbdee7b7f394507d24b123e821cca0354dc4e03cfd
HERE=$(cd "$(dirname "$0")" && pwd)
CACHE=${XDG_CACHE_HOME:-$HOME/.cache}/linux-hardening
OUT_ROOT=${HARDENING_REPORTS:-$PWD/hardening-reports}
OS_RELEASE=${HARDENING_OS_RELEASE:-/etc/os-release}   # overrides for tests only
SYS_CONTENT=${HARDENING_SYS_CONTENT:-/usr/share/xml/scap/ssg/content}   # distro scap-security-guide package

profile= rule=
while [ $# -gt 0 ]; do
  case $1 in
    --rule) rule=$2; shift 2 ;;
    *) profile=$1; shift ;;
  esac
done
[[ -z $profile || $profile =~ ^[a-z0-9_-]+$ ]] || { echo "bad profile name: $profile" >&2; exit 64; }
[[ -z $rule || $rule =~ ^[a-z0-9_]+$ ]] || { echo "bad rule name: $rule" >&2; exit 64; }
[[ -z $rule || -n $profile ]] || { echo "--rule needs a profile" >&2; exit 64; }

command -v oscap >/dev/null || { echo "oscap missing: install openscap-scanner (apt/dnf/yum) or openscap-utils (zypper)" >&2; exit 69; }

# Map os-release to SSG product names; try the most specific first: rhel 9.4 -> rhel94, rhel9, rhel.
id=$(. "$OS_RELEASE"; echo "${ID,,}") ver=$(. "$OS_RELEASE"; echo "${VERSION_ID:-}") major=${ver%%.*}
case $id in
  amzn) id=al ;;                           # Amazon Linux 2023 -> al2023
  sles|sled) id=sle ;;
  sl-micro|sle-micro) id=slmicro ;;
  opensuse*) id=opensuse ;;                # leap and tumbleweed share one datastream
  centos) [ "${major:-0}" -ge 9 ] && id=cs ;;   # CentOS Stream 9/10 -> cs9/cs10
  rocky) id=rl ;;                          # not in upstream SSG; Rocky's own package ships ssg-rl<N>-ds.xml
esac
candidates="$id${ver//./} $id$major $id"

mkdir -p "$CACHE"
zip=$CACHE/ssg-$SSG_VERSION.zip
if [ ! -f "$zip" ]; then
  curl -fsSL -o "$zip.part" "https://github.com/ComplianceAsCode/content/releases/download/v$SSG_VERSION/scap-security-guide-$SSG_VERSION.zip"
  mv "$zip.part" "$zip"
fi
# Trust boundary: every run verifies a private copy and extracts from that same copy, so a swapped cache is never scanned.
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
cp "$zip" "$work/ssg.zip"
echo "$SSG_SHA512  $work/ssg.zip" | sha512sum -c --quiet || { rm -f "$zip"; echo "checksum mismatch, cached download removed" >&2; exit 65; }
# shellcheck disable=SC2086  # candidates is a word list
product=$(python3 -I - "$work/ssg.zip" "$work" "$SSG_VERSION" $candidates 2>"$work/known" <<'PY'
import sys, zipfile
z = zipfile.ZipFile(sys.argv[1]); names = set(z.namelist()); pre = f"scap-security-guide-{sys.argv[3]}/ssg-"
for p in sys.argv[4:]:
    if pre + p + "-ds.xml" in names:
        z.extract(pre + p + "-ds.xml", sys.argv[2]); print(p); break
else:
    print(" ".join(sorted(n[len(pre):-7] for n in names if n.startswith(pre) and n.endswith("-ds.xml"))), file=sys.stderr)
PY
)
ds=$work/scap-security-guide-$SSG_VERSION/ssg-$product-ds.xml
if [ -z "$product" ]; then
  # Fallback: the distro's own content package. Trust it only if root owns it and nobody else can write it.
  for c in $candidates; do
    f=$SYS_CONTENT/ssg-$c-ds.xml
    [ -f "$f" ] && [ "$(stat -c %u "$f")" = 0 ] && [ -z "$(find "$f" -perm /022)" ] || continue
    cp "$f" "$work/sys-ds.xml"; ds=$work/sys-ds.xml; product=$c
    echo "Using the distro's SCAP content: $f" >&2; break
  done
fi
[ -n "$product" ] || {
  echo "no SCAP content for this distro (tried: $candidates)." >&2
  echo "Pinned SSG $SSG_VERSION has: $(cat "$work/known")" >&2
  echo "Distro package content in $SYS_CONTENT: $(cd "$SYS_CONTENT" 2>/dev/null && ls ssg-*-ds.xml 2>/dev/null | paste -sd' ' || echo none; true)" >&2
  echo "On Rocky/RHEL-like systems: sudo dnf install -y scap-security-guide, then retry." >&2
  exit 69; }

if [ -z "$profile" ]; then
  echo "Standards available for $product (profile: title):"
  oscap info --profiles "$ds" | sed 's/^xccdf_org.ssgproject.content_profile_/  /; s/:/: /'
  exit 0
fi

profile_id=xccdf_org.ssgproject.content_profile_$profile
oscap info --profiles "$ds" | grep -q "^$profile_id:" \
  || { echo "profile $profile not in content for $product. Available:" >&2; oscap info --profiles "$ds" | sed 's/^xccdf_org.ssgproject.content_profile_/  /' >&2; exit 64; }

if [ -n "$rule" ]; then
  # Quick re-check of one rule; no report directory.
  sudo oscap xccdf eval --profile "$profile_id" --rule "xccdf_org.ssgproject.content_rule_$rule" "$ds" | grep -E '^(Title|Result)'
  exit 0
fi

mkdir -p "$OUT_ROOT"
out=$OUT_ROOT/$(date +%Y%m%d-%H%M%S)-$profile
# New private dir: reports reveal config weaknesses; mkdir fails if the path already exists.
mkdir -m 700 "$out"
echo "Scanning $product against $profile (takes a few minutes)..." >&2
# Root writes only into a dir root created; the user's shell copies the reports out, so no privileged write goes through $out.
priv=$(sudo mktemp -d)
trap 'rm -rf "$work"; sudo rm -rf "$priv"' EXIT
# oscap exits 2 when any rule fails; that is a normal scan result.
sudo oscap xccdf eval --profile "$profile_id" --results "$priv/results.xml" --report "$priv/report.html" "$ds" > "$out/eval.log" 2>&1 || [ $? -eq 2 ]
sudo cat "$priv/results.xml" > "$out/results.xml"
sudo cat "$priv/report.html" > "$out/report.html"
oscap xccdf generate fix --fix-type bash \
  --result-id "xccdf_org.open-scap_testresult_$profile_id" --output "$out/fixes.sh" "$out/results.xml"

echo "Report dir: $out"
python3 -I "$HERE/summary.py" "$out/results.xml" "$out/fixes.sh"
