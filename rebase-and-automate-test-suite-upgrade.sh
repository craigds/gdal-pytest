
#!/bin/bash
set -eu
set -o pipefail

die () {
    echo $1
    exit 1
}

# The directory this script is in.
SELF_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd )"

# Error if we're not in the GDAL repo
git show af2561ce24d1263819b18d367d0900bc6f524e34 > /dev/null  || die "Not in the GDAL repo"
ls .git > /dev/null  || die "Not in the root dir of the GDAL repo"

# Check there's no 'Automated' stuff in recent history.
AUTOMATED_COMMITS="$(git log --oneline | head -n 20 | grep Automated || true)"
if [ ! -z "$AUTOMATED_COMMITS" ] ; then
    die "HEAD isn't the right commit"
fi

# nope.
# rebase against upstream master
# git fetch upstream
# git rebase upstream/master

for STEP in 0 1 2 3 4 5 6 7 8 ; do
    MESSAGE=`cat $SELF_DIR/gdal-commit-messages.json | jq -r ".[${STEP}]"`
    echo
    echo "applying step ${STEP}: ${MESSAGE}" | head -n 1
    echo
    $SELF_DIR/pytestify-gdal.py --no-input --step $STEP --silent autotest
    
    REJ_FILES="$(find autotest -name '*.rej' -print -delete)"
    while [ ! -z "$REJ_FILES" ] ; do
        PY_FILES=" "
        for REJ in $REJ_FILES ; do
            PY_FILES="$PY_FILES ${REJ%.*}"
        done
        echo "patch created reject files, trying again with:"
        echo $PY_FILES
        $SELF_DIR/pytestify-gdal.py --no-input --step $STEP --silent $PY_FILES
        REJ_FILES="$(find autotest -name '*.rej' -print -delete)"
    done
    find autotest -name '*.orig' -delete
    python -m compileall autotest | (grep Sorry || true)  || die 'compile errors!'
    git add autotest
    git commit -m "$MESSAGE"
done

for COMMIT in 0fc98fe984a8b977be2991242dbd9db34cae38a9 ; do
    git cherry-pick $COMMIT
done

echo success
