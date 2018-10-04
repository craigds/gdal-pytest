
#!/bin/bash
set -eu
set -o pipefail

die () {
    echo $1
    exit 1
}

# The directory this script is in.
SELF_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd )"

# Check there's no 'Automated' stuff in recent history.
AUTOMATED_COMMITS="$(git log --oneline | head -n 20 | grep Automated || true)"
if [ ! -z "$AUTOMATED_COMMITS" ] ; then
    die "HEAD isn't the right commit"
fi

for STEP in 0 1 2 3 4 ; do
    MESSAGE=`cat $SELF_DIR/gdal-commit-messages.json | jq -r ".[${STEP}]"`
    echo
    echo "applying step ${STEP}: ${MESSAGE}" | head -n 1
    echo
    $SELF_DIR/pytestify-gdal.py --no-input --step $STEP --silent autotest
    
    REJ_FILES="$(find autotest -name '*.rej' -print -delete)"
    while [ ! -z "$REJ_FILES" ] ; do
        PY_FILES=" "
        for REJ in "$REJ_FILES" ; do
            PY_FILES="$PY_FILES ${REJ%.*}"
        done
        echo "patch created reject files, trying again with:"
        echo $PY_FILES
        $SELF_DIR/pytestify-gdal.py --no-input --step $STEP --silent $PY_FILES
        REJ_FILES="$(find autotest -name '*.rej' -print -delete)"
    done
    find autotest -name '*.orig' -delete
    git add autotest
    git commit -m "$MESSAGE"
done

echo success
