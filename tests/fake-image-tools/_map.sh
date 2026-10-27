# shellcheck shell=bash
# Shared by the fake crane/docker: image reference -> fixture directory name.
fixture_for() {
  case "$1" in
    *nope*|*missing*)        return 1 ;;
    *proxy@sha256:1010*|*proxy:1.1*) echo old1010 ;;
    *proxy*)                 echo old109 ;;
    *ubuntu-old*)            echo ubuntu-old ;;
    *ubuntu-fixed*)          echo ubuntu-fixed ;;
    *exec-vuln*|*api*|*vuln*) echo vuln ;;
    *exec-fixed*|*web*|*fixed*|*distroless*) echo fixed ;;
    *job*|*static*)          echo static ;;
    *none*)                  echo none ;;
    *)                       return 1 ;;
  esac
}
