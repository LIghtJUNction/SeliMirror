#!/system/bin/sh
# KernelSU/Magisk installer hook. This package stages a KPM, it cannot boot-load it.
SKIPUNZIP=0
case "$ARCH" in
  arm64|arm64-v8a) ;;
  *) abort "SeliMirror requires ARM64." ;;
esac
ui_print "- SeliMirror v0.1.0, experimental"
ui_print "- Installing a KPM distribution package, NOT a KernelSU policy patch."
ui_print "- No automatic SELinux hook loading is performed."
ui_print "- This reference build requires the pinned SM8150 4.14.268 kernel."
ui_print "- Read README.txt and upstream README.md before using it."
set_perm "$MODPATH/bin/selimirror.kpm" 0 0 0644
set_perm "$MODPATH/bin/rskctl" 0 0 0755
