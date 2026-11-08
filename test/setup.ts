// tests must never see the real off switch in the home dir
process.env.SAFE_YOLO_OFF_FILE ??= "/fake/safe-yolo-off"
