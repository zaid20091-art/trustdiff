import os


def symlink_or_skip(test, target, link, *, directory=False):
    try:
        os.symlink(target, link, target_is_directory=directory)
    except OSError as exc:
        if os.name == "nt" and getattr(exc, "winerror", None) in {5, 1314}:
            test.skipTest("Windows symlink permission unavailable")
        raise
