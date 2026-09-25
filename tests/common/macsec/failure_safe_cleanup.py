import logging
import shlex
from contextlib import AbstractContextManager, contextmanager


logger = logging.getLogger(__name__)


class FailureSafeCleanup(AbstractContextManager):
    """Run registered cleanup actions without masking a body failure."""

    def __init__(self, description):
        self.description = description
        self._callbacks = []

    def callback(self, function, *args, **kwargs):
        run_last = kwargs.pop("_run_last", False)
        callback = (function, args, kwargs)
        if run_last:
            self._callbacks.insert(0, callback)
        else:
            self._callbacks.append(callback)

    def restore(self):
        first_error = None
        while self._callbacks:
            function, args, kwargs = self._callbacks.pop()
            try:
                function(*args, **kwargs)
            except BaseException as error:
                if first_error is None:
                    first_error = error
        if first_error is not None:
            raise first_error

    def __exit__(self, exc_type, exc_value, traceback):
        try:
            self.restore()
        except BaseException as cleanup_error:
            if exc_type is None:
                raise
            logger.error(
                "%s cleanup failed after test error: %r",
                self.description,
                cleanup_error,
            )
        return False


def _checked_shell(host, command):
    result = host.shell(command, module_ignore_errors=True)
    if result.get("failed") or result.get("rc", 0) != 0:
        raise RuntimeError(
            "Command failed while preserving SONiC configuration")
    return result


@contextmanager
def preserve_config_db_files(host):
    """Restore every persisted config_db*.json file after a transition."""
    result = _checked_shell(
        host, "mktemp -d /tmp/macsec_config_backup.XXXXXX")
    backup_dir = result.get("stdout", "").strip()
    if not backup_dir.startswith("/tmp/macsec_config_backup."):
        raise RuntimeError("Unable to create MACsec config backup directory")
    quoted_dir = shlex.quote(backup_dir)

    cleanup = FailureSafeCleanup("Persisted CONFIG_DB")
    cleanup.callback(
        _checked_shell, host, "sudo rm -rf -- {}".format(quoted_dir))
    try:
        _checked_shell(
            host,
            "sudo cp -a /etc/sonic/config_db*.json {}/".format(
                quoted_dir),
        )
        cleanup.callback(
            _checked_shell,
            host,
            "sudo cp -a {}"
            "/config_db*.json /etc/sonic/".format(quoted_dir),
        )
        with cleanup:
            yield
    except BaseException:
        try:
            cleanup.restore()
        except BaseException:
            logger.exception(
                "Persisted CONFIG_DB cleanup failed during setup")
        raise
