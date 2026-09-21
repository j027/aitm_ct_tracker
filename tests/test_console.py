import os
import re
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from ct_watcher.console import log


def test_log_writes_one_line_per_call(capsys):
    log("first")
    log("second")
    captured = capsys.readouterr()
    assert captured.out == "first\nsecond\n"


def test_log_does_not_merge_concurrent_lines(capsys):
    threads = 8
    per_thread = 200

    def worker(n):
        for i in range(per_thread):
            log(f"thread-{n}-line-{i}")

    workers = [threading.Thread(target=worker, args=(n,)) for n in range(threads)]
    for t in workers:
        t.start()
    for t in workers:
        t.join()

    lines = capsys.readouterr().out.splitlines()
    assert len(lines) == threads * per_thread
    assert all(re.fullmatch(r"thread-\d+-line-\d+", line) for line in lines)
    assert len(set(lines)) == threads * per_thread
