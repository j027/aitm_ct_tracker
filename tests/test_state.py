import os
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from ct_watcher.state import WatcherState


def test_increment_cert_count_is_thread_safe():
    st = WatcherState()
    threads = 8
    per_thread = 1000

    def worker():
        for _ in range(per_thread):
            st.increment_cert_count()

    workers = [threading.Thread(target=worker) for _ in range(threads)]
    for t in workers:
        t.start()
    for t in workers:
        t.join()

    assert st.cert_count == threads * per_thread


def test_snapshot_resets_cert_count_but_not_total_alerts():
    st = WatcherState()
    st.increment_cert_count()
    st.increment_cert_count()
    st.increment_alerts_count()

    certs, alerts = st.snapshot_and_reset_stats()
    assert (certs, alerts) == (2, 1)
    assert st.cert_count == 0

    st.increment_cert_count()
    certs, alerts = st.snapshot_and_reset_stats()
    assert (certs, alerts) == (1, 1)
    assert st.cert_count == 0
