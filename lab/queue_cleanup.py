"""Discard framework fixture jobs only from the dedicated, workerless VPN lab Redis."""


def clear_fixture_jobs():
    import frappe
    from redis import Redis
    from rq import Queue, Worker

    if (
        frappe.local.site != "test.local"
        or frappe.conf.db_name != "ivpn_poc"
        or frappe.conf.redis_queue != "redis://127.0.0.1:16411"
    ):
        raise RuntimeError("Refusing to clean a queue outside the dedicated VPN lab")
    connection = Redis.from_url(frappe.conf.redis_queue)
    if Worker.all(connection=connection):
        raise RuntimeError("Unexpected workers on the disposable fixture queue")
    for queue in Queue.all(connection=connection):
        queue.empty()
    return all(queue.count == 0 for queue in Queue.all(connection=connection))
