# Controlled impairment

Use `python eval/impairment.py --trials 3` from the checkout root after the lab is up.
The firewall container alone has NET_ADMIN. The harness replaces its eth0 root qdisc,
measures delay/loss conditions, and removes that qdisc even after a failed scan. It should
only be used on this disposable lab target because it replaces any existing root qdisc.
Run `docker compose -f lab/docker-compose.lab.yml exec -T firewall tc qdisc show dev eth0`
to verify cleanup. No host interface is changed.
