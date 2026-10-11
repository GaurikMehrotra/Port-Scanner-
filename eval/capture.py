"""Capture own lab traffic in a scanner namespace, with cleanup and bounded duration."""

import argparse
import subprocess
import time
import uuid
from pathlib import Path

from benchmarks import COMPOSE, TARGETS
from detect import detect


def capture(output: Path, mode: str) -> list[dict[str, object]]:
    output.parent.mkdir(parents=True, exist_ok=True)
    name = "labscan-capture-" + uuid.uuid4().hex[:10]
    subprocess.run(
        COMPOSE + ["run", "-d", "--name", name, "--entrypoint", "sleep", "raw", "60"],
        check=True,
        capture_output=True,
        text=True,
    )
    process = None
    try:
        with output.open("wb") as stream, output.with_suffix(".log").open("wb") as errors:
            process = subprocess.Popen(
                [
                    "docker",
                    "run",
                    "--rm",
                    "--network",
                    f"container:{name}",
                    "--cap-drop",
                    "ALL",
                    "--cap-add",
                    "NET_RAW",
                    "--entrypoint",
                    "tshark",
                    "labscan-reference",
                    "-i",
                    "eth0",
                    "-p",
                    "-f",
                    "net 172.30.0.0/24 or arp",
                    "-a",
                    "duration:12",
                    "-w",
                    "-",
                ],
                stdout=stream,
                stderr=errors,
            )
            for _ in range(100):
                if process.poll() is not None:
                    raise RuntimeError(output.with_suffix(".log").read_text())
                if "Capturing on" in output.with_suffix(".log").read_text():
                    break
                time.sleep(0.05)
            else:
                raise RuntimeError("Capture did not become ready within five seconds")
            if mode in ("syn", "udp"):
                subprocess.run(
                    [
                        "docker",
                        "exec",
                        name,
                        "labscan",
                        TARGETS,
                        "--scan-type",
                        mode,
                        "--output-format",
                        "json",
                    ],
                    check=True,
                    capture_output=True,
                )
            elif mode == "nmap-udp":
                subprocess.run(
                    [
                        "docker",
                        "run",
                        "--rm",
                        "--network",
                        f"container:{name}",
                        "--cap-drop",
                        "ALL",
                        "--cap-add",
                        "NET_RAW",
                        "labscan-reference",
                        "-sU",
                        "-Pn",
                        "-n",
                        "--reason",
                        "--max-rate",
                        "20",
                        "--max-retries",
                        "0",
                        "-p",
                        "22,53,80,81,82,6379,8000",
                        *TARGETS.split(","),
                    ],
                    check=True,
                    capture_output=True,
                )
            elif mode == "benign":
                code = """import asyncio
from pathlib import Path
from labscan.scope import ScopeGuard
guard = ScopeGuard.from_file(Path('configs/scope.yaml'))
async def main():
    for _ in range(6):
        guard.check('172.30.0.10')
        reader, writer = await asyncio.open_connection('172.30.0.10', 80)
        guard.check('172.30.0.10')
        writer.write(b'HEAD / HTTP/1.0\\r\\nHost: lab.test\\r\\n\\r\\n')
        await writer.drain()
        await asyncio.wait_for(reader.read(1024), 1)
        writer.close()
        await writer.wait_closed()
        await asyncio.sleep(0.2)
asyncio.run(main())"""
                subprocess.run(["docker", "exec", name, "python", "-c", code], check=True)
            else:
                raise ValueError("Unknown capture mode")
            if process.wait(timeout=20):
                raise RuntimeError(output.with_suffix(".log").read_text())
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            process.wait(timeout=10)
        subprocess.run(["docker", "rm", "-f", name], check=True, capture_output=True)
    return detect(output, 5, 10)


if __name__ == "__main__":
    import json

    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["syn", "udp", "nmap-udp", "benign"])
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    alerts = capture(args.output, args.mode)
    args.output.with_suffix(".alerts.json").write_text(json.dumps(alerts, indent=2))
    print(json.dumps(alerts, indent=2))
