"""Compare the bundled baseline and SYN burst without starting the web server."""

from importlib.resources import files

from packet_trail.analysis import analyze

for filename in ("normal.pcap", "syn-burst.pcap"):
    capture = files("packet_trail").joinpath("samples", filename).read_bytes()
    report = analyze(capture, name=filename)
    print(f"{filename}: {report['summary']['packet_count']} packets")
    for flag in report["flags"]:
        print(f"  {flag['title']}: {flag['evidence']}")
