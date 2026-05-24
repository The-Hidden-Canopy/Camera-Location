"""Allow running as: python -m camdiscover"""
import sys


def main():
    # Install SIGINT/SIGTERM/SIGBREAK handlers on the main thread so closing
    # the desktop window, Ctrl+C, or taskkill always tears down any
    # temporary netsh IPs before the process dies.
    try:
        from .network import install_signal_handlers
        install_signal_handlers()
    except Exception:
        pass

    if len(sys.argv) > 1 and sys.argv[1] == "web":
        from .webapp import create_app
        app = create_app()
        host = "0.0.0.0"
        port = 5000
        # Parse --host and --port
        args = sys.argv[2:]
        for i, arg in enumerate(args):
            if arg == "--host" and i + 1 < len(args):
                host = args[i + 1]
            elif arg == "--port" and i + 1 < len(args):
                port = int(args[i + 1])
        print(f"\n  Camera Discovery Octopus — Web UI")
        print(f"  http://{host}:{port}\n")
        app.run(host=host, port=port, debug=False, threaded=True)
    else:
        from .cli import main as cli_main
        cli_main()


if __name__ == "__main__":
    main()
