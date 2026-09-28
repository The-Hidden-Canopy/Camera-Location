"""Allow running as: python -m camdiscover"""
import os
import sys


def main():
    try:
        from .network import install_signal_handlers
        install_signal_handlers()
    except Exception:
        pass

    if len(sys.argv) > 1 and sys.argv[1] == "web":
        from .webapp import create_app

        host = "0.0.0.0"
        port = 5000
        db_path = None
        site_id = None
        backend_token = None
        backend_nonce = None
        args = sys.argv[2:]
        for i, arg in enumerate(args):
            if arg == "--host" and i + 1 < len(args):
                host = args[i + 1]
            elif arg == "--port" and i + 1 < len(args):
                port = int(args[i + 1])
            elif arg == "--db-path" and i + 1 < len(args):
                db_path = args[i + 1]
            elif arg == "--site-id" and i + 1 < len(args):
                site_id = args[i + 1]

        # Electron passes these via env when it launches the backend.
        backend_token = os.environ.get("CAM_BACKEND_TOKEN")
        backend_nonce = os.environ.get("CAM_BACKEND_NONCE")

        app = create_app(
            db_path=db_path, site_id=site_id,
            backend_token=backend_token, backend_nonce=backend_nonce,
        )
        print(f"\n  Hidden Canopy Network Discovery - Web UI")
        print(f"  http://{host}:{port}\n")
        app.run(host=host, port=port, debug=False, threaded=True)
    else:
        from .cli import main as cli_main
        cli_main()


if __name__ == "__main__":
    main()
