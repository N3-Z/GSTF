import asyncio
import sys
import argparse
from core.scan import start_scan


def parse_metadata(metadata_list):
    """Parse ['key=value', ...] into gRPC metadata tuples [('key', 'value'), ...]."""
    result = []
    for item in metadata_list:
        if '=' not in item:
            print(f"[!] Skipping invalid metadata '{item}' — expected format: KEY=VALUE")
            continue
        key, value = item.split('=', 1)
        result.append((key.strip().lower(), value.strip()))
    return result if result else None


def main():
    parser = argparse.ArgumentParser(
        description="GSTF - gRPC Security Testing Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  Basic scan:
    python main.py -f auth.proto -u localhost:50051

  With Bearer token:
    python main.py -f auth.proto -u localhost:50051 -m "authorization=Bearer <token>"

  Auto-login then scan:
    python main.py -f auth.proto -u localhost:50051 \\
      --auth-rpc Login --auth-data "username=admin" --auth-data "password=admin123"

  Targeted scan (SQL injection only on Login):
    python main.py -f auth.proto -u localhost:50051 --attack sqli --service Login

  CI/CD mode (quiet + exit code):
    python main.py -f auth.proto -u localhost:50051 -q
    echo "Exit code: $?"   # 0 = clean, 1 = vulnerabilities found
        """
    )

    # Required
    parser.add_argument('-f', '--file', required=True,
                        help="Path to the .proto file")
    parser.add_argument('-u', '--url',  required=True,
                        help="gRPC server URL (e.g. localhost:50051)")

    # Connection
    parser.add_argument('-s', '--secure', action='store_true',
                        help="Enable TLS/SSL")
    parser.add_argument('-m', '--metadata', action='append', default=[], metavar='KEY=VALUE',
                        help="Metadata header. Can be repeated. e.g. -m \"authorization=Bearer token\"")

    # Auth flow
    parser.add_argument('--auth-rpc', metavar='RPC',
                        help="RPC to call for authentication before scanning (e.g. Login)")
    parser.add_argument('--auth-data', action='append', default=[], metavar='KEY=VALUE',
                        help="Data for auth RPC. Can be repeated. e.g. --auth-data \"username=admin\"")
    parser.add_argument('--auth-field', default='token', metavar='FIELD',
                        help="Response field containing the token (default: token)")
    parser.add_argument('--auth-header', default=None, metavar='KEY=TEMPLATE',
                        help="Header template for token. e.g. \"authorization=Bearer {token}\" (default)")

    # Scan filters
    parser.add_argument('--attack', metavar='TYPES',
                        help="Comma-separated attack types to run. e.g. sqli,xss,lfi")
    parser.add_argument('--service', metavar='NAMES',
                        help="Comma-separated service names to test. e.g. Login,Signup")

    # Output & behavior
    parser.add_argument('-q', '--quiet', action='store_true',
                        help="Only show vulnerable results (suppress not-vuln lines)")
    parser.add_argument('--delay', type=int, default=0, metavar='MS',
                        help="Delay in ms between requests (default: 0)")
    parser.add_argument('--payloads', default='./core/modules/payloads.yaml', metavar='PATH',
                        help="Path to payloads YAML file (default: ./core/modules/payloads.yaml)")
    parser.add_argument('--timeout', type=int, default=30, metavar='SEC',
                        help="Per-request timeout in seconds (default: 30)")
    parser.add_argument('--max-per-attack', type=int, default=2, metavar='N',
                        help="Stop testing an attack on a param after N vulnerable payloads found "
                             "(default: 2, set 0 to disable)")
    parser.add_argument('--proxy', default=None, metavar='URL',
                        help="HTTP proxy URL for traffic interception, "
                             "e.g. http://127.0.0.1:8080 (Burp) or http://127.0.0.1:8082 (mitmproxy)")

    args = parser.parse_args()

    attacks_filter  = [a.strip() for a in args.attack.split(',')]  if args.attack  else None
    services_filter = [s.strip() for s in args.service.split(',')]  if args.service else None

    result = asyncio.run(start_scan(
        pathname        = args.file,
        secure          = args.secure,
        url             = args.url,
        metadata        = parse_metadata(args.metadata),
        quiet           = args.quiet,
        delay_ms        = args.delay,
        attacks_filter  = attacks_filter,
        services_filter = services_filter,
        payloads_path   = args.payloads,
        auth_rpc        = args.auth_rpc,
        auth_data       = parse_metadata(args.auth_data),
        auth_field      = args.auth_field,
        auth_header     = args.auth_header,
        timeout              = args.timeout,
        max_vuln_per_attack  = args.max_per_attack,
        proxy                = args.proxy,
    ))

    # CI/CD exit code: 1 if vulnerabilities found, 0 if clean
    sys.exit(1 if result['vulnerable'] > 0 else 0)


if __name__ == "__main__":
    main()
