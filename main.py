#!/usr/bin/env python3
"""
Phishing URL Detector
Main terminal interface for Windows/Linux.
"""

from url_analyzer import analyze_url


def print_separator():
    print("-" * 60)


def display_result(result):
    print_separator()
    print("PHISHING URL ANALYSIS")
    print_separator()

    print(f"URL         : {result['url']}")
    print(f"Protocol    : {result['protocol']}")
    print(f"Hostname    : {result['hostname']}")
    print(f"Port        : {result['port'] or 'Default'}")
    print(f"Path        : {result['path'] or '/'}")

    print_separator()

    print(f"Risk Score  : {result['score']}/100")
    print(f"Risk Level  : {result['risk_level']}")

    print_separator()
    print("Indicators:")
    print()

    if result["indicators"]:
        for indicator in result["indicators"]:
            print(f"[!] {indicator}")
    else:
        print("[+] No suspicious indicators detected")

    print_separator()


def main():
    print("=" * 60)
    print("        PHISHING URL DETECTOR")
    print("=" * 60)
    print("Static URL analysis tool")
    print("The tool does not visit the target website.")
    print()

    while True:
        url = input("Enter URL (or 'q' to quit): ").strip()

        if url.lower() == "q":
            print("\nExiting...")
            break

        if not url:
            print("[!] Please enter a URL.\n")
            continue

        result = analyze_url(url)

        display_result(result)
        print()


if __name__ == "__main__":
    main()
