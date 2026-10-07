import argparse

from .analyzer import analyze


def main():
    parser = argparse.ArgumentParser(description="Explica o tráfego de um ficheiro .pcap.")
    parser.add_argument("pcap", help="caminho do ficheiro .pcap")
    args = parser.parse_args()

    r = analyze(args.pcap)

    print(f"Total de pacotes: {r['total']}")
    print("\n== Protocolos ==")
    for nome, n in r["protocols"].items():
        print(f"{nome}: {n} pacotes")

    print("\n== Consultas DNS ==")
    for d in r["dns"]:
        print(f"- {d}")
    for d in r["suspicious_dns"]:
        print(f"AVISO: '{d}' parece um nome gerado aleatoriamente.")

    print("\n== Conexões TCP mais frequentes ==")
    for (src, dst, porta), n in r["connections"]:
        extra = " (porta 80: HTTP, sem cifra)" if porta == 80 else ""
        print(f"{src} -> {dst}:{porta}  {n} pacotes{extra}")


if __name__ == "__main__":
    main()