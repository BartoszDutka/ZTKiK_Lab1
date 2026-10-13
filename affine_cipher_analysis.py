import sys
from math import gcd

try:
    import matplotlib.pyplot as plt
except ModuleNotFoundError:
    plt = None

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

# Tabela 2.1 — prawdopodobieństwo wystąpienia liter w angielskim
ENGLISH_FREQ = {
    'A': 0.082, 'B': 0.015, 'C': 0.028, 'D': 0.043, 'E': 0.127, 'F': 0.022,
    'G': 0.020, 'H': 0.061, 'I': 0.070, 'J': 0.002, 'K': 0.008, 'L': 0.040,
    'M': 0.024, 'N': 0.067, 'O': 0.075, 'P': 0.019, 'Q': 0.001, 'R': 0.060,
    'S': 0.063, 'T': 0.091, 'U': 0.028, 'V': 0.010, 'W': 0.023, 'X': 0.001,
    'Y': 0.020, 'Z': 0.001,
}

SAMPLE_CIPHERTEXT = "GAFZGNYFQGZJFGHQGAFCHKSDSPFUFSPFUFQHQTGXESFEDSFMXSGAFMHQDCFIDJHQRSPEGXTSDEAPGAFPSFDYDKXNGGAFDMMHQFRHEAFSDQYCFDSQFYGADGMSFLNFQRPDQDCPZHZHZDEXBFSMNCGXXCMXSKSFDVHQTZHJECFZNKZGHGNGHXQRHEAFSZLNHRVCPDQYSFCHDKCP"


def clean_text(text: str) -> str:
    return "".join(ch for ch in text.upper() if ch in ALPHABET)


def inverse_mod(a: int, m: int = 26) -> int:
    return pow(a, -1, m)


def affine_encrypt(text: str, a: int, b: int) -> str:
    text = clean_text(text)
    return "".join(ALPHABET[(a * ALPHABET.index(ch) + b) % 26] for ch in text)


def affine_decrypt(ciphertext: str, a: int, b: int) -> str:
    a_inv = inverse_mod(a)
    return "".join(ALPHABET[a_inv * (ALPHABET.index(ch) - b) % 26].lower() for ch in ciphertext)


def english_score(text: str) -> float:
    """Ocena zgodności tekstu z częstościami liter z tabeli 2.1 (nie chi^2).

    Średnia prawdopodobieństw liter z ENGLISH_FREQ; wyższy wynik oznacza
    większą zgodność z typowym tekstem angielskim. Próg w find_key (0.055)
    to prosty heurystyczny cut-off, nie test statystyczny.
    """
    text = clean_text(text)
    if not text:
        return 0.0
    return sum(ENGLISH_FREQ.get(ch, 0.0) for ch in text) / len(text)


def draw_letter_histogram(text: str, output_file: str = "letter_histogram.png"):
    if plt is None:
        print("Matplotlib is not available; no graphical histogram was generated.")
        return

    cleaned = clean_text(text)
    counts = {ch: cleaned.count(ch) for ch in ALPHABET}
    letters = [ch for ch in ALPHABET if counts[ch] > 0]
    values = [counts[ch] for ch in letters]

    fig, ax = plt.subplots(figsize=(12, 6))
    ax.bar(letters, values, color="steelblue")
    ax.set_title("Letter frequency in ciphertext")
    ax.set_xlabel("Letter")
    ax.set_ylabel("Frequency")
    ax.grid(axis="y", linestyle="--", alpha=0.3)

    for i, value in enumerate(values):
        ax.text(i, value + 0.3, str(value), ha="center", va="bottom", fontsize=8)

    fig.tight_layout()
    fig.savefig(output_file, dpi=200)
    plt.close(fig)
    print(f"Graphical histogram saved to: {output_file}")


def solve_system(x1: int, y1: int, x2: int, y2: int):
    dx = (x1 - x2) % 26
    dy = (y1 - y2) % 26
    g = gcd(dx, 26)

    if dy % g != 0:
        return []

    m = 26 // g
    a0 = (dy // g) * pow(dx // g, -1, m) % m

    return [(a, (y1 - a * x1) % 26) for a in range(a0, 26, m)]


def find_key(ciphertext: str, threshold: float = 0.055):
    ciphertext = clean_text(ciphertext)
    if len(ciphertext) < 2:
        return None, None, []

    counts = {c: ciphertext.count(c) for c in ALPHABET}
    ciphertext_top = sorted(ALPHABET, key=lambda c: (-counts[c], c))[:6]
    english_top = sorted(ALPHABET, key=lambda c: -ENGLISH_FREQ[c])[:6]

    invalid = []

    for i in range(len(english_top)):
        for j in range(i + 1, len(english_top)):
            p1, p2 = english_top[i], english_top[j]
            for c1 in ciphertext_top:
                for c2 in ciphertext_top:
                    if c1 == c2:
                        continue

                    x1, y1 = ALPHABET.index(p1), ALPHABET.index(c1)
                    x2, y2 = ALPHABET.index(p2), ALPHABET.index(c2)

                    keys = solve_system(x1, y1, x2, y2)
                    if not keys:
                        continue

                    for a, b in keys:
                        if gcd(a, 26) != 1:
                            invalid.append((a, b, "NWD(a,26)!=1"))
                            continue

                        plaintext = affine_decrypt(ciphertext, a, b)
                        score = english_score(plaintext)

                        if score >= threshold:
                            return (a, b), plaintext, invalid

                        invalid.append((a, b, f"M={score:.3f}"))

    return None, None, invalid


def main():
    args = sys.argv[1:]

    if args and args[0] == "encrypt":
        if len(args) < 4:
            raise SystemExit("Usage: python affine_cipher_analysis.py encrypt a b text")

        a = int(args[1])
        b = int(args[2])
        text = " ".join(args[3:])

        if gcd(a, 26) != 1:
            raise SystemExit(
                f"Invalid key: a={a}, gcd(a,26)={gcd(a, 26)}. "
                "Choose an odd a different from 13."
            )

        print(affine_encrypt(text, a, b))
        return

    if args and args[0] == "analyze":
        text = " ".join(args[1:]) if len(args) > 1 else SAMPLE_CIPHERTEXT
        ciphertext = clean_text(text)
    elif args:
        ciphertext = clean_text(" ".join(args))
    else:
        ciphertext = SAMPLE_CIPHERTEXT

    print(f"Ciphertext: {ciphertext}\n")
    draw_letter_histogram(ciphertext)
    print()

    key, plaintext, invalid = find_key(ciphertext)

    if key is None:
        print("No valid key found. The ciphertext is too short or the letter pair was incorrect.")
        print("Rejected keys:", invalid[:10])
        return

    a, b = key
    print(f"Found key: (a, b) = ({a}, {b})")
    print(f"Plaintext: {plaintext}")
    print(f"Check: {affine_encrypt(plaintext, a, b) == ciphertext}")
    print()
    print(f"Rejected key pairs (count={len(invalid)}):")
    if not invalid:
        print("  (none — first candidate already gave readable English)")
    else:
        for ra, rb, reason in invalid:
            print(f"  (a, b) = ({ra}, {rb})  -> {reason}")
    print()
    print(
        "Note: plaintext quality uses english_score = mean of letter "
        "probabilities from Table 2.1 (heuristic threshold 0.055, not chi^2)."
    )


if __name__ == "__main__":
    main()
