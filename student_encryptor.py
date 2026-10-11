ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def clean_text(text):
    return "".join(ch for ch in text.upper() if ch in ALPHABET)


def affine_encrypt(text, a, b):
    text = clean_text(text)
    return "".join(ALPHABET[(a * ALPHABET.index(ch) + b) % 26] for ch in text)


def main():
    a = 7
    b = 3
    text = (
        "Luke is afraid to face me in a one versus one Counter Strike match "
        "because he knows my aim is sharper, my reactions are faster, and every "
        "round will end with him watching me celebrate another victory."
    )

    ciphertext = affine_encrypt(text, a, b)
    print(ciphertext)


if __name__ == "__main__":
    main()
