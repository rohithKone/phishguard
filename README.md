# PhishGuard

A small, self-contained phishing-link checker with a responsive web frontend and a local Python backend. It scores common URL warning signs and explains each signal.

## Run it

Requires Python 3.9 or newer. There are no third-party Python packages to install.

```bash
cd phishing-detector
python server.py
```

Open [http://127.0.0.1:8000](http://127.0.0.1:8000) in your browser. Stop the server with Ctrl+C.

## What it checks

- Plain HTTP, IP-address hosts, `@` signs, and embedded credentials
- Punycode, URL shorteners, unusually long hostnames, and many subdomains or hyphens
- Sensitive-action wording and well-known brand names in a hostname

The score is an explainable heuristic, not a machine-learning verdict or domain-reputation lookup. It does not visit submitted URLs, contact external reputation services, or store submissions. A low score does not guarantee a site is safe. For sensitive accounts, navigate to the official site directly.

## Project layout

```text
phishing-detector/
├── server.py
├── README.md
└── static/
    ├── index.html
    ├── styles.css
    └── app.js
```

