# Fonts

`space-grotesk.woff2` — Space Grotesk, latin subset, variable weight axis 500–700
(one file covers all three weights; Google serves the same file for each).

Licensed under the SIL Open Font License 1.1 <https://openfontlicense.org>, which permits
redistribution and self-hosting. Source: Google Fonts (`fonts.gstatic.com`, v22).

Self-hosted deliberately rather than linked from fonts.googleapis.com: the app's CSP is
`style-src 'self' 'unsafe-inline'` and `font-src 'self' data:` (see `backend/app/main.py`),
so a Google Fonts link would be blocked in production — and widening a deliberately tight
policy to add a third-party request is the wrong trade for 22 KB.
