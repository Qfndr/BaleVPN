# Bundled fonts

The unmodified font files are embedded in the executable and served only by
the local management UI. No CDN or third-party font request is made.

- Vazirmatn v33.003 by Saber Rastikerdar:
  https://github.com/rastikerdar/vazirmatn/tree/v33.003
  Source: `fonts/webfonts/Vazirmatn[wght].woff2`.
  License: `Vazirmatn-OFL.txt` (SIL Open Font License 1.1).
- Inter v4.1 by Rasmus Andersson:
  https://github.com/rsms/inter/tree/v4.1
  Source: `docs/font-files/InterVariable.woff2`.
  License: `Inter-LICENSE.txt` (SIL Open Font License 1.1).

Both variable fonts include their weight range in one WOFF2 file. Inter renders
Latin text; Vazirmatn supplies Persian/Arabic glyphs. Technical identifiers keep
their monospace styles. System fonts remain available as a user preference.
