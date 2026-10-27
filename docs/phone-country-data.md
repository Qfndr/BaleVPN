# Offline country selection

Country calling codes, national prefixes and shared-code hints derive from Google libphonenumber PhoneNumberMetadata.xml, retrieved 2026-10-27:
https://github.com/google/libphonenumber/blob/master/resources/PhoneNumberMetadata.xml
Copyright The Libphonenumber Authors; Apache-2.0. Full license: licenses/libphonenumber-Apache-2.0.txt.

Country names use the operating browser’s Intl.DisplayNames; country codes and flags are bundled locally. No third-party lookup, CDN request, phone upload or new runtime dependency is used by the selector.

Flag SVGs: https://github.com/lipis/flag-icons/tree/main/flags/4x3
Copyright (c) 2013 Panayiotis Lipiridis; MIT. Full license: licenses/flag-icons-MIT.txt. AC/TA use Unicode regional-flag fallback because the source set has no corresponding SVG.

The selector recognizes calling codes and available leading-digit hints, not phone ownership or full number validity. Shared calling codes can require manual country selection. National numbers are prefixed only on submission; name search remains available. Italy/Vatican significant zero is retained. Other literal national trunk prefixes from the dataset are removed for international submission. Existing explicit + or 00 numbers retain their international code. Persian/Arabic digits are converted locally.
