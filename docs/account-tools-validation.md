# Account tools validation — 2.6.3-dev.3

This development build adds independent account port editing and explicitly requested account details. It does not change the tunnel data path, packet encryption, congestion windows, compression or call admission policy. There is no claim of a measured throughput increase.

The regression checks use local fixtures and temporary, independent data directories. They do not use an existing user's accounts or send real Bale calls or OTP requests.

- Application Rust tests cover encrypted phone metadata bound to the authenticated token, compatibility with old device records, encrypted session transfer, occupied/duplicate port rejection and concurrent updates of different account ports.
- Signaling Rust tests cover matching a verified login transaction to its phone and selecting the correct user's cached display name and username. Existing network health tests remain ignored.
- `scripts/smoke-aggregate.py` exercises real application subprocesses: a stopped account's ports change while its sibling keeps the same PID; its public identity survives restart; occupied, duplicate and running-account edits fail; the parent's profile proxy remains restricted. External SOCKS paths continue to work.
- `scripts/test-ui-account-tools-browser.cjs` covers stopping, editing and restarting only the selected account, rejected saves, masked phone display, absence of phone data in browser storage and periodic state polling, stale-response isolation, keyboard focus and responsive dialogs in all three designs. It confirms that port editing does not submit login or call requests.
- Existing browser checks cover account routing, encrypted transfer, tabs, Persian/English, both themes, preference restoration, visible save failures and live chart inspection.

Run the additional browser fixture with Playwright installed:

```sh
node scripts/test-ui-account-tools-browser.cjs
```

An installed Chromium path can be supplied with `BALEVPN_BROWSER_EXECUTABLE`; `BALEVPN_PLAYWRIGHT_MODULE` can select an existing Playwright installation. Set `BALEVPN_SCREENSHOTS` to a directory to save Persian dialog screenshots.

Live Bale calls, actual account phone retrieval from the service, mobile builds and macOS execution are outside these local checks. Old or manually imported sessions can legitimately have no recorded login phone and do not need to be signed in again for that reason. The reported second-server connection issue was resolved by approving its own pending caller; call admission was not weakened.
