# Private call recovery

When encrypted recovery callbacks are configured, `CallClient` first saves a
minimal bound `requestCall` intent with `response: {}` and awaits that save before
sending the call request. Failure to save the intent sends no call RPC. The
intent contains no chat history, OTP, RSA key or raw auth token.

A response received while the same account and operation still own the client
replaces that intent with only the bounded `call_type` and `call_update` fields.
This happens before strict call projection. A healthy `CallSession` removes the
candidate only after it has adopted the exact parsed call ID. Saving or parsing
a response does not accept a call or grant media access.

If the account stops, the vault locks, the process exits, or ownership changes
while the request is in flight, the saved intent remains. A late response must
not bypass the account/epoch guard to write into the vault. An empty intent does
not recover a lost call ID and does not prove that the service created a call.
It records uncertainty and blocks automatic redial in the Lab. A separate,
verified read/cleanup procedure is needed before another call; none is implied.

If saving a bounded response fails, the same `CallClient` retains a private
serialized copy until explicit close or acknowledgement. The owner can call
`retrySaveCallRecovery()` to retry only that save, then `recoverRequestCall()`
without an argument to reparse it. Neither method sends a call request. Both
remain bound to the same account credentials and enforce the existing size and
24-hour recovery limits. Closing the client wipes its private buffer; only the
already saved encrypted intent or response survives. No raw recovery contents
are added to public state or HTTP routes.

Normal Lab failure cleanup closes its call client. Therefore in-memory recovery
is not promised after such cleanup; the persisted intent still preserves the
uncertain-operation warning. Filesystem atomic replacement is used, with no
claim of durability through storage hardware failure.
