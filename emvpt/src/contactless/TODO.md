# Kernel 2 Spec Compliance TODOs

Gaps between current implementation and EMV Contactless Book C-2.

## High Priority (may affect production card testing)

- [ ] **PDOL default values** — if card requests tags we don't have (9F6E, DF8101, etc.), we fill with zeros. Spec defines per-tag defaults. Build a default value table for common PDOL tags.
- [ ] **TTQ full construction** — only a few bits set from pre-processing. Need full TTQ construction per Book C-2 Table A.1: offline-only reader, online cryptogram required, EMV contact chip supported, etc.
- [ ] **CDA Transaction Data Hash input order** — delegating to contact CDA code (`handle_application_cryptogram_card_authentication`). Verify hash input matches Kernel 2 spec exactly: PDOL-related data + CDOL1-related data + tag 77 excluding 9F4B.
- [ ] **Application Capabilities Information** — production cards may send additional contactless-specific data objects we currently ignore.
- [ ] **L1/L2 error recovery** — READ RECORD timeout/bad SW just `continue`s. Spec mandates specific outcomes (EndApplication, TryAgain) for specific error conditions.

## Medium Priority (edge cases for some cards)

- [ ] **Relay Resistance Protocol** — newer MC cards may require it. Not implemented.
- [ ] **Mag Stripe profile** — returns TryAnotherInterface. Some cards only support mag stripe contactless.
- [ ] **Multi-app PPSE selection** — takes first app. Should respect priority ordering and support SELECT_NEXT on failure.
- [ ] **Balance reading** — parse balance from GPO response if card returns it.
- [ ] **Kernel Configuration flags** — DF811B stored but bits not used (EMV/Mag preference, IDS support).
- [ ] **Issuer script processing** — process issuer scripts in GENERATE AC response or after online auth.
- [ ] **Field off timing** — NFC field hold time in outcome hardcoded to 0.

## Low Priority (not needed for basic testing)

- [ ] **Torn transaction management** — detect and recover interrupted NFC transactions. Requires persistent storage.
- [ ] **IDS (Integrated Data Storage)** — tag DF8128 support.
- [ ] **Formal state machine** — current implementation is procedural. Spec defines states with transitions and timeouts.
- [ ] **UI Request Data generation** — structs defined but not populated during transaction flow.
- [ ] **Error Indication (DF8115)** — struct defined but not systematically populated with L1/L2/L3 codes.
