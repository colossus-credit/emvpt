![Build and test](https://github.com/mrautio/emvpt/workflows/Docker%20Image%20CI/badge.svg)

# emvpt - Minimum Viable Payment Terminal

Project's intention is to support simple EMV transaction cases for chip and contactless/NFC.

## Terminal simulator run

Note!
- You'll need a smart card reader device.
- If you need a test payment card, you can check [emv-card-simulator](https://github.com/mrautio/emv-card-simulator) project out.

```sh
cd terminalsimulator
cargo run -- --help
```

### Online authorization

To send an ARQC to an external Colossus switch for online authorization, use `--switch-url` and `--icc-public-key`. The switch would receive an ISO 8583 0100 message with EMV data and the ICC public key, and the terminal simulator would an ARPC with the authorization decision.

```sh
cd terminalsimulator
cargo run -- --switch-url <SWITCH_URL> --icc-public-key <PATH_TO_ICC_KEY_DIR> \
--amount 10000 \
--print-tags # With debug tag printing
```

- `--switch-url` - URL of the authorization switch (e.g. `http://localhost:3000`)
- `--icc-public-key` - Directory containing `icc_modulus.bin` and `icc_exponent.bin`
- `--amount` - Transaction amount in cents (optional, defaults to 1)

## Library

```sh
emvpt$ cargo test
```

## Docker

```sh
docker build -t emvpt -f Dockerfile . && docker run --rm -t emvpt
```

## Update dependencies

Run the [GitHub Actions Workflow](https://github.com/mrautio/emvpt/actions/workflows/update-dependencies.yml).

## References

* [EMV Contact Specifications](https://www.emvco.com/emv-technologies/contact/)
* [EMV Contactless Specifications](https://www.emvco.com/emv-technologies/contactless/)
  * EMV Contactless Book C-1 - Kernel 1 (JCB and Visa)
  * EMV Contactless Book C-2 - Kernel 2 (MasterCard)
  * EMV Contactless Book C-3 - Kernel 3 (Visa)
  * EMV Contactless Book C-4 - Kernel 4 (American Express)
  * EMV Contactless Book C-5 - Kernel 5 (JCB)
  * EMV Contactless Book C-6 - Kernel 6 (Discover)
  * EMV Contactless Book C-7 - Kernel 7 (UnionPay)
* ISO codes
  * [Processing codes](http://www.fintrnmsgtool.com/iso-processing-code.html)
  * [Country codes](https://www.currency-iso.org/dam/downloads/lists/list_one.xml)
    * [FI country code](https://www.iso.org/obp/ui/#iso:code:3166:FI)
