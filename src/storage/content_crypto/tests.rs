use super::*;
use serde_json::{Value, json};
use std::io::{BufRead, Cursor};

fn encrypted(bytes: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    encrypt(
        &mut Cursor::new(bytes),
        &mut output,
        &[7; 32],
        "scope",
        || Ok(()),
    )
    .unwrap();
    output
}
#[test]
fn frame_boundaries_short_reads_and_new_randomness() {
    struct Short<'a>(&'a [u8]);
    impl Read for Short<'_> {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            let n = out.len().min(self.0.len()).min(17);
            out[..n].copy_from_slice(&self.0[..n]);
            self.0 = &self.0[n..];
            Ok(n)
        }
    }
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("result");
    for size in [0, 1, 17, CHUNK_BYTES, CHUNK_BYTES + 1, 2 * CHUNK_BYTES + 13] {
        let plain: Vec<_> = (0..size).map(|i| (i % 251) as u8).collect();
        let bytes = encrypted(&plain);
        assert_eq!(bytes.len(), 160 + size + 20 * size.div_ceil(CHUNK_BYTES));
        assert_ne!(bytes, encrypted(&plain));
        decrypt_and_publish(&mut Short(&bytes), &target, &[7; 32], "scope", || Ok(())).unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), plain);
        let mut short = Vec::new();
        encrypt(&mut Short(&plain), &mut short, &[7; 32], "scope", || Ok(())).unwrap();
        decrypt_and_publish(&mut Cursor::new(short), &target, &[7; 32], "scope", || {
            Ok(())
        })
        .unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), plain);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&target).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
}
#[test]
fn corruption_truncation_reordering_cancel_and_io_failure_preserve_target() {
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("result");
    std::fs::write(&target, b"previous").unwrap();
    let bytes = encrypted(&vec![9; 2 * CHUNK_BYTES + 17]);
    let mut cases: Vec<_> = [0, 8, 12, 64, 123, 124, bytes.len() - 1]
        .map(|len| bytes[..len].to_vec())
        .into();
    for offset in [0, 11, 15, 32, 64, 76, 123, 124, 128, bytes.len() - 1] {
        let mut bad = bytes.clone();
        bad[offset] ^= 1;
        cases.push(bad);
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    cases.push(trailing);
    let mut reorder = bytes.clone();
    let length = CHUNK_BYTES + 20;
    reorder[124..124 + length].copy_from_slice(&bytes[124 + length..124 + 2 * length]);
    reorder[124 + length..124 + 2 * length].copy_from_slice(&bytes[124..124 + length]);
    cases.push(reorder);
    for bad in cases {
        assert!(
            decrypt_and_publish(&mut Cursor::new(bad), &target, &[7; 32], "scope", || Ok(()))
                .is_err()
        );
        assert_eq!(std::fs::read(&target).unwrap(), b"previous");
        assert_eq!(std::fs::read_dir(temp.path()).unwrap().count(), 1);
    }
    for (key, scope) in [([0; 32], "scope"), ([7; 32], "wrong")] {
        assert!(
            decrypt_and_publish(&mut Cursor::new(&bytes), &target, &key, scope, || Ok(())).is_err()
        );
        assert_eq!(std::fs::read(&target).unwrap(), b"previous");
    }
    // Includes cancellation after EOF authentication but before publication.
    for limit in 1..=5 {
        let mut count = 0;
        assert!(
            decrypt_and_publish(&mut Cursor::new(&bytes), &target, &[7; 32], "scope", || {
                count += 1;
                ensure!(count < limit, "cancelled");
                Ok(())
            })
            .is_err()
        );
        assert_eq!(std::fs::read(&target).unwrap(), b"previous");
        assert_eq!(std::fs::read_dir(temp.path()).unwrap().count(), 1);
    }
    struct Broken;
    impl Read for Broken {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("broken source"))
        }
    }
    assert!(decrypt_and_publish(&mut Broken, &target, &[7; 32], "scope", || Ok(())).is_err());
    assert_eq!(std::fs::read(&target).unwrap(), b"previous");
}
#[test]
fn password_envelope_authenticates_identity_and_exact_format() {
    let id = "00010203-0405-4607-8809-0a0b0c0d0e0f";
    let password = "恢复材料安全口令😀pass123";
    let bytes = create_password_location(id, &[7; 32], password).unwrap();
    assert_eq!(bytes.len(), 124);
    let (actual_id, key) = unlock_password_location(&bytes, password).unwrap();
    assert_eq!(actual_id, id);
    assert_eq!(*key, [7; 32]);
    assert_ne!(
        bytes,
        create_password_location(id, &[7; 32], password).unwrap()
    );
    assert!(create_password_location(id, &[7; 32], "short").is_err());
    assert!(create_password_location(id, &[7; 32], &"😀".repeat(513)).is_err());
    for offset in [12, 28, 32, 64, 76, 123] {
        let mut bad = bytes.clone();
        bad[offset] ^= 1;
        assert!(unlock_password_location(&bad, password).is_err());
    }
    assert_eq!(
        unlock_password_location(&bytes, "incorrect password")
            .unwrap_err()
            .downcast_ref::<ContentError>()
            .unwrap()
            .0,
        ErrorCode::UnlockFailed
    );
    assert_eq!(
        password_location_id(&bytes[..123])
            .unwrap_err()
            .downcast_ref::<ContentError>()
            .unwrap()
            .0,
        ErrorCode::DamagedLocation
    );
    let mut unknown = bytes;
    unknown[11] = 2;
    assert_eq!(
        password_location_id(&unknown)
            .unwrap_err()
            .downcast_ref::<ContentError>()
            .unwrap()
            .0,
        ErrorCode::UnsupportedFormat
    );
}
#[test]
fn independent_upstream_node_vectors() {
    let vector: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/storage-content-v1-vector.json"
    ))
    .unwrap();
    let text = |name: &str| vector[name].as_str().unwrap();
    let key: [u8; 32] = hex::decode(text("locationKeyHex"))
        .unwrap()
        .try_into()
        .unwrap();
    let temp = tempfile::tempdir().unwrap();
    let destination = temp.path().join("plain");
    decrypt_and_publish(
        &mut Cursor::new(hex::decode(text("ciphertextHex")).unwrap()),
        &destination,
        &key,
        text("scope"),
        || Ok(()),
    )
    .unwrap();
    assert_eq!(
        std::fs::read(destination).unwrap(),
        hex::decode(text("plaintextHex")).unwrap()
    );
    for (field, password) in [
        ("recoveryHex", "recoveryPassword"),
        ("recoveryUnicodeHex", "recoveryUnicodePassword"),
    ] {
        assert_eq!(
            *import_recovery(
                &hex::decode(text(field)).unwrap(),
                text("scope"),
                text(password)
            )
            .unwrap(),
            key
        );
    }
    let vector: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/storage-content-classification-v2-vector.json"
    ))
    .unwrap();
    let bytes = hex::decode(vector["recoveryV2Hex"].as_str().unwrap()).unwrap();
    let (actual, anchor) =
        import_classification_recovery(&bytes, text("scope"), text("recoveryPassword")).unwrap();
    assert_eq!(*actual, key);
    assert_eq!(anchor, vector["anchor"].as_str().unwrap());
    let mut bad = bytes;
    bad[156] ^= 1;
    assert!(import_classification_recovery(&bad, text("scope"), text("recoveryPassword")).is_err());
}
#[test]
fn recovery_scoping_anchor_and_canonical_ids() {
    let key = [7; 32];
    let password = "correct recovery password";
    let anchor = "00010203-0405-4607-8809-0a0b0c0d0e0f";
    let bytes = export_classification_recovery(&key, "scope", anchor, password).unwrap();
    assert_eq!(bytes.len(), 204);
    let (actual, id) = import_classification_recovery(&bytes, "scope", password).unwrap();
    assert_eq!(*actual, key);
    assert_eq!(id, anchor);
    assert!(import_classification_recovery(&bytes, "other", password).is_err());
    assert!(import_classification_recovery(&bytes, "scope", "incorrect password").is_err());
    for id in [
        "A0010203-0405-4607-8809-0a0b0c0d0e0f",
        "000102030405460788090a0b0c0d0e0f",
        "../",
        "",
    ] {
        assert!(canonical_uuid(id).is_err());
    }
}

fn bridge_call(input: &Value) -> Result<Value> {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let text = |name| {
        input[name]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("missing field"))
    };
    let key = || -> Result<[u8; 32]> { Ok(STANDARD.decode(text("key")?)?.as_slice().try_into()?) };
    let bytes = || -> Result<Vec<u8>> { Ok(STANDARD.decode(text("bytes")?)?) };
    match text("op")? {
        "encode-commit" => {
            let record = serde_json::from_value(input["record"].clone())?;
            Ok(json!(STANDARD.encode(
                crate::storage::content_history::encode(&record, &key()?)?
            )))
        }
        "decode-commit" => Ok(serde_json::to_value(
            crate::storage::content_history::decode(&bytes()?, &key()?, text("id")?)?,
        )?),
        "object-scope" => Ok(json!(crate::storage::content_history::object_scope(
            text("id")?,
            text("objectId")?
        )?)),
        "history" | "history-heads" => {
            let history = crate::storage::content_history::History::replay(
                text("id")?,
                serde_json::from_value(input["records"].clone())?,
            )?;
            if text("op")? == "history-heads" {
                let heads: std::collections::BTreeMap<_, _> = history
                    .heads()
                    .iter()
                    .map(|(id, heads)| {
                        let mut heads = heads.clone();
                        heads.sort();
                        (id, heads)
                    })
                    .collect();
                Ok(serde_json::to_value(heads)?)
            } else {
                Ok(json!(history.live_entries()?.into_iter().map(|record|
                    Ok(json!({"entryId":record.entry_id,"operationId":record.operation_id,"path":history.path(record)?}))
                ).collect::<Result<Vec<_>>>()?))
            }
        }
        "encrypt" => {
            let mut source = std::fs::File::open(text("source")?)?;
            let mut destination = std::fs::File::create(text("destination")?)?;
            encrypt(
                &mut source,
                &mut destination,
                &key()?,
                text("scope")?,
                || Ok(()),
            )?;
            Ok(json!(true))
        }
        "decrypt" => {
            let mut source = std::fs::File::open(text("source")?)?;
            let mut calls = 0;
            decrypt_and_publish(
                &mut source,
                Path::new(text("destination")?),
                &key()?,
                text("scope")?,
                || {
                    calls += 1;
                    ensure!(
                        input["cancelAfter"]
                            .as_u64()
                            .is_none_or(|limit| calls < limit),
                        "cancelled"
                    );
                    Ok(())
                },
            )?;
            Ok(json!(true))
        }
        "export-v1" => Ok(json!(STANDARD.encode(export_recovery(
            &key()?,
            text("scope")?,
            text("password")?
        )?))),
        "import-v1" => Ok(json!(STANDARD.encode(
            import_recovery(&bytes()?, text("scope")?, text("password")?)?.as_ref()
        ))),
        "export-v2" => Ok(json!(STANDARD.encode(export_classification_recovery(
            &key()?,
            text("scope")?,
            text("id")?,
            text("password")?
        )?))),
        "import-v2" => {
            let (key, id) =
                import_classification_recovery(&bytes()?, text("scope")?, text("password")?)?;
            Ok(json!({"key": STANDARD.encode(key.as_ref()), "id": id}))
        }
        "create-password" => Ok(json!(STANDARD.encode(create_password_location(
            text("id")?,
            &key()?,
            text("password")?
        )?))),
        "unlock-password" => {
            let (id, key) = unlock_password_location(&bytes()?, text("password")?)?;
            Ok(json!({"key": STANDARD.encode(key.as_ref()), "id": id}))
        }
        "password-id" => Ok(json!(password_location_id(&bytes()?)?)),
        _ => anyhow::bail!("unknown operation"),
    }
}
#[test]
#[ignore = "test-only JSON-lines bridge used by tools/content_crypto_parity.py"]
fn contract_bridge() {
    if std::env::var("FOLDERSPAN_CONTENT_CRYPTO_BRIDGE").as_deref() != Ok("1") {
        return;
    }
    for line in std::io::stdin().lock().lines() {
        let input: Value = serde_json::from_str(&line.unwrap()).unwrap();
        if input["op"] == "quit" {
            break;
        }
        let value = match bridge_call(&input) {
            Ok(value) => json!({"status":200,"value":value}),
            Err(error) => {
                json!({"status":400,"value":error.downcast_ref::<ContentError>().map(|e| e.0)})
            }
        };
        println!("@CLOUD@{value}");
        std::io::stdout().flush().unwrap();
    }
}
