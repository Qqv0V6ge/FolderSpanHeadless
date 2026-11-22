use super::*;
use serde_json::json;

fn id(n: u32) -> String {
    format!("{n:08x}-0000-4000-8000-000000000000")
}
fn root() -> Commit {
    serde_json::from_value(json!({"vaultId":id(1),"operationId":id(1),"entryId":id(1),
        "parentId":"","name":"","kind":"Root","ciphertextDigest":"ab".repeat(32)}))
    .unwrap()
}
fn file(n: u32, name: &str) -> Commit {
    serde_json::from_value(
        json!({"vaultId":id(1),"operationId":id(n),"entryId":id(n+1),
        "parentId":id(1),"name":name,"kind":"File","objectId":id(n+2),
        "ciphertextLength":160,"ciphertextDigest":"cd".repeat(32)}),
    )
    .unwrap()
}
fn revision(record: &Commit, n: u32) -> Commit {
    Commit {
        operation_id: id(n),
        parents: vec![record.operation_id.clone()],
        ..record.clone()
    }
}
#[test]
fn authenticated_codec_rejects_untrusted_lengths_fields_format_and_scope() {
    let record = file(10, "新😀 .txt ");
    let key = [3; 32];
    let bytes = encode(&record, &key).unwrap();
    assert_eq!(decode(&bytes, &key, &id(1)).unwrap(), record);
    assert!(decode(&bytes, &[4; 32], &id(1)).is_err());
    assert!(decode(&bytes, &key, &id(2)).is_err());
    for offset in [0, 11, 12, 15, 16, bytes.len() - 1] {
        let mut bad = bytes.clone();
        bad[offset] ^= 1;
        assert!(decode(&bad, &key, &id(1)).is_err());
    }
    for size in [0, 47, bytes.len() - 1] {
        assert!(decode(&bytes[..size], &key, &id(1)).is_err());
    }
    let mut bad = bytes.clone();
    bad.push(0);
    assert!(decode(&bad, &key, &id(1)).is_err());
    let mut payload = serde_json::to_value(&record).unwrap();
    payload["unknown"] = json!(true);
    let payload = serde_json::to_vec(&payload).unwrap();
    let mut signed = [
        b"FSPANCMT".as_slice(),
        &1u32.to_be_bytes(),
        &(payload.len() as u32).to_be_bytes(),
        &payload,
    ]
    .concat();
    signed.extend_from_slice(&authenticate(&key, &signed).unwrap());
    assert_eq!(
        decode(&signed, &key, &id(1))
            .unwrap_err()
            .downcast_ref::<ContentError>()
            .unwrap()
            .0,
        ErrorCode::DamagedLocation
    );
}
#[test]
fn independent_entries_merge_without_ordering_a_concurrent_revision_winner() {
    let a = file(10, "a");
    let b = file(20, "b");
    for input in [
        vec![root(), a.clone(), b.clone()],
        vec![b, a.clone(), root()],
    ] {
        assert_eq!(
            History::replay(&id(1), input)
                .unwrap()
                .live_entries()
                .unwrap()
                .len(),
            2
        );
    }
    let first = revision(&a, 30);
    let second = revision(&a, 40);
    let history = History::replay(
        &id(1),
        vec![second.clone(), root(), first.clone(), a.clone()],
    )
    .unwrap();
    assert_eq!(history.heads[&a.entry_id].len(), 2);
    assert!(history.head(&a.entry_id).is_err());
    let merged = Commit {
        parents: vec![first.operation_id.clone(), second.operation_id.clone()],
        ..revision(&first, 50)
    };
    let history = History::replay(
        &id(1),
        vec![root(), a.clone(), first, second, merged.clone()],
    )
    .unwrap();
    assert_eq!(history.head(&a.entry_id).unwrap(), Some(&merged));
}
#[test]
fn deletion_preserves_unobserved_writes_and_invalid_revision_graphs_fail_closed() {
    let a = file(10, "a");
    let b = file(20, "b");
    let updated = revision(&a, 30);
    let deletion = Commit {
        kind: Kind::Delete,
        object_id: String::new(),
        ciphertext_length: 0,
        ciphertext_digest: String::new(),
        size: 0,
        ..revision(&a, 40)
    };
    assert!(
        History::replay(
            &id(1),
            vec![root(), a.clone(), updated.clone(), deletion.clone()]
        )
        .unwrap()
        .live_entries()
        .is_err()
    );
    assert!(
        History::replay(&id(1), vec![root(), a.clone(), deletion])
            .unwrap()
            .live_entries()
            .unwrap()
            .is_empty()
    );
    let cycle = Commit {
        parents: vec![id(50)],
        ..updated.clone()
    };
    let second = revision(&updated, 50);
    let cross = Commit {
        parents: vec![a.operation_id.clone()],
        ..b
    };
    for input in [
        vec![],
        vec![root(), updated],
        vec![root(), a.clone(), a.clone()],
        vec![root(), a.clone(), cross],
        vec![root(), a.clone(), cycle, second],
        vec![a],
    ] {
        assert!(History::replay(&id(1), input).is_err());
    }
}
#[test]
fn directory_rename_preserves_identity_and_detects_deleted_parents_and_name_conflicts() {
    let directory = Commit {
        kind: Kind::Directory,
        object_id: String::new(),
        ciphertext_length: 0,
        ciphertext_digest: String::new(),
        size: 0,
        ..file(10, "before")
    };
    let child = Commit {
        parent_id: directory.entry_id.clone(),
        ..file(20, "child")
    };
    let renamed = Commit {
        name: "after".to_owned(),
        ..revision(&directory, 30)
    };
    let history = History::replay(
        &id(1),
        vec![root(), directory.clone(), child.clone(), renamed.clone()],
    )
    .unwrap();
    assert_eq!(history.path(&child).unwrap(), "/after/child");
    let deletion = Commit {
        kind: Kind::Delete,
        ..revision(&renamed, 40)
    };
    assert!(
        History::replay(&id(1), vec![root(), directory, child, renamed, deletion])
            .unwrap()
            .live_entries()
            .is_err()
    );
    assert!(
        History::replay(&id(1), vec![root(), file(10, "same"), file(20, "same")])
            .unwrap()
            .live_entries()
            .is_err()
    );
}
#[test]
fn record_validation_bounds_names_ids_objects_and_ordinary_directory_context() {
    for name in [
        "..",
        " ../ ",
        "/absolute",
        "a/b",
        "a\\b",
        "nul\0",
        "control\u{85}",
    ] {
        assert!(file(10, name).validate().is_err());
    }
    assert!(file(10, &"😀".repeat(128)).validate().is_err());
    assert!(file(10, &"😀".repeat(127)).validate().is_ok());
    let mut record = file(10, "name");
    record.entry_id = record.vault_id.clone();
    assert!(record.validate().is_err());
    let ordinary = DirectoryBinding {
        relative_path: "safe/sub".to_owned(),
        reference: Some(json!({"id":"native"})),
    };
    let directory = Commit {
        kind: Kind::Directory,
        ordinary_directory: Some(ordinary.clone()),
        object_id: String::new(),
        ciphertext_length: 0,
        ciphertext_digest: String::new(),
        size: 0,
        ..file(10, "folder")
    };
    directory.validate().unwrap();
    for reference in [
        json!({"content":{"vaultId":id(1),"entryId":id(2)}}),
        json!({"ancestorPath":"/outside"}),
        json!({"unknown":true}),
    ] {
        let mut changed = directory.clone();
        changed.ordinary_directory.as_mut().unwrap().reference = Some(reference);
        assert!(changed.validate().is_err());
    }
    for relative in [
        "../escape",
        ".folderspan-vault",
        "/absolute",
        "x//y",
        "x/..",
    ] {
        let mut changed = directory.clone();
        changed.ordinary_directory.as_mut().unwrap().relative_path = relative.to_owned();
        assert!(changed.validate().is_err());
    }
    assert_eq!(
        object_scope(&id(1), &id(2)).unwrap(),
        "FolderSpan vault object v1\0".to_owned()
            + &serde_json::to_string(&[id(1), id(2)]).unwrap()
    );
}
