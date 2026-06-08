use serde_json::{Value, json};

use crate::core::claim_path_pointer::{ClaimPathElement, ClaimPathPointer, ClaimValue};
use crate::oid4vp::dcql::{
    ClaimsQuery, CredentialFormat, CredentialMeta, CredentialQuery, CredentialSet, DcqlQuery,
    TrustedAuthorityQuery, TrustedAuthorityType,
};
use crate::oid4vp::selection::matching::*;

fn sd_jwt_credential(id: &str, vct: &str, claims: Value) -> CredentialView {
    CredentialView {
        id: id.to_string(),
        format: CredentialFormat::DcSdJwt,
        vct: Some(vct.to_string()),
        doctype: None,
        credential_types: vec![],
        claims,
        issuer: Some("https://issuer.example.com".to_string()),
        trusted_authorities: vec![CredentialAuthority {
            authority_type: TrustedAuthorityType::Aki,
            value: "issuer-aki".to_string(),
        }],
        holder_binding_supported: true,
    }
}

fn mdoc_credential(id: &str, doctype: &str, claims: Value) -> CredentialView {
    CredentialView {
        id: id.to_string(),
        format: CredentialFormat::MsoMdoc,
        vct: None,
        doctype: Some(doctype.to_string()),
        credential_types: vec![],
        claims,
        issuer: Some("https://issuer.example.com".to_string()),
        trusted_authorities: vec![CredentialAuthority {
            authority_type: TrustedAuthorityType::Aki,
            value: "issuer-aki".to_string(),
        }],
        holder_binding_supported: true,
    }
}

fn sd_jwt_query(id: &str, vct: &str) -> CredentialQuery {
    CredentialQuery {
        id: id.to_string(),
        format: CredentialFormat::DcSdJwt,
        multiple: None,
        meta: CredentialMeta::SdJwt {
            vct_values: vec![vct.to_string()],
        },
        claims: None,
        claim_sets: None,
        trusted_authorities: None,
        require_cryptographic_holder_binding: None,
    }
}

fn mdoc_query(id: &str, doctype: &str) -> CredentialQuery {
    CredentialQuery {
        id: id.to_string(),
        format: CredentialFormat::MsoMdoc,
        multiple: None,
        meta: CredentialMeta::MsoMdoc {
            doctype_value: doctype.to_string(),
        },
        claims: None,
        claim_sets: None,
        trusted_authorities: None,
        require_cryptographic_holder_binding: None,
    }
}

fn claim(path: ClaimPathPointer) -> ClaimsQuery {
    ClaimsQuery {
        path,
        id: None,
        values: None,
    }
}

fn path(elements: &[&str]) -> ClaimPathPointer {
    ClaimPathPointer::new(
        elements
            .iter()
            .map(|element| ClaimPathElement::from(*element))
            .collect(),
    )
}

#[test]
fn credential_query_matches_format_and_meta_constraints() {
    let sd_query = sd_jwt_query("pid", "https://example.com/pid");
    let sd_credential = sd_jwt_credential("c1", "https://example.com/pid", json!({}));
    let mdoc = mdoc_credential("c2", "org.iso.18013.5.1.mDL", json!({}));

    let candidate = match_credential_query(&sd_query, &sd_credential).unwrap();
    assert_eq!(candidate.credential_query_id, "pid");
    assert_eq!(candidate.credential_id, "c1");
    assert!(match_credential_query(&sd_query, &mdoc).is_none());

    let wrong_vct = sd_jwt_credential("c3", "https://example.com/other", json!({}));
    assert!(match_credential_query(&sd_query, &wrong_vct).is_none());

    let mdoc_query = mdoc_query("mdl", "org.iso.18013.5.1.mDL");
    assert!(match_credential_query(&mdoc_query, &mdoc).is_some());

    let wrong_doctype = mdoc_credential("c4", "org.iso.18013.5.1.mID", json!({}));
    assert!(match_credential_query(&mdoc_query, &wrong_doctype).is_none());
}

#[test]
fn w3c_type_values_match_required_type_combinations() {
    let query = CredentialQuery {
        id: "vc".to_string(),
        format: CredentialFormat::JwtVcJson,
        multiple: None,
        meta: CredentialMeta::W3CFormat {
            type_values: vec![vec![
                "VerifiableCredential".to_string(),
                "UniversityDegreeCredential".to_string(),
            ]],
        },
        claims: None,
        claim_sets: None,
        trusted_authorities: None,
        require_cryptographic_holder_binding: None,
    };

    let credential = CredentialView {
        id: "c1".to_string(),
        format: CredentialFormat::JwtVcJson,
        vct: None,
        doctype: None,
        credential_types: vec![
            "VerifiableCredential".to_string(),
            "UniversityDegreeCredential".to_string(),
        ],
        claims: json!({}),
        issuer: None,
        trusted_authorities: vec![],
        holder_binding_supported: true,
    };
    assert!(match_credential_query(&query, &credential).is_some());

    let partial_credential = CredentialView {
        credential_types: vec!["VerifiableCredential".to_string()],
        ..credential
    };
    assert!(match_credential_query(&query, &partial_credential).is_none());
}

#[test]
fn claim_path_matching_selects_nested_index_and_array_values() {
    let mut query = sd_jwt_query("pid", "vct");
    query.claims = Some(vec![
        claim(path(&["address", "city"])),
        claim(ClaimPathPointer::new(vec![
            ClaimPathElement::from("nationalities"),
            ClaimPathElement::Index(0),
        ])),
        claim(ClaimPathPointer::new(vec![
            ClaimPathElement::from("emails"),
            ClaimPathElement::Null,
        ])),
    ]);

    let credential = sd_jwt_credential(
        "c1",
        "vct",
        json!({
            "address": { "city": "Berlin" },
            "nationalities": ["DE", "FR"],
            "emails": ["a@example.com", "b@example.com"]
        }),
    );

    let candidate = match_credential_query(&query, &credential).unwrap();
    assert_eq!(
        candidate.matched_claims[0].selected_values,
        vec![json!("Berlin")]
    );
    assert_eq!(
        candidate.matched_claims[1].selected_values,
        vec![json!("DE")]
    );
    assert_eq!(candidate.matched_claims[2].selected_values.len(), 2);

    let missing_claim = sd_jwt_credential("c2", "vct", json!({ "address": {} }));
    assert!(match_credential_query(&query, &missing_claim).is_none());
}

#[test]
fn mdoc_claim_path_uses_namespace_and_data_element() {
    let mut query = mdoc_query("mdl", "org.iso.18013.5.1.mDL");
    query.claims = Some(vec![claim(ClaimPathPointer::new(vec![
        ClaimPathElement::from("org.iso.18013.5.1"),
        ClaimPathElement::from("family_name"),
    ]))]);

    let credential = mdoc_credential(
        "c1",
        "org.iso.18013.5.1.mDL",
        json!({ "org.iso.18013.5.1": { "family_name": "Doe" } }),
    );

    let candidate = match_credential_query(&query, &credential).unwrap();
    assert_eq!(
        candidate.matched_claims[0].selected_values,
        vec![json!("Doe")]
    );
}

#[test]
fn value_filters_are_type_aware() {
    for (claim_name, allowed, matching, non_matching) in [
        (
            "country",
            ClaimValue::String("DE".to_string()),
            json!("DE"),
            json!("US"),
        ),
        ("age", ClaimValue::Integer(18), json!(18), json!("18")),
        (
            "active",
            ClaimValue::Boolean(true),
            json!(true),
            json!(false),
        ),
    ] {
        let mut query = sd_jwt_query("pid", "vct");
        query.claims = Some(vec![ClaimsQuery {
            path: path(&[claim_name]),
            id: None,
            values: Some(vec![allowed]),
        }]);

        let matching = sd_jwt_credential("c1", "vct", json!({ claim_name: matching }));
        let non_matching = sd_jwt_credential("c2", "vct", json!({ claim_name: non_matching }));

        assert!(match_credential_query(&query, &matching).is_some());
        assert!(match_credential_query(&query, &non_matching).is_none());
    }
}

#[test]
fn trusted_authorities_require_matching_typed_reference() {
    let mut query = sd_jwt_query("pid", "vct");
    query.trusted_authorities = Some(vec![
        TrustedAuthorityQuery {
            authority_type: TrustedAuthorityType::Aki,
            values: vec!["untrusted-aki".to_string()],
        },
        TrustedAuthorityQuery {
            authority_type: TrustedAuthorityType::EtsiTl,
            values: vec!["issuer-etsi".to_string()],
        },
    ]);

    let mut credential = sd_jwt_credential("c1", "vct", json!({}));
    assert!(match_credential_query(&query, &credential).is_none());

    credential.trusted_authorities.push(CredentialAuthority {
        authority_type: TrustedAuthorityType::EtsiTl,
        value: "issuer-etsi".to_string(),
    });
    assert!(match_credential_query(&query, &credential).is_some());
}

#[test]
fn holder_binding_is_required_by_default_unless_explicitly_disabled() {
    let query = sd_jwt_query("pid", "vct");
    let mut credential = sd_jwt_credential("c1", "vct", json!({}));
    credential.holder_binding_supported = false;
    assert!(match_credential_query(&query, &credential).is_none());

    let mut query_without_binding = query;
    query_without_binding.require_cryptographic_holder_binding = Some(false);
    assert!(match_credential_query(&query_without_binding, &credential).is_some());
}

#[test]
fn claim_sets_use_first_satisfiable_set_and_reject_when_none_match() {
    let mut query = sd_jwt_query("pid", "vct");
    query.claims = Some(vec![
        ClaimsQuery {
            path: path(&["given_name"]),
            id: Some("gn".to_string()),
            values: None,
        },
        ClaimsQuery {
            path: path(&["family_name"]),
            id: Some("fn".to_string()),
            values: None,
        },
        ClaimsQuery {
            path: path(&["date_of_birth"]),
            id: Some("dob".to_string()),
            values: None,
        },
    ]);
    query.claim_sets = Some(vec![
        vec!["gn".to_string(), "fn".to_string(), "dob".to_string()],
        vec!["gn".to_string()],
    ]);

    let credential = sd_jwt_credential("c1", "vct", json!({ "given_name": "Alice" }));
    let candidate = match_credential_query(&query, &credential).unwrap();
    assert_eq!(candidate.matched_claim_set_index, Some(1));
    assert_eq!(candidate.matched_claims.len(), 1);

    query.claim_sets = Some(vec![vec!["gn".to_string(), "fn".to_string()]]);
    assert!(match_credential_query(&query, &credential).is_none());
}

#[test]
fn no_claims_filter_matches_without_selecting_disclosed_claims() {
    let query = sd_jwt_query("pid", "vct");
    let credential = sd_jwt_credential("c1", "vct", json!({ "anything": "works" }));

    let candidate = match_credential_query(&query, &credential).unwrap();
    assert!(candidate.matched_claims.is_empty());
    assert!(candidate.matched_claim_set_index.is_none());
}

#[test]
fn dcql_without_credential_sets_requires_every_credential_query() {
    let query = DcqlQuery {
        credentials: vec![
            sd_jwt_query("pid", "https://example.com/pid"),
            mdoc_query("mdl", "org.iso.18013.5.1.mDL"),
        ],
        credential_sets: None,
    };

    let result = match_dcql_query(
        &query,
        &[sd_jwt_credential(
            "c1",
            "https://example.com/pid",
            json!({}),
        )],
    );
    assert!(!result.is_satisfied());
    assert_eq!(result.unsatisfied_queries, vec!["mdl"]);

    let result = match_dcql_query(
        &query,
        &[
            sd_jwt_credential("c1", "https://example.com/pid", json!({})),
            mdoc_credential("c2", "org.iso.18013.5.1.mDL", json!({})),
        ],
    );
    assert!(result.is_satisfied());
    assert_eq!(result.candidates["pid"].len(), 1);
    assert_eq!(result.candidates["mdl"].len(), 1);
}

#[test]
fn empty_wallet_reports_all_queries_unsatisfied() {
    let query = DcqlQuery {
        credentials: vec![
            sd_jwt_query("pid", "https://example.com/pid"),
            mdoc_query("mdl", "org.iso.18013.5.1.mDL"),
        ],
        credential_sets: None,
    };

    let result = match_dcql_query(&query, &[]);

    assert!(!result.is_satisfied());
    assert_eq!(result.unsatisfied_queries.len(), 2);
    assert!(result.unsatisfied_queries.contains(&"pid".to_string()));
    assert!(result.unsatisfied_queries.contains(&"mdl".to_string()));
    assert!(result.select().is_empty());
}

#[test]
fn credential_sets_use_first_satisfiable_required_option_and_skip_optional_by_default() {
    let query = DcqlQuery {
        credentials: vec![
            sd_jwt_query("pid", "https://example.com/pid"),
            sd_jwt_query("alt_pid", "https://example.com/alt-pid"),
            sd_jwt_query("bonus", "https://example.com/bonus"),
        ],
        credential_sets: Some(vec![
            CredentialSet {
                options: vec![vec!["pid".to_string()], vec!["alt_pid".to_string()]],
                required: None,
            },
            CredentialSet {
                options: vec![vec!["bonus".to_string()]],
                required: Some(false),
            },
        ]),
    };

    let credentials = vec![
        sd_jwt_credential("c1", "https://example.com/pid", json!({})),
        sd_jwt_credential("c2", "https://example.com/alt-pid", json!({})),
        sd_jwt_credential("c3", "https://example.com/bonus", json!({})),
    ];

    let result = match_dcql_query(&query, &credentials);
    assert!(result.is_satisfied());
    assert_eq!(result.selected_credential_query_ids, vec!["pid"]);

    let selected = result.select();
    assert_eq!(selected.len(), 1);
    assert_eq!(selected[0].credential_query_id, "pid");
    assert_eq!(selected[0].credential_id, "c1");
}

#[test]
fn credential_sets_report_required_unsatisfied_option() {
    let query = DcqlQuery {
        credentials: vec![
            sd_jwt_query("pid", "https://example.com/pid"),
            mdoc_query("mdl", "org.iso.18013.5.1.mDL"),
        ],
        credential_sets: Some(vec![CredentialSet {
            options: vec![vec!["pid".to_string(), "mdl".to_string()]],
            required: Some(true),
        }]),
    };

    let result = match_dcql_query(
        &query,
        &[sd_jwt_credential(
            "c1",
            "https://example.com/pid",
            json!({}),
        )],
    );

    assert!(!result.is_satisfied());
    assert!(result.unsatisfied_queries.contains(&"mdl".to_string()));
    assert!(result.select().is_empty());
}

#[test]
fn selection_prefers_specific_candidate_and_honors_multiple() {
    let mut query = sd_jwt_query("pid", "vct");
    query.claims = Some(vec![
        claim(path(&["given_name"])),
        claim(path(&["family_name"])),
    ]);
    let query = DcqlQuery {
        credentials: vec![query],
        credential_sets: None,
    };
    let credentials = vec![
        sd_jwt_credential("c1", "vct", json!({ "given_name": "Alice" })),
        sd_jwt_credential(
            "c2",
            "vct",
            json!({ "given_name": "Bob", "family_name": "Smith" }),
        ),
    ];

    let selected = match_dcql_query(&query, &credentials).select();
    assert_eq!(selected.len(), 1);
    assert_eq!(selected[0].credential_id, "c2");

    let mut query = sd_jwt_query("pid", "vct");
    query.multiple = Some(true);
    let selected = match_dcql_query(
        &DcqlQuery {
            credentials: vec![query],
            credential_sets: None,
        },
        &credentials,
    )
    .select();
    assert_eq!(selected.len(), 2);
}
