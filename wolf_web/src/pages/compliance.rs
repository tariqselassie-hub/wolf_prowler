use dioxus::prelude::*;
use dioxus_fullstack::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ComplianceMetric {
    pub name: String,
    pub status: String, // PASS, FAIL, WARN
    pub details: String,
}

#[server]
async fn get_compliance_status() -> Result<Vec<ComplianceMetric>, ServerFnError> {
    // Simulate compliance checks
    Ok(vec![
        ComplianceMetric {
            name: "Data Encryption".to_string(),
            status: "PASS".to_string(),
            details: "AES-256-GCM / Kyber-1024 active".to_string(),
        },
        ComplianceMetric {
            name: "Audit Logging".to_string(),
            status: "PASS".to_string(),
            details: "Immutable ledger enabled".to_string(),
        },
        ComplianceMetric {
            name: "Access Control".to_string(),
            status: "WARN".to_string(),
            details: "2 Admin accounts without MFA".to_string(),
        },
        ComplianceMetric {
            name: "Network Segmentation".to_string(),
            status: "FAIL".to_string(),
            details: "VLAN tagging missing on Interface eth0".to_string(),
        },
    ])
}

#[component]
pub fn CompliancePage() -> Element {
    let metrics = use_resource(get_compliance_status);

    rsx! {
        div { class: "p-8 space-y-8",
            h1 { class: "text-3xl font-bold uppercase tracking-widest text-yellow-500", "Compliance & Governance" }

            div { class: "bg-gray-900/50 border border-yellow-900/30 p-6 rounded",
                 h3 { class: "text-lg font-bold text-gray-400 mb-6", "AUTOMATED AUDIT REPORT" }

                 div { class: "overflow-x-auto",
                    table { class: "w-full text-left",
                        thead { class: "text-xs text-gray-500 uppercase bg-gray-800/50",
                            tr {
                                th { class: "px-6 py-3", "Control" }
                                th { class: "px-6 py-3", "Status" }
                                th { class: "px-6 py-3", "Details" }
                            }
                        }
                        tbody { class: "divide-y divide-gray-800",
                            match &*metrics.read_unchecked() {
                                Some(Ok(items)) => rsx! {
                                    for item in items.iter() {
                                        tr { key: "{item.name}", class: "hover:bg-gray-800/30 transition shadow-sm",
                                            td { class: "px-6 py-4 font-medium text-gray-300", "{item.name}" }
                                            td { class: "px-6 py-4",
                                                span { class: match item.status.as_str() {
                                                    "PASS" => "px-2 py-1 bg-green-900/30 text-green-400 rounded text-xs font-bold",
                                                    "WARN" => "px-2 py-1 bg-yellow-900/30 text-yellow-400 rounded text-xs font-bold",
                                                    "FAIL" => "px-2 py-1 bg-red-900/30 text-red-400 rounded text-xs font-bold",
                                                    _ => "text-gray-500"
                                                }, "{item.status}" }
                                            }
                                            td { class: "px-6 py-4 text-gray-400 font-mono text-sm", "{item.details}" }
                                        }
                                    }
                                },
                                _ => rsx! { tr { key: "loading", td { colspan: "3", class: "px-6 py-4 text-center text-gray-500", "Auditing..." } } }
                            }
                        }
                    }
                 }
            }

            div { class: "flex justify-end",
                button { class: "px-6 py-3 bg-yellow-600 hover:bg-yellow-700 text-black font-bold rounded shadow-lg shadow-yellow-900/20",
                    "GENERATE PDF REPORT"
                }
            }
        }
    }
}
