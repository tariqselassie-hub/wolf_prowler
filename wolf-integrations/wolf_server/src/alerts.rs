use chrono::{DateTime, Utc};
use dioxus::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SecurityAlert {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub severity: String,
    pub title: String,
    pub description: String,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub data: Option<T>,
    pub error: Option<String>,
}

#[component]
pub fn AlertsDashboard() -> Element {
    let alerts = use_resource(|| async move {
        let client = reqwest::Client::new();
        // Adjust URL if your server runs on a different port/host
        let res = client
            .get("http://localhost:3030/api/v1/alerts/history?limit=50")
            .send()
            .await;

        match res {
            Ok(resp) => {
                if let Ok(api_resp) = resp.json::<ApiResponse<Vec<SecurityAlert>>>().await {
                    api_resp.data.unwrap_or_default()
                } else {
                    vec![]
                }
            }
            Err(_) => vec![],
        }
    });

    rsx! {
        div { class: "p-6 bg-gray-50 min-h-screen",
            div { class: "max-w-7xl mx-auto",
                div { class: "flex justify-between items-center mb-6",
                    h1 { class: "text-3xl font-bold text-gray-900", "🛡️ Security Alerts" }
                    button {
                        class: "px-4 py-2 bg-indigo-600 text-white rounded-md hover:bg-indigo-700 transition-colors shadow-sm",
                        onclick: move |_| alerts.restart(),
                        "Refresh Data"
                    }
                }

                div { class: "bg-white shadow rounded-lg overflow-hidden border border-gray-200",
                    match &*alerts.read_unchecked() {
                        Some(list) if !list.is_empty() => rsx! {
                            table { class: "min-w-full divide-y divide-gray-200",
                                thead { class: "bg-gray-50",
                                    tr {
                                        th { class: "px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider", "Severity" }
                                        th { class: "px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider", "Time" }
                                        th { class: "px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider", "Title" }
                                        th { class: "px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider", "Source" }
                                    }
                                }
                                tbody { class: "bg-white divide-y divide-gray-200",
                                    for alert in list {
                                        tr { key: "{alert.id}", class: "hover:bg-gray-50 transition-colors",
                                            td { class: "px-6 py-4 whitespace-nowrap",
                                                span {
                                                    class: match alert.severity.as_str() {
                                                        "Critical" => "px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-red-100 text-red-800",
                                                        "High" => "px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-orange-100 text-orange-800",
                                                        "Medium" => "px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-yellow-100 text-yellow-800",
                                                        _ => "px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-green-100 text-green-800",
                                                    },
                                                    "{alert.severity}"
                                                }
                                            }
                                            td { class: "px-6 py-4 whitespace-nowrap text-sm text-gray-500",
                                                "{alert.timestamp.format(\"%Y-%m-%d %H:%M:%S\")}"
                                            }
                                            td { class: "px-6 py-4",
                                                div { class: "text-sm font-medium text-gray-900", "{alert.title}" }
                                                div { class: "text-sm text-gray-500", "{alert.description}" }
                                            }
                                            td { class: "px-6 py-4 whitespace-nowrap text-sm text-gray-500",
                                                "{alert.source}"
                                            }
                                        }
                                    }
                                }
                            }
                        },
                        Some(_) => rsx! {
                            div { class: "p-12 text-center text-gray-500", "No alerts found. System is secure." }
                        },
                        None => rsx! {
                            div { class: "p-12 text-center text-gray-500", "Loading security data..." }
                        }
                    }
                }
            }
        }
    }
}
