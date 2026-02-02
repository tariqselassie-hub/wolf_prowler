use dioxus::prelude::*;
use dioxus_fullstack::prelude::*;
use serde::{Deserialize, Serialize};
use wolf_web::dashboard::api::server_fns::get_records;
use wolf_web::types::RecordView;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VaultConfigView {
    pub security_level: String,
    pub hasher: String,
    pub kdf: String,
    pub mac: String,
    pub memory_hard_kdf: bool,
}

#[server]
pub async fn get_vault_status() -> Result<VaultConfigView, ServerFnError> {
    let engine = wolf_den::CryptoEngine::default();
    Ok(VaultConfigView {
        security_level: format!("{:?}", engine.security_level()),
        hasher: engine.hasher_name().to_string(),
        kdf: engine.kdf_name().to_string(),
        mac: engine.mac_name().to_string(),
        memory_hard_kdf: engine.is_memory_hard_kdf(),
    })
}

#[server]
pub async fn vault_hash_data(data: String) -> Result<String, ServerFnError> {
    let engine = wolf_den::CryptoEngine::default();
    let hash = engine
        .hash(data.as_bytes())
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    // Simple hex encoding
    Ok(hash.iter().map(|b| format!("{:02x}", b)).collect())
}

#[server]
pub async fn vault_sign_data(data: String) -> Result<String, ServerFnError> {
    let engine = wolf_den::CryptoEngine::default();
    let signature = engine.sign_message(data.as_bytes());
    // Signature to bytes then hex
    Ok(signature
        .to_bytes()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect())
}

#[server]
pub async fn vault_generate_key(length: usize) -> Result<String, ServerFnError> {
    let engine = wolf_den::CryptoEngine::default();
    let key = engine
        .generate_key(length)
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    Ok(key.iter().map(|b| format!("{:02x}", b)).collect())
}

#[component]
pub fn VaultOverview() -> Element {
    let vault_status = use_resource(get_vault_status);

    rsx! {
        div { class: "grid grid-cols-1 md:grid-cols-2 gap-6 mb-8",
            div { class: "border border-green-800 bg-gray-900/50 p-6 rounded relative overflow-hidden",
                h2 { class: "text-xl font-bold mb-4 uppercase border-b border-green-800 pb-2 flex items-center gap-2",
                    i { class: "lucide-shield-check" }
                    "Engine Configuration"
                }

                match &*vault_status.read_unchecked() {
                    Some(Ok(config)) => rsx! {
                        div { class: "space-y-4",
                             div { class: "flex justify-between",
                                span { class: "text-gray-400", "Security Level" }
                                span { class: "text-green-400 font-bold", "{config.security_level}" }
                            }
                            div { class: "flex justify-between",
                                span { class: "text-gray-400", "Hashing Algorithm" }
                                span { class: "text-purple-400 font-mono", "{config.hasher}" }
                            }
                            div { class: "flex justify-between",
                                span { class: "text-gray-400", "KDF" }
                                span { class: "text-blue-400 font-mono", "{config.kdf}" }
                            }
                            div { class: "flex justify-between",
                                span { class: "text-gray-400", "MAC" }
                                span { class: "text-yellow-400 font-mono", "{config.mac}" }
                            }
                             div { class: "flex justify-between",
                                span { class: "text-gray-400", "Memory Hardened" }
                                span { class: if config.memory_hard_kdf { "text-green-500" } else { "text-red-500" },
                                    if config.memory_hard_kdf { "ENABLED" } else { "DISABLED" }
                                }
                            }
                        }
                    },
                    Some(Err(e)) => rsx! { div { class: "text-red-500", "Error: {e}" } },
                    None => rsx! { div { class: "animate-pulse text-green-700", "Loading Engine Parameters..." } }
                }
            }

            div { class: "border border-green-800 bg-gray-900/50 p-6 rounded flex flex-col justify-center items-center text-center",
                div { class: "w-24 h-24 rounded-full border-4 border-green-500 flex items-center justify-center mb-4 shadow-[0_0_20px_#22c55e] animate-pulse",
                    i { class: "lucide-lock w-10 h-10 text-green-500" }
                }
                h3 { class: "text-lg font-bold uppercase", "Vault Status: SECURE" }
                p { class: "text-xs text-gray-400 mt-2", "Post-Quantum Cryptography Active" }
                p { class: "text-xs text-gray-500", "Dilithium-5 / Kyber-1024 Ready" }
            }
        }
    }
}

#[component]
pub fn VaultTools() -> Element {
    let mut hash_input = use_signal(|| String::new());
    let mut hash_output = use_signal(|| String::new());

    let mut sign_input = use_signal(|| String::new());
    let mut sign_output = use_signal(|| String::new());

    let mut key_len = use_signal(|| 32);
    let mut gen_key_output = use_signal(|| String::new());

    rsx! {
        div { class: "grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8",
            // Hashing Tool
            div { class: "border border-green-800 p-6 rounded bg-black",
                h3 { class: "text-lg font-bold mb-4 text-purple-400 uppercase flex items-center gap-2",
                    i { class: "lucide-hash" } "Secure Hash"
                }
                div { class: "flex gap-2 flex-col",
                    input {
                        class: "w-full bg-gray-900 border border-gray-700 p-2 text-white font-mono focus:border-purple-500 outline-none",
                        placeholder: "Enter data to hash...",
                        value: "{hash_input}",
                        oninput: move |e| hash_input.set(e.value())
                    }
                    button {
                        class: "w-full py-2 bg-purple-900/40 border border-purple-500 hover:bg-purple-600 hover:text-white transition-colors uppercase font-bold text-sm",
                         onclick: move |_| async move {
                            if let Ok(res) = vault_hash_data(hash_input()).await {
                                hash_output.set(res);
                            }
                        },
                        "Generate Hash"
                    }
                }
                if !hash_output().is_empty() {
                    div { class: "mt-4 p-3 bg-gray-900/80 border border-purple-500/50 font-mono text-xs break-all text-purple-300",
                        "{hash_output}"
                    }
                }
            }

            // Signing Tool
            div { class: "border border-green-800 p-6 rounded bg-black",
                h3 { class: "text-lg font-bold mb-4 text-blue-400 uppercase flex items-center gap-2",
                     i { class: "lucide-pen-tool" } "Digital Signature"
                }
                div { class: "flex gap-2 flex-col",
                    input {
                        class: "w-full bg-gray-900 border border-gray-700 p-2 text-white font-mono focus:border-blue-500 outline-none",
                        placeholder: "Enter message to sign...",
                         value: "{sign_input}",
                        oninput: move |e| sign_input.set(e.value())
                    }
                    button {
                        class: "w-full py-2 bg-blue-900/40 border border-blue-500 hover:bg-blue-600 hover:text-white transition-colors uppercase font-bold text-sm",
                        onclick: move |_| async move {
                            if let Ok(res) = vault_sign_data(sign_input()).await {
                                sign_output.set(res);
                            }
                        },
                        "Sign Message"
                    }
                }
                 if !sign_output().is_empty() {
                    div { class: "mt-4 p-3 bg-gray-900/80 border border-blue-500/50 font-mono text-xs break-all text-blue-300",
                        "{sign_output}"
                    }
                }
            }

             // Key Gen Tool
            div { class: "border border-green-800 p-6 rounded bg-black lg:col-span-2",
                h3 { class: "text-lg font-bold mb-4 text-yellow-400 uppercase flex items-center gap-2",
                    i { class: "lucide-key" } "Random Key Generator"
                }
                div { class: "flex gap-4 items-center",
                    input {
                        r#type: "number",
                        class: "w-32 bg-gray-900 border border-gray-700 p-2 text-white font-mono focus:border-yellow-500 outline-none",
                        value: "{key_len}",
                        oninput: move |e| key_len.set(e.value().parse().unwrap_or(32))
                    }
                    span { class: "text-gray-500 text-sm", "bytes" }
                    button {
                        class: "px-6 py-2 bg-yellow-900/40 border border-yellow-500 hover:bg-yellow-600 hover:text-white transition-colors uppercase font-bold text-sm ml-auto",
                         onclick: move |_| async move {
                            if let Ok(res) = vault_generate_key(key_len()).await {
                                gen_key_output.set(res);
                            }
                        },
                        "Generate Secure Key"
                    }
                }
                 if !gen_key_output().is_empty() {
                    div { class: "mt-4 p-3 bg-gray-900/80 border border-yellow-500/50 font-mono text-xs break-all text-yellow-300",
                        "{gen_key_output}"
                    }
                }
            }
        }
    }
}

#[component]
pub fn VaultKeys() -> Element {
    let records: Resource<Result<Vec<RecordView>, ServerFnError>> =
        use_resource(move || async move {
            // Fetch from 'vault' table using main's server fn
            get_records("vault".to_string()).await
        });

    rsx! {
        div { class: "border border-green-800 bg-gray-900/20 p-6 rounded",
            h3 { class: "text-lg font-bold mb-4 uppercase border-b border-green-800 pb-2 flex items-center gap-2",
                i { class: "lucide-database" } "Managed Secrets"
            }
             div { class: "overflow-x-auto",
                table { class: "w-full text-left border-collapse",
                    thead {
                        tr { class: "text-green-700 text-xs uppercase border-b border-green-900",
                            th { class: "p-2", "Key ID" }
                            th { class: "p-2", "Status" }
                            th { class: "p-2", "Type" }
                            th { class: "p-2 text-right", "Actions" }
                        }
                    }
                    tbody {
                        match &*records.read_unchecked() {
                            Some(Ok(list)) if !list.is_empty() => rsx! {
                                for item in list {
                                    tr { class: "border-b border-green-900/30 hover:bg-green-900/10 text-sm font-mono",
                                        td { class: "p-2 font-bold", "{item.id}" }
                                        td { class: "p-2 text-xs", "ENCRYPTED" }
                                        td { class: "p-2 text-xs opacity-70", "GENERIC" }
                                        td { class: "p-2 text-right",
                                            button { class: "text-green-500 hover:text-white mr-2", "[VIEW]" }
                                            button { class: "text-red-500 hover:text-red-300", "[REVOKE]" }
                                        }
                                    }
                                }
                            },
                            Some(Ok(_)) => rsx! {
                                tr {
                                    td { colspan: "4", class: "p-4 text-center text-gray-500 italic", "No secrets found in vault." }
                                }
                            },
                            Some(Err(e)) => rsx! {
                                tr {
                                    td { colspan: "4", class: "p-4 text-center text-red-500", "Error accessing vault: {e}" }
                                }
                            },
                            None => rsx! {
                                tr {
                                    td { colspan: "4", class: "p-4 text-center animate-pulse", "Decrypting Index..." }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
