use dioxus::prelude::*;
use dioxus_fullstack::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UserInfo {
    pub id: String,
    pub username: String,
    pub role: String,
    pub last_login: String,
}

#[server]
async fn get_users() -> Result<Vec<UserInfo>, ServerFnError> {
    // Simulate users
    Ok(vec![
        UserInfo {
            id: "001".to_string(),
            username: "admin".to_string(),
            role: "SYSADMIN".to_string(),
            last_login: "Just Now".to_string(),
        },
        UserInfo {
            id: "002".to_string(),
            username: "watcher".to_string(),
            role: "OBSERVER".to_string(),
            last_login: "2 hours ago".to_string(),
        },
    ])
}

#[component]
pub fn AdministrationPage() -> Element {
    let users = use_resource(get_users);

    rsx! {
        div { class: "p-8 space-y-8",
            h1 { class: "text-3xl font-bold uppercase tracking-widest text-purple-500", "User Administration" }

            div { class: "grid grid-cols-1 md:grid-cols-2 gap-6",
                // User List
                div { class: "bg-gray-900/50 border border-purple-900/30 p-6 rounded col-span-2",
                    h3 { class: "text-lg font-bold text-gray-400 mb-6", "AUTHORIZED PERSONNEL" }
                    div { class: "space-y-2",
                        match &*users.read_unchecked() {
                            Some(Ok(items)) => rsx! {
                                for user in items.iter() {
                                    div { key: "{user.id}", class: "flex items-center justify-between p-4 bg-gray-800/50 rounded hover:bg-gray-800 transition",
                                        div { class: "flex items-center gap-4",
                                            div { class: "w-10 h-10 rounded-full bg-purple-900/50 flex items-center justify-center text-purple-300 font-bold",
                                                "{user.username.chars().next().unwrap_or('?')}"
                                            }
                                            div {
                                                div { class: "font-bold text-gray-200", "{user.username}" }
                                                div { class: "text-xs text-gray-500", "Last Active: {user.last_login}" }
                                            }
                                        }
                                        div { class: "flex items-center gap-4",
                                            span { class: "px-2 py-1 bg-purple-900/20 text-purple-300 text-xs rounded border border-purple-900/50", "{user.role}" }
                                            button { class: "text-gray-500 hover:text-red-400", "Revoke" }
                                        }
                                    }
                                }
                            },
                             _ => rsx! { div { class: "text-gray-500", "Loading personnel..." } }
                        }
                    }
                }
            }
        }
    }
}
