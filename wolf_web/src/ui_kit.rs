#![allow(non_snake_case)]
use dioxus::prelude::*;

#[derive(Props, Clone, PartialEq)]
pub struct CardProps {
    #[props(default = String::new())]
    class: String,
    children: Element,
}

#[component]
pub fn Card(props: CardProps) -> Element {
    rsx! {
        div { class: "border border-green-800 bg-black/80 backdrop-blur-sm p-6 rounded relative overflow-hidden group hover:border-green-500/50 transition-all duration-300 {props.class}",
            {props.children}
        }
    }
}

#[derive(Props, Clone, PartialEq)]
pub struct ButtonProps {
    #[props(default = String::new())]
    class: String,
    #[props(default = false)]
    disabled: bool,
    #[props(optional)]
    onclick: Option<EventHandler<MouseEvent>>,
    children: Element,
}

#[component]
pub fn Button(props: ButtonProps) -> Element {
    rsx! {
        button {
            class: "px-4 py-2 border border-green-600 bg-green-900/10 hover:bg-green-500 hover:text-black hover:shadow-[0_0_15px_rgba(34,197,94,0.6)] transition-all duration-200 uppercase font-bold tracking-wider text-sm disabled:opacity-50 disabled:cursor-not-allowed {props.class}",
            disabled: props.disabled,
            onclick: move |evt| if let Some(handler) = &props.onclick {
                handler.call(evt);
            },
            {props.children}
        }
    }
}

#[derive(Props, Clone, PartialEq)]
pub struct BadgeProps {
    label: String,
    #[props(default = "green".to_string())]
    color: String, // green, red, yellow, blue
}

#[component]
pub fn Badge(props: BadgeProps) -> Element {
    let (bg, text, border) = match props.color.as_str() {
        "red" => ("bg-red-900/20", "text-red-400", "border-red-500/30"),
        "yellow" => ("bg-yellow-900/20", "text-yellow-400", "border-yellow-500/30"),
        "blue" => ("bg-blue-900/20", "text-blue-400", "border-blue-500/30"),
        _ => ("bg-green-900/20", "text-green-400", "border-green-500/30"),
    };

    rsx! {
        span { class: "px-2 py-1 text-xs font-mono font-bold uppercase rounded border {bg} {text} {border}",
            "{props.label}"
        }
    }
}

#[derive(Props, Clone, PartialEq)]
pub struct SparklineProps {
    data: Vec<f32>,
    #[props(default = 100.0)]
    width: f32,
    #[props(default = 30.0)]
    height: f32,
    #[props(default = "green".to_string())]
    color: String,
}

#[component]
pub fn Sparkline(props: SparklineProps) -> Element {
    if props.data.len() < 2 {
        return rsx! { div { "No Data" } };
    }

    let min = props.data.iter().fold(f32::INFINITY, |a, &b| a.min(b));
    let max = props.data.iter().fold(f32::NEG_INFINITY, |a, &b| a.max(b));
    let range = max - min;
    let step = props.width / (props.data.len() - 1) as f32;

    let points = props.data.iter().enumerate().map(|(i, &d)| {
        let x = i as f32 * step;
        let y = props.height - ((d - min) / range * props.height);
        format!("{},{}", x, y)
    }).collect::<Vec<_>>().join(" ");

    let stroke = match props.color.as_str() {
        "red" => "#ef4444",
        "yellow" => "#eab308",
        _ => "#22c55e",
    };

    rsx! {
        svg {
            width: "{props.width}",
            height: "{props.height}",
            view_box: "0 0 {props.width} {props.height}",
            fill: "none",
            stroke: "{stroke}",
            stroke_width: "2",
            polyline { points: "{points}" }
        }
    }
}
