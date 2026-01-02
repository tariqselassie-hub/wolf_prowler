use crate::dashboard::state::{MetricPoint, SystemMetricsData};
use chrono::Utc;
use std::sync::Arc;

use tokio::sync::RwLock;
use tokio::time::{interval, Duration};

const MAX_HISTORY_POINTS: usize = 100;

/// Background task that continuously updates system metrics with real data
use sysinfo::{ProcessesToUpdate, System, Networks, Disks};
// ... imports


pub async fn system_metrics_collector(system_metrics: Arc<RwLock<SystemMetricsData>>) {
    let mut sys = System::new_all();
    let mut networks = Networks::new_with_refreshed_list();
    let mut disks = Disks::new_with_refreshed_list();
    let mut interval = interval(Duration::from_secs(2)); // Update every 2 seconds

    loop {
        interval.tick().await;

        // Refresh system information
        sys.refresh_cpu_all();
        sys.refresh_memory();
        sys.refresh_processes(ProcessesToUpdate::All, true);
        networks.refresh(true);
        disks.refresh(true);

        // Calculate average CPU usage across all cores
        let cpu_usage = sys.global_cpu_usage() as f64;

        // Calculate memory usage percentage
        let memory_usage = (sys.used_memory() as f64 / sys.total_memory() as f64) * 100.0;

        // Get process count
        let process_count = sys.processes().len();

        // Calculate Network I/O (Sum across all interfaces)
        let mut rx = 0;
        let mut tx = 0;
        for (_interface_name, data) in &networks {
            rx += data.received();
            tx += data.transmitted();
        }
        // Conversion to KB/s
        let rx_kbps = (rx as f64 / 2.0) / 1024.0;
        let tx_kbps = (tx as f64 / 2.0) / 1024.0;

        // Disk Usage (Root partition)
        // Find disk mounted at "/" or take first one
        let mut disk_usage_percent = 0.0;
        for disk in &disks {
            if disk.mount_point().to_str() == Some("/") {
                 disk_usage_percent = (disk.total_space() - disk.available_space()) as f64 / disk.total_space() as f64 * 100.0;
                 break;
            }
        }
        
        // Update the shared state
        let mut metrics = system_metrics.write().await;
        let now = Utc::now();

        // Update current values
        metrics.current_cpu_usage = cpu_usage;
        metrics.current_memory_usage = memory_usage;
        metrics.process_count = process_count;
        metrics.current_network_rx_kbps = rx_kbps;
        metrics.current_network_tx_kbps = tx_kbps;
        metrics.current_disk_usage_percent = disk_usage_percent; // Placeholder until verified

        // Add to CPU history
        metrics.cpu_usage_history.push_back(MetricPoint {
            timestamp: now,
            value: cpu_usage,
        });
        if metrics.cpu_usage_history.len() > MAX_HISTORY_POINTS {
            metrics.cpu_usage_history.pop_front();
        }

        // Add to Memory history
        metrics.memory_usage_history.push_back(MetricPoint {
            timestamp: now,
            value: memory_usage,
        });
        if metrics.memory_usage_history.len() > MAX_HISTORY_POINTS {
            metrics.memory_usage_history.pop_front();
        }

        drop(metrics); // Release lock
    }
}
