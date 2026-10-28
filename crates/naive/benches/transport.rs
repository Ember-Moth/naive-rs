//! Standalone release benchmark. tests/perf/run.py supplies the local server.
use naive::{Config, NaiveClient, NaiveStream};
use std::{
    collections::HashMap,
    env,
    time::{Duration, Instant},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[cfg(unix)]
fn usage() -> (f64, u64) {
    let mut r = std::mem::MaybeUninit::<libc::rusage>::uninit();
    // SAFETY: getrusage initializes r on success.
    assert_eq!(
        unsafe { libc::getrusage(libc::RUSAGE_SELF, r.as_mut_ptr()) },
        0
    );
    let r = unsafe { r.assume_init() };
    let cpu = r.ru_utime.tv_sec as f64
        + r.ru_utime.tv_usec as f64 / 1e6
        + r.ru_stime.tv_sec as f64
        + r.ru_stime.tv_usec as f64 / 1e6;
    let rss = r.ru_maxrss as u64
        * if cfg!(target_vendor = "apple") {
            1
        } else {
            1024
        };
    (cpu, rss)
}

#[cfg(unix)]
fn rss_now() -> u64 {
    let output = std::process::Command::new("ps")
        .args(["-o", "rss=", "-p", &std::process::id().to_string()])
        .output()
        .unwrap();
    std::str::from_utf8(&output.stdout)
        .unwrap()
        .trim()
        .parse::<u64>()
        .unwrap()
        * 1024
}

#[cfg(windows)]
fn windows_memory() -> windows_sys::Win32::System::ProcessStatus::PROCESS_MEMORY_COUNTERS {
    use windows_sys::Win32::System::{ProcessStatus::*, Threading::GetCurrentProcess};
    let mut counters = unsafe { std::mem::zeroed::<PROCESS_MEMORY_COUNTERS>() };
    counters.cb = std::mem::size_of_val(&counters) as u32;
    let size = counters.cb;
    assert_ne!(
        unsafe { GetProcessMemoryInfo(GetCurrentProcess(), &mut counters, size) },
        0
    );
    counters
}
#[cfg(windows)]
fn usage() -> (f64, u64) {
    use windows_sys::Win32::{
        Foundation::FILETIME,
        System::Threading::{GetCurrentProcess, GetProcessTimes},
    };
    let mut created: FILETIME = unsafe { std::mem::zeroed() };
    let mut exited = created;
    let mut kernel = created;
    let mut user = created;
    assert_ne!(
        unsafe {
            GetProcessTimes(
                GetCurrentProcess(),
                &mut created,
                &mut exited,
                &mut kernel,
                &mut user,
            )
        },
        0
    );
    let ticks = |time: FILETIME| ((time.dwHighDateTime as u64) << 32) | time.dwLowDateTime as u64;
    (
        (ticks(kernel) + ticks(user)) as f64 / 10_000_000.0,
        windows_memory().PeakWorkingSetSize as u64,
    )
}
#[cfg(windows)]
fn rss_now() -> u64 {
    windows_memory().WorkingSetSize as u64
}

fn native_buffers() -> serde_json::Value {
    #[cfg(feature = "perf-tuning")]
    {
        let mut counters = naive_sys::BufferStats::default();
        // SAFETY: writes this POD record; native counters are atomic.
        unsafe {
            naive_sys::naive_get_buffer_stats(&mut counters);
        }
        serde_json::json!({"allocations":counters.allocations,"live_buffers":counters.live_buffers,
            "live_capacity":counters.live_capacity,"peak_capacity":counters.peak_capacity})
    }
    #[cfg(not(feature = "perf-tuning"))]
    {
        serde_json::Value::Null
    }
}

fn configuration(args: &HashMap<String, String>) -> Config {
    let mut config = Config::new(env::var("NAIVE_BENCH_PROXY").unwrap());
    if let Ok(ca) = env::var("NAIVE_BENCH_CA") {
        config.extra_root_certificates = Some(std::fs::read_to_string(ca).unwrap());
    }
    config.host_resolver_rules = Some("MAP localhost 127.0.0.1".into());
    config.connect_timeout = Duration::from_secs(30);
    if let Ok(path) = env::var("NAIVE_BENCH_NETLOG") {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static LOG_INDEX: AtomicUsize = AtomicUsize::new(0);
        if LOG_INDEX.fetch_add(1, Ordering::Relaxed) == 0 {
            config.net_log = Some(path.into());
        }
    }
    #[cfg(feature = "perf-tuning")]
    {
        config.io_workers = args
            .get("io-workers")
            .map(|s| s.parse().unwrap())
            .unwrap_or(1);
    }
    let _ = args;
    config
}

fn quantile(values: &mut [f64], fraction: f64) -> f64 {
    values.sort_by(f64::total_cmp);
    values[((values.len() - 1) as f64 * fraction).round() as usize]
}

async fn warm(stream: &mut NaiveStream) {
    let data = [0x5a; 256];
    let mut receive = [0; 256];
    for _ in 0..10 {
        stream.write_all(&data).await.unwrap();
        stream.flush().await.unwrap();
        stream.read_exact(&mut receive).await.unwrap();
        assert_eq!(data, receive);
    }
}

async fn run(args: HashMap<String, String>) {
    let number = |name: &str, default: usize| {
        args.get(name)
            .map(|v| v.parse().unwrap())
            .unwrap_or(default)
    };
    let mode = args.get("mode").map(String::as_str).unwrap_or("bulk");
    let connections = number("connections", 1);
    let clients_count = number("clients", 1);
    let block = number("block", 65536);
    let total = number("bytes", 128 * 1024 * 1024);
    let iterations = number("iterations", 500);
    let parallel = number("parallel", 1);
    let soak_seconds = number("seconds", 60);
    let origin: u16 = env::var("NAIVE_BENCH_ORIGIN_PORT")
        .unwrap()
        .parse()
        .unwrap();
    let startup = Instant::now();
    let mut clients = Vec::new();
    for _ in 0..clients_count {
        clients.push(NaiveClient::new(configuration(&args)).await.unwrap());
    }
    let cold_init_ms = startup.elapsed().as_secs_f64() * 1000.0;
    let mut connects = tokio::task::JoinSet::new();
    for n in 0..connections {
        let client = clients[n % clients.len()].clone();
        connects.spawn(async move {
            let start = Instant::now();
            let mut stream = client.connect("127.0.0.1", origin).await.unwrap();
            let connect_ms = start.elapsed().as_secs_f64() * 1000.0;
            warm(&mut stream).await;
            (stream, connect_ms)
        });
    }
    let mut streams = Vec::new();
    let mut connect_ms = Vec::new();
    while let Some(result) = connects.join_next().await {
        let (stream, ms) = result.unwrap();
        streams.push(stream);
        connect_ms.push(ms);
    }
    let rss_ready = rss_now();
    let (cpu_start, _) = usage();
    let start = Instant::now();
    let mut latencies = Vec::new();
    let mut payload_bytes = 0;
    let mut tasks = tokio::task::JoinSet::new();
    let mut memory_samples = Vec::new();
    let mut task_failure = None;
    match mode {
        "bulk" | "small-writes" => {
            let bytes = total / connections;
            payload_bytes = bytes * connections;
            for stream in streams.drain(..) {
                tasks.spawn(async move {
                    let (mut read, mut write) = tokio::io::split(stream);
                    let send = async {
                        let buffer = vec![0x5a; block];
                        let mut remaining = bytes;
                        while remaining > 0 {
                            let n = block.min(remaining);
                            write.write_all(&buffer[..n]).await.unwrap();
                            remaining -= n;
                        }
                        write.flush().await.unwrap();
                    };
                    let receive = async {
                        let mut buffer = vec![0; 65536];
                        let mut remaining = bytes;
                        while remaining > 0 {
                            let n = buffer.len().min(remaining);
                            let n = read.read(&mut buffer[..n]).await.unwrap();
                            assert!(n > 0 && buffer[..n].iter().all(|b| *b == 0x5a));
                            remaining -= n;
                        }
                    };
                    tokio::join!(send, receive);
                    Vec::new()
                });
            }
        }
        "latency" => {
            for mut stream in streams.drain(..) {
                tasks.spawn(async move {
                    let buffer = vec![0x5a; block];
                    let mut receive = vec![0; block];
                    let mut values = Vec::with_capacity(iterations);
                    for _ in 0..iterations {
                        let begin = Instant::now();
                        stream.write_all(&buffer).await.unwrap();
                        stream.flush().await.unwrap();
                        stream.read_exact(&mut receive).await.unwrap();
                        assert_eq!(receive, buffer);
                        values.push(begin.elapsed().as_secs_f64() * 1e6);
                    }
                    values
                });
            }
            payload_bytes = iterations * block * connections;
        }
        "idle" => {
            let mut blocked = tokio::task::JoinSet::new();
            for mut stream in streams.drain(..) {
                blocked.spawn(async move {
                    let mut b = [0];
                    let _ = stream.read(&mut b).await;
                });
            }
            tokio::time::sleep(Duration::from_millis(300)).await;
            let resident = rss_now();
            let (cpu, peak) = usage();
            let mut record = serde_json::json!({"mode":mode,"connections":connections,"clients":clients_count,
                "rss_ready_bytes":rss_ready,"rss_blocked_bytes":resident,"peak_rss_bytes":peak,
                "cpu_seconds":cpu-cpu_start,"cold_init_ms":cold_init_ms,"chromium":naive::native_version(),
                "native_buffers":native_buffers()});
            for client in &clients {
                client.shutdown().await.unwrap();
            }
            while let Some(result) = blocked.join_next().await {
                result.unwrap();
            }
            record["native_after_shutdown"] = native_buffers();
            println!("{record}");
            return;
        }
        "churn" => {
            drop(streams);
            for _ in 0..iterations {
                let begin = Instant::now();
                let client = NaiveClient::new(configuration(&args)).await.unwrap();
                client.shutdown().await.unwrap();
                latencies.push(begin.elapsed().as_secs_f64() * 1e6);
            }
        }
        "churn-parallel" => {
            drop(streams);
            for _ in 0..parallel {
                let config = configuration(&args);
                tasks.spawn(async move {
                    let mut result = Vec::new();
                    for _ in 0..iterations / parallel {
                        let start = Instant::now();
                        let client = NaiveClient::new(config.clone()).await.unwrap();
                        client.shutdown().await.unwrap();
                        result.push(start.elapsed().as_secs_f64() * 1e6);
                    }
                    result
                });
            }
        }
        "soak" => {
            let end = Instant::now() + Duration::from_secs(soak_seconds as u64);
            for (i, mut stream) in streams.drain(..).enumerate() {
                let client = clients[i % clients.len()].clone();
                tasks.spawn(async move {
                    let data = vec![0x5a; block];
                    let mut receive = vec![0; block];
                    let mut count = 0;
                    // A message-count cadence makes faster variants exhaust the
                    // loopback server's source-port range (~16k on this host).
                    // Keep reconnect pressure comparable and bounded in time.
                    let mut reconnect_at =
                        Instant::now() + Duration::from_millis(1000 + (i as u64 % 32) * 17);
                    while Instant::now() < end {
                        if count % 41 == 0 {
                            let mut abandoned = [0];
                            assert!(
                                tokio::time::timeout(Duration::ZERO, stream.read(&mut abandoned))
                                    .await
                                    .is_err()
                            );
                        }
                        stream.write_all(&data).await.unwrap();
                        stream.flush().await.unwrap();
                        if let Err(error) = stream.read_exact(&mut receive).await {
                            panic!(
                                "soak stream {i}, messages {count}, elapsed {:.3}s: {error:?}",
                                start.elapsed().as_secs_f64()
                            );
                        }
                        assert_eq!(receive, data);
                        count += 1;
                        if Instant::now() >= reconnect_at {
                            stream.close();
                            stream = client.connect("127.0.0.1", origin).await.unwrap();
                            reconnect_at = Instant::now() + Duration::from_secs(1);
                        }
                    }
                    vec![(count * block) as f64]
                });
            }
            'monitor: for second in 0..soak_seconds {
                tokio::time::sleep(Duration::from_secs(1)).await;
                memory_samples.push(serde_json::json!({"second":second+1,"rss":rss_now(),"buffers":native_buffers()}));
                while let Some(result) = tasks.try_join_next() {
                    match result {
                        Ok(values) => latencies.extend(values),
                        Err(error) => {
                            task_failure = Some(error.to_string());
                            tasks.abort_all();
                            break 'monitor;
                        }
                    }
                }
            }
        }
        _ => panic!("unknown mode"),
    }
    while let Some(result) = tasks.join_next().await {
        match result {
            Ok(values) => latencies.extend(values),
            Err(error) => {
                task_failure.get_or_insert_with(|| error.to_string());
                tasks.abort_all();
            }
        }
    }
    if let Some(error) = task_failure {
        for client in &clients {
            client.shutdown().await.unwrap();
        }
        panic!("benchmark task failed: {error}");
    }
    if mode == "soak" {
        payload_bytes = latencies.iter().sum::<f64>() as usize;
        latencies.clear();
    }
    let seconds = start.elapsed().as_secs_f64();
    let (cpu, peak) = usage();
    let mut result = serde_json::json!({"mode":mode,"connections":connections,"clients":clients_count,
        "block":block,"payload_bytes":payload_bytes,"seconds":seconds,"cpu_seconds":cpu-cpu_start,
        "payload_mib_per_second":payload_bytes as f64/1048576.0/seconds,
        "cpu_ms_per_mib":(cpu-cpu_start)*1000.0/(payload_bytes.max(1) as f64/1048576.0),
        "peak_rss_bytes":peak,"rss_ready_bytes":rss_ready,"cold_init_ms":cold_init_ms,
        "connect_p50_ms":quantile(&mut connect_ms,0.5),"connect_p99_ms":quantile(&mut connect_ms,0.99),
        "chromium":naive::native_version(),"native_buffers":native_buffers(),"memory_samples":memory_samples});
    if !latencies.is_empty() {
        result["p50_us"] = quantile(&mut latencies, 0.5).into();
        result["p95_us"] = quantile(&mut latencies, 0.95).into();
        result["p99_us"] = quantile(&mut latencies, 0.99).into();
    }
    for client in &clients {
        client.shutdown().await.unwrap();
    }
    result["native_after_shutdown"] = native_buffers();
    println!("{result}");
}

fn main() {
    let args: Vec<_> = env::args().skip(1).filter(|a| a != "--bench").collect();
    assert!(args.len() % 2 == 0);
    let args: HashMap<_, _> = args
        .chunks_exact(2)
        .map(|p| (p[0].trim_start_matches("--").to_owned(), p[1].clone()))
        .collect();
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            tokio::time::timeout(Duration::from_secs(90), run(args))
                .await
                .unwrap();
        });
}
