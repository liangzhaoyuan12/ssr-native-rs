pub fn is_numeric(s: &str) -> bool {
    s.chars().all(|c| c.is_ascii_digit())
}

pub fn set_nofile_limit(_limit: u64) {
    #[cfg(unix)]
    {
        if let Err(e) = rlimit::setrlimit(rlimit::Resource::NOFILE, _limit, _limit) {
            log::warn!("setrlimit NOFILE failed: {}", e);
        }
    }
}
