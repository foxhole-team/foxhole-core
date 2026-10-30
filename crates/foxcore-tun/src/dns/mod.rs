mod lease;
mod proxy;
mod upstream;

#[cfg(test)]
mod tests;

pub(crate) use lease::DnsQueryLease;
pub(crate) use proxy::*;
pub(crate) use upstream::*;
