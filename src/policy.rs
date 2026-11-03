use std::net::IpAddr;

use anyhow::{Context, Result, bail};
use ipnet::IpNet;
use serde::{Deserialize, Deserializer, Serialize, de::Error as _};
use url::Host;

use crate::domain::DnsName;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum NetworkPolicy {
    Unrestricted {},
    Selected(NetworkSelectors),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct NetworkSelectors {
    include_cidrs: Vec<IpNet>,
    include_domains: Vec<String>,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum UnvalidatedNetworkPolicy {
    Unrestricted {},
    Selected {
        include_cidrs: Vec<IpNet>,
        include_domains: Vec<String>,
    },
}

impl NetworkPolicy {
    pub fn new(include_cidrs: Vec<IpNet>, include_domains: Vec<String>) -> Result<Self> {
        if include_cidrs.is_empty() && include_domains.is_empty() {
            return Ok(Self::unrestricted());
        }
        Self::selected(include_cidrs, include_domains)
    }

    fn selected(include_cidrs: Vec<IpNet>, include_domains: Vec<String>) -> Result<Self> {
        Ok(Self::Selected(NetworkSelectors {
            include_cidrs: normalize_cidrs(include_cidrs),
            include_domains: normalize_domains(include_domains)?,
        }))
    }

    pub fn unrestricted() -> Self {
        Self::Unrestricted {}
    }
    pub fn is_unrestricted(&self) -> bool {
        matches!(self, Self::Unrestricted {})
    }
    pub fn is_empty(&self) -> bool {
        !self.is_unrestricted()
            && self.include_cidrs().is_empty()
            && self.include_domains().is_empty()
    }

    pub fn include_cidrs(&self) -> &[IpNet] {
        match self {
            Self::Unrestricted {} => &[],
            Self::Selected(selectors) => &selectors.include_cidrs,
        }
    }
    pub fn include_domains(&self) -> &[String] {
        match self {
            Self::Unrestricted {} => &[],
            Self::Selected(selectors) => &selectors.include_domains,
        }
    }
    pub fn allows_name_resolution(&self) -> bool {
        self.is_unrestricted() || !self.include_domains().is_empty()
    }
    pub(crate) fn allows_ipv6(&self) -> bool {
        self.allows_name_resolution()
            || self
                .include_cidrs()
                .iter()
                .any(|network| network.addr().is_ipv6())
    }
    pub fn matches_domain(&self, hostname: &str) -> bool {
        let Some(hostname) = normalize_candidate_domain(hostname) else {
            return false;
        };
        self.include_domains()
            .iter()
            .any(|suffix| domain_matches_suffix(&hostname, suffix))
    }
    pub(crate) fn matches_dns_name(&self, name: &DnsName) -> bool {
        self.include_domains()
            .iter()
            .any(|suffix| name.ends_with_ascii_suffix(suffix))
    }
    pub fn contains_ip(&self, address: IpAddr) -> bool {
        self.include_cidrs()
            .iter()
            .any(|network| network.contains(&address))
    }
    pub(crate) fn contains_exact_ip(&self, address: IpAddr) -> bool {
        self.include_cidrs().iter().any(|network| {
            network.prefix_len() == network.max_prefix_len() && network.addr() == address
        })
    }

    /// Computes the access available through both policies, preserving an empty intersection.
    pub fn intersection(&self, other: &Self) -> Self {
        if self.is_unrestricted() {
            return other.clone();
        }
        if other.is_unrestricted() {
            return self.clone();
        }
        let mut cidrs = Vec::new();
        for left in self.include_cidrs() {
            for right in other.include_cidrs() {
                if left.contains(&right.network()) {
                    cidrs.push(*right);
                } else if right.contains(&left.network()) {
                    cidrs.push(*left);
                }
            }
        }
        let mut domains = Vec::new();
        for left in self.include_domains() {
            for right in other.include_domains() {
                if domain_matches_suffix(left, right) {
                    domains.push(left.clone());
                } else if domain_matches_suffix(right, left) {
                    domains.push(right.clone());
                }
            }
        }
        Self::selected(cidrs, domains).expect("intersected selectors are normalized")
    }
}

impl Default for NetworkPolicy {
    fn default() -> Self {
        Self::unrestricted()
    }
}

impl<'de> Deserialize<'de> for NetworkPolicy {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        match UnvalidatedNetworkPolicy::deserialize(deserializer)? {
            UnvalidatedNetworkPolicy::Unrestricted {} => Ok(Self::unrestricted()),
            UnvalidatedNetworkPolicy::Selected {
                include_cidrs,
                include_domains,
            } => Self::selected(include_cidrs, include_domains).map_err(D::Error::custom),
        }
    }
}

fn normalize_cidrs(include_cidrs: Vec<IpNet>) -> Vec<IpNet> {
    let mut candidates = include_cidrs
        .into_iter()
        .map(|network| network.trunc())
        .collect::<Vec<_>>();
    candidates.sort_unstable();

    let mut previous: Option<IpNet> = None;
    candidates.retain(|candidate| {
        // Canonical CIDRs sort by address, then prefix length. Retained ranges
        // are disjoint, so only the last one can contain the next candidate.
        if previous.is_some_and(|existing| existing.contains(&candidate.network())) {
            return false;
        }
        previous = Some(*candidate);
        true
    });
    candidates.shrink_to_fit();
    candidates
}

fn normalize_domains(include_domains: Vec<String>) -> Result<Vec<String>> {
    let mut candidates = include_domains
        .into_iter()
        .map(|domain| normalize_domain(&domain))
        .collect::<Result<Vec<_>>>()?;
    candidates.sort_unstable_by(|left, right| left.rsplit('.').cmp(right.rsplit('.')));

    let mut normalized: Vec<String> = Vec::new();
    for candidate in candidates {
        // Sorting from the root label keeps each suffix before its descendants.
        // Only the last retained suffix can cover the next name.
        if normalized
            .last()
            .is_some_and(|existing| domain_matches_suffix(&candidate, existing))
        {
            continue;
        }
        normalized.push(candidate);
    }
    normalized.sort_unstable_by(|left, right| {
        left.split('.')
            .count()
            .cmp(&right.split('.').count())
            .then_with(|| left.cmp(right))
    });
    Ok(normalized)
}

fn normalize_domain(value: &str) -> Result<String> {
    let trimmed = value.trim();
    let domain = trimmed.strip_suffix('.').unwrap_or(trimmed);
    if domain.is_empty() {
        bail!("network include domain must not be empty");
    }
    if domain.contains('*') {
        bail!(
            "network include domain `{value}` must not contain a wildcard; the apex already includes every subdomain"
        );
    }

    let canonical = match Host::parse(domain)
        .with_context(|| format!("invalid network include domain `{value}`"))?
    {
        Host::Domain(domain) => domain,
        Host::Ipv4(_) | Host::Ipv6(_) => {
            bail!("network include domain `{value}` is an IP address; use --include-cidr")
        }
    };
    validate_dns_name(&canonical)
        .with_context(|| format!("invalid network include domain `{value}`"))?;
    Ok(canonical)
}

fn normalize_candidate_domain(value: &str) -> Option<String> {
    let domain = value.strip_suffix('.').unwrap_or(value);
    if domain.is_empty() {
        return None;
    }
    match Host::parse(domain).ok()? {
        Host::Domain(domain) => Some(domain),
        Host::Ipv4(_) | Host::Ipv6(_) => None,
    }
}

fn validate_dns_name(domain: &str) -> Result<()> {
    if domain.len() > 253 {
        bail!("domain name exceeds 253 bytes");
    }
    for label in domain.split('.') {
        if label.is_empty() {
            bail!("domain name contains an empty label");
        }
        if label.len() > 63 {
            bail!("domain label exceeds 63 bytes");
        }
        if label.starts_with('-') || label.ends_with('-') {
            bail!("domain label must not start or end with a hyphen");
        }
        if !label
            .bytes()
            .all(|character| character.is_ascii_alphanumeric() || character == b'-')
        {
            bail!("domain label contains a character other than a letter, digit, or hyphen");
        }
    }
    Ok(())
}

fn domain_matches_suffix(hostname: &str, suffix: &str) -> bool {
    hostname == suffix
        || hostname
            .strip_suffix(suffix)
            .is_some_and(|prefix| prefix.ends_with('.'))
}

#[cfg(test)]
mod tests {
    use super::NetworkPolicy;
    use crate::domain::DnsName;

    #[test]
    fn empty_policy_is_unrestricted() {
        let policy = NetworkPolicy::default();

        assert!(policy.is_unrestricted());
        assert!(policy.allows_name_resolution());
    }

    #[test]
    fn cidrs_are_canonicalized_and_redundant_networks_are_removed() {
        let policy = NetworkPolicy::new(
            vec![
                "10.20.4.7/16".parse().unwrap(),
                "10.20.8.0/24".parse().unwrap(),
                "2001:db8:1::9/48".parse().unwrap(),
                "10.20.0.0/16".parse().unwrap(),
            ],
            Vec::new(),
        )
        .unwrap();

        assert_eq!(
            policy
                .include_cidrs()
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            ["10.20.0.0/16", "2001:db8:1::/48"]
        );
        assert!(!policy.is_unrestricted());
        assert!(!policy.allows_name_resolution());
        assert!(policy.allows_ipv6());
        assert!(policy.contains_ip("10.20.255.254".parse().unwrap()));
        assert!(policy.contains_ip("2001:db8:1:ffff::1".parse().unwrap()));
        assert!(!policy.contains_ip("10.21.0.1".parse().unwrap()));
        assert!(!policy.contains_ip("2001:db8:2::1".parse().unwrap()));
    }

    #[test]
    fn cidr_normalization_preserves_adjacent_selectors_and_removes_nested_selectors() {
        let expected = [
            "0.0.0.0/32",
            "10.0.0.0/8",
            "11.0.0.0/9",
            "11.128.0.0/9",
            "255.255.255.255/32",
            "::/128",
            "2001:db8::/32",
            "2001:db9::/33",
            "2001:db9:8000::/33",
            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128",
        ]
        .map(|value| value.parse().unwrap());
        let mut input = expected.to_vec();
        for nested in [
            "10.0.0.7/16",
            "10.255.255.255/32",
            "11.255.255.255/32",
            "2001:db8::7/64",
            "2001:db8:ffff:ffff::/64",
            "2001:db9:8000::1/128",
        ] {
            input.push(nested.parse().unwrap());
        }
        input.extend(expected);
        input.reverse();
        let policy = NetworkPolicy::new(input, Vec::new()).unwrap();
        assert_eq!(policy.include_cidrs(), expected);
        let all = NetworkPolicy::new(
            expected
                .into_iter()
                .chain(["0.0.0.1/0".parse().unwrap(), "::1/0".parse().unwrap()])
                .collect(),
            Vec::new(),
        )
        .unwrap();
        assert_eq!(
            all.include_cidrs(),
            [
                "0.0.0.0/0".parse::<ipnet::IpNet>().unwrap(),
                "::/0".parse().unwrap()
            ]
        );
        assert!(!all.is_unrestricted());
    }

    #[test]
    fn ipv4_only_cidr_policy_does_not_require_ipv6_interface_state() {
        let policy = NetworkPolicy::new(vec!["192.0.2.0/24".parse().unwrap()], Vec::new()).unwrap();

        assert!(!policy.allows_ipv6());
    }

    #[test]
    fn domains_are_idna_normalized_and_redundant_suffixes_are_removed() {
        let policy = NetworkPolicy::new(
            Vec::new(),
            vec![
                "Login.BÜCHER.example.".to_string(),
                "BÜCHER.example".to_string(),
                "xn--bcher-kva.example".to_string(),
            ],
        )
        .unwrap();

        assert_eq!(policy.include_domains(), ["xn--bcher-kva.example"]);
        assert!(policy.matches_domain("xn--bcher-kva.example"));
        assert!(policy.matches_domain("login.bücher.example."));
        assert!(!policy.matches_domain("notbÜcher.example"));
    }

    #[test]
    fn domain_normalization_preserves_label_boundaries_and_presentation_order() {
        let policy = NetworkPolicy::new(
            Vec::new(),
            [
                "deep.a.b.example",
                "login.BÜCHER.example",
                "x.ab.example",
                "ORG.",
                "ab.example",
                "x.a.example",
                "a.b.example",
                "a.example",
                "xn--bcher-kva.example",
                "b.a-example",
                "a.example.org",
                "org",
            ]
            .map(str::to_string)
            .to_vec(),
        )
        .unwrap();
        assert_eq!(
            policy.include_domains(),
            [
                "org",
                "a.example",
                "ab.example",
                "b.a-example",
                "xn--bcher-kva.example",
                "a.b.example",
            ]
        );
    }

    #[test]
    fn domain_selector_matches_the_apex_and_only_label_bounded_subdomains() {
        let policy = NetworkPolicy::new(Vec::new(), vec!["anthem.com".to_string()]).unwrap();

        assert!(policy.matches_domain("anthem.com"));
        assert!(policy.matches_domain("login.care.anthem.com"));
        assert!(!policy.matches_domain("notanthem.com"));
        assert!(!policy.matches_domain("anthem.com.example"));
    }

    #[test]
    fn domain_selector_accepts_arbitrary_query_labels_under_the_suffix() {
        let policy =
            NetworkPolicy::new(Vec::new(), vec!["elevancehealth.com".to_string()]).unwrap();

        assert!(policy.matches_domain("_service.jira.elevancehealth.com"));
        assert!(
            policy.matches_dns_name(
                &DnsName::from_ascii("_SERVICE.Jira.ElevanceHealth.Com").unwrap()
            )
        );
        assert!(
            policy.matches_dns_name(
                &DnsName::from_wire_labels(vec![
                    vec![b'c', b'a', b'c', b'h', b'e', b'.', b'k', b'e', b'y'],
                    b"jira".to_vec(),
                    b"elevancehealth".to_vec(),
                    b"com".to_vec(),
                ])
                .unwrap()
            )
        );
        assert!(!policy.matches_domain("_service.jira.notelevancehealth.com"));
    }

    #[test]
    fn wildcard_ip_and_malformed_domain_selectors_are_rejected() {
        for domain in [
            "*.anthem.com",
            "192.0.2.1",
            "[2001:db8::1]",
            "bad_label.example",
            "-bad.example",
            "anthem..com",
            ".",
        ] {
            assert!(
                NetworkPolicy::new(Vec::new(), vec![domain.to_string()]).is_err(),
                "selector unexpectedly accepted: {domain}"
            );
        }
    }

    #[test]
    fn serialized_policy_uses_normalized_cidr_and_domain_lists() {
        let policy = NetworkPolicy::new(
            vec!["10.20.4.7/16".parse().unwrap()],
            vec!["ANTHEM.COM".to_string()],
        )
        .unwrap();

        let encoded = serde_json::to_value(&policy).unwrap();
        assert_eq!(
            encoded["include_cidrs"],
            serde_json::json!(["10.20.0.0/16"])
        );
        assert_eq!(
            encoded["include_domains"],
            serde_json::json!(["anthem.com"])
        );

        let decoded: NetworkPolicy = serde_json::from_value(encoded).unwrap();
        assert_eq!(decoded, policy);
    }

    #[test]
    fn deserialization_enforces_domain_validation() {
        let result = serde_json::from_value::<NetworkPolicy>(serde_json::json!({
            "kind": "selected",
            "include_cidrs": [],
            "include_domains": ["*.example.com"]
        }));

        assert!(result.is_err());
    }
    #[test]
    fn intersection_narrows_cidrs_and_domain_suffixes() {
        let first = NetworkPolicy::new(
            vec![
                "10.0.0.0/8".parse().unwrap(),
                "2001:db8::/32".parse().unwrap(),
            ],
            vec!["example.com".to_string()],
        )
        .unwrap();
        let second = NetworkPolicy::new(
            vec![
                "10.20.0.0/16".parse().unwrap(),
                "2001:db8:20::/48".parse().unwrap(),
            ],
            vec!["api.example.com".to_string()],
        )
        .unwrap();
        let intersection = first.intersection(&second);
        assert_eq!(intersection, second);
        assert_eq!(intersection, second.intersection(&first));
        assert_eq!(
            intersection,
            NetworkPolicy::unrestricted().intersection(&second)
        );
    }

    #[test]
    fn empty_intersections_remain_denied_when_serialized() {
        let first = NetworkPolicy::new(vec!["10.0.0.0/8".parse().unwrap()], Vec::new()).unwrap();
        let second = NetworkPolicy::new(vec!["192.0.2.0/24".parse().unwrap()], Vec::new()).unwrap();
        let denied = first.intersection(&second);
        assert!(denied.is_empty());
        assert!(!denied.is_unrestricted());
        let decoded: NetworkPolicy =
            serde_json::from_value(serde_json::to_value(&denied).unwrap()).unwrap();
        assert_eq!(decoded, denied);
        assert!(decoded.is_empty());
    }
}
