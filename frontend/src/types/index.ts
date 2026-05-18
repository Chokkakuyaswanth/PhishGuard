export type RiskLevel = 'safe' | 'suspicious' | 'malicious' | 'unknown'

export interface ThreatIndicator {
  type: string
  severity: 'low' | 'medium' | 'high' | 'critical'
  description: string
  source: string
  value?: string
}

export interface URLFeatures {
  url_length: number
  domain_length: number
  subdomain_count: number
  has_ip: boolean
  uses_https: boolean
  dot_count: number
  hyphen_count: number
  special_char_count: number
  digit_ratio: number
  entropy: number
  suspicious_keywords: number
  is_url_shortener: boolean
  tld_risk: number
  path_depth: number
  query_param_count: number
  has_encoded_chars: boolean
  [key: string]: unknown
}

export interface CTIResult {
  virustotal?: Record<string, unknown>
  urlhaus?: Record<string, unknown>
  whois?: Record<string, unknown>
  enriched: boolean
}

export interface ScanResult {
  id?: string
  url: string
  score: number
  level: RiskLevel
  ml_probability: number
  features?: URLFeatures
  cti?: CTIResult
  indicators: ThreatIndicator[]
  explanation: string[]
  scanned_at?: string
  source: string
}

export interface ScanRequest {
  url: string
  source?: string
}
