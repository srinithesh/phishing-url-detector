# Phishing URL Detector
# Uses heuristic analysis to detect potential phishing URLs
# Cybersecurity Portfolio Project - Author: [Your Name]

import re
from urllib.parse import urlparse

# Known phishing indicators
SUSPICIOUS_KEYWORDS = [
    'login', 'signin', 'verify', 'secure', 'account',
    'update', 'confirm', 'banking', 'paypal', 'amazon',
    'netflix', 'microsoft', 'apple', 'google', 'facebook'
]

TRUSTED_DOMAINS = [
    'google.com', 'facebook.com', 'amazon.com', 
    'microsoft.com', 'apple.com', 'paypal.com',
    'netflix.com', 'twitter.com', 'instagram.com'
]

def analyze_url(url):
    """
    Analyzes URL for phishing indicators
    Returns risk score and detailed analysis
    """
    risk_score = 0
    indicators = []
    safe_signs = []
    
    # Add http if missing for parsing
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()
        full_url = url.lower()
    except:
        return 10, ["❌ Invalid URL format"], [], "INVALID"
    
    # Check 1: HTTPS
    if url.startswith('https://'):
        safe_signs.append("✅ Uses HTTPS (encrypted connection)")
    else:
        risk_score += 2
        indicators.append("🚨 No HTTPS - data not encrypted")
    
    # Check 2: IP address instead of domain
    if re.match(r'\d+\.\d+\.\d+\.\d+', domain):
        risk_score += 3
        indicators.append("🚨 Uses IP address instead of domain name")
    
    # Check 3: URL length
    if len(url) > 75:
        risk_score += 1
        indicators.append(f"⚠️ Unusually long URL ({len(url)} chars)")
    else:
        safe_signs.append("✅ Normal URL length")
    
    # Check 4: Multiple subdomains
    subdomain_count = domain.count('.')
    if subdomain_count > 3:
        risk_score += 2
        indicators.append(f"⚠️ Many subdomains ({subdomain_count} dots) - suspicious")
    
    # Check 5: Suspicious keywords in URL
    found_keywords = []
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in full_url:
            found_keywords.append(keyword)
    
    if found_keywords:
        risk_score += len(found_keywords)
        indicators.append(f"⚠️ Suspicious keywords: {', '.join(found_keywords)}")
    
    # Check 6: Legitimate brand names in suspicious domains
    for trusted in TRUSTED_DOMAINS:
        brand = trusted.split('.')[0]
        if brand in domain and trusted not in domain:
            risk_score += 4
            indicators.append(f"🚨 DANGER: '{brand}' in URL but not official {trusted}")
    
    # Check 7: Hyphens in domain (common in phishing)
    hyphen_count = domain.count('-')
    if hyphen_count > 1:
        risk_score += 1
        indicators.append(f"⚠️ Multiple hyphens in domain ({hyphen_count})")
    
    # Check 8: Special characters in URL
    if '@' in url:
        risk_score += 3
        indicators.append("🚨 '@' symbol in URL - classic phishing trick")
    
    # Check 9: Double slash redirect
    if '//' in parsed.path:
        risk_score += 2
        indicators.append("⚠️ Double slash in path - possible redirect")
    
    # Check 10: .exe or suspicious file extensions
    suspicious_ext = ['.exe', '.zip', '.rar', '.bat', '.cmd']
    for ext in suspicious_ext:
        if ext in path:
            risk_score += 3
            indicators.append(f"🚨 Suspicious file extension: {ext}")
    
    # Determine risk level
    if risk_score == 0:
        risk_level = "✅ SAFE"
    elif risk_score <= 2:
        risk_level = "🟡 LOW RISK"
    elif risk_score <= 5:
        risk_level = "🟠 MEDIUM RISK"
    elif risk_score <= 8:
        risk_level = "🔴 HIGH RISK"
    else:
        risk_level = "🚨 VERY HIGH RISK - LIKELY PHISHING"
    
    return risk_score, indicators, safe_signs, risk_level


def main():
    print("=" * 55)
    print("🎣 PHISHING URL DETECTOR")
    print("   Cybersecurity Portfolio Project")
    print(f"   By [Your Name] | DSU Cybersecurity")
    print("=" * 55)
    print()
    
    while True:
        url = input("Enter URL to analyze (or 'quit'): ").strip()
        
        if url.lower() == 'quit':
            print("\nStay safe online! 🛡️")
            break
        
        if not url:
            continue
        
        score, indicators, safe_signs, risk_level = analyze_url(url)
        
        print(f"\n{'='*55}")
        print(f"URL: {url}")
        print(f"Risk Level: {risk_level}")
        print(f"Risk Score: {score}/10")
        
        if safe_signs:
            print(f"\n✅ Positive Signs:")
            for sign in safe_signs:
                print(f"   {sign}")
        
        if indicators:
            print(f"\n⚠️ Risk Indicators Found:")
            for indicator in indicators:
                print(f"   {indicator}")
        
        print(f"\n{'Recommendation':}")
        if score <= 2:
            print("   Appears safe but always stay cautious")
        elif score <= 5:
            print("   Proceed with caution - verify the source")
        else:
            print("   DO NOT click or enter any information!")
        
        print("=" * 55 + "\n")


if __name__ == "__main__":
    main()
