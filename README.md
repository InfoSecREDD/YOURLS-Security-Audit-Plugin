# Advanced Security Audit and URL Threat Detection Pro

A robust security plugin for YOURLS (Your Own URL Shortener) that protects your users from malicious URLs through threat detection, audit logging, and automatic disabling of dangerous links.

## Features

- **Real-time Threat Detection**: Checks URLs against multiple security APIs before shortening
- **Periodic Security Scanning**: Automatically rechecks existing shortened URLs for new threats
- **Automatic Disabling**: Redirects malicious URLs to a warning page to protect users
- **Multiple API Integration**:
  - Google Safe Browsing integration
  - Bing URL Reputation API support
  - Internal heuristic checks
- **Performance Optimized**:
  - Response caching to minimize API calls
  - Batched processing of URL security checks
- **Admin Configuration**:
  - Material Design admin dashboard
  - Configurable cache expiration
  - Domain whitelisting
- **Comprehensive Audit Logging**: Detailed logs of all security events and URL activities

## Installation

1. Download the plugin files
2. Create a `yourl_audit` directory in your YOURLS `user/plugins/` folder
3. Upload the plugin files to the new directory
4. Activate the plugin from the YOURLS admin interface
5. Configure your API keys and settings

## Configuration

### API Keys

For maximum security, it's recommended to configure both Google Safe Browsing and Bing URL Reputation APIs:

1. **Google Safe Browsing API**:
   - Get an API key from the [Google Cloud Console](https://console.cloud.google.com/)
   - Enable the Safe Browsing API in your Google Cloud project
   - Enter your API key in the plugin settings

2. **Bing URL Reputation API**:
   - Get an API key from [Microsoft Azure](https://azure.microsoft.com/)
   - Configure the Bing Web Search API
   - Enter your API key in the plugin settings

### Plugin Settings

Access the plugin settings at Admin → Security Audit Dashboard:

- **Cache Expiration**: Control how long threat check results are cached (in seconds)
- **Whitelisted Domains**: Comma-separated list of trusted domains to bypass checks
- **Fail Open on API Error**: Determine behavior when APIs are unavailable

## How It Works

### New URL Shortening

When a user attempts to shorten a URL:
1. The plugin checks if the domain is whitelisted
2. If not whitelisted, it performs threat detection through:
   - Internal pattern matching for suspicious keywords
   - Google Safe Browsing API (if configured)
   - Bing URL Reputation API (if configured)
3. If any threats are detected, the URL is blocked with a detailed error message
4. If no threats are found, the URL is shortened normally with an audit log entry

### Existing URL Monitoring

The plugin continuously protects your users by:
1. Periodically checking batches of existing URLs (every hour)
2. If a URL is flagged as malicious after it was shortened:
   - The URL is automatically disabled
   - The shortened link is redirected to a warning page
   - The event is logged in the audit log
   - Users are protected from the newly-discovered threat

### Warning Page

When a user clicks a disabled link, they'll see a warning page explaining:
- That the link was disabled for security reasons
- The specific reason the URL was flagged
- The shortened URL ID for reference

## Security Best Practices

For maximum security:
1. Configure both Google and Bing APIs for redundant protection
2. Set appropriate cache expiration times (shorter times provide more security but increase API usage)
3. Only whitelist domains you absolutely trust
4. Regularly review the audit logs for suspicious patterns
5. Keep the plugin updated to the latest version

## Troubleshooting

### API Issues
- Ensure your API keys are correctly entered and have the proper permissions
- Check that you have sufficient quota for your API calls
- If APIs are unreliable in your environment, consider enabling "Fail open on API error"

### Performance Concerns
- Increase the cache expiration time to reduce API calls
- Add frequently-used trusted domains to the whitelist
- The plugin limits batch processing to 10 URLs at a time to prevent overloading

## Support and Development

- **Author**: InfoSecREDD
- **Website**: https://infosecredd.dev
- **Version**: 3.1

For issues, feature requests, or contributions, please contact the author or submit through the project repository.

## License

This plugin is licensed under MIT - see the plugin page for details.

---

*Protect your users from malicious links with Advanced Security Audit and URL Threat Detection Pro - because security matters in URL shortening.*
